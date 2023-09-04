from unicorn import *
from capstone import *
from unicorn.arm_const import *
from elfParser import *
from setEmulData import *
from logger import *
from scenario import *
from config import * 
import os

# 레퍼런스 파일 생성
def make_refer(input, addr):
    global insn_cnt, refsIdx, reffIdx, MODE, insn_size

    f = open ('reference.txt', 'a')
    if MODE == 2:
        mc = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    else: # MODE == 4
        mc = Cs(CS_ARCH_ARM, CS_MODE_ARM)

    mc.syntax = None
    mc.detail = True
    virtual_addr = 0
    sec_name = ""

    for insn in mc.disasm(input, addr):
        insn_size += insn.size

        if e_sec[refsIdx][1] -2  == insn.address or e_sec[refsIdx][1] == insn.address:
            f.write("\nsection\t\t : %s\n" % e_sec[refsIdx][3])
            if e_sec[refsIdx][0] != 0:
                f.write("REAL ADDRESS : %s\n\n" % hex(e_sec[refsIdx][0]))
                virtual_addr = e_sec[refsIdx][0]
                sec_name = e_sec[refsIdx][3]
                
            refsIdx += 1
            if refsIdx == len(e_sec):
                refsIdx = len(e_sec)-1   
                     
        if func_list[reffIdx][1] == insn.address + (MODE == 2):
            f.write("\nfunction\t : %s\n\n" % (func_list[reffIdx][0]))
            reffIdx += 1
            if reffIdx == len(func_list):
                reffIdx = len(func_list)-1
        
        if virtual_addr != 0 and (sec_name == '.data') :
            f.write("0x%x:[0x%x] " %(insn.address, virtual_addr))
            for j in range(len(insn.bytes)):
                f.write("\\x%x" %insn.bytes[j])
                
        else:
            f.write("0x%x:\t%s\t%s\n" %(insn.address, insn.mnemonic, insn.op_str))
        
        temp_ins = [insn.address, insn.mnemonic, insn.op_str]
        instructions.append(temp_ins)
            
        virtual_addr += MODE

        ins_cnt += 1

    f.close()

    if len(instructions)/int(len(CODE)/MODE) < 1:
        ins_cnt += 1
        retaddr = (START_ADDRESS - (MODE == 2)) + ins_cnt * MODE
        with open(elf_file, "rb") as f:
            f.seek(retaddr,0)
            fcode = f.read()

        return fcode, retaddr
    else:
        return 0, addr

#레지스터 초기화 및 메모리 자동 매핑
def auto_set(uc):
    PAGE_SIZE = 4*1024

    #Flash memory 영역 mapping
    if flash_size > PAGE_SIZE:
        uc.mem_map(START_ADDRESS // (PAGE_SIZE) * (PAGE_SIZE), (flash_size // (PAGE_SIZE) + 1) * (PAGE_SIZE))
    else:
        uc.mem_map(START_ADDRESS // (PAGE_SIZE) * (PAGE_SIZE), (PAGE_SIZE))

    #Ram memory 영역 mapping
    if stack_addr - ram_addr[0] > PAGE_SIZE:
        uc.mem_map((ram_addr[0]) // (PAGE_SIZE) * (PAGE_SIZE), (stack_addr - ram_addr[0] // (PAGE_SIZE) + 1) * (PAGE_SIZE))
    else:
        uc.mem_map((ram_addr[0]) // (PAGE_SIZE) * (PAGE_SIZE), (PAGE_SIZE))

    #레지스터 초기화
    uc.reg_write(UC_ARM_REG_SP, stack_addr)
    uc.reg_write(UC_ARM_REG_FP, stack_addr)
    uc.reg_write(UC_ARM_REG_LR, exit_addr)

#메모리에 데이터 업로드
def upload(uc):
    for i in range(len(e_sec)):
        # read file from start address to eof
        with open(elf_file, "rb") as f:
            f.seek(e_sec[i][1],0)
            cod = f.read(e_sec[i][2])

        if e_sec[i][0] != 0:
            uc.mem_write(e_sec[i][0],cod)

# 입출력 파일 생성
def make_io_data_files(uc, i):
    # Log_VirOUT 파일 생성

    if i == 0:
        with open(log_folder + "/" + date + ' LogVirOUT.csv', 'w') as file:
            wr = csv.writer(file)
            out_data_list = []
            addr = vir_out_addr
            for i in range(vir_out_len // MODE):
                out_data = int.from_bytes(uc.mem_read(addr, MODE), byteorder="little")
                out_data_list.append(out_data)
                addr += MODE
            
            wr.writerow(out_data_list)
    else:
        with open(log_folder + "/" + date + ' LogVirOUT_Faulty.csv', 'w') as file:
            wr = csv.writer(file)
            out_data_list = []
            addr = vir_out_addr
            for i in range(vir_out_len // MODE):
                out_data = int.from_bytes(uc.mem_read(addr, MODE), byteorder="little")
                out_data_list.append(out_data)
                addr += MODE
            
            wr.writerow(out_data_list)

    # Log_VirIN 파일 생성
    in_data_list = []
    with open(log_vir_in_file, 'r') as read:
        rr = csv.reader(read)
        for line in rr:
            in_data_list.append(line)
    with open(log_folder + "/" + date + ' LogVirIN.csv', 'w') as write:
        wr = csv.writer(write)
        wr.writerows(in_data_list)



# CSV -> 입력 데이터 획득
def get_input_data():
    list_vir_in_data = []
    with open(log_vir_in_file, newline='') as file:
        reader = csv.reader(file)
        for row in reader:
            list_vir_in_data.append(list(map(int, row)))
    
    return list_vir_in_data

# 데이터 입력
def input_data(uc, vir_in_data):
    addr = vir_in_addr
    for data in vir_in_data:
        uc.mem_write(addr, data.to_bytes(MODE, byteorder="little"))
        addr += MODE

# 오류 주입 시나리오(+ 입력 데이터 변경) 실행을 위한 콜백 함수
sync_ctr = 0

def scene_hook(uc, address, size, scene_data):
    global sync_ctr

    # 입력 데이터 변경
    vir_in_data = get_input_data()
    
    for i in range(len(vir_in_data)):
        if vir_in_data[i][0] == sync_ctr:
            input_data(uc, vir_in_data[i][1:])

    # 오류 주입 시나리오
    if scene_data.Fault_list and LOG_MATRIX:
        for i in range(len(scene_data.Fault_list)): 
            if hex(address) == LOG_MATRIX[int(scene_data.Fault_list[i]['ctr']) + 1][1]:
                if scene_data.check_nop(i): # NOP 시나리오
                    scene_data.nop(uc)
                else: # 레지스터 수정 시나리오
                    scene_data.modify_regs(uc, i)
    
    sync_ctr += 1
    if address == exit_addr_real - (MODE == 2):
        sync_ctr = 0

# 명령어 당 hooking 시 호출되는 콜백 함수
def code_hook(uc, address, size, scene_data):
    
    write_log_regs(uc, address, scene_data)

    if address == exit_addr_real - (MODE == 2):
        uc.emu_stop()

# 프로그램 실행
def run():

    # reference.txt 파일 생성
    if os.path.isfile('reference.txt'):
        os.remove('reference.txt')

    refcod = REF_CODE
    refaddr = START_ADDRESS - (MODE == 2)

    # while len(instructions)/int(len(CODE)/MODE) < 1:
    while refaddr <= START_ADDRESS  + len(CODE):
        refcod, refaddr = make_refer(refcod,refaddr)
    
    print("Emulating the code..")

    # 시나리오 객체 생성
    scene_data = Scenario()
    
    # 에뮬레이팅
    try:
        if scene_data.Fault_list:
            cnt = 2
        else:
            cnt = 1
        
        for i in range(cnt):
            # 로그 파일 생성
            make_log_file(i)

            # initialize Unicorn
            if MODE == 2: # (thumb mode)
                mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
            else: # MODE == 4 (arm mode)
                mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)

            # 자동 메모리 매핑
            auto_set(mu)

            # 섹션 데이터 메모리에 업로드
            upload(mu)

            # 오류 주입 시나리오 콜백 함수 추가
            mu.hook_add(UC_HOOK_CODE, scene_hook, scene_data, begin= START_ADDRESS, end= START_ADDRESS + len(CODE))
            
            # 콜백 함수 추가
            mu.hook_add(UC_HOOK_CODE, code_hook, scene_data, begin= START_ADDRESS, end= START_ADDRESS + len(CODE))
    
            # main 함수 길이만큼 에뮬레이션 시작
            mu.emu_start(emu_ADDRESS, emu_ADDRESS + main_len)

            print(">>> Emulation done.")

            make_io_data_files(mu, i)

    except UcError as e:
        with open(get_log_file_name(), 'w', newline='') as file:
            write = csv.writer(file)
            write.writerows(log_matrix)

        print("ERROR: %s" % e)
        

