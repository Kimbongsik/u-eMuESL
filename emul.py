from unicorn import *
from capstone import *
from unicorn.arm_const import *
from elfParser import *
from setEmulData import *
from logger import ctr, write_log_regs, make_log_file, log_matrix, LogReg_header
from scenario import *
from config import * 
import os

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

#프로그램 input 데이터
def get_input_data(indata_arr):
    for i in range(len(indata_arr)):
        print("InData%d address is " %(i),end = "")
        print(indata_arr[i])

def get_output_data(uc,out_addr,len_addr):
    output = []
    len_mem = uc.mem_read(len_addr,MODE)
    cvt_len = int.from_bytes(len_mem, byteorder='little')
    # change mem to int
    for i in range(cvt_len):
        out_mem = uc.mem_read(out_addr+i*MODE,MODE)
        cvt_output = int.from_bytes(out_mem,byteorder="little")
        output.append(cvt_output)
    return output

#referenc.txt 파일 생성
def make_refer(input, addr):
    global make_ins_inIdx, make_ins_cnt, refsIdx, reffIdx, MODE

    f = open ('reference.txt', 'a')
    if MODE == 2:
        mc = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    else: # MODE == 4
        mc = Cs(CS_ARCH_ARM, CS_MODE_ARM)

    mc.syntax = None
    mc.detail = True
    virtual_addr = 0
    sec_name = ""
    num = 0
    # copy mnemonics to copy_mne
    # add modified register at copy_mne

    for insn in mc.disasm(input, addr):
        #print("%x, %x, %x" % (insn.address,e_sec[refsIdx][1],func_list[reffIdx][1]))
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

            if virtual_addr in InData_arr:
                if num == 0:
                    f.write("  -------------------------------------------------InData\n")
                else:
                    f.write("  -------------------------------------------------InData%d\n" %num)
                num += 1
            else:
                f.write("\n")
                
        else:
            f.write("0x%x:\t%s\t%s\n" %(insn.address, insn.mnemonic, insn.op_str))
        
        temp_ins = [insn.address, insn.mnemonic, insn.op_str]
        instructions.append(temp_ins)
            
        virtual_addr += MODE

        line = []
        copy_mne.append(line)
        copy_mne[make_ins_inIdx].append(insn.mnemonic)
        (regiread,regi_write) = insn.regs_access()
        for r in regi_write:
            copy_mne[make_ins_inIdx].append(insn.reg_name(r))
        make_ins_inIdx += 1

    f.close()

    if len(copy_mne)/int(len(CODE)/MODE) < 1:
        make_ins_cnt += 1
        line = []
        copy_mne.append(line)
        copy_mne[make_ins_inIdx].append("NONE")
        make_ins_inIdx += 1
        retaddr = (START_ADDRESS - (MODE == 2)) + make_ins_inIdx * MODE
        with open(elf_file, "rb") as f:
            f.seek(retaddr,0)
            fcode = f.read()

        return fcode, retaddr
    else:
        return 0, addr

# 명령어 당 hooking 시 호출되는 콜백 함수
def code_hook(uc, address, size, scene_data):
    if scene_data.Fault_list:
        for i in range(len(scene_data.Fault_list)):
            if scene_data.check_nop(i) and int(scene_data.Fault_list[i]['ctr']) == ctr:
                scene_data.nop(uc)
            elif scene_data.check_nop(i) == False and int(scene_data.Fault_list[i]['ctr']) == ctr:
                pass

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

    while len(copy_mne)/int(len(CODE)/MODE) < 1:
        refcod, refaddr = make_refer(refcod,refaddr)
    
    print("Emulating the code..")

    # 시나리오 객체 생성
    scene_data = Scenario()
    
    # 에뮬레이팅
    try:
        if scene_data:
            for i in range(2):

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

                # 콜백 함수 추가
                mu.hook_add(UC_HOOK_CODE, code_hook, scene_data, begin= START_ADDRESS, end= START_ADDRESS + len(CODE))
       
                # main 함수 길이만큼 에뮬레이션 시작
                mu.emu_start(emu_ADDRESS, emu_ADDRESS + main_len)

                print(">>> Emulation done.")

                # print("InData = ", end="")
                # InData = get_input_data(InData_arr)
                # OutData = get_output_data(mu,OutData_addr,length_addr)
                # print("OutData = ", end="")
                # print(OutData)

    except UcError as e:
        print("ERROR: %s" % e)

