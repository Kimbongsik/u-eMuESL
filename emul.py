from unicorn import *
from capstone import *
from unicorn.arm_const import *
from setdata import *
from logger import *
import os

def auto_set(uc):
    PAGE_SIZE = 4*1024

    #mapping Flash memory
    if flash_size > PAGE_SIZE:
        uc.mem_map(START_ADDRESS // (PAGE_SIZE) * (PAGE_SIZE), ((flash_size // (PAGE_SIZE)) * (PAGE_SIZE)) + (PAGE_SIZE))
    else:
        uc.mem_map(START_ADDRESS // (PAGE_SIZE) * (PAGE_SIZE), (PAGE_SIZE))

    #mapping RAM memory
    if stack_addr - ram_addr[0] > PAGE_SIZE:
        uc.mem_map((ram_addr[0]) // (PAGE_SIZE) * (PAGE_SIZE), (stack_addr - ram_addr[0] // (PAGE_SIZE)) * (PAGE_SIZE) + (PAGE_SIZE))
    else:
        uc.mem_map((ram_addr[0]) // (PAGE_SIZE) * (PAGE_SIZE), (PAGE_SIZE))

    uc.reg_write(UC_ARM_REG_SP, stack_addr)
    uc.reg_write(UC_ARM_REG_FP, stack_addr)
    uc.reg_write(UC_ARM_REG_LR, exit_addr)

def upload(uc):
    for i in range(len(e_sec)):
        # read file from start address to eof
        with open(elf_file, "rb") as f:
            f.seek(e_sec[i][1],0)
            cod = f.read(e_sec[i][2])

        if e_sec[i][0] != 0:
            uc.mem_write(e_sec[i][0],cod)

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

# def _make_refer(input, addr):
#     f = open ('reference.txt', 'a')
#     mc = Cs(CS_ARCH_ARM, CS_MODE_ARM)
#     mc.syntax = None
#     mc.detail = True
    
#     for insn in mc.disasm(input, addr):
#         #print("%x, %x, %x" % (insn.address,e_sec[refsIdx][1],func_list[reffIdx][1]))
#         if insn.address in e_sec:
#             f.write("\nsection\t\t : %s\n" % e_sec[refsIdx][3])
#         f.write("[0x%x]: " %insn.address)
#         for j in range(len(insn.bytes)):
#             f.write("\\x%x" %insn.bytes[j])
#         f.write("\n")
            
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


def code_hook(uc, address, size, user_data):
    temp = sys.stdout
    sys.stdout = open(filename, 'a') # open log file
    
    write_log(uc, address, user_data)

    sys.stdout = temp

    if address == exit_addr_real - (MODE == 2):
        uc.emu_stop()

def run():

    if os.path.isfile('reference.txt'):
        os.remove('reference.txt')

    refcod = REF_CODE
    refaddr = START_ADDRESS - (MODE == 2)

    while len(copy_mne)/int(len(CODE)/MODE) < 1:
        refcod, refaddr = make_refer(refcod,refaddr)
        print("refcod: ", refcod)
        print("refaddr: ", refaddr)

    ptr = 0
    addr = START_ADDRESS

    # while(addr < 101412):
    #     input = CODE[ptr : ptr + MODE]
    #     addr = addr + MODE

    #     start = time.time()
    #     _make_refer(input, addr)
    #     print("function time: ", time.time() - start)
    #     ptr += MODE
    
    print("Emulating the code..")

    try:
        # initialize Unicorn
        if MODE == 2: # (thumb mode)
            mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        else: # MODE == 4 (arm mode)
            mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)

        # map 4MB memory for emulating
        auto_set(mu)

        upload(mu)

        # add callback function
        mu.hook_add(UC_HOOK_CODE, code_hook, copy_mne, begin= START_ADDRESS, end= START_ADDRESS + len(CODE))
        
        # add address should be same as main function length
        mu.emu_start(emu_ADDRESS, emu_ADDRESS + main_len)

        print(">>> Emulation done.")

        # print("InData = ", end="")
        # InData = get_input_data(InData_arr)
        # OutData = get_output_data(mu,OutData_addr,length_addr)
        # print("OutData = ", end="")
        # print(OutData)

    except UcError as e:
        print("ERROR: %s" % e)

