from unicorn import *
from capstone import *
from unicorn.arm_const import *
from setdata import *
from logger import *

def upload(uc, elf_file, e_section_list):
    for i in range(len(e_section_list)):
        with open(elf_file, "rb") as f:
            f.seek(e_section_list[i][1],0) # go to section data offset
            code = f.read(e_section_list[i][2]) # read as much as original_size
        
        if e_section_list[i][0] != 0: # virtual address != 0
            uc.mem_write(e_section_list[i][0], code) # virtual_address
        else:
            uc.mem_write(e_section_list[i][1], code) # offset(flash address)

def get_input_data(indata_arr):
    for i in range(len(indata_arr)):
        print("InData%d address is " %(i),end = "")
        print(indata_arr[i])

def get_output_data(uc,out_addr,len_addr):
    output = []
    len_mem = uc.mem_read(len_addr,4)
    cvt_len = int.from_bytes(len_mem, byteorder='little')
    # change mem to int
    for i in range(cvt_len):
        out_mem = uc.mem_read(out_addr+i*4,4)
        cvt_output = int.from_bytes(out_mem,byteorder="little")
        output.append(cvt_output)
    return output

def make_refer(input, addr):
    global make_ins_inIdx, make_ins_cnt, refsIdx, reffIdx

    f = open ('reference.txt', 'a')
    mc = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    mc.syntax = None
    mc.detail = True

    # copy mnemonics to copy_mne
    # add modified register at copy_mne
    for insn in mc.disasm(input, addr):
        #print("%x, %x, %x" % (insn.address,e_sec[refsIdx][1],func_list[reffIdx][1]))
        if (e_sec[refsIdx][1]) == insn.address:
            f.write("\nsection\t\t : %s\n\n" % (e_sec[refsIdx][3]))
            refsIdx += 1
            if refsIdx == len(e_sec):
                refsIdx = len(e_sec)-1
        if func_list[reffIdx][1] == insn.address:
            f.write("\nfunction\t : %s\n\n" % (func_list[reffIdx][0]))
            reffIdx += 1
            if reffIdx == len(func_list):
                reffIdx = len(func_list)-1
        f.write("0x%x:\t%s\t%s\n" %(insn.address, insn.mnemonic, insn.op_str)) #remove comment when make reference file
        line = []
        copy_mne.append(line)
        copy_mne[make_ins_inIdx].append(insn.mnemonic)
        (regiread,regi_write) = insn.regs_access()
        for r in regi_write:
            copy_mne[make_ins_inIdx].append(insn.reg_name(r))
        make_ins_inIdx += 1

    f.close()

    if len(copy_mne)/int(len(CODE)/4) < 1:
        make_ins_cnt += 1
        line = []
        copy_mne.append(line)
        copy_mne[make_ins_inIdx].append("NONE")
        make_ins_inIdx += 1
        retaddr = START_ADDRESS + make_ins_inIdx * 4
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

    if address == exit_addr_real:
        uc.emu_stop()

def run():

    refcod = CODE
    refaddr = START_ADDRESS
    while len(copy_mne)/int(len(CODE)/4) < 1:
        refcod, refaddr = make_refer(refcod,refaddr)

    print(refaddr)

    print("Emulating the code..")

    try:
        # initialize Unicorn as ARM mode
        mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)

        # map 4MB memory for emulating
        mu.mem_map(START_ADDRESS, 4*1024*1024) # emulate to _init
        mu.mem_map(0x0, 1024)  
        mu.mem_map(STACK_ADDRESS - STACK_SIZE, STACK_SIZE) # stack region

        upload(mu, elf_file, e_section_list)

        # initialize machine registers
        mu.reg_write(UC_ARM_REG_SP, STACK_ADDRESS)
        mu.reg_write(UC_ARM_REG_FP, STACK_ADDRESS)
        mu.reg_write(UC_ARM_REG_LR, exit_addr)

        

        # add callback function
        mu.hook_add(UC_HOOK_CODE, code_hook, copy_mne, begin= START_ADDRESS, end= START_ADDRESS + len(CODE))
        
        # add address should be same as main function length
        mu.emu_start(emu_ADDRESS, emu_ADDRESS + main_len)

        print(">>> Emulation done. Below is the CPU context")

        print("InData = ", end="")
        InData = get_input_data(InData_arr)
        OutData = get_output_data(mu,OutData_addr,length_addr)
        print("OutData = ", end="")
        print(OutData)

    except UcError as e:
        print("ERROR: %s" % e)

