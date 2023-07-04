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

# disassemble and make instruction array for making reference file
def make_ins_arr(input, addr):
    global make_ins_inIdx
    global make_ins_cnt

    mc = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    mc.syntax = None
    mc.detail = True

    for ins in mc.disasm(input, addr):
        line = []
        copy_mne.append(line)
        copy_mne[make_ins_inIdx].append(ins.mnemonic)
        regi_write = ins.regs_access()
        for reg in regi_write:
            copy_mne[make_ins_inIdx].append(ins.reg_name(reg))
        make_ins_inIdx += 1

    if len(copy_mne) / int(len(CODE) / 4) < 1:
        make_ins_cnt += 1
        line = []
        copy_mne.append(line)
        copy_mne[make_ins_inIdx].append("NONE") # if failed to disassemble, make them to NONE
        make_ins_inIdx += 1

        retaddr = emu_ADDRESS + make_ins_inIdx * 4
        with open(elf_file, "rb") as f:
            f.seek(retaddr,0)
            fcode = f.read()
        
        f.close()

        return fcode, retaddr
    
    else:
        return 0, addr

def make_refer_file():
    ref_code = CODE
    ref_addr = emu_ADDRESS
    while len(copy_mne) / int(len(CODE) / 4) < 0.99:
        ref_code, ref_addr = make_ins_arr(ref_code, ref_addr)


def get_output_data(uc,out_addr,len_addr):
    output = []
    len_mem = uc.mem_read(len_addr,4)
    cvt_len = int.from_bytes(len_mem, byteorder='little')
    # change mem to int
    for i in range(cvt_len):
        out_mem = uc.mem_read(out_addr+i*4,4)
        print(out_mem)
        cvt_output = int.from_bytes(out_mem,byteorder="little")
        output.append(cvt_output)
    return output


def code_hook(uc, address, size, user_data):
    temp = sys.stdout
    sys.stdout = open(filename, 'a') # open log file
    
    write_log(uc, address, user_data)

    sys.stdout = temp

    if address == exit_addr_real:
        uc.emu_stop()

def run():

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

        #make_refer_file()

        # add callback function
        mu.hook_add(UC_HOOK_CODE, code_hook, copy_mne, begin= START_ADDRESS, end= START_ADDRESS + len(CODE))
        
        # add address should be same as main function length
        mu.emu_start(emu_ADDRESS, emu_ADDRESS + main_len)

        print(">>> Emulation done. Below is the CPU context")
        print("OutData = ", end="")

        OutData = get_output_data(mu,OutData_addr,length_addr)
        print(OutData)

    except UcError as e:
        print("ERROR: %s" % e)

