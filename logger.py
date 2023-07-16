from setdata import *
from unicorn import *
from unicorn.arm_const import *
from capstone import *
from ccycle import *

# print all register
def print_all_reg(uc):
    r0 = uc.reg_read(UC_ARM_REG_R0) 
    r1 = uc.reg_read(UC_ARM_REG_R1)
    r2 = uc.reg_read(UC_ARM_REG_R2)
    r3 = uc.reg_read(UC_ARM_REG_R3)
    r4 = uc.reg_read(UC_ARM_REG_R4)
    r5 = uc.reg_read(UC_ARM_REG_R5)
    r6 = uc.reg_read(UC_ARM_REG_R6)
    r7 = uc.reg_read(UC_ARM_REG_R7)
    r8 = uc.reg_read(UC_ARM_REG_R8)
    r9 = uc.reg_read(UC_ARM_REG_R9)
    r10 = uc.reg_read(UC_ARM_REG_R10)
    fp = uc.reg_read(UC_ARM_REG_FP)
    ip = uc.reg_read(UC_ARM_REG_IP)
    sp = uc.reg_read(UC_ARM_REG_SP)
    lr = uc.reg_read(UC_ARM_REG_LR)
    pc = uc.reg_read(UC_ARM_REG_PC)
    cpsr = uc.reg_read(UC_ARM_REG_CPSR)
    
    print("R0 = 0x%x" %r0, end = ', ')
    print("R1 = 0x%x" %r1, end = ', ')
    print("R2 = 0x%x" %r2, end = ', ')
    print("R3 = 0x%x" %r3, end = ', ')
    print("R4 = 0x%x" %r4, end = ', ')
    print("R5 = 0x%x" %r5, end = ', ')
    print("R6 = 0x%x" %r6, end = ', ')
    print("R7 = 0x%x" %r7, end = ', ')
    print("R8 = 0x%x" %r8, end = ', ')
    print("R9 = 0x%x" %r9, end = ', ')
    print("R10 = 0x%x" %r10, end = ', ')
    print("FP = 0x%x" %fp, end = ', ')
    print("IP = 0x%x" %ip, end = ', ')
    print("SP = 0x%x" %sp, end = ', ')
    print("LR = 0x%x" %lr, end = ', ')
    print("PC = 0x%x" %pc, end = ', ')
    print("CPSR = 0x%x" %cpsr, end = ' ')

# print 'len' length memory at 'addr' address
def print_instruction(uc,addr, m_len):
    mc = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    tot_mem = uc.mem_read(addr,m_len)
    for j in mc.disasm(bytes(tot_mem), addr):
        print(j.mnemonic +  " " + j.op_str, end = '')
        modified_mem = j.op_str.find('[')
    print(' ', end=' ')
    return modified_mem, j.op_str
    
def print_mem(uc, modify_mem, op_str):
    global modified_mem_addr
    ins = ''

    for i in range(modify_mem + 1, len(op_str)):
        if op_str[i] == ']' :
            break
        else:
            ins += op_str[i]
    if ins.find(',') != -1 :
        ins_list = ins.split(',')
        reg = ins_list[0]
        val = ins_list[1][2:]
        reg_val = eval('uc.reg_read(UC_ARM_REG_' + reg.upper() +')') + int(val, 16)
        mem_val = uc.mem_read(reg_val, 4)
    else:
        reg_val = eval('uc.reg_read(UC_ARM_REG_' + ins.upper() +')')
        mem_val = uc.mem_read(reg_val, 4)
    
    print("modified address: [" , hex(reg_val), "]")
    
    print("/ memory before modification: ", end ='')
    for j in range(len(mem_val)):
        print("\\x%x" %mem_val[j], end = "")
    print()
    modified_mem_addr = reg_val

def write_log(uc, address, user_data):
    global mem_modified
    temp = sys.stdout
    addr = int((address-START_ADDRESS)/4)

    if mem_modified == True:
        print("/ memory after modification: ", end ='')
        mem_val = uc.mem_read(modified_mem_addr, 4)
        for i in range(len(mem_val)):
            print("\\x%x" %mem_val[i], end = "")
        print()
        mem_modified = False

    print("[" + str(hex(address)) + "]", end=' ')
    print("instruction :", end=' ')
    modify_mem, op_str = print_instruction(uc, address, 4)
    print("/ register data :", end=' ')
    print_all_reg(uc)
    print("/ modified register : ", end ='')
    print(user_data[addr][1:], end = '')
    print("/ clock count : ", end ='')
    clock.cycle_cal(user_data[addr][0], user_data[addr][1:], op_str)
    if modify_mem != -1 and user_data[addr][0].find('str') != -1:
        print_mem(uc, modify_mem, op_str)
        mem_modified = True
    sys.stdout = temp