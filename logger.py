from setdata import *
from unicorn import *
from unicorn.arm_const import *
from capstone import *
from ccycle import *
import pandas as pd
import csv


# Logger 변수
ctr = 0
mem_modified = False
modified_mem_addr = 0
LogReg_header =  ['ctr','Address','Opcode', 'Operands',
        'bR0','bR1','bR2','bR3','bR4','bR5','bR6','bR7','bR8','bR9','bR10','bFP','bIP','bSP','bLR','bPC','bCPSR',
        'aR0','aR1','aR2','aR3','aR4','aR5','aR6','aR7','aR8','aR9','aR10','aFP','aIP','aSP','aLR','aPC','aCPSR']
log_matrix = [LogReg_header]

# 로그 파일 생성
try:
    filename = "./log/" + datetime.datetime.now().strftime("%Y-%m-%d %H_%M_%S") + " " + input_data["files"]["log_file_name"] + ".csv"
except:
    filename = "./log/" + datetime.datetime.now().strftime("%Y-%m-%d %H_%M_%S") + ".csv"


# 모든 레지스터 값 반환
def ret_all_reg(uc):
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
    
    return [r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, fp, ip, sp, lr, pc, cpsr]

# 명령어(op code, op string) 반환
def print_instruction(addr):
    for i in range(len(instructions)):
        for j in range(3):
            if instructions[i][0] == addr:
                return instructions[i][1], instructions[i][2]

# 변경된 메모리 데이터 출력(not use)
def _print_mem(uc, modify_mem, op_str):
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
        mem_val = uc.mem_read(reg_val, MODE)
    else:
        reg_val = eval('uc.reg_read(UC_ARM_REG_' + ins.upper() +')')
        mem_val = uc.mem_read(reg_val, MODE)
    
    print("modified address: [" , hex(reg_val), "]")
    
    print("/ memory before modification: ", end ='')
    for j in range(len(mem_val)):
        print("\\x%x" %mem_val[j], end = "")
    print()
    modified_mem_addr = reg_val

# 레지스터 로그 파일 생성
def write_log_regs(uc, address, user_data):
    global ctr

    b_regs = ret_all_reg(uc)
    op_code, op_str = print_instruction(address)

    b_regs.insert(0,ctr)
    b_regs.insert(1, hex(address))
    b_regs.insert(2,op_code)
    b_regs.insert(3,op_str)

    log_matrix.append(b_regs)

    
    if ctr >= 1 :
        for i in range(4, len(b_regs)):
            log_matrix[ctr].append(b_regs[i])

    ctr += 1

    if address == exit_addr_real - (MODE == 2):
        with open(filename, 'w', newline='') as file:
            write = csv.writer(file)
            write.writerows(log_matrix)