from unicorn import *
from unicorn.arm_const import *
from capstone import *
from config import *
from setEmulData import *
import pandas as pd
import datetime
import csv

# Logger 변수
ctr = 0
mem_modified = False
modified_mem_addr = 0
LogReg_header =  ['ctr','Address','Opcode', 'Operands',
        'bR0','bR1','bR2','bR3','bR4','bR5','bR6','bR7','bR8','bR9','bR10','bFP','bIP','bSP','bLR','bPC','bCPSR',
        'aR0','aR1','aR2','aR3','aR4','aR5','aR6','aR7','aR8','aR9','aR10','aFP','aIP','aSP','aLR','aPC','aCPSR']
log_matrix = [LogReg_header]

log_file = ""

# 로그 파일 생성
def make_log_file(i):
    global log_file
    try:
        if i == 0:
            log_file = "./log/" + datetime.datetime.now().strftime("%Y-%m-%d %H_%M_%S") + " " + log_file_name + ".csv"
        elif i == 1:
            log_file = "./log/" + datetime.datetime.now().strftime("%Y-%m-%d %H_%M_%S") + " " + log_file_name + "(Fault Log).csv"
    except:
        log_file = "./log/" + datetime.datetime.now().strftime("%Y-%m-%d %H_%M_%S") + " " + ".csv"
    
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

# 레지스터 로그 파일 생성
def write_log_regs(uc, address, scene_data):
    global ctr, log_file, LOG_MATRIX

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
        LOG_MATRIX.extend(log_matrix.copy())

        with open(log_file, 'w', newline='') as file:
            write = csv.writer(file)
            write.writerows(log_matrix)
        log_matrix.clear()
        log_matrix.append(LogReg_header)
        ctr = 0
    