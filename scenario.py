from unicorn import *
from unicorn.arm_const import *
from config import *
from setEmulData import *
import csv

class Scenario:
    def __init__(self):
        self.Fault_header=['ctr','isNOP','r0','r1','r2','r3','r4','r5','r6','r7','r8','r9','r10','fp','ip','sp','lr','pc','cpsr']
        self.REG = {'r0' : UC_ARM_REG_R0, 'r1' : UC_ARM_REG_R1, 'r2' : UC_ARM_REG_R2, 'r3' : UC_ARM_REG_R3,
            'r4' : UC_ARM_REG_R4, 'r5' : UC_ARM_REG_R5, 'r6' : UC_ARM_REG_R6, 'r7' : UC_ARM_REG_R7,
            'r8' : UC_ARM_REG_R8, 'r9' : UC_ARM_REG_R9, 'r10' : UC_ARM_REG_R10, "fp" : UC_ARM_REG_FP,
            "ip" : UC_ARM_REG_IP, "sp" : UC_ARM_REG_SP, "lr" : UC_ARM_REG_LR, "pc": UC_ARM_REG_PC,
            "cpsr" : UC_ARM_REG_CPSR}
        self.Fault_list = []
        self.set_scene_data()
        
    def set_scene_data(self):
        try:
            with open(fault_reg, newline='') as file:
                reader = csv.reader(file)
                for row in reader:
                    self.Fault_list.append(dict(zip(self.Fault_header, row)))
            del self.Fault_list[0]
        
        except:
            print("err: no file(FaultReg.csv)")
            exit(1)

    def check_nop(self, i):
        if self.Fault_list[i]['isNOP'] == 'TRUE':
            return True
        else:
            return False

    def flip_reg(self, uc, reg):
        reg_data = uc.reg_read(self.REG[reg])

        if MODE == 4:
            flipped_reg_data = reg_data ^ 0xFFFFFFFF
        else:
            flipped_reg_data = reg_data ^ 0xFFFF
        
        uc.reg_write(self.REG[reg], flipped_reg_data)

    def change_reg(self, uc, reg, data):
        uc.reg_write(self.REG[reg], data)
        
    def nop(self, uc):
        pc_data = uc.reg_read(self.REG['pc'])
        uc.reg_write(self.REG['pc'], pc_data + MODE)

