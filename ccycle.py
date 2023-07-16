from setdata import *
import json

N = 0   # The number of registers in the register list to be loaded or stored, including PC or LR
P = 0   # The number of cycles required for a pipline refill.
        # This ranges from 1 to 3 depending on the alignment and width of the target instruction, and whether the processor manages to speculate the address early
B = 0   # The number of cycles required to perform the barrier operation. For DSB and DMB, the minumum number of cycles is zero. For ISB, the minimum number of cycles is equivalent to the number required for a pipeline refill
# W = 0   # The number of cycles spent waiting for an appropriate event, but unicorn engine doesn't use system call, so we don't use it


div_num = [0,0,2,3,4,5,6,7,8,9,10,11,12]
total_cycle = 0


class ARM:
    def __init__(self, core, p, b, dn):
        self.json_file = "./input.json"
        self.core = core
        self.div_num = div_num[dn]
        self.P = p
        self.B = b
        self.N = 0
    
    def cycle_cal(self, ins, modified_ins, op_str):
        with open(self.json_file) as j_f:
            arch = json.load(j_f)

        with open(arch['arch'][self.core]) as arch_f:
            ins_set = json.load(arch_f)
        
        j_f.close()
        try:
            ins_key = ins_set['ins_set'][ins]

            if type(ins_key) == int:
                print(ins_key)

            elif type(ins_key) == list:

                # branch instructions, check if branches
                if ins_key[1] == list:
                    if op_str.find('pc') == -1:
                        print(ins_key[0])
                    else:
                        print(1 + self.P)
                
                else:
                    sum_cyc = 0
                    for i in range(len(ins_key)):
                        if ins_key[i] == "P":
                            ins_key[i] = self.P
                        elif ins_key[i] == "B":
                            ins_key[i] = self.B
                        elif ins_key[i] == "N":
                            self.N = len(op_str[op_str.find('{') + 1: op_str.find('}')].split(','))
                            ins_key[i] = self.N
                        sum_cyc += ins_key[i]
                    print(sum_cyc)

            else :
                if ins_key == "div_num":
                    print(self.div_num)
            
        except:
            print("Invalid instruction")



    