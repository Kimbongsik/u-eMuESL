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
    
    def cycle_cal(self, ins, modified_ins):
        self.instructions = json.load(j_f)

        try:
            ins_key = self.instructions['hw'][self.core][ins]

            if type(ins_key) == int:
                return ins_key

            elif type(ins_key) == list:

                # branch instructions, check if branches
                if ins_key[1] == list:
                    if 'pc' in modified_ins:
                        return ins_key[0]
                    else:
                        return 1 + self.P
                
                else:
                    sum_cyc = 0
                    for i in range(len(ins_key)):
                        if ins_key[i] == "P":
                            ins_key[i] = self.P
                        elif ins_key[i] == "B":
                            ins_key[i] = self.B
                        elif ins_key[i] == "N":
                            modified_ins
                        sum_cyc += ins_key[i]
                    return sum_cyc

            else :
                if ins_key == "div_num":
                    return self.div_num
            
        except:
            print("Invalid instruction")

        f.close()


    