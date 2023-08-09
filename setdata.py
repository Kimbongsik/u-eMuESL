from elfParser import *
import sys
import json
import datetime
import ccycle
import pandas as pd

instructions = []
OutData = []
copy_mne = []
make_ins_inIdx = 0
make_ins_cnt = 0

# clock 
clock = ccycle.ARM("Cortex-M4", 1, 1, 1)

try:
    with open("./input.json", "r") as j_f:
        input_data = json.load(j_f)
except:
    sys.stderr.write("No File: %s\n" % "input.json")
    exit(1)

elf_file = input_data["files"]["elf_file"]

# elf parsing object
e = ElfParser(elf_file)
MODE = e.check_mode()

# get section data
e_section_list, ram_addr, flash_addr, ram_size, flash_size = e.section_data_list()

# mapping address
START_ADDRESS = e.get_start_addr()
# code to emulate
CODE = e.get_code(START_ADDRESS)
REF_CODE = e.get_code(START_ADDRESS - (MODE == 2))

refsIdx = 1
reffIdx = 0

e_sec = e.check_list(e_section_list)

f_list = list(e.func_sort.items())
func_list = e.check_list(f_list)

exit_addr = e.get_func_address('exit')
exit_addr_real = e.get_func_address('_exit') 
emu_ADDRESS = e.get_func_address('main')
main_len = e.get_main_len()

# input & output data
OutData_addr, length_addr, stack_addr = e.get_output_symbol_data()
InData_arr = e.get_indata_arr()

j_f.close()
