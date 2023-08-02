from elfParser import *
import sys
import json
import datetime
import ccycle


instructions = []
OutData = []
copy_mne = []
make_ins_inIdx = 0
make_ins_cnt = 0

mem_modified = False
modified_mem_addr = 0

clock = ccycle.ARM("Cortex-M4", 1, 1, 1)

try:
    with open("./input.json", "r") as j_f:
        input_data = json.load(j_f)
except:
    sys.stderr.write("No File: %s\n" % "input.json")
    exit(1)

try:
    filename = "./log/" + datetime.datetime.now().strftime("%Y-%m-%d %H_%M_%S") + " " + input_data["files"]["log_file_name"] + ".txt"
except:
    filename = "./log/" + datetime.datetime.now().strftime("%Y-%m-%d %H_%M_%S") + ".txt"


# elf parsing object
elf_file = input_data["files"]["elf_file"]
e = ElfParser(elf_file)


#ARM mode or THUMB mode (TODO: auto set to recognize the file is thumb or arm)
MODE = 0

if elf_file == "./source/toy_ex_mod_add":
    MODE = 4
elif elf_file == "./source/toy_ex_mod_add_m4":
    MODE = 2

else:
    exit()

# get section data
e_section_list, ram_addr, flash_addr, ram_size, flash_size = e.section_data_list()


refsIdx = 1
reffIdx = 0

e_sec = e.check_list(e_section_list)

f_list = list(e.func_sort.items())
func_list = e.check_list(f_list)


# mapping address
START_ADDRESS = e.get_start_addr(e_sec)

exit_addr = e.get_func_address('exit')
exit_addr_real = e.get_func_address('_exit')
emu_ADDRESS = e.get_func_address('main') # start emulating at main function
main_len = e.get_main_len()



# code to emulate
CODE = e.get_code(START_ADDRESS)

# input & output data
OutData_addr, length_addr, stack_addr = e.get_output_symbol_data()
InData_arr = e.get_indata_arr()

j_f.close()
