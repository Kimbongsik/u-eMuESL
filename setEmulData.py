from elfParser import *
from config import *

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

func_list = e.check_list(list(e.func_sort.items()))

exit_addr = e.get_func_address('exit')
exit_addr_real = e.get_func_address('_exit') 
emu_ADDRESS = e.get_func_address('main')
main_len = e.get_main_len()

instructions = []
OutData = []
copy_mne = []
make_ins_inIdx = 0
make_ins_cnt = 0

# input & output data
OutData_addr, length_addr, stack_addr = e.get_output_symbol_data()
InData_arr = e.get_indata_arr()