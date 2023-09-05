from elfParser import *
from config import *

# elf parsing object
e = ElfParser(elf_file)
MODE = e.check_mode()

# 섹션 데이터
e_section_list, ram_addr, flash_addr, ram_size, flash_size = e.section_data_list()

# mapping address
START_ADDRESS = e.get_start_addr()

# 에뮬레이트 코드
CODE = e.get_code(START_ADDRESS)

# 레퍼런스 파일 생성용 에뮬레이트 코드
REF_CODE = e.get_code(START_ADDRESS - (MODE == 2))

# 레퍼런스 파일용 인덱스
refsIdx = 1
reffIdx = 0

# 명령어 저장 리스트
instructions = []

# 섹션 리스트
e_sec = e.check_list(e_section_list)
func_list = e.check_list(list(e.func_sort.items()))

# 스택 주소
stack_addr = e.get_stack_symbol()
exit_addr = e.get_func_address('exit')
exit_addr_real = e.get_func_address('_exit') 
emu_ADDRESS = e.get_func_address('main')
main_len = e.get_main_len()
vir_out_len = e.get_symbol_len('vir_OUT')
vir_in_len = e.get_symbol_len('vir_IN')

# input & output data
vir_in_addr, vir_out_addr = e.get_io_symbol_data()



insn_cnt = 0
insn_size = 0

