import lief
import sys

class ElfParser:
    
    def __init__(self, elf_file):
        self.elf_file = lief.parse(elf_file)
        self.elf_file_name = elf_file
        self.functions = {}
        self.func_sort = {}
        self.setup()
    
    # ELF 파싱 셋업
    def setup(self):
        try:
            for f in self.elf_file.exported_functions:
                tmp = f.name
                c = 0
                while tmp in self.functions:
                    c += 1
                    tmp = f.name + str(c)

                self.functions[tmp] = f.address
        except:
            pass

        self.func_sort = dict(sorted(self.functions.items(), key = lambda x : x[1]))

    # 모드(ARM mode와 Thumb mode 확인)
    def check_mode(self):
        if self.get_start_addr() %2 == 1:
            MODE = 2
        else:
            MODE = 4
        return MODE
    
    # Emulation 시작 주소 추출
    def get_start_addr(self):
        return self.get_func_address('_init')

    # 함수 시작 주소 추출
    def get_func_address(self, func_name):
        try:
            return self.func_sort.get(func_name)
        except:
            print("Err: func name doesn't exist in the file")
            exit(1)
    
    # main 함수 길이 추출
    def get_main_len(self):
        return self.elf_file.get_symbol("main").size
    
    # 에뮬레이션을 수행할 코드 추출
    def get_code(self, address):
        try:
            with open(self.elf_file_name, "rb") as f:
                
                f.seek(address, 0)
                code = f.read()
        except:
            sys.stderr.write("No File: %s\n" % self.elf_file)
            exit(1)
        return code
    
    # 프로그램 데이터(OutData, length, stack) 심볼 추출
    def get_io_symbol_data(self):

        symb_vir_in = self.elf_file.get_symbol("vir_IN")
        symb_vir_out = self.elf_file.get_symbol("vir_OUT")
        in_addr = symb_vir_in.value
        out_addr =  symb_vir_out.value

        return in_addr, out_addr 

    # 전역변수 vir_OUT 길이 추출
    def get_symbol_len(self, symb):
        return self.elf_file.get_symbol(symb).size


    # 스택 데이터 추출
    def get_stack_symbol(self):
        symb_stack = self.elf_file.get_symbol("_stack")
        stack_addr = symb_stack.value
        return stack_addr

    # 섹션 정보(RAM 주소, 파일 오프셋, 섹션 크기, 섹션명) 리스트로 추출
    def section_data_list(self):
        sections = []
        tmp_ram = []
        tmp_flash = []
        ram_size = 0
        flash_size = 0
        cnt = 0

        for section in self.elf_file.sections:
            section_list = []
            sections.append(section_list)
            sections[cnt].append(section.virtual_address)
            sections[cnt].append(section.offset)
            sections[cnt].append(section.original_size)
            sections[cnt].append(section.name)
            cnt += 1

            if section.virtual_address != 0 and section.virtual_address != section.offset:
                ram_size += section.original_size
                tmp_ram.append(section.virtual_address)
            
            elif section.virtual_address == section.offset:
                flash_size += section.original_size
                tmp_flash.append(section.offset)
    
        return sections, tmp_ram, tmp_flash, ram_size, flash_size

    # 섹션 데이터 리스트 출력
    def _print_section_data_list(self):
        for section in self.elf_file.sections:
            print('section name : ',end = "")
            print(section.name)

            print('section Flash_address(offset) : ',end = "")
            print(hex(section.offset))

            print('section RAM_address(virtual_address) : ',end = "")
            print(hex(section.virtual_address))

            print('section content size : ',end = "")
            print(section.original_size)
            print("--------------------------")

    def check_list(self,list_input):
        i = 0
        a = len(list_input)-1
        while i < a:
            if list_input[i][1] == list_input[i+1][1]:
                del list_input[i+1]
                a = a - 1
                i = i + 1
            i = i + 1
        return list_input



