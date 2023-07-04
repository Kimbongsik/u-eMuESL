import lief
import sys

class ElfParser:
    
    def __init__(self, elf_file):
        self.elf_file = lief.parse(elf_file)
        self.elf_file_name = elf_file
        self.functions = {}
        self.func_sort = {}
        self.setup()
    
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

    def get_start_add(self):
        return self.func_sort.get('_init')
    
    def get_func_address(self, func_name):
        try:
            return self.func_sort.get(func_name)
        except:
            print("Err: func name doesn't exist in the file")
            exit(1)
    
    def get_main_len(self):
        return self.elf_file.get_symbol("main").size
    
    def get_code(self, address):
        try:
            with open(self.elf_file_name, "rb") as f:
                f.seek(address, 0)
                code = f.read()
        except:
            sys.stderr.write("No File: %s\n" % self.elf_file)
            exit(1)
        return code
    
    def get_output_symbol_data(self):
        symb_out = self.elf_file.get_symbol("OutData")
        symb_len = self.elf_file.get_symbol("length")
        out_addr = symb_out.value
        len_addr = symb_len.value

        return out_addr, len_addr
    
    def section_data_list(self):
        sections = []
        cnt = 0
        for section in self.elf_file.sections:
            section_list = []
            sections.append(section_list)
            sections[cnt].append(section.virtual_address)
            sections[cnt].append(section.offset)
            sections[cnt].append(section.original_size)
            sections[cnt].append(section.name)
            cnt += 1
        return sections
    
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




# e =ElfParser("./source/toy_ex_mod_add")
# e._print_section_data_list()

