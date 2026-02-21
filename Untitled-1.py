import uuid
import lzma
import uefi_firmware

file_name = 'imagefv_b.img'
fd = open(file_name, 'rb')
fd.seek(0)

def bytes2guid(data: bytes) -> str:
    return '{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}'.format(
        data[3], data[2], data[1], data[0], data[5], data[4], data[7], data[6], data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15])

class ELF32_HEADER:
    def __init__(self, header:bytes):
        self.indet = header[0:0x10]
        self.type = header[0x10:0x12] # 类型
        self.machine = header[0x12:0x14] # ISA
        self.version = header[0x14:0x18] # 版本
        self.prgmentry = header[0x18:0x1C] # 程序entry point
        self.prgm_head_offset = header[0x1C:0x20] # 程序头表地址
        self.prgm_head_elmt_size = header[0x2A:0x2C] # 程序头表元素大小
        self.prgm_head_elmt_num = header[0x2C:0x2E] # 程序头表元素数量
        self.PUflags = header[0x24:0x28] # 处理器标志
        self.head_size = header[0x28:0x2A] # ELF头大小
        self.sec_head_offset = header[0x20:0x24] # 节头表起始地址
        self.sec_head_elmt_size = header[0x2E:0x30] # 节头表元素大小
        self.sec_head_elmt_num = header[0x30:0x32] # 节头表元素数量
        self.sec_head_str_indx = header[0x32:0x34] # 节头表字符串表索引
    
    def __len__(self):
        return 0x34
    
    def get_type(self, byteorder:str):
        dic = {0: '未知', 1: '可重定位文件', 2: '可执行文件', 3: '共享目标文件', 4: '核心转储文件'}
        tmp = int.from_bytes(self.type, byteorder)
        return dic[tmp]

class IDENTIFY:
    def __init__(self, data:ELF32_HEADER):
        self.magic = data.indet[0:4] # ELF magic
        self.type = data.indet[4:5] # 64bit/32bit
        self.format = data.indet[5:6] # little/big endian
        self.version = data.indet[6:7] # ELF version
        self.osabi = data.indet[7:8] # OS ABI
        self.abiversion = data.indet[8:9] # ABI版本
        self.type_str = '32bit' if int.from_bytes(self.type) == 1 else '64bit'
        self.format_str = 'little' if int.from_bytes(self.format) == 1 else 'big'

class PRGM_HEAD_TABLE_ITEM:
    
    len = 0x20
    
    def __init__(self, data:bytes):
        self.type = data[0:0x4] # 段类型
        self.offset = data[0x4:0x8] # 段在文件中的偏移
        self.vaddr = data[0x8:0xC] # 段在虚拟内存中的起始地址
        self.paddr = data[0xC:0x10] # 段在物理内存中的起始地址
        self.filesz = data[0x10:0x14] # 段在文件中的大小
        self.memsz = data[0x14:0x18] # 段在虚拟内存中的大小
        self.flags = data[0x18:0x1C] # 段属性
        self.align = data[0x1C:0x20] # 段对齐
    
    def __len__(self):
        return 0x20
    
    def get_permission(self, byteorder:str):
        pass
        tmp = '{:0>32b}'.format(int.from_bytes(self.flags, byteorder))[-8:]
        flag_map = {'1': '可', '0': '不可'}
        result = flag_map[tmp[-1]] + '读' + flag_map[tmp[-2]] + '写' + flag_map[tmp[-3]] + '执行'
        return result
    
    def get_offset(self, byteorder:str):
        pass
        return int.from_bytes(self.offset, byteorder)
    
    def get_size(self, byteorder:str):
        pass
        return int.from_bytes(self.filesz, byteorder)
    
    def available(self, byteorder:str):
        pass
        if self.get_type(byteorder) != ('空' or '未使用' or '未知'):
            return True
        return False
    
    def get_type(self, byteorder:str):
        pass
        dic = {0: '空', 1: '可加载', 2: '动态链接', 3: '连接器路径', 4: '辅助信息', 5: '未使用', 6: '程序头表索引', 7: '线程局部存储', int.from_bytes(b'\x64\x74\xE5\x51'): 'GNU扩展栈权限', int.from_bytes(b'\x64\x74\xE5\x52') : 'GNU扩展只读重定位'}
        tmp = int.from_bytes(self.type, byteorder)
        try :
            return dic[tmp]
        except KeyError:
            return '未知'

class EXT_EFI_FIRMWARE_VOLUME_HEADER:
    
    def __init__(self, data):
        self.ExtHeaderSize = data[0:0x02] # 扩展头大小
        self.Reserved = data[0x02:0x04] # 保留
        self.FvName = data[0x04:0x14] # FV名称GUID
        
    def __len__(self):
        return 0x14

class EFI_FIRMWARE_VOLUME_HEADER:

    def __init__(self, data: bytes):
        self.ZeroVector = data[0:0x10] # 全0向量
        self.FileSystemGUID = data[0x10:0x20] # GUID
        self.FvLength = data[0x20:0x28] # FV大小
        self.Signature = data[0x28:0x2C] # 固定值0x4856465F
        self.Attributes = data[0x2C:0x30] # 属性
        self.HeaderLength = data[0x30:0x32] # 头总长度
        self.Checksum = data[0x32:0x34] # 校验和
        self.ExtendedHeaderOffset = data[0x34:0x36] # 扩展头偏移，以本头起始地址为base
        self.Reserved = data[0x36] # 保留
        self.Reversion = data[0x37] # 版本号
        self.have_ext_head = False
        if self.Signature != b'_FVH':
            raise Exception("不是有效的FV数据")
        if int.from_bytes(self.ExtendedHeaderOffset) != 0:
            self.ExtendedHeader = EXT_EFI_FIRMWARE_VOLUME_HEADER(data[int.from_bytes(self.ExtendedHeaderOffset):])
            self.have_ext_head = True
    
    def __len__(self) -> int:
        return int.from_bytes(self.HeaderLength)

class EFI_FFS_FILE_HEADER:
    
    def __init__(self, data: bytes):
        self.data = data
        self.Name = data[0:0x10] # 文件名GUID
        self.IntegrityCheck = data[0x10:0x12] # 校验
        self.Type = data[0x12] # 类型
        self.Attributes = data[0x13] # 属性
        self.Size = data[0x14:0x17] # 大小，24位，小端序，包含头长度
        self.State = data[0x17] # 状态
        if self.is_large_file():
            self.Size = data[0x18:0x1F]
    def __len__(self):
        return 0x18
    
    def verify_head(self):
        checksum = 0
        for i, d in enumerate(self.data[: 0x18]):
            if i == 0x11 or i == 0x17:
                pass
            else:
                checksum = (checksum + d) & 0xFF
        if checksum == 0:
            return True
        return False
        
    def get_type(self):
        dic = {0x00: '空', 0x01: 'raw', 0x02: 'freeformat', 0x03: 'Security Core', 0x04: 'PEI Core', 0x05: 'DXE Core', 0x06: 'PEI Module', 0x07: 'DXE Drive', 0x08: 'Combine PEI DXE', 0x09: 'UEFI APP', 0x0a: 'Management Mode(MM) Driver', 0x0b: 'Firmware Volume Image', 0x0C: 'Combine MM DXE', 0x0D: 'MM Core', 0x0E: 'MM Standalone', 0x0F: 'MM Standalone Core', 0xF0: 'FV_FFS_PAD'}
        try:
            return dic[self.Type]
        except:
            if 0xC0 <= self.Type <=0xDF:
                return 'OEM Define'
            if 0xE0 <= self.Type <= 0xEF:
                return 'Debug Define'
            if 0xF1 <= self.Type <= 0xFF:
                return 'FFS Internal Reserved'
        
    def get_check_sum(self):
        pass
    
    def is_large_file(self):
        if self.Attributes & 0x01 == 1:
            return True
        return False
    
    def get_full_size(self):
        return int.from_bytes(self.Size, 'little')

    def get_context_size(self):
        if self.is_large_file():
            return int.from_bytes(self.Size, 'little') - 0x18
        return int.from_bytes(self.Size, 'little') - 0x14

header = fd.read(0x40)
elf_header = ELF32_HEADER(header)
eid = IDENTIFY(elf_header)

print(f'{file_name} magic:', str(eid.magic))
print(f'{file_name} 格式:', eid.type_str)
print(f'{file_name} 存储方式:', eid.format_str)
print(f'{file_name} 版本:', int.from_bytes(eid.version))
print(f'{file_name} ABI:', int.from_bytes(eid.osabi))
print(f'{file_name} ABI版本:', int.from_bytes(eid.abiversion))
print(f'{file_name} 类型:', elf_header.get_type(eid.format_str))
print('{0} 程序entry point: 0x{1:X}'.format(file_name, int.from_bytes(elf_header.prgmentry, eid.format_str)))
if int.from_bytes(elf_header.prgm_head_elmt_num, eid.format_str) != 0:
    print('{0} 程序头表起始地址: 0x{1:X}'.format(file_name, int.from_bytes(elf_header.prgm_head_offset, eid.format_str)))
    print(f'{file_name} 程序头表元素大小:', str(int.from_bytes(elf_header.prgm_head_elmt_size, eid.format_str)))
    print(f'{file_name} 程序头表元素数量:', str(int.from_bytes(elf_header.prgm_head_elmt_num, eid.format_str)))
else:
    print(f'{file_name} 程序头表为空')
if int.from_bytes(elf_header.sec_head_elmt_num, eid.format_str) != 0:
    print('{0} 节头表起始地址: 0x{1:X}'.format(file_name, int.from_bytes(elf_header.sec_head_offset, eid.format_str)))
    print(f'{file_name} 节头表元素数量:', str(int.from_bytes(elf_header.sec_head_elmt_num, eid.format_str)))
    print(f'{file_name} 节头表元素大小:', str(int.from_bytes(elf_header.sec_head_elmt_size, eid.format_str)))
    print('{0} 节头表字符串表索引: 0x{1:X}'.format(file_name, int.from_bytes(elf_header.sec_head_str_indx, eid.format_str)))
else:
    print(f'{file_name} 节头表为空')

if int.from_bytes(elf_header.prgm_head_elmt_num, eid.format_str) != 0:
    fd.seek(int.from_bytes(elf_header.prgm_head_offset, eid.format_str))
    print('开始读取程序头表数据...')
    items:list[PRGM_HEAD_TABLE_ITEM] = []
    rm = 0
    for i in range(int.from_bytes(elf_header.prgm_head_elmt_num, eid.format_str)):
        pht_elmt_data = fd.read(int.from_bytes(elf_header.prgm_head_elmt_size, eid.format_str))
        items.append(PRGM_HEAD_TABLE_ITEM(pht_elmt_data))
        print(f'段{i}信息:')
        print('\t状态:', items[i - rm].get_permission(eid.format_str))
        print('\t文件中起始地址: {:X}'.format(items[i - rm].get_offset(eid.format_str)))
        print('\t长度: {:X}'.format(items[i - rm].get_size(eid.format_str)))
        print('\t段类型:', items[i - rm].get_type(eid.format_str))
        if not items[i - rm].available(eid.format_str):
            items.pop(-1)
            rm += 1
    if items:
        print(f'发现{i + 1 - rm}个可用段！')
        print('开始读取有效段数据...')
        for i in range(len(items)):
            fd.seek(int.from_bytes(items[i].offset, eid.format_str))
            efi_fvh = EFI_FIRMWARE_VOLUME_HEADER(fd.read(0x38))
            if efi_fvh.have_ext_head:
                fd.seek(int.from_bytes(items[i].offset, eid.format_str))
                efi_fvh = EFI_FIRMWARE_VOLUME_HEADER(fd.read(0x4C))
            fd.seek(int.from_bytes(items[i].offset, eid.format_str))
            file_volume = fd.read(int.from_bytes(items[i].filesz, eid.format_str) + 0x4C)
            print('当前位置: 0x{:X}'.format(fd.tell()))
            bin_file = open(f'Section{i + 1}.bin', 'wb')
            bin_file.write(file_volume)
            bin_file.close()
            print(f'可用段{i}信息:')
            print('\t状态:', items[i].get_permission(eid.format_str))
            print('\t文件中起始地址: {:X}'.format(items[i].get_offset(eid.format_str)))
            print('\t长度:', items[i].get_size(eid.format_str))
            print('\t段类型:', items[i].get_type(eid.format_str))
            print('\tGUID:', bytes2guid(efi_fvh.FileSystemGUID))
            guid = uuid.UUID(bytes2guid(efi_fvh.FileSystemGUID))
            print('\tGUID版本:', guid.version)
            print('\tGUID变体:', guid.variant)
            if efi_fvh.have_ext_head:
                print(f'\t扩展头位于偏移量0x{efi_fvh.ExtendedHeaderOffset.hex().upper()}，将基于FV扩展头偏移量0x{efi_fvh.ExtendedHeaderOffset.hex().upper()}读取FFS文件头')
            else:
                print('\t此段不含扩展头，直接读取FFS文件头')
                print('FFS文件头信息:')
                ffs_head = EFI_FFS_FILE_HEADER(file_volume[int.from_bytes(efi_fvh.HeaderLength, eid.format_str):int.from_bytes(efi_fvh.HeaderLength, eid.format_str) + 0x18])
                print('\t起始地址: 0x{:X}'.format(items[i].get_offset(eid.format_str) + int.from_bytes(efi_fvh.HeaderLength, eid.format_str)))
                print('\t文件头校验', '通过' if ffs_head.verify_head() else '不通过', sep='')
                if ffs_head.verify_head():
                    print('\tGUID:', bytes2guid(ffs_head.Name))
                    if ffs_head.is_large_file():
                        ffs_head = EFI_FFS_FILE_HEADER(file_volume[int.from_bytes(efi_fvh.HeaderLength, eid.format_str):int.from_bytes(efi_fvh.HeaderLength, eid.format_str) + 0x1F])
                    print('\t长度: 0x{:X}'.format(ffs_head.get_full_size()))
                    print('\t类型:', ffs_head.get_type())
                    fd.seek(items[i].get_offset(eid.format_str) + int.from_bytes(efi_fvh.HeaderLength, eid.format_str))
                    ffs = fd.read(ffs_head.get_full_size())
                    bin_file = open(f'File{i + 1}.bin', 'wb')
                    bin_file.write(ffs)
                    bin_file.close()

                    '''
                    parser = uefi_firmware.AutoParser(ffs)
                    print('文件类型:', parser.type())
                    if parser.type() != 'unknown':
                        firmware = parser.parse()
                        #firmware.data
                        firmware.showinfo()
                    '''


fd.close()