import io
import lzma
import uuid

offset = 0x501C

file_name = 'secdata.img'#'img/imagefv_b.img'
fd = open(file_name, 'rb')
fd.seek(0)

class ELF32_HEADER:
    def __init__(self, data:bytes):
        self.Magic = data[0:0x04] # ELF magic
        self.Class = data[0x04] # 64bit/32bit
        self.Format = data[0x05] # 小/大端序
        self.ELF_Version = data[0x06] # ELF规范版本
        self.OS_ABI = data[0x07] # OS ABI
        self.ABI_Version = data[0x08] # ABI版本
        self.Type_Str = '32bit' if self.Class == 1 else '64bit'
        self.Format_Str = 'little' if self.Format == 1 else 'big'
        self.Type = data[0x10:0x12] # 类型
        self.Arch = data[0x12:0x14] # ISA
        self.Version = data[0x14:0x18] # ELF版本
        self.PRGM_Entry = data[0x18:0x1C] # 程序entry point
        self.PRGM_Header_Table_Offset = data[0x1C:0x20] # 程序头表地址
        self.SEC_Header_Table_Offset = data[0x20:0x24] # 节头表起始地址
        self.PU_Flags = data[0x24:0x28] # 处理器标志
        self.Header_Size = data[0x28:0x2A] # ELF头大小
        self.PRGM_Header_ELMT_Size = data[0x2A:0x2C] # 程序头表元素大小
        self.PRGM_Header_ELMT_Num = data[0x2C:0x2E] # 程序头表元素数量
        self.SEC_Header_ELMT_Size = data[0x2E:0x30] # 节头表元素大小
        self.SEC_Header_ELMT_Num = data[0x30:0x32] # 节头表元素数量
        self.SEC_Header_String_Index = data[0x32:0x34] # 节头表字符串表索引

    def __len__(self):
        return 0x34

    def get_type(self):
        return {
            0: '未知',
            1: '可重定位文件',
            2: '可执行文件',
            3: '共享目标文件',
            4: '核心转储文件'
        }.get(int.from_bytes(self.Type, self.Format_Str), '未知')

class PRGM_HEAD_TABLE_ELMT:

    def __init__(self, data:bytes):
        self.Type = data[0:0x4] # 段类型
        self.Offset = data[0x4:0x8] # 段在文件中的偏移
        self.Virtual_Address = data[0x8:0xC] # 段在虚拟内存中的起始地址
        self.Physical_Address = data[0xC:0x10] # 段在物理内存中的起始地址
        self.File_Size = data[0x10:0x14] # 段在文件中的大小
        self.Virtual_Memory_Size = data[0x14:0x18] # 段在虚拟内存中的大小
        self.Attributes = data[0x18:0x1C] # 段属性
        self.Alignment = data[0x1C:0x20] # 段对齐

    def __len__(self):
        return 0x20

    def get_permission(self, byteorder:str):
        tmp = '{:0>32b}'.format(int.from_bytes(self.Attributes, byteorder))[-8:]
        flag_map = {'1': '可', '0': '不可'}
        result = flag_map[tmp[-1]] + '读' + flag_map[tmp[-2]] + '写' + flag_map[tmp[-3]] + '执行'
        return result

    def get_offset(self, byteorder:str):
        return int.from_bytes(self.Offset, byteorder)

    def get_size(self, byteorder:str):
        return int.from_bytes(self.File_Size, byteorder)

    def available(self, byteorder:str):
        if self.get_type(byteorder) != ('空' or '未使用' or '未知'):
            return True
        return False

    def get_type(self, byteorder:str):
        return {
            0: '空',
            1: '可加载',
            2: '动态链接',
            3: '连接器路径',
            4: '辅助信息',
            5: '未使用',
            6: '程序头表索引',
            7: '线程局部存储',
            int.from_bytes(b'\x64\x74\xE5\x51'): 'GNU扩展栈权限',
            int.from_bytes(b'\x64\x74\xE5\x52') : 'GNU扩展只读重定位'
        }.get(int.from_bytes(self.Type, byteorder), '未知')

class EFI_FIRMWARE_VOLUME_HEADER:

    def __init__(self, data: bytes):
        self.Zero_Vector = data[0:0x10] # 全0向量
        self.File_System_GUID = data[0x10:0x20] # GUID
        self.File_Volume_Length = data[0x20:0x28] # FV大小
        self.Signature = data[0x28:0x2C] # 固定值0x4856465F('_FVH')
        self.Attributes = data[0x2C:0x30] # 属性
        self.Header_Length = data[0x30:0x32] # 头总长度
        self.Checksum = data[0x32:0x34] # 校验和
        self.Extend_Header_Offset = data[0x34:0x36] # 扩展头偏移，以本头起始地址为基址
        self.Reversion = data[0x37] # 版本号
        self.Have_EXT_Header = False
        if int.from_bytes(self.Extend_Header_Offset) != 0:
            self.Have_EXT_Header = True

    def verify(self) -> bool:
        return self.Signature == b'_FVH'

    def get_alignment(self) -> int:
        return 1 << ((int.from_bytes(self.Attributes, 'little') & 0x001F0000) >> 16)

class EFI_FIRMWARE_VOLUME_EXT_HEADER(EFI_FIRMWARE_VOLUME_HEADER):

    def __init__(self, data: bytes):
        super().__init__(data[:0x38])
        base = int.from_bytes(self.Extend_Header_Offset, 'little')
        self.File_Volume_Name_GUID = data[base:base + 0x10] # 16 字节FV名称GUID
        self.Extend_Header_Size = data[base + 0x10:base + 0x14] #扩展头大小，4 字节，小端序
        self.First_Align = (int.from_bytes(self.Extend_Header_Offset, 'little') + int.from_bytes(self.Extend_Header_Size, 'little')) & ~(super().get_alignment() - 1)
        self.BlockMap = [] # 初始化块映射表
        offset = 0x38 # 扩展头结束的位置，即块映射表起始
        total_len = len(data)
        while offset + 8 <= total_len:
            num_blocks = int.from_bytes(data[offset:offset + 4], 'little')
            block_len = int.from_bytes(data[offset + 4:offset + 8], 'little')
            if num_blocks == 0 and block_len == 0:
                break
            self.BlockMap.append((num_blocks, block_len))
            offset += 8

class EFI_FIRMWARE_FILE_SYSTEM_FILE_HEADER:

    def __init__(self, data: bytes):
        self.Data = data
        self.NameGUID = data[0:0x10] # 文件名GUID
        self.Checksum = data[0x10:0x12] # 校验
        self.Type = data[0x12] # 类型
        self.Attributes = data[0x13] # 属性
        self.Size = data[0x14:0x17] # 总大小，小端序，包含头长度
        self.State = data[0x17] # 状态
        if self.is_large_file():
            self.Size = data[0x18:0x1F] # 大文件大小

    def __len__(self) -> int:
        return 0x20 if self.is_large_file() else 0x18

    def verify(self) -> bool:
        checksum = 0
        for i, d in enumerate(self.Data[:0x18]):
            if i == 0x11 or i == 0x17:
                pass
            else:
                checksum = (checksum + d) & 0xFF
        if checksum == 0:
            return True
        return False

    def get_type(self) -> str:
        return {
            0x00: 'Null',
            0x01: 'Raw',
            0x02: 'Free Format',
            0x03: 'Security Core',
            0x04: 'PEI Core',
            0x05: 'DXE Core',
            0x06: 'PEI Module',
            0x07: 'DXE Drive',
            0x08: 'Combine PEI DXE',
            0x09: 'UEFI APP',
            0x0A: 'Management Mode(MM) Driver',
            0x0B: 'Firmware Volume Image',
            0x0C: 'Combine MM DXE',
            0x0D: 'MM Core',
            0x0E: 'MM Standalone',
            0x0F: 'MM Standalone Core',
            0xF0: 'Padding'
        }.get(self.Type, 'OEM 定义' if 0xC0 <= self.Type <=0xDF else '调试定义'if 0xE0 <= self.Type <= 0xEF else 'Firmware File System 内部保留' if 0xF1 <= self.Type <= 0xFF else '未知')

    def gen_check_sum(self):
        pass

    def is_large_file(self) -> bool:
        if self.Attributes & 0x01 == 1:
            return True
        return False

    def get_context_size(self) -> int:
        if self.is_large_file():
            return int.from_bytes(self.Size, 'little') - 0x20
        return int.from_bytes(self.Size, 'little') - 0x18

class EFI_SECTION_HEADER:
    
    def __init__(self, data: bytes):
        self.Size = data[0x0:0x03]
        self.Type = data[0x03]
        self.Header_Size = 0x04
    
    def __len__(self):
        return 0x04
    
    def get_type(self) -> str:
        return {
            0x00: "EFI_SECTION_ALL",
            0x01: "EFI_SECTION_COMPRESSION",
            0x02: "EFI_SECTION_GUID_DEFINED",
            0x03: "EFI_SECTION_DISPOSABLE",
            0x10: "EFI_SECTION_PE32",
            0x11: "EFI_SECTION_PIC",
            0x12: "EFI_SECTION_TE",
            0x13: "EFI_SECTION_DXE_DEPEX",
            0x14: "EFI_SECTION_VERSION",
            0x15: "EFI_SECTION_USER_INTERFACE",
            0x16: "EFI_SECTION_COMPATIBILITY16",
            0x17: "EFI_SECTION_FIRMWARE_VOLUME_IMAGE",
            0x18: "EFI_SECTION_FREEFORM_SUBTYPE_GUID",
            0x19: "EFI_SECTION_RAW",
            0x1A: "EFI_SECTION_PEI_DEPEX",
            0x1B: "EFI_SECTION_SMM_DEPEX"
        }.get(self.Type, "EFI_SECTION_UNKNOWN")

class EFI_SECTION_EXT_HEADER:
    
    def __init__(self, data: bytes):
        self.Type = data[0x03]
        self.Size = data[0x04:0x08]
        self.Header_Size = 0x08
    
    def __len__(self):
        return 0x08
    
    def get_type(self) -> str:
        return {
            0x00: "EFI_SECTION_ALL",
            0x01: "EFI_SECTION_COMPRESSION",
            0x02: "EFI_SECTION_GUID_DEFINED",
            0x03: "EFI_SECTION_DISPOSABLE",
            0x10: "EFI_SECTION_PE32",
            0x11: "EFI_SECTION_PIC",
            0x12: "EFI_SECTION_TE",
            0x13: "EFI_SECTION_DXE_DEPEX",
            0x14: "EFI_SECTION_VERSION",
            0x15: "EFI_SECTION_USER_INTERFACE",
            0x16: "EFI_SECTION_COMPATIBILITY16",
            0x17: "EFI_SECTION_FIRMWARE_VOLUME_IMAGE",
            0x18: "EFI_SECTION_FREEFORM_SUBTYPE_GUID",
            0x19: "EFI_SECTION_RAW",
            0x1A: "EFI_SECTION_PEI_DEPEX",
            0x1B: "EFI_SECTION_SMM_DEPEX"
        }.get(self.Type, "EFI_SECTION_UNKNOWN")

class EFI_SECTION_GUID_DEFINED_HEADER(EFI_SECTION_HEADER):
    
    def __init__(self, data: bytes):
        super().__init__(data)
        self.GUID = data[0x04:0x14]
        self.Data_Offset = data[0x14:0x16]
        self.Attributes = data[0x16:0x18]
        self.Header_Size = 0x18

    def process(self, data: bytes) -> bytes:
        match int.from_bytes(self.GUID, 'little'):
            case 0xCF0394D77BDC6E9D42593914EE4E5898:
                return lzma.decompress(data)
            case 0x89E8EAA672CA9A904BFB1352D42AE6BD:
                pass

    def verify(self) -> bool:
        return int.from_bytes(self.Attributes, 'little') & 0x02 == 1

    def require_process(self) -> bool:
        return int.from_bytes(self.Attributes, 'little') & 0x01 == 1

class EFI_SECTION_GUID_DEFINED_EXT_HEADER(EFI_SECTION_EXT_HEADER):
    
    def __init__(self, data: bytes):
        super().__init__(data)
        self.GUID = data[0x08:0x18]
        self.Data_Offset = data[0x18:0x1A]
        self.Attributes = data[0x1A:0x1C]
        self.Header_Size = 0x1C

    def process(self, data: bytes) -> bytes:
        match int.from_bytes(self.GUID):
            case 0x98584EEE143959429d6EDC7BD79403CF:
                return lzma.decompress(data)
            case 0xBDE62AD45213FB4B909ACA72A6EAE889:
                pass

    def verify(self) -> bool:
        return int.from_bytes(self.Attributes, 'little') & 0x02 == 1

    def require_process(self) -> bool:
        return int.from_bytes(self.Attributes, 'little') & 0x01 == 1

class EFI_SECTION_USER_INTERFACE_HEADER(EFI_SECTION_HEADER):
    
    def __init__(self, data: bytes):
        super().__init__(data[:0x04])

class EFI_SECTION_USER_INTERFACE_EXT_HEADER(EFI_SECTION_EXT_HEADER):
    
    def __init__(self, data: bytes):
        super().__init__(data[:0x08])

def dump(data: bytes, path: str):
    bf = open(path, 'wb')
    bf.write(data)

def bytes2guid(data: bytes) -> str:
    return '{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}'.format(
        data[3], data[2], data[1], data[0], data[5], data[4], data[7], data[6], data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15])

def parse_sections(align: int, fd: io.BufferedReader, full_size: int, header_pos: int, ident: str): # 上层只负责获取长度及起始, 嵌套需自行处理
    pos = header_pos
    while pos + 0x04 < header_pos + full_size:
        print(ident + '节信息:')
        ident += '\t'
        fd.seek(pos)
        common_head = EFI_SECTION_HEADER(fd.read(0x04))
        if int.from_bytes(common_head.Size, 'little') == 0xFFFFFF:
            fd.seek(pos)
            common_head = EFI_SECTION_EXT_HEADER(fd.read(0x08))
        print(ident + '节类型:', common_head.get_type())
        print(ident + '节头起始位置: 0x{:X}'.format(pos))
        print(ident + '节总长度: 0x{:X}'.format(int.from_bytes(common_head.Size, 'little')))
        match common_head.Type:
            case 0x02:
                fd.seek(pos)
                guid_def_sec_header = EFI_SECTION_GUID_DEFINED_HEADER(fd.read(0x18))
                if int.from_bytes(guid_def_sec_header.Size, 'little') == 0xFFFFFF:
                    fd.seek(pos)
                    guid_def_sec_header = EFI_SECTION_GUID_DEFINED_EXT_HEADER(fd.read(0x1C))
                guid = uuid.UUID(bytes2guid(guid_def_sec_header.GUID))
                print(ident + '节GUID:', bytes2guid(guid_def_sec_header.GUID))
                print(ident + 'GUID版本:', guid.version)
                print(ident + 'GUID变体:', guid.variant)
                print(ident + '节内容起始地址: 0x{:X}'.format(int.from_bytes(guid_def_sec_header.Data_Offset, 'little') + pos))
                pos += (guid_def_sec_header.Header_Size + align - 1) & ~(align - 1)
                if guid_def_sec_header.require_process():
                    print(ident + '此节内容需要处理, 以下为处理后的内容, 偏移从0开始, 上述偏移失效')
                    context: bytes = guid_def_sec_header.process(fd.read(int.from_bytes(guid_def_sec_header.Size, 'little') - guid_def_sec_header.Header_Size))
                    print(ident + '处理后内容长度: 0x{:X}'.format(len(context)))
                    dump(context, 'lzma.bin')
                    parse_sections(align, io.BytesIO(context), len(context), 0, '')
                    print('处理结束')
                else:
                    parse_sections(align, fd, int.from_bytes(guid_def_sec_header.Size, 'little') - guid_def_sec_header.Header_Size, 0, ident)
                pos += int.from_bytes(guid_def_sec_header.Size, 'little') - guid_def_sec_header.Header_Size
            case 0x15:
                fd.seek(pos)
                ui_sec_header = EFI_SECTION_USER_INTERFACE_HEADER(fd.read(0x08))
                if int.from_bytes(ui_sec_header.Size, 'little') == 0xFFFFFF:
                    fd.seek(pos)
                    ui_sec_header = EFI_SECTION_USER_INTERFACE_EXT_HEADER(fd.read(0x0C))
                print(ident + '节内容起始地址: 0x{:X}'.format(pos))
                print(ident + '节内容长度: 0x{:X}'.format(int.from_bytes(ui_sec_header.Size, 'little') - ui_sec_header.Header_Size))
                fd.seek(pos + ui_sec_header.Header_Size)
                print(ident + '节内容（字符串）:', fd.read(int.from_bytes(ui_sec_header.Size, 'little') - ui_sec_header.Header_Size)[:-2].decode('utf-16le'))
                pos += (int.from_bytes(ui_sec_header.Size, 'little') + align - 1) & ~(align - 1)
            case 0x17:
                parse_firmware_volume(fd, pos + common_head.Header_Size, ident)
                pos += (int.from_bytes(common_head.Size, 'little') + align - 1) & ~(align - 1)
            case 0x19:
                print(ident + '保存RAW数据')
                dump(fd.read(int.from_bytes(common_head.Size, 'little') - len(common_head)), 'img/RAW_Sec_Data@0x{:X}.bin'.format(pos))
                pos += int.from_bytes(common_head.Size, 'little')
            case _:
                print(ident + '跳过未知数据')
                if pos + int.from_bytes(common_head.Size, 'little') > full_size or int.from_bytes(common_head.Size, 'little') == 0:
                    break
                pos += int.from_bytes(common_head.Size, 'little')
        ident = ident[:-1]

def parse_ffs_files(align: int, fd: io.BufferedReader, full_size: int, header_pos: int, ident: str): # 上层只负责获取长度及起始, 嵌套需自行处理
    pos = header_pos
    while pos + 0x18 < header_pos + full_size:
        print(ident + 'Firmware File System头信息:')
        ident += '\t'
        fd.seek(pos)
        ffs_file_header = EFI_FIRMWARE_FILE_SYSTEM_FILE_HEADER(fd.read(0x18))
        print(ident + 'Firmware File System文件头起始地址: 0x{:X}'.format(pos))
        guid = uuid.UUID(bytes2guid(ffs_file_header.NameGUID))
        print(ident + 'Firmware File System文件头GUID:', bytes2guid(ffs_file_header.NameGUID))
        print(ident + 'GUID版本:', guid.version)
        print(ident + 'GUID变体:', guid.variant)
        print(ident + 'Firmware File System文件长度: 0x{:X}'.format(int.from_bytes(ffs_file_header.Size, 'little')))
        print(ident + 'Firmware File System文件类型:', ffs_file_header.get_type())
        print(ident + 'Firmware File System文件头校验' + ('通过' if ffs_file_header.verify() else '不通过, 跳过内容解析'))
        if ffs_file_header.verify():
            if ffs_file_header.is_large_file():
                fd.seek(pos)
                ffs_file_header = EFI_FIRMWARE_FILE_SYSTEM_FILE_HEADER(fd.read(0x20))
            match ffs_file_header.Type:
                case 0x0:
                    print(ident + '当前位置: 0x{:X}'.format(pos))
                    print(ident + '跳过泛型数据')
                    pos += (int.from_bytes(ffs_file_header.Size, 'little') + align - 1) & ~(align - 1)
                case 0x01:
                    print(ident + '当前位置: 0x{:X}'.format(pos))
                    print(ident + '保存RAW数据')
                    dump(fd.read(int.from_bytes(ffs_file_header.Size, 'little') - len(ffs_file_header)), bytes2guid(ffs_file_header.NameGUID))
                    pos += (int.from_bytes(ffs_file_header.Size, 'little') + align - 1) & ~(align - 1)
                case 0x02:
                    parse_sections(align, fd, int.from_bytes(ffs_file_header.Size, 'little') - len(ffs_file_header), pos + len(ffs_file_header), ident)
                    pos += (int.from_bytes(ffs_file_header.Size, 'little') + align - 1) & ~(align - 1)
                case 0x0B:
                    print(ident + '当前位置: 0x{:X}'.format(fd.tell()))
                    parse_sections(align, fd,int.from_bytes(ffs_file_header.Size, 'little') , pos + len(ffs_file_header), ident)
                    pos += (int.from_bytes(ffs_file_header.Size, 'little') + align - 1) & ~(align - 1)
                case 0xF0:
                    print(ident + '当前位置: 0x{:X}'.format(pos))
                    print(ident + '跳过空数据')
                    pos += (int.from_bytes(ffs_file_header.Size, 'little') + align - 1) & ~(align - 1)
                case _:
                    print(ident + '当前位置: 0x{:X}'.format(pos))
                    print(ident + '跳过未知数据')
                    if pos + int.from_bytes(ffs_file_header.Size, 'little') > full_size or int.from_bytes(ffs_file_header.Size, 'little') == 0:
                        break
                    pos += (int.from_bytes(ffs_file_header.Size, 'little') + align - 1) & ~(align - 1)
        elif pos + int.from_bytes(ffs_file_header.Size, 'little') > full_size or int.from_bytes(ffs_file_header.Size, 'little') == 0:
            break
        else:
            pos += (int.from_bytes(ffs_file_header.Size, 'little') + align - 1) & ~(align - 1)
        ident = ident[:-1]

def parse_firmware_volume(fd: io.BufferedReader, header_pos: int, ident: str): # 上层只负责获取起始, 头已定义长度, 此结构不会自嵌套
    fd.seek(header_pos)
    fv_header = EFI_FIRMWARE_VOLUME_HEADER(fd.read(0x38))
    print(ident + '固件卷详细信息:')
    guid = uuid.UUID(bytes2guid(fv_header.File_System_GUID))
    ident += '\t'
    print(ident + '头GUID:', bytes2guid(fv_header.File_System_GUID))
    print(ident + 'GUID版本:', guid.version)
    print(ident + 'GUID变体:', guid.variant)
    print(ident + '固件卷总大小: 0x{:X}'.format(int.from_bytes(fv_header.File_Volume_Length, 'little')))
    print(ident + '头长度 (含块映射): 0x{:X}'.format(int.from_bytes(fv_header.Header_Length, 'little')))
    print(ident + '对齐要求: {} 字节'.format(fv_header.get_alignment()))
    print(ident + '固件卷头校验' + ('通过' if fv_header.verify() else '不通过, 跳过内容解析'))
    if fv_header.verify: 
        if fv_header.Have_EXT_Header:
            fd.seek(header_pos)
            fv_header = EFI_FIRMWARE_VOLUME_EXT_HEADER(fd.read(int.from_bytes(fv_header.Extend_Header_Offset, 'little') + 0x14))
            fd.seek(header_pos)
            fv_header = EFI_FIRMWARE_VOLUME_EXT_HEADER(fd.read(int.from_bytes(fv_header.Extend_Header_Offset, 'little') + int.from_bytes(fv_header.Extend_Header_Size, 'little')))
            print(ident + '扩展头位于偏移量0x{:X}'.format(int.from_bytes(fv_header.Extend_Header_Offset, 'little')))
            print(ident + '扩展头大小: 0x{:X}'.format(int.from_bytes(fv_header.Extend_Header_Size, 'little')))
            print(ident + '固件卷名称GUID:', bytes2guid(fv_header.File_Volume_Name_GUID))
            guid = uuid.UUID(bytes2guid(fv_header.File_Volume_Name_GUID))
            print(ident + 'GUID版本:', guid.version)
            print(ident + 'GUID变体:', guid.variant)
            ffs_rel_start = max(int.from_bytes(fv_header.Header_Length, 'little'), int.from_bytes(fv_header.Extend_Header_Offset, 'little') + int.from_bytes(fv_header.Extend_Header_Size, 'little'))
            # 取块映射结束和扩展头结束的最大值
            # 按对齐要求向上取整
            if fv_header.get_alignment() > 1:
                ffs_rel_start = (ffs_rel_start + fv_header.get_alignment() - 1) & ~(fv_header.get_alignment() - 1)
            ffs_abs_start = header_pos + ffs_rel_start
            ffs_context_length = header_pos + int.from_bytes(fv_header.File_Volume_Length, 'little') - int.from_bytes(fv_header.Header_Length, 'little') - ffs_abs_start
            # 解析 Firmware File System 文件
            parse_ffs_files(fv_header.get_alignment(), fd, ffs_context_length, ffs_abs_start, ident)
        else:
            print(ident + '此段不含扩展头')
            parse_ffs_files(fv_header.get_alignment(), fd, int.from_bytes(fv_header.File_Volume_Length, 'little') - int.from_bytes(fv_header.Header_Length, 'little'),
                            header_pos + int.from_bytes(fv_header.Header_Length, 'little'), ident)

elf32_header = ELF32_HEADER(fd.read(0x40))
ident = ''

print(f'{ident}{file_name} 魔数:', str(elf32_header.Magic))
print(f'{ident}{file_name} 格式:', elf32_header.Type_Str)
print(f'{ident}{file_name} 存储方式:', elf32_header.Format_Str)
print(f'{ident}{file_name} ELF版本:', elf32_header.ELF_Version)
print(f'{ident}{file_name} ABI:', elf32_header.OS_ABI)
print(f'{ident}{file_name} ABI版本:', elf32_header.ABI_Version)
print(f'{ident}{file_name} 类型:', elf32_header.get_type())
print('{0} 程序entry point: 0x{1:X}'.format(file_name, int.from_bytes(elf32_header.PRGM_Entry, elf32_header.Format_Str)))
if int.from_bytes(elf32_header.PRGM_Header_ELMT_Num, elf32_header.Format_Str) != 0:
    print('{0} 程序头表起始地址: 0x{1:X}'.format(file_name, int.from_bytes(elf32_header.PRGM_Header_Table_Offset, elf32_header.Format_Str)))
    print(f'{ident}{file_name} 程序头表元素大小:', str(int.from_bytes(elf32_header.PRGM_Header_ELMT_Size, elf32_header.Format_Str)))
    print(f'{ident}{file_name} 程序头表元素数量:', str(int.from_bytes(elf32_header.PRGM_Header_ELMT_Num, elf32_header.Format_Str)))
else:
    print(f'{ident}{file_name} 程序头表为空')
if int.from_bytes(elf32_header.SEC_Header_ELMT_Num, elf32_header.Format_Str) != 0:
    print(ident + '{0} 节头表起始地址: 0x{1:X}'.format(file_name, int.from_bytes(elf32_header.SEC_Header_Table_Offset, elf32_header.Format_Str)))
    print(f'{ident}{file_name} 节头表元素数量:', str(int.from_bytes(elf32_header.SEC_Header_ELMT_Num, elf32_header.Format_Str)))
    print(f'{ident}{file_name} 节头表元素大小:', str(int.from_bytes(elf32_header.SEC_Header_ELMT_Size, elf32_header.Format_Str)))
    print(ident + '{0} 节头表字符串表索引: 0x{1:X}'.format(file_name, int.from_bytes(elf32_header.SEC_Header_String_Index, elf32_header.Format_Str)))
else:
    print(ident + f'{ident}{file_name} 节头表为空')

if int.from_bytes(elf32_header.PRGM_Header_ELMT_Num, elf32_header.Format_Str) != 0:
    fd.seek(int.from_bytes(elf32_header.PRGM_Header_Table_Offset, elf32_header.Format_Str))
    print(ident + '开始读取程序头表数据...')
    for i in range(int.from_bytes(elf32_header.PRGM_Header_ELMT_Num, elf32_header.Format_Str)):
        pht_elmt_data = fd.read(int.from_bytes(elf32_header.PRGM_Header_ELMT_Size, elf32_header.Format_Str))
        crnt_pos = fd.tell()
        elmt = PRGM_HEAD_TABLE_ELMT(pht_elmt_data)
        print(f'{ident}段{i}信息:')
        ident += '\t'
        print(ident + '状态:', elmt.get_permission(elf32_header.Format_Str))
        print(ident + '段头起始地址: 0x{:X}'.format(elmt.get_offset(elf32_header.Format_Str)))
        print(ident + '长度: 0x{:X}'.format(elmt.get_size(elf32_header.Format_Str)))
        print(ident + '段类型:', elmt.get_type(elf32_header.Format_Str))
        ident = ident[:-1]
        if elmt.available(elf32_header.Format_Str):
            ident += '\t'
            print(ident + '开始解析可用段数据')
            parse_firmware_volume(fd, elmt.get_offset(elf32_header.Format_Str), ident)
            ident = ident[:-1]
        fd.seek(crnt_pos)
        
    '''
    parser = uefi_firmware.AutoParser(ffs)
    print('文件类型:', parser.type())
    if parser.type() != 'unknown':
        firmware = parser.parse()
        #firmware.data
        firmware.showinfo()
    '''

fd.close()