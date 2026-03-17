#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UEFI Firmware Section 解析器示例
将通用头部解析与具体节类型解析分离，利用 Python 3.10+ 的 match 语句实现类型分派。
"""

import struct
from enum import IntEnum
from dataclasses import dataclass
from typing import Union


# ----------------------------------------------------------------------
# 1. 节类型枚举（仅列出常用类型，可根据规范扩展）
# ----------------------------------------------------------------------
class SectionType(IntEnum):
    EFI_SECTION_COMPRESSION = 0x01
    EFI_SECTION_GUID_DEFINED = 0x02
    EFI_SECTION_PE32 = 0x10
    EFI_SECTION_PIC = 0x11
    EFI_SECTION_TE = 0x12
    EFI_SECTION_DXE_DEPEX = 0x13
    EFI_SECTION_VERSION = 0x14
    EFI_SECTION_USER_INTERFACE = 0x15
    EFI_SECTION_COMPATIBILITY16 = 0x16
    EFI_SECTION_FIRMWARE_VOLUME_IMAGE = 0x17
    EFI_SECTION_FREEFORM_SUBTYPE_GUID = 0x18
    EFI_SECTION_RAW = 0x19
    EFI_SECTION_PEI_DEPEX = 0x1B
    EFI_SECTION_SMM_DEPEX = 0x1C


# ----------------------------------------------------------------------
# 2. 通用头部结构
# ----------------------------------------------------------------------
@dataclass
class CommonHeader:
    """EFI_COMMON_SECTION_HEADER (4 字节)"""
    size: int          # 24 位小端整数，实际占用低 3 字节
    type: SectionType  # 1 字节类型

    @classmethod
    def from_bytes(cls, data: bytes) -> 'CommonHeader':
        """
        从 4 字节数据解析通用头部。
        data 必须至少 4 字节。
        """
        if len(data) < 4:
            raise ValueError("Insufficient data for CommonHeader")
        # size 位于低 3 字节（小端）
        size = struct.unpack('<I', data[0:3] + b'\x00')[0] & 0x00FFFFFF
        type_ = SectionType(data[3])
        return cls(size, type_)


# ----------------------------------------------------------------------
# 3. 节的基类
# ----------------------------------------------------------------------
class Section:
    """所有节的抽象基类"""
    def __init__(self, header: CommonHeader):
        self.header = header

    def __repr__(self):
        return f"{self.__class__.__name__}(type={self.header.type.name}, size={self.header.size})"


# ----------------------------------------------------------------------
# 4. 具体节类型的实现
# ----------------------------------------------------------------------
class Pe32Section(Section):
    """EFI_SECTION_PE32: 包含 PE32 镜像"""
    def __init__(self, header: CommonHeader, data: bytes):
        super().__init__(header)
        self.data = data

    @classmethod
    def parse(cls, header: CommonHeader, body: bytes) -> 'Pe32Section':
        return cls(header, body)


class TeSection(Section):
    """EFI_SECTION_TE: 包含 TE 镜像"""
    def __init__(self, header: CommonHeader, data: bytes):
        super().__init__(header)
        self.data = data

    @classmethod
    def parse(cls, header: CommonHeader, body: bytes) -> 'TeSection':
        return cls(header, body)


class VersionSection(Section):
    """EFI_SECTION_VERSION: 版本信息（16位版本号 + 字符串）"""
    def __init__(self, header: CommonHeader, version: int, build_string: str):
        super().__init__(header)
        self.version = version
        self.build_string = build_string

    @classmethod
    def parse(cls, header: CommonHeader, body: bytes) -> 'VersionSection':
        # 格式：前 2 字节为小端版本号，后续为以 NULL 结尾的 Unicode 或 ASCII 字符串
        version = struct.unpack('<H', body[:2])[0]
        # 查找第一个空字符的位置
        null_pos = body.find(b'\x00', 2)
        if null_pos == -1:
            str_data = body[2:]
        else:
            str_data = body[2:null_pos]
        # 尝试解码为 UTF-16-LE，失败则回退到 ASCII
        try:
            build_string = str_data.decode('utf-16-le')
        except UnicodeDecodeError:
            build_string = str_data.decode('ascii', errors='ignore')
        return cls(header, version, build_string)


class UserInterfaceSection(Section):
    """EFI_SECTION_USER_INTERFACE: 可读的名称字符串"""
    def __init__(self, header: CommonHeader, name: str):
        super().__init__(header)
        self.name = name

    @classmethod
    def parse(cls, header: CommonHeader, body: bytes) -> 'UserInterfaceSection':
        # 字符串以 NULL 结尾，可能是 Unicode 或 ASCII
        null_pos = body.find(b'\x00')
        if null_pos == -1:
            str_data = body
        else:
            str_data = body[:null_pos]
        try:
            name = str_data.decode('utf-16-le')
        except UnicodeDecodeError:
            name = str_data.decode('ascii', errors='ignore')
        return cls(header, name)


class RawSection(Section):
    """EFI_SECTION_RAW: 原始数据块"""
    def __init__(self, header: CommonHeader, data: bytes):
        super().__init__(header)
        self.data = data

    @classmethod
    def parse(cls, header: CommonHeader, body: bytes) -> 'RawSection':
        return cls(header, body)


# 可根据需要继续添加其他节类型...

# ----------------------------------------------------------------------
# 5. 主解析函数：先解析通用头部，再根据类型分派
# ----------------------------------------------------------------------
def parse_section(data: bytes) -> Section:
    """
    从完整的节数据（包含头部）解析出一个节对象。
    返回 Section 的子类实例。
    """
    # 解析通用头部（固定 4 字节）
    header = CommonHeader.from_bytes(data[:4])

    # 计算节体长度：header.size 是整个节的大小（包括头部），减去已解析的 4 字节
    body = data[4:header.size]

    # 根据类型分发到具体子类的 parse 方法
    match header.type:
        case SectionType.EFI_SECTION_PE32:
            return Pe32Section.parse(header, body)
        case SectionType.EFI_SECTION_TE:
            return TeSection.parse(header, body)
        case SectionType.EFI_SECTION_VERSION:
            return VersionSection.parse(header, body)
        case SectionType.EFI_SECTION_USER_INTERFACE:
            return UserInterfaceSection.parse(header, body)
        case SectionType.EFI_SECTION_RAW:
            return RawSection.parse(header, body)
        # 可继续添加其他已知类型...
        case _:
            # 未知类型：可以抛出异常，或返回一个包含原始数据的通用节
            raise ValueError(f"Unsupported section type: {header.type} (0x{header.type:02X})")


# ----------------------------------------------------------------------
# 6. 演示示例
# ----------------------------------------------------------------------
if __name__ == '__main__':
    # 伪造一些节数据进行测试

    # 示例1：PE32 节
    # 构造一个大小为 0x100 的 PE32 节
    header_bytes = struct.pack('<I', 0x100)[:3] + bytes([SectionType.EFI_SECTION_PE32])
    body_bytes = b'\xCD' * (0x100 - 4)   # 填充数据
    pe32_data = header_bytes + body_bytes

    section = parse_section(pe32_data)
    print(section)  # 应输出 Pe32Section

    # 示例2：Version 节
    # 版本号 0x0102，字符串 "1.0.0" 以 UTF-16-LE 编码，空字符结尾
    version_num = struct.pack('<H', 0x0102)
    name_str = "1.0.0\0".encode('utf-16-le')
    body_bytes = version_num + name_str
    total_size = 4 + len(body_bytes)  # 4 字节头部 + 体长
    header_bytes = struct.pack('<I', total_size)[:3] + bytes([SectionType.EFI_SECTION_VERSION])
    version_data = header_bytes + body_bytes

    section = parse_section(version_data)
    print(section)
    if isinstance(section, VersionSection):
        print(f"  version = 0x{section.version:04X}, build_string = {section.build_string!r}")

    # 示例3：UI 节
    ui_str = "HelloWorld\0".encode('utf-16-le')
    total_size = 4 + len(ui_str)
    header_bytes = struct.pack('<I', total_size)[:3] + bytes([SectionType.EFI_SECTION_USER_INTERFACE])
    ui_data = header_bytes + ui_str

    section = parse_section(ui_data)
    print(section)
    if isinstance(section, UserInterfaceSection):
        print(f"  name = {section.name!r}")