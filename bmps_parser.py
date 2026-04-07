class BITMAP_FILE_HEADER:
    
    def __init__(self, data: bytes):
        self.Std_H = b'BM'
        self.Type = data[:0x2]
        self.Size = data[0x2:0x6] # full file size
        self.Rsv1 = data[0x6:0x8]
        self.Rsv2 = data[0x8:0xA]
        self.Offset = data[0xA:0xD]
    
    def verify(self):
        return self.Type == self.Std_H and self.Rsv1 == b'\x00\x00' and self.Rsv2 == b'\x00\x00'
    
class BITMAP_INFO_HEADER:
    
    def __init__(self, data: bytes):
        self.Size = data[:0x04]
        self.Width = data[0x04:0x08]
        self.Height = data[0x08:0x0A]
        self.Plains = data[0x0A:0x0C]
        self.Bit_Count = data[0x0C:0x10]
        self.Compression = data[0x10:0x14]
        self.Size_Image = data[0x14:0x18]
        self.X_Pixel_Per_Meter = data[0x18:0x1C]
        self.Y_Pixel_Per_Meter = data[0x1C:0x20]
        self.Clr_Used = data[0x20:0x24]
        self.Clr_Important = data[0x24:0x28]
    
class MI_LOGO_IMAGE_HEADER:
    
    def __init__(self, data: bytes):
        self.Std_H = b'LOGO!!!!'
        self.Magic = data[:0x08]
    
    def verify(self):
        return self.Magic == self.Std_H