import gzip

def extract_gz_heuristic(image_file, gz_offset, output_file=None):
    """
    使用启发式方法确定GZ文件大小并提取
    """
    
    if output_file is None:
        output_file = f"extracted_{gz_offset}.gz"
    
    with open(image_file, 'rb') as f:
        # 获取文件总大小
        f.seek(0, 2)  # 移动到文件末尾
        file_size = f.tell()
        
        # 计算可能的最大大小（从偏移到文件末尾）
        max_possible_size = file_size - gz_offset
        
        # 尝试不同的大小进行提取和验证
        for try_size in [64*1024, 128*1024, 256*1024, 512*1024,
                         1024*1024, 4*1024*1024, max_possible_size]:
            
            if try_size > max_possible_size:
                try_size = max_possible_size
            
            print(f"尝试提取 {try_size} 字节...")
            
            f.seek(gz_offset)
            data = f.read(try_size)
            
            # 验证是否是有效的GZ文件
            if len(data) < 10 or data[:4] != b'\x1f\x8b\x08\x00':
                continue
            
            # 尝试解压缩验证完整性
            try:
                decompressed = gzip.decompress(data)
                # 成功！保存文件
                with open(output_file, 'wb') as out_f:
                    out_f.write(data)
                
                print(f"成功提取！文件大小: {try_size} 字节")
                print(f"解压缩后大小: {len(decompressed)} 字节")
                return True
            except gzip.BadGzipFile:
                # 继续尝试更大的大小
                continue
            except EOFError:
                # 文件不完整，需要更大的大小
                continue
    
    print("未能找到完整的GZ文件")
    return False
extract_gz_heuristic('logo.img', 0x1000)