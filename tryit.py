from PIL import Image
import gzip
"""width, height = 1080, 2400
img = Image.new('RGB', (width, height), color=(63, 168, 255))
dpi = 73
img.info['dpi'] = (dpi, dpi)
img.save('img.bmp')"""

def compress_bmp_gzip_compress(input_bmp_path, output_gz_path):
    """
    使用 gzip.compress 函数压缩 BMP 文件。
    """
    # 以二进制读模式读取整个 BMP 文件
    with open(input_bmp_path, 'rb') as f_in:
        bmp_data = f_in.read()
    
    # 压缩数据
    # mtime=None: 根据官方文档，gzip 头部必须包含时间戳，
    #             传入 None 时，默认会用当前时间填充[reference:2]。
    #             如果你希望头部时间戳也为 0，可以传入 mtime=0。
    compressed_data = gzip.compress(bmp_data, compresslevel=9, mtime=0)
    
    # 将压缩后的数据写入文件
    with open(output_gz_path, 'wb') as f_out:
        f_out.write(compressed_data)

# 使用示例
f = open("temp.gz", 'rb').read()
print(f[:0x20])
gzip.decompress(f)
#print('a' + '\t'[:-1] + 'b')