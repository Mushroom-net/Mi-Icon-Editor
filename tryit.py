import uefi_firmware
with open('imagefv_b.img', 'rb') as fh:
  file_content = fh.read()
parser = uefi_firmware.AutoParser(file_content)
print(parser.type())
if parser.type() != 'unknown':
  firmware = parser.parse()
  firmware.showinfo()