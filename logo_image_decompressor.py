#
# Logo.img extractor for Xiaomi Pad 5 (nabu)
#
#    .
#   /|\    While it is completely safe to extract the logo.img from your device, caution should
#  /_._\   be exercised when attempting to replace the logo, since a successful replacement hasn't
#          been done yet.
#
# Status: Check README.md on how to get logo.img from your device.
#

import gzip
import os

# name of the image you want to read data from
input_file = "img/RAW_Sec_Data@0x25BC58.bin"

# offsets and sizes of the decompressed bitmaps
offsets = []
sizes = []

# Step 1: Separate gzip archive and determine offsets & sizes of the bitmaps
with open(input_file, "rb") as full_file, open("temp.gz", "wb") as out:
    full_file.seek(0x4010)
    while True:
        ofs = int.from_bytes(full_file.read(4), "little")
        size = int.from_bytes(full_file.read(4), "little")
        if ofs == 0 and size == 0:
            break
        offsets += [ofs]
        sizes += [size]
    full_file.seek(0x5000)
    out.write(full_file.read())

# Step 2: Extract logos from gzip archive
with gzip.GzipFile("temp.gz", mode="rb") as gz_in, open('uncompressed.bin', 'wb') as f_out:
    f_out.write(gz_in.read())

os.remove("temp.gz")


# Step 3: Separate bitmaps from the uncompressed binary file
with open("uncompressed.bin", "rb") as f_in:
    i = 1
    for offset in offsets:
        f_in.seek(offset)
        size = sizes[i-1]
        with open("logo_" + str(i) + ".bmp", "wb") as logo_f:
            print("Saving logo_" + str(i) + ".bmp")
            logo_f.write(f_in.read(size))
        i += 1

os.remove("uncompressed.bin")
