fd = open('logo.img', 'rb')
fd.seek(0x501C)
gz = fd.read()
picture = open('tmp.gz', 'wb')
picture.write(gz)
fd.close()
picture.close()
'''import exgz_hurestic
exgz_hurestic.extract_gz_heuristic('logo.img', 0x501C)'''