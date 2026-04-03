logo = open('img/Section_Raw_175B1FFC-1F22-46C6-8E56-F4B3B570C3F1_logo.img', 'rb')
logo.seek(0x4000)
open('logo.img', 'wb').write(logo.read())
0x25FC5C