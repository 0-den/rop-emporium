# Ret2Win

## Description

## Solution

### 表層解析

```
✦ ❯ file ret2win32 
ret2win32: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=e1596c11f85b3ed0881193fe40783e1da685b851, not stripped
```

```
❯ checksec --file=ret2win32
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   72) Symbols	  No	0		3	ret2win32
```

```
❯ nm ret2win32
0804a030 B __bss_start
0804a034 b completed.7283
0804a028 D __data_start
0804a028 W data_start
08048490 t deregister_tm_clones
08048470 T _dl_relocate_static_pie
08048510 t __do_global_dtors_aux
08049f10 d __do_global_dtors_aux_fini_array_entry
0804a02c D __dso_handle
08049f14 d _DYNAMIC
0804a030 D _edata
0804a038 B _end
080486c4 T _fini
080486d8 R _fp_hw
08048540 t frame_dummy
08049f0c d __frame_dummy_init_array_entry
080489a4 r __FRAME_END__
0804a000 d _GLOBAL_OFFSET_TABLE_
         w __gmon_start__
08048828 r __GNU_EH_FRAME_HDR
08048374 T _init
08049f10 d __init_array_end
08049f0c d __init_array_start
080486dc R _IO_stdin_used
080486c0 T __libc_csu_fini
08048660 T __libc_csu_init
         U __libc_start_main@@GLIBC_2.0
08048546 T main
         U memset@@GLIBC_2.0
         U printf@@GLIBC_2.0
         U puts@@GLIBC_2.0
080485ad t pwnme
         U read@@GLIBC_2.0
080484d0 t register_tm_clones
0804862c t ret2win
         U setvbuf@@GLIBC_2.0
08048430 T _start
0804a030 B stdout@@GLIBC_2.0
         U system@@GLIBC_2.0
0804a030 D __TMC_END__
08048480 T __x86.get_pc_thunk.bx
```



ret2winのアドレスは\x2c\x86\x04\x08

ここに移動させればいいっぽい

典型的なbuffer-overflowの脆弱性があって44byte入力してアドレスを入力すると解ける
