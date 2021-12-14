from pwn import *

BINARY = "./ret2win32"
ELF = ELF(BINARY)

context.os = "linux"
context.arch = "i386"
context.binary = BINARY
