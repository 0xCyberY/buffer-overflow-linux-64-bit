# buffer-overflow-linux-64-bit
buffer overflow linux 64 bit

gdb-peda$ file app
Reading symbols from app...
(No debugging symbols found in app)
gdb-peda$ 
gdb-peda$ run
Starting program: /home/kali/Desktop/Buffer_linux/app 
Oops, I'm leaking! 0x7fffffffe0c0
Pwn me ¯\_(ツ)_/¯ 
> 
[Inferior 1 (process 24099) exited normally]
Warning: not running
gdb-peda$ disassemble main
Dump of assembler code for function main:
   0x000000000040082f <+0>:     push   rbp
   0x0000000000400830 <+1>:     mov    rbp,rsp
   0x0000000000400833 <+4>:     sub    rsp,0x40
   0x0000000000400837 <+8>:     mov    eax,0x0
   0x000000000040083c <+13>:    call   0x4007b5 <__init>
   0x0000000000400841 <+18>:    lea    rax,[rbp-0x40]
   0x0000000000400845 <+22>:    mov    rsi,rax
   0x0000000000400848 <+25>:    mov    edi,0x400919
   0x000000000040084d <+30>:    mov    eax,0x0
   0x0000000000400852 <+35>:    call   0x400620 <printf@plt>
   0x0000000000400857 <+40>:    mov    edi,0x400930
   0x000000000040085c <+45>:    call   0x400610 <puts@plt>
   0x0000000000400861 <+50>:    mov    edi,0x400946
   0x0000000000400866 <+55>:    mov    eax,0x0
   0x000000000040086b <+60>:    call   0x400620 <printf@plt>
   0x0000000000400870 <+65>:    mov    rdx,QWORD PTR [rip+0x200819]        # 0x601090 <stdin@@GLIBC_2.2.5>
   0x0000000000400877 <+72>:    lea    rax,[rbp-0x40]
   0x000000000040087b <+76>:    mov    esi,0x200
   0x0000000000400880 <+81>:    mov    rdi,rax
   0x0000000000400883 <+84>:    call   0x400650 <fgets@plt>
   0x0000000000400888 <+89>:    mov    eax,0x0
   0x000000000040088d <+94>:    leave  
   0x000000000040088e <+95>:    ret    
End of assembler dump.

gdb-peda$ 
______________________________________
┌─[kali@kali]─[~/Desktop/Buffer_linux]
└──╼ $python -c 'print "A"*300' > f
______________________________________
gdb-peda$ run < f
Starting program: /home/kali/Desktop/Buffer_linux/app < f
Oops, I'm leaking! 0x7fffffffe0c0
Pwn me ¯\_(ツ)_/¯ 
> 
Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x0 
RCX: 0x7ffff7edef4e (<__GI___libc_read+14>:     cmp    rax,0xfffffffffffff000)
RDX: 0x0 
RSI: 0x7ffff7faea03 --> 0xfb1680000000000a 
RDI: 0x7ffff7fb1680 --> 0x0 
RBP: 0x4141414141414141 ('AAAAAAAA')
RSP: 0x7fffffffe108 ('A' <repeats 200 times>...)
RIP: 0x40088e (<main+95>:       ret)
R8 : 0x7fffffffe0c0 ('A' <repeats 200 times>...)
R9 : 0x0 
R10: 0xfffffffffffff24a 
R11: 0x246 
R12: 0x4006a0 (<_start>:        xor    ebp,ebp)
R13: 0x0 
R14: 0x0 
R15: 0x0
EFLAGS: 0x10202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x400883 <main+84>:  call   0x400650 <fgets@plt>
   0x400888 <main+89>:  mov    eax,0x0
   0x40088d <main+94>:  leave  
=> 0x40088e <main+95>:  ret    
   0x40088f:    nop
   0x400890 <__libc_csu_init>:  push   r15
   0x400892 <__libc_csu_init+2>:        push   r14
   0x400894 <__libc_csu_init+4>:        mov    r15d,edi
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe108 ('A' <repeats 200 times>...)
0008| 0x7fffffffe110 ('A' <repeats 200 times>...)
0016| 0x7fffffffe118 ('A' <repeats 200 times>...)
0024| 0x7fffffffe120 ('A' <repeats 200 times>...)
0032| 0x7fffffffe128 ('A' <repeats 196 times>, "\n")
0040| 0x7fffffffe130 ('A' <repeats 188 times>, "\n")
0048| 0x7fffffffe138 ('A' <repeats 180 times>, "\n")
0056| 0x7fffffffe140 ('A' <repeats 172 times>, "\n")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x000000000040088e in main ()
gdb-peda$ info registers
rax            0x0                 0x0
rbx            0x0                 0x0
rcx            0x7ffff7edef4e      0x7ffff7edef4e
rdx            0x0                 0x0
rsi            0x7ffff7faea03      0x7ffff7faea03
rdi            0x7ffff7fb1680      0x7ffff7fb1680
rbp            0x4141414141414141  0x4141414141414141
rsp            0x7fffffffe108      0x7fffffffe108
r8             0x7fffffffe0c0      0x7fffffffe0c0
r9             0x0                 0x0
r10            0xfffffffffffff24a  0xfffffffffffff24a
r11            0x246               0x246
r12            0x4006a0            0x4006a0
r13            0x0                 0x0
r14            0x0                 0x0
r15            0x0                 0x0
rip            0x40088e            0x40088e <main+95>
eflags         0x10202             [ IF RF ]
cs             0x33                0x33
ss             0x2b                0x2b
ds             0x0                 0x0
es             0x0                 0x0
fs             0x0                 0x0
gs             0x0                 0x0

gdb-peda$run < pattern 
Starting program: /home/kali/Desktop/Buffer_linux/app < pattern
Oops, I'm leaking! 0x7fffffffe0c0
Pwn me ¯\_(ツ)_/¯ 
> 
Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x0 
RCX: 0xfbad20ab 
RDX: 0x0 
RSI: 0x7ffff7faea03 --> 0xfb16800000000025 
RDI: 0x7ffff7fb1680 --> 0x0 
RBP: 0x4141334141644141 ('AAdAA3AA')
RSP: 0x7fffffffe108 ("IAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A"...)
RIP: 0x40088e (<main+95>:       ret)
R8 : 0x7fffffffe0c0 ("AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA"...)
gdb-peda$ pattern_search 
Registers contain pattern buffer:
RBP+0 found at offset: 64
Registers point to pattern buffer:
[RSP] --> offset 72 - size ~203
[R8] --> offset 0 - size ~203
Pattern buffer found at:
0x00007fffffffe0c0 : offset    0 - size  300 ($sp + -0x48 [-18 dwords])

