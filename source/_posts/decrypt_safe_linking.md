
---
title:  how2heap-decrypt_safe_linking学习
categories: [CTF]
tags: [pwn]

---
在2.32glibc中，新增的防护之指针异或加密机制到 fastbin 和 tcache 当中，将 pos >> 12 后的值 key，与原来的 next 进行异或，作为新的 next 值。

## 新机制说明

![image-20221016145439852](image-20221016145439852.png)

以free函数为例子，在2.32glibc中在释放chunk时 不是直接把 fd 值放入 `p->fd`中。而是经过 `PROTECT_PTR`或 `REVEAL_PTR`处理。 `PROTECT_PTR`和 `REVEAL_PTR`在宏定义中定义：

```c
/* Safe-Linking:
   Use randomness from ASLR (mmap_base) to protect single-linked lists
   of Fast-Bins and TCache.  That is, mask the "next" pointers of the
   lists' chunks, and also perform allocation alignment checks on them.
   This mechanism reduces the risk of pointer hijacking, as was done with
   Safe-Unlinking in the double-linked lists of Small-Bins.
   It assumes a minimum page size of 4096 bytes (12 bits).  Systems with
   larger pages provide less entropy, although the pointer mangling
   still works.  */
#define PROTECT_PTR(pos, ptr) \
  ((__typeof (ptr)) ((((size_t) pos) >> 12) ^ ((size_t) ptr)))
#define REVEAL_PTR(ptr)  PROTECT_PTR (&ptr, ptr)
```

`PROTECT_PTR`和 `REVEAL_PTR` 使用ASLR（mmap_base）的随机性来保护单链接列表Fast Bins和TCache。也就是说，屏蔽列出块，并对其执行分配对齐检查。这种机制降低了指针劫持的风险，就像对在小箱子的双重链接列表中安全断开链接。它假定最小页面大小为4096字节（12位）。具有的系统较大的页面提供较少的熵，尽管指针会被破坏仍然有效.用一个官方例子来描述:

![libc_figure_6](libc_figure_6.png)

即 **tcache_entry->next中存放的chunk地址为与自身地址进行异或运算后所得到的值**， 这就要求我们在利用 tcache_entry 进行任意地址写之前 **需要我们提前泄漏出相应 chunk 的地址，即我们需要提前获得堆基址后才能进行任意地址写**，这给传统的利用方式无疑是增加了不少的难度.





## how2heap-decrypt_safe_linking手法分析

在how2heap提供了一个`decrypt_safe_linking.c`的例子让我们在新机制下获得 fastbin 和 tcache的真实fd。

但是我觉得例子不过深刻于是魔改了下。

```c
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

long decrypt(long cipher)
{
	puts("The decryption uses the fact that the first 12bit of the plaintext (the fwd pointer) is known,");
	puts("because of the 12bit sliding.");
	puts("And the key, the ASLR value, is the same with the leading bits of the plaintext (the fwd pointer)");
	long key = 0;
	long plain;

	for(int i=1; i<6; i++) {
		int bits = 64-12*i;
		if(bits < 0) bits = 0;
		plain = ((cipher ^ key) >> bits) << bits;
		key = plain >> 12;
		printf("round %d:\n", i);
		printf("key:    %#016lx\n", key);
		printf("plain:  %#016lx\n", plain);
		printf("cipher: %#016lx\n\n", cipher);
	}
	return plain;
}

int main()
{
	/*
	 * This technique demonstrates how to recover the original content from a poisoned
	 * value because of the safe-linking mechanism.
	 * The attack uses the fact that the first 12 bit of the plaintext (pointer) is known
	 * and the key (ASLR slide) is the same to the pointer's leading bits.
	 * As a result, as long as the chunk where the pointer is stored is at the same page
	 * of the pointer itself, the value of the pointer can be fully recovered.
	 * Otherwise, we can also recover the pointer with the page-offset between the storer
	 * and the pointer. What we demonstrate here is a special case whose page-offset is 0. 
	 * For demonstrations of other more general cases, plz refer to 
	 * https://github.com/n132/Dec-Safe-Linking
	 */

	setbuf(stdin, NULL);
	setbuf(stdout, NULL);

	// step 1: allocate chunks
	long *a = malloc(0x200);
	long *b = malloc(0x200);
	long *c = malloc(0x200);
	long *d = malloc(0x200);
	printf("First, we create chunk a @ %p and chunk b @ %p\n", a, b);
	malloc(0x10);
	puts("And then create a padding chunk to prevent consolidation.");


	// step 2: free chunks
	puts("Now free chunk a and then free chunk b.");
	free(a);
	free(c);
	free(d);
	free(b);
	
	printf("Now the freelist is: [%p -> %p]\n", b, a);
	printf("Due to safe-linking, the value actually stored at b[0] is: %#lx\n", b[0]);

	// step 3: recover the values
	puts("Now decrypt the poisoned value");
	long plaintext = decrypt(b[0]);

	printf("value: %p\n", a);
	printf("recovered value: %#lx\n", plaintext);
	assert(plaintext == (long)a);
}

```

### 过程分析

1.我们先创建4个chunk和一个隔离chunk，

```c
	// step 1: allocate chunks
	long *a = malloc(0x200);
	long *b = malloc(0x200);
	long *c = malloc(0x200);
	long *d = malloc(0x200);
	malloc(0x10);
```

![img](16658363725510.png)

2。然后我们释放一个chunk a。

```
	free(a);
```

![image-20221015202118323](image-20221015202118323.png)

可以看 加入了tcachebins 且fd 处存放的不是0，而是  0x555555559 （右移12位）

3.继续依次 c  d b 释放后 chunk。

```c
	free(c);
	free(d);
	free(b);
```

![image-20221015202508995](image-20221015202508995.png)

ps：可以看 b c d 的fd ，与0x555555559 后，就是真正的fd的

![img](1665836803212.png)

3.对d chunk的fd 进行 decrypt 函数解密。

```c
long decrypt(long cipher)
{
	puts("The decryption uses the fact that the first 12bit of the plaintext (the fwd pointer) is known,");
	puts("because of the 12bit sliding.");
	puts("And the key, the ASLR value, is the same with the leading bits of the plaintext (the fwd pointer)");
	long key = 0;
	long plain;

	for(int i=1; i<6; i++) {
		int bits = 64-12*i;
		if(bits < 0) bits = 0;
		plain = ((cipher ^ key) >> bits) << bits;
		key = plain >> 12;
		printf("round %d:\n", i);
		printf("key:    %#016lx\n", key);
		printf("plain:  %#016lx\n", plain);
		printf("cipher: %#016lx\n\n", cipher);
	}
	return plain;
}

```

可以看到6就循环后，d chunk的fd 的真实fd就还原过来。

```
round 1:
key:    0000000000000000
plain:  0000000000000000
cipher: 0x0055500000cd89

round 2:
key:    0x00000550000000
plain:  0x00550000000000
cipher: 0x0055500000cd89

round 3:
key:    0x00000555550000
plain:  0x00555550000000
cipher: 0x0055500000cd89

round 4:
key:    0x00000555555550
plain:  0x00555555550000
cipher: 0x0055500000cd89

round 5:
key:    0x00000555555559
plain:  0x005555555598d0
cipher: 0x0055500000cd89

```

### 利用分析

从上面的例子可以看出，fd 位置存放值就是 原本fd的值（前一个tache的真实地址）右移 12位与fd 位置的地址值。但由于我们只 12位原本fd的值，因此我们还有3个地址位是原本的。又异或可逆性，我们可以将没变的3个地址位或2个地址右移 12位与上fd 位置存放值，还原出原本 fd一部分值 高4-6位。在把原本 fd一部分与旧原本 fd一部分再右移 12位与上fd 位置存放值，又可以得到一部分原本fd值。![image-20221016213012185](image-20221016213012185.png)因此我们可以更具异或可逆性，慢慢还原出来。

python版脚本如下

```python


#0x0055500000cd89


def decrypt(cipher):
    key=0
    plain=0
    for i in range(5):
        bits= 64-12*(i+1)
        if(bits<0):
            bits=0
        plain = ((cipher ^ key) >> bits) << bits
        key = plain >> 12
        print("round %d:\n"%(i))
        print("key:    %#016lx\n"%key)
        print("plain:  %#016lx\n"%plain)
        print("cipher: %#016lx\n\n"%cipher)

decrypt(0x0055500000cd89)
```

## 后记思考

其实若是第一个tache 那么放入fd 的值就是 (fd^0)>>12.

同时，7个 连续小于等于0x240的tache或fast bin 的间地址差不会超过0x1000.

因此泄露出第一个tache的fd里的值为keys，直接与其他tache的fd相与。就可以得到原址。



## 参考链接

在uclibc-ng中引入的补丁：https://gogs.waldemar-brodkorb.de/oss/uclibc-ng/commit/886878b22424d6f95bcdeee55ada72049d21547c  就是在取p->fd和存放p->fd时都改成调用REVEAL_PTR

https://research.checkpoint.com/2020/safe-linking-eliminating-a-20-year-old-malloc-exploit-primitive/  机制介绍

https://www.researchinnovations.com/post/bypassing-the-upcoming-safe-linking-mitigation 机制绕过