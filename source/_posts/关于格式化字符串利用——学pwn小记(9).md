---
title:  关于格式化字符串利用——学pwn小记(9)
categories: [CTF]
tags: [pwn]

---

格式化字符是格式化字符串函数根据某一字符串参数的内容来进行解析,根据其值来处理解析的其他参数的个数和值的情形。换句话说,一个函数第一个参数作为格式化字符串，根据其来解析之后的参数的过程就是格式化字符串的过程。<!-- more -->

## 格式化字符串函数

能进行格式化字符串操作的函数被称为格式化字符串函数。常见的格式化字符串函数有：

```c
#include <stdio.h>
int printf(const chr *format,...);
int fprintf(FILE *stream,const chr *format,...);
int dprintf(int fd,const chr *format,...);
int sprintf(char *str,const chr *format,....);
int snprintf(char *str,size_t size,const chr *format,....);  

#include <stdarg.h>
int vprintf(const chr *format,va_list ap);
int vfprintf(FILE *stream,const chr *format,va_list ap);
int vdprintf(int fd,const chr *format,va_list ap);
int vsprintf(char *str,const chr *format,va_list ap);
int vsnprintf(char *str,size_t size,const chr *format,va_list ap);  
    
 
```

## 格式化字符串参数

### 指示符

%c：输出字符，配上%n可用于向指定地址写数据。

%d：输出十进制整数，配上%n可用于向指定地址写数据。

%x：输出16进制数据，如%i$x表示要泄漏偏移i处4字节长的16进制数据，%i$lx表示要泄漏偏移i处8字节长的16进制数据，32bit和64bit环境下一样。

%p：输出16进制数据，与%x基本一样，只是附加了前缀0x，在32bit下输出4字节，在64bit下输出8字节，可通过输出字节的长度来判断目标环境是32bit还是64bit。

%s：输出的内容是字符串，即将偏移处指针指向的字符串输出，如%i$s表示输出偏移i处地址所指向的字符串，在32bit和64bit环境下一样，可用于读取GOT表等信息。

%n：将%n之前printf已经打印的字符个数赋值给偏移处指针所指向的地址位置，如%100×10$n表示将0x64写入偏移10处保存的指针所指向的地址（4字节），而%$hn表示写入的地址空间为2字节，%$hhn表示写入的地址空间为1字节，%$lln表示写入的地址空间为8字节，在32bit和64bit环境下一样。有时，直接写4字节会导致程序崩溃或等候时间过长，可以通过%$hn或%$hhn来适时调整。

%n是通过格式化字符串漏洞改变程序流程的关键方式，而其他格式化字符串参数可用于读取信息或配合%n写数据。

### 修饰符

hh ： 类型  1-byte

h   ： 类型  2-byte

l    ： 类型  4-byte

ll    :   类型  8-byte


### 格式化字符串利用

#### 数据泄露

##### 栈数据泄露

我们可以利用多个`%08x.%08x.%08x.%08x`或`%p,%p,%p,%p`来泄露上面的信息.
		同时，如果我们知道了要泄露数据在栈上的位置我们可以通过`%(x)$p`来泄露第`（x）`个参数的信息。

##### 任意地址数据泄露 

类似"%s"的格式，我们可以用它泄露出参数指针所指向内存的数据。

例如`'%(x)$s’+hackaddress`,若第`（x）`个参数刚好存放的是hackaddress，则会读取hackaddress所指向的值。



注意：类似"\x07"、“\x08”、"\x20"等不可见字符可能泄露不出来。

#### 内存覆盖

我们可以利用格式化字符串，对任意地址进行覆盖。

我们可以通过`%n`将前面字符的数量写入特点地址中，例如：

`wwww%10$n`表将4写入第10个参数所对应的地址中（在使用中要注意，栈上数据对其，即32位4个字节一个单位,64位8个字节一个单位）

同时我们可以利用修饰符来降低我们覆盖地址时工作，'%hhn'让我们一次只写入一个字节的数据，从而避免为改一字节而改变整个单位数据。

我们也可以用`%（x）c%n`来代替（x）个'w'从而减短payload长度。



## 参考文献



https://ctf-wiki.org/pwn/linux/fmtstr/fmtstr_intro/

https://firmianay.gitbooks.io/ctf-all-in-one/content/doc/3.1.1_format_string.html