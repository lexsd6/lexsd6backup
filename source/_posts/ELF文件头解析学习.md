title:  对linux 命令执行的总结
categories: [ELF]
tags: [code,Linux]
---
## ELF文件解析--ELF header 分析

`ELF` 是`Executable and Linking Format`的缩写，即可执行和可链接的格式，是`Unix/Linux`系统`ABI (Application Binary Interface)`规范的一部分。`Unix/Linux`下的可执行二进制文件、目标代码文件、共享库文件和core dump文件都属于`ELF`文件。<!--more-->

### ELF格式视图

ELF文件有链接视图和执行视图，两种视图形式：

**链接视图：**
静态链接器（即编译后参与生成最终ELF过程的链接器，如ld ）会以链接视图解析ELF。编译时生成的 .o（目标文件）以及链接后的 .so （共享库）均可通过链接视图解析，链接视图可以没有段表（如目标文件不会有段表）。
**执行视图：**
动态链接器（即加载器，如x86架构 linux下的 /lib/ld-linux.so.2或者安卓系统下的 /system/linker均为动态链接器）会以执行视图解析ELF并动态链接，执行视图可以没有节表。

![img](v2-85a5b44f20d53e6e992269dccc20ac6b_720w.jpg)

左边是`ELF`的链接视图，可以理解为是目标代码文件的内容布局。右边是`ELF`的执行视图，可以理解为可执行文件的内容布局。

对于两种视图来说，`ELF Header`是两种说共有的。

同时，在两个视图的区别上，对于链接视图来说`section`是主要特征，同时对于`Section Header Table ` 在链接视图中也是必要的，但`Program Header Table`来说是非必要的。但对于执行视图来说`Segment`是主要特征，同时对于`Program Header Table ` 在链接视图中也是必要的，但`Section Header Table`是非必要的。



**`segments`与`sections`区分与联系**

`segments`与`sections`区别在于：

- 节（section)
  - 在汇编中经常提到的`.text`，`.bss`，`.data`这些都属于`section`层面上的。
  - `.text`：保存程序代码。
  - `.data`：保存已经初始化的全局变量和局部静态变量
  - `.bss`： 保存未初始化的全局变量和局部静态变量
  - 目标代码文件中的`section`和`section header table`中的条目是一一对应的。`section`的信息用于**链接器**对**代码重定位**。
- 段（segment)
  - 我们平常说的代码段与数据段这些都是是`segment`层面上的。
  - 目标代码中的`section`会被链接器组织到可执行文件的各个`segment`中。`.text section`的内容会组装到代码段中，`.data`, `.bss`等节的内容会包含在数据段中。
  - 而文件载入内存执行时，是以`segment`组织的，每个`segment`对应`ELF`文件中`program header table`中的一个条目，用来建立可执行文件的进程映像。

段（`segments`）与节（`sections`）同时又是是包含的关系，一个`segment`包含若干个`section`。当`ELF`文件被操作系统加载到内存中后（加载到内存中也就是说这个`elf`要运行），系统会将多个具有相同权限（`flg`值）`section`合并成一个`segment`（优化空间利用），减少内存碎片。



### ELF Header 分析

之前说，在ELF文件中无论说基于执行视图还是链接视图，`ELF Header`是都有的结构。在elf文件中

`ELF header`的定义可以在Linux系统的 `/usr/include`目录下`elf.h` 文件中找到。(用vs 装上c/c++相关插件后，可以直接定位到)

在32位与64位系统下，`ELF header`的定义是不同的：

`Elf32_Ehdr`是32位 ELF header的结构体。定义如下：

```c
typedef struct
{
  unsigned char	e_ident[EI_NIDENT];	/* Magic number and other info */
  Elf32_Half	e_type;			/* Object file type */
  Elf32_Half	e_machine;		/* Architecture */
  Elf32_Word	e_version;		/* Object file version */
  Elf32_Addr	e_entry;		/* Entry point virtual address */
  Elf32_Off	e_phoff;		/* Program header table file offset */
  Elf32_Off	e_shoff;		/* Section header table file offset */
  Elf32_Word	e_flags;		/* Processor-specific flags */
  Elf32_Half	e_ehsize;		/* ELF header size in bytes */
  Elf32_Half	e_phentsize;		/* Program header table entry size */
  Elf32_Half	e_phnum;		/* Program header table entry count */
  Elf32_Half	e_shentsize;		/* Section header table entry size */
  Elf32_Half	e_shnum;		/* Section header table entry count */
  Elf32_Half	e_shstrndx;		/* Section header string table index */
} Elf32_Ehdr;
```

`Elf64_Ehdr`是64位ELF header的结构体。定义如下：

```c
typedef struct
{
  unsigned char	e_ident[EI_NIDENT];	/* Magic number and other info */
  Elf64_Half	e_type;			/* Object file type */
  Elf64_Half	e_machine;		/* Architecture */
  Elf64_Word	e_version;		/* Object file version */
  Elf64_Addr	e_entry;		/* Entry point virtual address */
  Elf64_Off	e_phoff;		/* Program header table file offset */
  Elf64_Off	e_shoff;		/* Section header table file offset */
  Elf64_Word	e_flags;		/* Processor-specific flags */
  Elf64_Half	e_ehsize;		/* ELF header size in bytes */
  Elf64_Half	e_phentsize;		/* Program header table entry size */
  Elf64_Half	e_phnum;		/* Program header table entry count */
  Elf64_Half	e_shentsize;		/* Section header table entry size */
  Elf64_Half	e_shnum;		/* Section header table entry count */
  Elf64_Half	e_shstrndx;		/* Section header string table index */
} Elf64_Ehdr;
```

`Elf64_Addr` 和 `Elf64_Off` 都是64位无符号整数。而`Elf32_Addr` 和 `Elf32_Off`是32位无符号整数。这导致ELF header的所占的字节数不同。32位的ELF header占52个字节，64位的ELF header占64个字节。

![ELF header字节布局](bVbivLE.png)

#### e_ident

`e_ident`占16个字节。前四个字节被称作ELF的Magic Number。

```c
unsigned char	e_ident[EI_NIDENT];	/* Magic number and other info */
```

![e_ident各字节含义](bVbivL1.png)

如上图，前4个字节是ELF的`Magic Number`，固定为`7f 45 4c 46`，也对应着字符串`\177ELF`
第5个字节为`EI_CLASS`代表当前ELF文件是32位还是64位的。值为 ELFCLASS32（0x1）表32位，数值为 ELFCLASS64 （0x2）表64位。
第6个字节为`EI_DATA`了数据的编码方式，即我们通常说的little endian或是big endian。值 `ELFDATA2LSB` 表little endian，即为 小端排序，低位字节在前，或者直接说低位字节在低位地址，比如`0x7f454c46`，存储顺序就是`46 4c 45 7f` 。 值 `ELFDATA2MSB`表big endian就是大端排序，高位字节在前，直接说就是高位字节在低位地址，比如`0x7f454c46`，在文件中的存储顺序是`7f 45 4c 46`。

第7个字节为`EI_VERSION`指明了ELF header的版本号，目前值都是EV_CURRENT（1）。

第8个字节为`EI_OSABI`表操作系统`ABI`标识，现在默认为0，

第9-16个字节，都填充为0。

#### e_type

`e_type` 代表文件类。

```c
Elf32_Half	e_type;			/* Object file type */
Elf64_Half	e_type;			/* Object file type */
```

当其值为`ET_REL`（1）表可重定位文 件（如目标文件）

当其值为`ET_EXEC`（2）表可执行文件（可直接执行的文件）

当其值为`ET_DYN`（3）表共享目标文件（如SO库）

当其值为`ET_CORE`（4）表Core文件（吐核文件）

#### e_machine

`e_machine`为架构信息。

```c
 Elf32_Half	e_machine;		/* Architecture */
 Elf64_Half	e_machine;		/* Architecture */
```

当值为`EM_X86_64`(62)表x86-64架构，

#### e_verison

   `e_version`为文件版本，目前常见的ELF 文件版本均为`EV_CURRENT（1）`。

```c
 Elf32_Word	e_version;		/* Object file version */
 Elf64_Word	e_version;		/* Object file version */
```

#### e_entry

`e_entry`表入口虚拟地址（RVA）。即`_start`函数所在的地方（地址）。

```c
Elf32_Addr	e_entry;		/* Entry point virtual address */
Elf64_Addr	e_entry;		/* Entry point virtual address */
```

#### e_phoff

`e_phoff`为程序头表（段表）的偏移，程序头表离启始位置的值。

```c
Elf32_Off	e_phoff;     /* Program header table file offset */
Elf64_Off	e_phoff;     /* Program header table file offset */
```

#### e_shoff

`e_shoff`为节头表的偏移，节头表离启始位置的值。

```c
Elf32_Off	e_shoff;		/* Section header table file offset */
Elf64_Off	e_shoff;		/* Section header table file offset */
```

#### e_flags

处理器特定的标志，一般为`0`。

```c
Elf32_Word	e_flags;		/* Processor-specific flags */
Elf64_Word	e_flags;		/* Processor-specific flags */
```

#### e_ehsize

`Elf_Header`的大小（字节），`64`位则为`64`，如果是`32`位则为`52`。

```c
Elf32_Half	e_ehsize;		/* ELF header size in bytes */
Elf64_Half	e_ehsize;		/* ELF header size in bytes */
```

#### e_phentsize

·`e_phentsize`表程序头表/段表`（Program Header）`的大小（字节）

```c
Elf32_Half	e_phentsize;		/* Program header table entry size */
Elf64_Half	e_phentsize;		/* Program header table entry size */
```

#### e_phnum

`e_phnum`表段的数量。

```c
Elf32_Half	e_phnum;		/* Program header table entry count */
Elf64_Half	e_phnum;		/* Program header table entry count */
```

#### e_shentsize

`e_shentsize`表节头`（Section Header）`的大小（字节）。当`ELF`文件被操作系统加载到内存中后（加载到内存中也就是说这个`elf`要运行），系统会将多个具有相同权限（`flg`值）`section`合并成一个`segment`（优化空间利用），在这个过程中`section`的数量可能会发生改变。

```c
Elf32_Half	e_shentsize;		/* Section header table entry size */
Elf64_Half	e_shentsize;		/* Section header table entry size */
```

#### e_shnum

`e_shnum`表节头数量

```c
Elf32_Half	e_shnum;		/* Section header table entry count */
Elf64_Half	e_shnum;		/* Section header table entry count */
```

#### e_shstrndx

`e_shstrndx`表节字符串表的节索引。

```c
Elf32_Half	e_shstrndx;		/* Section header string table index */
Elf64_Half	e_shstrndx;		/* Section header string table index */
```



### 代码解析Elf头

结合上面知识，我们可以用c语言，来解析Elf 头解析。效果如下：

![image-20230107155708294](image-20230107155708294.png)

原代码如下

```c
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <elf.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <stdint.h>
#include <sys/stat.h>
#include <fcntl.h>

void e_ident_read(char *e_ident)
{
    int i=0;
    printf("头标志:");
    for(i=0;i<16;i++)
    {printf("%x ",e_ident[i]);}

    printf("\n[*]Magic Number:%4s\n",e_ident);
    if(e_ident[4]==2)
    {
        printf("[*]EI_CLASS: x64 (%d)\n",e_ident[4]);
    }
    else
    {
        printf("[*]EI_CLASS: x86 (%d)\n",e_ident[4]);
    }

    if(e_ident[5]==2)
    {
        printf("[*]EI_DATA: big endian (%d)\n",e_ident[5]);
    }
    else
    {
        printf("[*]EI_DATA: little endian (%d)\n",e_ident[5]);
    }   

    printf("[*]EI_VERSION: %d\n",e_ident[6]);
    printf("[*]EI_OSABI: %d\n",e_ident[7]);

}
void e_type_check(int e_type)
{

   if(e_type==1)
    {
        printf("文件类型: ET_REL\n");
    }
    else if(e_type==2)
    { 
        printf("文件类型: ET_EXEC\n");
    }
    else if(e_type==3)
    {
        printf("文件类型: ET_DYN\n");       
    }
    else if(e_type==4)
    {
        printf("文件类型: ET_CORE\n");   
    }
    else{
        printf("文件类型: %hx\n",e_type);
    }
}

void x64_header_read(FILE *fp)
{
    Elf64_Ehdr elf_header;
    rewind(fp);
    fread(&elf_header,sizeof(Elf64_Ehdr),1,fp);
    if(elf_header.e_machine==62)
    {
    printf("运行平台: EM_X86_64\n");
    }
    else{
    printf("运行平台: %hx\n",elf_header.e_machine);
    }
    printf("运行版本:%hx\n",elf_header.e_version);
    printf("入口虚拟RVA: 0x%lx\n",elf_header.e_entry);
    printf("程序头文件偏移: 0x%lx\n",elf_header.e_phoff);
    printf("节头表文件偏移: 0x%lx\n",elf_header.e_shoff);
    printf("ELF文件头大小: 0x%x\n",elf_header.e_ehsize);
    printf("ELF程序头大小: 0x%x\n",elf_header.e_phentsize);
    printf("ELF程序头表计数: 0x%x\n",elf_header.e_phnum);
    printf("ELF节头表大小: 0x%x\n",elf_header.e_shentsize);
    printf("ELF节头表计数: 0x%x\n",elf_header.e_shnum);
    printf("字符串表索引节头: 0x%x\n",elf_header.e_shstrndx);

}
void x32_header_read(FILE *fp)
{
    Elf32_Ehdr elf_header;
    rewind(fp);
    fread(&elf_header,sizeof(Elf32_Ehdr),1,fp);

    e_type_check(elf_header.e_type);
    if(elf_header.e_machine==62)
    {
    printf("运行平台: EM_X86_64\n");
    }
    else{
    printf("运行平台: %hx\n",elf_header.e_machine);
    }
    printf("运行版本:%hx\n",elf_header.e_version);
    printf("入口虚拟RVA: 0x%x\n",elf_header.e_entry);
    printf("程序头文件偏移: 0x%x(bytes)\n",elf_header.e_phoff);
    printf("节头表文件偏移: 0x%x(bytes)\n",elf_header.e_shoff);
    printf("ELF文件头大小: 0x%x\n",elf_header.e_ehsize);
    printf("ELF程序头大小: 0x%x\n",elf_header.e_phentsize);
    printf("ELF程序头表数量: 0x%x\n",elf_header.e_phnum);
    printf("ELF节头表大小: 0x%x\n",elf_header.e_shentsize);
    printf("ELF节头表数量: 0x%x\n",elf_header.e_shnum);
    printf("字符串表索引节头: 0x%x\n",elf_header.e_shstrndx);
}

 void  main(int argc,char* argv[])
 {
    FILE *fp;
    char *typecheck;
    if  (argc<2)
    {
        printf("[x]not find test ELF file !\n");
        exit(0);
    }
    fp=fopen((char*)argv[1],"r");
    if(fp==NULL)
    {
        printf("[x]don't open file\n");
        exit(0);
    }
    typecheck=malloc(0x20);
    fread(typecheck,0x10,1,fp);
 
    if(typecheck[1]!='E'&&typecheck[2]!='L'&&typecheck[3]!='L')
    {
        printf("[x]don't is ELF file!\n");
    }
    e_ident_read(typecheck);
 
    if(typecheck[4]==2)
    {
        x64_header_read(fp);
    }
    else if(typecheck[4]==1)
    {
        x32_header_read(fp);
    }
    else{
        printf("[x]get some wrong!\n");
    }

 }
```



### 参考链接

https://ch3nye.top/Linux%E4%BA%8C%E8%BF%9B%E5%88%B6%E5%88%86%E6%9E%90%E7%AC%94%E8%AE%B0(ELF)/

https://copyright1999.github.io/2021/10/10/%E8%A7%A3%E6%9E%90ELF%E6%96%87%E4%BB%B6-%E4%B8%80/

https://segmentfault.com/a/1190000016766079