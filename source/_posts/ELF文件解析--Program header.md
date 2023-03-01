title: ELF文件解析--Program header
categories: [ELF]
tags: [code,Linux]
---



​	Program header 是ELF文件中存放的是系统加载可执行程序所需要的所有信息，是程序装载必须的一部分。	且Program header 是由一个或多个相同结构的程序段(Segment)组成的。 每个程序段(Segment)用于描述一段硬盘数据和内存数据.<!--more-->

## program header  table

多个program header组成了program header table。在program header table 中记录了起始位置、每个表项(program header)的大小、偏移、类型等信息。而program header table 的位置/偏移、数量、大小 信息 被  ELF header中的 `e_phoff` 、  `e_phnum`  、`e_phentsize`这个几个变量所记住。

## program header

在 32位程序下，program header的内容为

```c
typedef struct {
    Elf32_Word    p_type;        /* segment type */
    Elf32_Off    p_offset;    /* segment offset */
    Elf32_Addr    p_vaddr;    /* virtual address of segment */
    Elf32_Addr    p_paddr;    /* physical address - ignored? */
    Elf32_Word    p_filesz;    /* number of bytes in file for seg. */
    Elf32_Word    p_memsz;    /* number of bytes in mem. for seg. */
    Elf32_Word    p_flags;    /* flags */
    Elf32_Word    p_align;    /* memory alignment */
} Elf32_Phdr;
```

在 64位程序下，program header的内容为

```c
typedef struct {
    Elf64_Half    p_type;        /* entry type */
    Elf64_Half    p_flags;    /* flags */
    Elf64_Off    p_offset;    /* offset */
    Elf64_Addr    p_vaddr;    /* virtual address */
    Elf64_Addr    p_paddr;    /* physical address */
    Elf64_Xword    p_filesz;    /* file size */
    Elf64_Xword    p_memsz;    /* memory size */
    Elf64_Xword    p_align;    /* memory & file alignment */
} Elf64_Phdr;
```

对比可见虽然在x86与x64的program header定义有所差异的，但 结构体的内的 变量的个数与变量名是一样。各种的作用也是相同的：

| 变量名   | 含义                                                         |
| -------- | ------------------------------------------------------------ |
| p_type   | 描述了段的而类型或解释该段的作用                             |
| p_offset | 描述了从文件到该段的文件偏移                                 |
| p_vaddr  | 描述了段在内存中的偏移                                       |
| p_paddr  | 描述了物理地址相关，在应用层无作用。                         |
| p_filesz | p_offset描述了段在文件中的偏移。那么此成员就描述了在文件中所占的大小，可以为0 |
| p_memsz  | 同上，描述了内存中映像所占的字节数。 可以为0                 |
| p_flags  | 此成员描述了段的标志,包括读、写、执行                        |
| p_align  | 描述了对齐。对于可加载的段 p_vaddr和p_offset取值必须是合适的。此成员给出了段在文件中和内存中如何对齐。数值 0 1 标识不需要对齐。否则就必须是2的倍数。 p_vaddr和p_offset在取模后应该相等。 |

## 代码读取 Program header

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
    printf("程序头(Phdr):\n");
    printf("段类型\t段偏移\t段虚拟地址\t段物理地址\t段文件大小\t段内存大小\t读写执行\t段的对齐\n");
    x64_get_phnum(elf_header,fp);
}

void x64_get_phnum(Elf64_Ehdr elf_header,FILE *fp)
{

                int phnum, i,temp;
                char* interp ;
                phnum=elf_header.e_phnum;
                Elf64_Phdr *phdr = (Elf64_Phdr*)malloc(sizeof(Elf64_Phdr) * elf_header.e_phnum);
                rewind(fp);
                temp = fseek(fp, elf_header.e_phoff, SEEK_SET);
                temp = fread(phdr, sizeof(Elf64_Phdr) * elf_header.e_phnum, 1, fp);


                for (i  = 0; i < phnum; i++) {
                            printf("0x%x\t%d\t0x%x\t0x%x\t%d\t%d\t%d\t0x%x\n",phdr[i].p_type,phdr[i].p_offset,phdr[i].p_vaddr,phdr[i].p_paddr,phdr[i].p_filesz,phdr[i].p_memsz,phdr[i].p_flags,phdr[i].p_align);
                }

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
    printf("程序头(Phdr):\n");
    printf("段类型\t段偏移\t段虚拟地址\t段物理地址\t段文件大小\t段内存大小\t读写执行\t段的对齐\n");
    x32_get_phnum(elf_header,fp);
}

void x32_get_phnum(Elf32_Ehdr elf_header,FILE *fp)
{

                int phnum, i,temp;
                char* interp ;
                phnum=elf_header.e_phnum;
                Elf32_Phdr *phdr = (Elf32_Phdr*)malloc(sizeof(Elf32_Phdr) * elf_header.e_phnum);
                rewind(fp);
                temp = fseek(fp, elf_header.e_phoff, SEEK_SET);
                temp = fread(phdr, sizeof(Elf32_Phdr) * elf_header.e_phnum, 1, fp);
                rewind(fp);
               /// fseek(fp, phdr[elf_header.e_phnum].ph_size, SEEK_SET);
//                 typedef struct elf32_phdr{
//   Elf32_Word    p_type;  //段的类型，LOAD，DYNAMIC等
//   Elf32_Off    p_offset;  //段在文件中的偏移量
//   Elf32_Addr    p_vaddr;  //段的虚拟地址
//   Elf32_Addr    p_paddr;  //段的物理地址
//   Elf32_Word    p_filesz;  //段在文件中的大小
//   Elf32_Word    p_memsz;  //段在内存中的大小
//   Elf32_Word    p_flags;  //读写执行标记
//   Elf32_Word    p_align;  //段的对齐
// } Elf32_Phdr;



                for (i  = 0; i < phnum; i++) {
                            printf("0x%x\t%d\t0x%x\t0x%x\t%d\t%d\t%d\t0x%x\n",phdr[i].p_type,phdr[i].p_offset,phdr[i].p_vaddr,phdr[i].p_paddr,phdr[i].p_filesz,phdr[i].p_memsz,phdr[i].p_flags,phdr[i].p_align);
                }

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

