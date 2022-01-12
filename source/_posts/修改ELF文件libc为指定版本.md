
---
title:  修改ELF文件libc为指定版本
categories: [Linux]
tags: [pwn,Linux,libc]

---

最近在学习堆时,常常遇到本地libc与题目libc不匹配导致一些骚套路无法在本地调试和利用.要想gdb,不仅得要安个符合版本的虚拟机或起一个docker还有部署一边pwn环境,这一点很烦(#`Д´).于是想找下有没有更方便的方法.  于是找到了patchelf更换libc的方法。

<!-- more -->

### glibc-all-in-one与patchelf安装

glibc-all-in-one，正如其名是一个多版本libc的下载安装管理工具，主要支持2.19，2.23-2.29版本的libc和i686, amd64的架构。这是github一个开源项目因此我们git它既可。

安装命令：

```shell
git clone https://github.com/matrix1001/glibc-all-in-one.git 
cd glibc-all-in-one 
chmod a+x build download extract
```

patchelf在ubuntu直接`apt install patchelf`即可。

### 对应libc编译

我们可以通过在glibc-all-in-one目录下执行`./build`即可获对应版本的libc和ld.so

例如：`./build 2.29 i686`

下载安装编译 32位的2.29 版本libc。

### patchelf更改程序libc

执行`patchelf --set-interpreter ld.so  elf`    来修改文件ld.so

执行`patchelf --replace-needed   old_libc.so  new_libc.so elf   `来修改文件libc.so

以更改gundam文件为例,例如：

```shell
sudo patchelf --set-interpreter /glibc/2.26/amd64/lib/ld-2.26.so --set-rpath /glibc/2.26/amd64/lib/ ~/Desktop/pwn/buu/gumad/gundam

patchelf --replace-needed /glibc/2.23/amd64/lib/libc-2.23.so /glibc/2.26/amd64/lib/libc-2.26.so ~/Desktop/pwn/buu/gumad/gundam
```

## 参考文献

https://www.nopnoping.xyz/2020/04/17/%E4%BF%AE%E6%94%B9%E7%A8%8B%E5%BA%8F%E4%B8%BA%E6%8C%87%E5%AE%9Alibc%E7%89%88%E6%9C%AC-pwndbg%E5%AE%89%E8%A3%85/

https://blog.csdn.net/github_36788573/article/details/103291343

https://blog.csdn.net/qq_41560595/article/details/114597342