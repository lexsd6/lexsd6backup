---
title:  NahamCon CTF WP
categories: [CTF]
tags: [wp,web,crypto]

---



某周末,在某大佬的推荐下打了下NahamCon CTF在最后几小时里体验了下这真'雨露均沾'的ctf的感觉.(但菜还是菜这点没变(눈_눈)  )

<!--more-->

## web

### Agent 95

进入题目，看到

![image-20200615234157462](C:\Users\lexs\AppData\Roaming\Typora\typora-user-images\image-20200615234157462.png)

分析要抓包改header，User-Agent改成: Mozilla/4.0(compatible;MSIE6.0;Windows 95)

![image-20200615235227934](image-20200615235227934.png)



### Localghost

进入题目 F12查看原代码，发现可疑js。

![image-20200615235426204](image-20200615235426204.png)

进入http://jh2i.com:50003/jquery.jscroll2.js看到

```
var _0xbcec=["\x75\x73\x65\x20\x73\x74\x72\x69\x63\x74","\x6A\x73\x63\x72\x6F\x6C\x6C","\x3C\x73\x6D\x61\x6C\x6C\x3E\x4C\x6F\x61\x64\x69\x6E\x67\x2E\x2E\x2E\x3C\x2F\x73\x6D\x61\x6C\x6C\x3E","\x61\x3A\x6C\x61\x73\x74","","\x66\x6C\x61\x67","\x53\x6B\x4E\x55\x52\x6E\x74\x7A\x63\x47\x39\x76\x62\x32\x39\x76\x61\x33\x6C\x66\x5A\x32\x68\x76\x63\x33\x52\x7A\x58\x32\x6C\x75\x58\x33\x4E\x30\x62\x33\x4A\x68\x5A\x32\x56\x39","\x73\x65\x74\x49\x74\x65\x6D","\x6C\x6F\x63\x61\x6C\x53\x74\x6F\x72\x61\x67\x65","\x64\x61\x74\x61","\x66\x75\x6E\x63\x74\x69\x6F\x6E","\x64\x65\x66\x61\x75\x6C\x74\x73","\x65\x78\x74\x65\x6E\x64","\x6F\x76\x65\x72\x66\x6C\x6F\x77\x2D\x79","\x63\x73\x73","\x76\x69\x73\x69\x62\x6C\x65","\x66\x69\x72\x73\x74","\x6E\x65\x78\x74\x53\x65\x6C\x65\x63\x74\x6F\x72","\x66\x69\x6E\x64","\x62\x6F\x64\x79","\x68\x72\x65\x66","\x61\x74\x74\x72","\x20","\x63\x6F\x6E\x74\x65\x6E\x74\x53\x65\x6C\x65\x63\x74\x6F\x72","\x74\x72\x69\x6D","\x73\x72\x63","\x69\x6D\x67","\x66\x69\x6C\x74\x65\x72","\x6C\x6F\x61\x64\x69\x6E\x67\x48\x74\x6D\x6C","\x6C\x65\x6E\x67\x74\x68","\x2E\x6A\x73\x63\x72\x6F\x6C\x6C\x2D\x69\x6E\x6E\x65\x72","\x3C\x64\x69\x76\x20\x63\x6C\x61\x73\x73\x3D\x22\x6A\x73\x63\x72\x6F\x6C\x6C\x2D\x69\x6E\x6E\x65\x72\x22\x20\x2F\x3E","\x77\x72\x61\x70\x41\x6C\x6C","\x63\x6F\x6E\x74\x65\x6E\x74\x73","\x70\x61\x67\x69\x6E\x67\x53\x65\x6C\x65\x63\x74\x6F\x72","\x68\x69\x64\x65","\x63\x6C\x6F\x73\x65\x73\x74","\x6A\x73\x63\x72\x6F\x6C\x6C\x2D\x6E\x65\x78\x74\x2D\x70\x61\x72\x65\x6E\x74","\x61\x64\x64\x43\x6C\x61\x73\x73","\x2E\x6A\x73\x63\x72\x6F\x6C\x6C\x2D\x69\x6E\x6E\x65\x72\x2C\x2E\x6A\x73\x63\x72\x6F\x6C\x6C\x2D\x61\x64\x64\x65\x64","\x6E\x6F\x74","\x70\x61\x72\x65\x6E\x74","\x3C\x64\x69\x76\x20\x63\x6C\x61\x73\x73\x3D\x22\x6A\x73\x63\x72\x6F\x6C\x6C\x2D\x6E\x65\x78\x74\x2D\x70\x61\x72\x65\x6E\x74\x22\x20\x2F\x3E","\x77\x72\x61\x70","\x75\x6E\x77\x72\x61\x70","\x63\x68\x69\x6C\x64\x72\x65\x6E","\x2E\x6A\x73\x63\x72\x6F\x6C\x6C\x2D\x61\x64\x64\x65\x64","\x72\x65\x6D\x6F\x76\x65\x44\x61\x74\x61","\x2E\x6A\x73\x63\x72\x6F\x6C\x6C","\x75\x6E\x62\x69\x6E\x64","\x64\x69\x76\x2E\x6A\x73\x63\x72\x6F\x6C\x6C\x2D\x69\x6E\x6E\x65\x72","\x62\x6F\x72\x64\x65\x72\x54\x6F\x70\x57\x69\x64\x74\x68","\x70\x61\x64\x64\x69\x6E\x67\x54\x6F\x70","\x73\x63\x72\x6F\x6C\x6C\x54\x6F\x70","\x74\x6F\x70","\x6F\x66\x66\x73\x65\x74","\x68\x65\x69\x67\x68\x74","\x63\x65\x69\x6C","\x77\x61\x69\x74\x69\x6E\x67","\x70\x61\x64\x64\x69\x6E\x67","\x6F\x75\x74\x65\x72\x48\x65\x69\x67\x68\x74","\x69\x6E\x66\x6F","\x6A\x53\x63\x72\x6F\x6C\x6C\x3A","\x66\x72\x6F\x6D\x20\x62\x6F\x74\x74\x6F\x6D\x2E\x20\x4C\x6F\x61\x64\x69\x6E\x67\x20\x6E\x65\x78\x74\x20\x72\x65\x71\x75\x65\x73\x74\x2E\x2E\x2E","\x6E\x65\x78\x74\x48\x72\x65\x66","\x77\x61\x72\x6E","\x6A\x53\x63\x72\x6F\x6C\x6C\x3A\x20\x6E\x65\x78\x74\x53\x65\x6C\x65\x63\x74\x6F\x72\x20\x6E\x6F\x74\x20\x66\x6F\x75\x6E\x64\x20\x2D\x20\x64\x65\x73\x74\x72\x6F\x79\x69\x6E\x67","\x61\x75\x74\x6F\x54\x72\x69\x67\x67\x65\x72","\x61\x75\x74\x6F\x54\x72\x69\x67\x67\x65\x72\x55\x6E\x74\x69\x6C","\x73\x63\x72\x6F\x6C\x6C\x2E\x6A\x73\x63\x72\x6F\x6C\x6C","\x62\x69\x6E\x64","\x63\x6C\x69\x63\x6B\x2E\x6A\x73\x63\x72\x6F\x6C\x6C","\x3C\x64\x69\x76\x20\x63\x6C\x61\x73\x73\x3D\x22\x6A\x73\x63\x72\x6F\x6C\x6C\x2D\x6C\x6F\x61\x64\x69\x6E\x67\x22\x3E","\x3C\x2F\x64\x69\x76\x3E","\x68\x74\x6D\x6C","\x6C\x61\x73\x74","\x3C\x64\x69\x76\x20\x63\x6C\x61\x73\x73\x3D\x22\x6A\x73\x63\x72\x6F\x6C\x6C\x2D\x61\x64\x64\x65\x64\x22\x20\x2F\x3E","\x61\x70\x70\x65\x6E\x64","\x65\x72\x72\x6F\x72","\x72\x65\x6D\x6F\x76\x65","\x2E\x6A\x73\x63\x72\x6F\x6C\x6C\x2D\x6E\x65\x78\x74\x2D\x70\x61\x72\x65\x6E\x74","\x63\x61\x6C\x6C\x62\x61\x63\x6B","\x63\x61\x6C\x6C","\x64\x69\x72","\x6C\x6F\x61\x64","\x64\x69\x76\x2E\x6A\x73\x63\x72\x6F\x6C\x6C\x2D\x61\x64\x64\x65\x64","\x61\x6E\x69\x6D\x61\x74\x65","\x64\x65\x62\x75\x67","\x6F\x62\x6A\x65\x63\x74","\x61\x70\x70\x6C\x79","\x6C\x6F\x67","\x73\x6C\x69\x63\x65","\x70\x72\x6F\x74\x6F\x74\x79\x70\x65","\x66\x6E","\x69\x6E\x69\x74\x69\x61\x6C\x69\x7A\x65\x64","\x65\x61\x63\x68"];
```

转为utf-8得到

```
['use strict', 'jscroll', '<small>Loading...</small>', 'a:last', '', 'flag', 'SkNURntzcG9vb29va3lfZ2hvc3RzX2luX3N0b3JhZ2V9', 'setItem', 'localStorage', 'data', 'function', 'defaults', 'extend', 'overflow-y', 'css', 'visible', 'first', 'nextSelector', 'find', 'body', 'href', 'attr', ' ', 'contentSelector', 'trim', 'src', 'img', 'filter', 'loadingHtml', 'length', '.jscroll-inner', '<div class="jscroll-inner" />', 'wrapAll', 'contents', 'pagingSelector', 'hide', 'closest', 'jscroll-next-parent', 'addClass', '.jscroll-inner,.jscroll-added', 'not', 'parent', '<div class="jscroll-next-parent" />', 'wrap', 'unwrap', 'children', '.jscroll-added', 'removeData', '.jscroll', 'unbind', 'div.jscroll-inner', 'borderTopWidth', 'paddingTop', 'scrollTop', 'top', 'offset', 'height', 'ceil', 'waiting', 'padding', 'outerHeight', 'info', 'jScroll:', 'from bottom. Loading next request...', 'nextHref', 'warn', 'jScroll: nextSelector not found - destroying', 'autoTrigger', 'autoTriggerUntil', 'scroll.jscroll', 'bind', 'click.jscroll', '<div class="jscroll-loading">', '</div>', 'html', 'last', '<div class="jscroll-added" />', 'append', 'error', 'remove', '.jscroll-next-parent', 'callback', 'call', 'dir', 'load', 'div.jscroll-added', 'animate', 'debug', 'object', 'apply', 'log', 'slice', 'prototype', 'fn', 'initialized', 'each']
```

将flag 进行base64解密：JCTF{spoooooky_ghosts_in_storage}



### Phphonebook

进入题目发现疑有文件包含漏洞，

构造: http://jh2i.com:50002/?file=php://filter/read=convert.base64-encode/resource=index.php 得到index.php源码。

```html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Phphonebook</title>
    <link href="main.css" rel="stylesheet">
  </head>
  <body>
	<?php
		$file=$_GET['file'];
		if(!isset($file))
		{
			echo "Sorry! You are in /index.php/?file=";
		} else
		{
			include(str_replace('.php','',$_GET['file']).".php");
			die();
		}
	?>
	  	<p>The phonebook is located at <code>phphonebook.php</code></p>

<div style="position:fixed; bottom:1%; left:1%;">
<br><br><br><br>
<b> NOT CHALLENGE RELATED:</b><br>THANK YOU to INTIGRITI for supporting NahamCon and NahamCon CTF!
<p>
<img width=600px src="https://d24wuq6o951i2g.cloudfront.net/img/events/id/457/457748121/assets/f7da0d718eb77c83f5cb6221a06a2f45.inti.png">
</p>
</div>

  </body>
 </html>
```

发现有waf ，file提交的参数里‘.php’会被过滤，并在末尾强制加上‘.php’.

同时发现phphonebook.php。同样用文件包含得到源码。

```
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Phphonebook</title>
    <link href="main.css" rel="stylesheet">
  </head>

  <body class="bg">
    <h1 id="header"> Welcome to the Phphonebook </h1>

    <div id="im_container">

      <img src="book.jpg" width="50%" height="30%"/>

      <p class="desc">
      This phphonebook was made to look up all sorts of numbers! Have fun...
      </p>

    </div>
<br>
<br>
    <div>
      <form method="POST" action="#">
        <label id="form_label">Enter number: </label>
        <input type="text" name="number">
        <input type="submit" value="Submit">
      </form>
    </div>

    <div id="php_container">
    <?php
      extract($_POST);

    	if (isset($emergency)){
    		echo(file_get_contents("/flag.txt"));
    	}
    ?>
  </div>
  </br>
  </br>
  </br>


<div style="position:fixed; bottom:1%; left:1%;">
<br><br><br><br>
<b> NOT CHALLENGE RELATED:</b><br>THANK YOU to INTIGRITI for supporting NahamCon and NahamCon CTF!
<p>
<img width=600px src="https://d24wuq6o951i2g.cloudfront.net/img/events/id/457/457748121/assets/f7da0d718eb77c83f5cb6221a06a2f45.inti.png">
</p>
</div>

  </body>
</html>
```

发现只要以post提交了emergency变量就可以得到flag

![image-20200616001450290](image-20200616001450290.png)



## Cryptography

### Homecooked

```python
import base64
num = 0
count = 0
cipher_b64 = b"MTAwLDExMSwxMDAsOTYsMTEyLDIxLDIwOSwxNjYsMjE2LDE0MCwzMzAsMzE4LDMyMSw3MDIyMSw3MDQxNCw3MDU0NCw3MTQxNCw3MTgxMCw3MjIxMSw3MjgyNyw3MzAwMCw3MzMxOSw3MzcyMiw3NDA4OCw3NDY0Myw3NTU0MiwxMDAyOTAzLDEwMDgwOTQsMTAyMjA4OSwxMDI4MTA0LDEwMzUzMzcsMTA0MzQ0OCwxMDU1NTg3LDEwNjI1NDEsMTA2NTcxNSwxMDc0NzQ5LDEwODI4NDQsMTA4NTY5NiwxMDkyOTY2LDEwOTQwMDA="

def a(num):
    if (num > 1):
        for i in range(2,num):
            if (num % i) == 0:
                return False
                break
        return True
    else:
        return False
       
def b(num):
    my_str = str(num)
    rev_str = reversed(my_str)
    if list(my_str) == list(rev_str):
       return True
    else:
       return False


cipher = base64.b64decode(cipher_b64).decode().split(",")

while(count < len(cipher)):
    if (a(num)):
        if (b(num)):
            print(chr(int(cipher[count]) ^ num), end='', flush=True)
            count += 1
            if (count == 13):
                num = 50000
            if (count == 26):
                num = 500000
    else:
        pass
    num+=1

print()
```

粗略审计mian代码了解大概函数流程：当a()与b()返回结果为True 时（函数a的作用是判num是否为质数，函数b的作用是判断num是否为回数。），输出cipher[count]与num相与的字符串。且在才count==13时num陡然变为5000 在count==26时num陡然变为50000。

cipher_b64 经过解密分析cipher为一个字符串列表：

```
cipher=[100,111,100,96,112,21,209,166,216,140,330,318,321,70221,70414,70544,71414,71810,72211,72827,73000,73319,73722,74088,74643,75542,1002903,1008094,1022089,1028104,1035337,1043448,1055587,1062541,1065715,1074749,1082844,1085696,1092966,1094000]
```

发现cipher刚好在第13个元素后及第26后元素大小突然猛增。

因此推测这是一个解密脚本，而flag应该是print输出的结果。按道理直接运行就可以得flag。

于执行代码：

![image-20200616093343738](image-20200616093343738.png)

发现果然运行就可以得flag，但flag分三部分给，第二部分给的慢，第三部分更慢。

推测是考点 因该是提高解密脚本效率

仔细审计代码,发现函数a

```python
def a(num):
    if (num > 1):
        for i in range(2,num):
            if (num % i) == 0:
                return False
                break
        return True
    else:
        return False
```

这个代码的时间复杂度为N。有很大的优化空间。

#### 解法1：

**根据数论，如果X不能被2到根号X之间的任一整数整除,则不是质数。**

我们可以优化函数a为：

```python
def a(num):
    if (num > 1):
         for i in range(2, int(num ** 0.5) + 1):
             if num % i == 0:
                return False
         return True
    else:
        return False
```

这样下来函数a的空间效率只有√N。

#### 解法2：

**偶数中除了2都不是质数，且奇数的因数也没有偶数**，因此可以进一步优化a函数：

```python
def a(num):
    if (num > 1):
     if num == 2:
        return True
     elif num % 2 == 0:
        return False
     for i in range(3, int(num ** 0.5) + 1, 2):
        if num % i == 0:
            return False
     return True
    else:
        return False
```

这样来函数a的空间效率只有√N/2。

#### 解法3：

利用**6N±1素数筛选法**任何一个自然数，总可以表示成如下形式之一：

6N,6N+1,6N+2,6N+3,6N+4,6N+5 (N=0,1,2,3,..),显然，当N≥1时，6N，6N+2,6N+3,6N+4都不是素数，只有形如6N+1和6N+5的自然数才可能是素数，所以除了2，3外，所有的素数都可以表示成6N±1的形式(N=0,1,2,3,..)，根据上述分析可以构造一面筛子，只对形如6N±1的自然数进行筛选，来减少筛选的次数。故可以修改a函数为：

```python
def a(num):
 if (num > 1):
    if (num == 2) or (num == 3):
        return True
    if (num % 6 != 1) and (num % 6 != 5):
        return False
    for i in range(5, int(num ** 0.5) + 1, 6):
        if (num % i == 0) or (num % (i + 2) == 0):
            return False
    return True
 else:
        return False
```

### December

source.py：

```python
#!/usr/bin/env python

from Crypto.Cipher import DES

with open('flag.txt', 'rb') as handle:
	flag = handle.read()

padding_size = len(flag) + (8 - ( len(flag) % 8 ))
flag = flag.ljust(padding_size, b'\x00')

with open('key', 'rb') as handle:
	key = handle.read().strip()

iv = "13371337"
des = DES.new(key, DES.MODE_OFB, iv)
ct = des.encrypt(flag)

with open('ciphertext','wb') as handle:
	handle.write(ct)
```

ciphertext：

```
症o迩\"郥^N@]X蹶i1鱑WETR^D垶b裓*?^VAAVC绀n?I鬩RTLE[ZD荩y擅/蚗l]RTWN7
```

根据分析这两个文件。推测这是一道DES.MODE_OFB的知道加密方式破解原文。再仔细审计加密脚本。发现没有告诉我们DES.MODE_OFB加密的原始key。

于是，经过谷歌后发现这可能是考DES.MODE_OFB的弱key(详细请移步https://en.wikipedia.org/wiki/Weak_key#Weak_keys_in_DES)。

写脚本用常见弱key进行爆破：

```
from Crypto.Cipher import DES

f = open('ciphertext', 'rb')
ciphertext = f.read()
f.close()
IV = b'13371337'
KEY=b'\x00\x00\x00\x00\x00\x00\x00\x00'
a = DES.new(KEY, DES.MODE_OFB, IV)
plaintext = a.decrypt(ciphertext)
print (plaintext)

KEY=b'\x1E\x1E\x1E\x1E\x0F\x0F\x0F\x0F'
a = DES.new(KEY, DES.MODE_OFB, IV)
plaintext = a.decrypt(ciphertext)
print (plaintext)

KEY="\xE1\xE1\xE1\xE1\xF0\xF0\xF0\xF0"
a = DES.new(KEY, DES.MODE_OFB, IV)
plaintext = a.decrypt(ciphertext)
print (plaintext)

KEY="\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
a = DES.new(KEY, DES.MODE_OFB, IV)
plaintext = a.decrypt(ciphertext)
print (plaintext)
```

### Unvreakable Vase

```
zmxhz3tkb2vzx3roaxnfzxzlbl9jb3vudf9hc19jcnlwdg9vb30=
```

观测题目所给密文,发现是base64。密文中的大小写都变成小写。

我们可以根据不断测试大小写字符加语法判断，进行手动猜测.....

`flag{does_this_even_count_as_cryptooo}`

做完后，大佬才知道有专门的脚本还原(눈_눈)

```python
from base64 import b64decode as decode
from itertools import product

data = 'zmxhz3tkb2vzx3roaxnfzxzlbl9jb3vudf9hc19jcnlwdg9vb30='
CHARSET = 'abcdefghijklmnopqrstuvwxyz_{}'


def case_variations(string):
    possibilities = []
    for char in string:
        possibilities.append([char.lower(), char.upper()])
    return ["".join(perm) for perm in product(*possibilities)]


flag = b""
real_data = ""
for i in range(0, len(data), 4):
    crib = data[i:i + 4]
    for case_variation in case_variations(crib):
        if all(chr(char) in CHARSET for char in decode(case_variation)):
            real_data += case_variation
            flag += decode(case_variation)
            print(flag)
            break

print(real_data)

```



### Ooo-la-la

```
N = 3349683240683303752040100187123245076775802838668125325785318315004398778586538866210198083573169673444543518654385038484177110828274648967185831623610409867689938609495858551308025785883804091
e = 65537
c = 87760575554266991015431110922576261532159376718765701749513766666239189012106797683148334771446801021047078003121816710825033894805743112580942399985961509685534309879621205633997976721084983

```

传统的RSA加密，yafu N到pq 带到脚本即可：

```python
import gmpy2
from Crypto.Util.number import long_to_bytes,bytes_to_long,getPrime,isPrime
N = 3349683240683303752040100187123245076775802838668125325785318315004398778586538866210198083573169673444543518654385038484177110828274648967185831623610409867689938609495858551308025785883804091
e = 65537
c = 87760575554266991015431110922576261532159376718765701749513766666239189012106797683148334771446801021047078003121816710825033894805743112580942399985961509685534309879621205633997976721084983

p = 1830213987675567884451892843232991595746198390911664175679946063194531096037459873211879206428213
q = 1830213987675567884451892843232991595746198390911664175679946063194531096037459873211879206428207

d = gmpy2.invert(e,(p-1)*(q-1))
m=pow(c,d,N)
print (long_to_bytes(m))
```



### Twinning

进入题目,nc jh2i.com 50013

得到:

```
Generating public and private key...

Public Key in the format (e,n) is: (65537,28795374863)
The Encrypted PIN is 28156503395
What is the PIN?
```

看见(e,n)推测是RSA.pin因该就是密文.我们要提交明文得到flag.

当我按照再次思路,yafu分解然后用Ooo-la-la提到rsa解密后提交答案是发现连接断开了.

看来得用全脚本来RSA.这时，有个问题出现了，怎么用python来分解N。

经过反复的nc：

```
 (e,n) is: (65537,28795374863) # 28795374863 = 169691 · 169693 
 (e,n) is: (65537,1063946864483) #	1063946864483 = 1031477 · 1031479
 (e,n) is: (65537,4953152922623) #4953152922623 = 2225567 · 2225569

```

发现n的值偏小，且分解出来的质数相近。

且p与q相差2

所以可以立一元二次方程 0 =p**2+2p-n

利用根为正数的求根公式得：

![image-20200618112429889](image-20200618112429889.png)

所以可以写代码为

```python
# -*- coding: utf-8 -*-
"""
Created on Mon Jun 13 22:01:50 2020

@author: 冰之幻魄
"""

from Crypto.Util.number import long_to_bytes,bytes_to_long,getPrime,isPrime
import socket
import re
import gmpy2

import random  

def getpq(n):
  n2=pow(n,0.5)
  m=pow((pow(int(n2+1),2)-n),0.5)
  return [int(int(n2)-m+1),int(int(n2)+m+1)]

s = socket.socket()   
#nc jh2i.com 50013
HOST = 'jh2i.com'  # 服务器的主机名或者 IP 地址
PORT =  50013      # 服务器使用的端口

s.connect((HOST, PORT))
x=s.recv(1024)

y=str(s.recv(1024),encoding ='utf8')


z=str(s.recv(1024),encoding ='utf8')

e,n=re.findall(r"\d+\.?\d*",y)
pin=re.findall(r"\d+\.?\d*",z)

pin=int(pin[0])
e=int(e)
n=int(n)
print(pin,e,n)  #9543182834506 65537 11828096639999
p,q=getpq(n)
print(p,q)
d=gmpy2.invert(e,(p-1)*(q-1))%((p-1)*(q-1))
m=pow(pin,d,n)
#print(m)
s.send(str(m).encode())
print(str(s.recv(1024),encoding ='utf8'))
print(str(s.recv(1024),encoding ='utf8'))
s.close()
```



### Raspberry

```
n = 7735208939848985079680614633581782274371148157293352904905313315409418467322726702848189532721490121708517697848255948254656192793679424796954743649810878292688507385952920229483776389922650388739975072587660866986603080986980359219525111589659191172937047869008331982383695605801970189336227832715706317
e = 65537
c = 5300731709583714451062905238531972160518525080858095184581839366680022995297863013911612079520115435945472004626222058696229239285358638047675780769773922795279074074633888720787195549544835291528116093909456225670152733191556650639553906195856979794273349598903501654956482056938935258794217285615471681
```

拿到题目分析发现 n、e、c，猜测是rsa解密。

分解N，发现分解出多个质数，但质数的数量刚好为整数：

![image-20200616112333257](image-20200616112333257.png)

按常规RSA的常规实现中 n=p*q（p、q均为质数)只有两个质数组成。

**但根据rsa原理与数论知识，如果n可以分解为多个素数的乘积。可看成是RSA算法的推广形式。**
         例如：若`n=p‘*q*s*t,则r=(p-1)*(q-1)*(s-1)*(t-1),d=e^-1 mod r。`

同理写成脚本为：

```python
from Crypto.Util.number import long_to_bytes,bytes_to_long,getPrime,isPrime
import gmpy2
import math

x=b''
y=[
(2208664111,3290718047),
(2982067987,2214452749),
(2465499073,2589229021),
(3644712913,3600488797),
(4205130337,3130932919),
(4268160257,3726115171),
(3510442297,3789130951),
(2758626487,2543358889),
(3650456981,4221911101),
(2642723827,2947867051),
(3810149963,2850808189),
(4033877203,3750978137)]

c=5300731709583714451062905238531972160518525080858095184581839366680022995297863013911612079520115435945472004626222058696229239285358638047675780769773922795279074074633888720787195549544835291528116093909456225670152733191556650639553906195856979794273349598903501654956482056938935258794217285615471681
n=1
k=1


for i in y:
    e=65537      
    q=i[1]
    p=i[0]
    n=p*q*n
    k=k*(p-1)*(q-1)
  
d=gmpy2.invert(e,k)%(k)
m=pow(c,d,n)
print( long_to_bytes(m))
    
```

得flag：

![image-20200616113311011](image-20200616113311011.png)

## 参考文献

[常见User-Agent](https://blog.csdn.net/wangqing84411433/article/details/89600335)

[文件包含漏洞的知识梳理](https://lexsd6.github.io/2020/05/31/%E5%AF%B9%E4%BA%8E%E6%96%87%E4%BB%B6%E5%8C%85%E5%90%AB%E6%BC%8F%E6%B4%9E%E7%9A%84%E7%9F%A5%E8%AF%86%E6%A2%B3%E7%90%86/)

[质数的几种判断方法](https://zhuanlan.zhihu.com/p/107300262)

