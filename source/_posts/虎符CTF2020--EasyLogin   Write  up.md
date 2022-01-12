---
title:  虎符CTF2020--EasyLogin WP
categories: [CTF]
tags: [wp,web]
date: 2020-4-21 11:51:27
---

最近因为疫情来家研究web,恰好前几天刚刚看了jwt正好在比赛上碰上于是写个简单wp的同时小小总结一下.

<!--more-->

## 0x01考点总汇

1. jwt令牌伪造
2. NodeJS 代码审计
3. NodeJS弱类型特性利用
4. jsonwebtoken 库缺陷

## 0x02解题思路分析

打开题目，从题目描述'![image-20200421101720306](image-20200421101720306.png)'中得到三个信息 题目环境是nodejs开发、可能有代码逻辑漏洞、可能是依赖库逻辑漏洞。

带着问题具体进入环境分析。发现是一个登陆界面。同时带有跳转至帐户注册的按钮。(一般情况下，由注册功能一般没有sql注入漏洞)

![image-20200421104215171](image-20200421104215171.png)

随便输入一个帐户密码，发现回显了一个奇怪的回显——‘Cannot read property 'split' of undefined‘而不是'帐户密码错误或不存在'之类的提示。所以怀疑登陆这可能存在逻辑问题。

![image-20200421104132782](image-20200421104132782.png)

抓包发分析，发现authorization的值为空。

![image-20200421104034329](image-20200421104034329.png)

进入帐户注册进行注册，发现用户名为admin无法注册。怀疑管理员帐户用户名为admin。

![image-20200421110531022](image-20200421110531022.png)

注册帐户登陆进入发现要flag的权限不够。

![image-20200421111725354](image-20200421111725354.png)

再退回抓取登陆包

![image-20200421111941094](image-20200421111941094.png)

发现authorization的值有了。对其值进行base64解码。发现这个是个jwt令牌

![image-20200421112825513](image-20200421112825513.png)

推测是不是可以用jwt令牌伪造绕过。

关于jwt令牌详细机制可以参考下：http://www.ruanyifeng.com/blog/2018/07/json_web_token-tutorial.html这篇文章。

这里再强调一下,jwt令牌由三部分组成:

- Header（头部）:有加密算法与令牌类型构成.
- Payload（负载）:用来存放实际需要传递的数据.
- Signature（签名）:主要通过一个加密密钥,用Header里的加密算法来加密 base64url加密后的Header与Payload数据.

因此通过控制jwt的Header中加密算法与Signature中加密钥匙，就可以伪造出一个jwt令牌。由于之前的加密中我已经得到了加密算法是HS256，所以尝试使用工具：c-jwt-cracker（https://github.com/brendan-rius/c-jwt-cracker）结果发现半爆不出来，猜测密钥长度过长转换思路。

在查看网站源代码在/static/js/app.js下发现提示

![image-20200421161224525](image-20200421161224525.png)

猜测配置错误路径，猜测NodeJS的常用文件名如api.js、app.js、controller.jsd等。但在主目录下

app.js

![image-20200421163813964](image-20200421163813964.png)

在app.js发现环境中发现还有rest与controller目录继续猜下面的文件名。

在controller目录发现了api.js文件,我们要要的关于登陆页面的jwt相关信息的代码

![image-20200421171905148](image-20200421171905148.png)

对这段代码审计可以知道secret与jwt令牌中的sid参数有关.同时我们还知道用 jsonwebtoken 库来操作jwt令牌的制作,但jsonwebtoken 库jwt.verify函数有个漏洞:验证时只要密钥(secret)处为 undefined 或者空之类的，即便后面的算法指名为 HS256，验证也还是按照 none 来验证通过.

因此我们可以想办法控制sid参数来让secret为空或 undefined .由于js是弱类型型的语言我们可以通过数字的索引为小数、大括号、中括号的方式来让返回值为undefined 。

![image-20200421175115467](image-20200421175115467.png)

同理利用弱类型特性,我们可以通过sid为小数或空数组来绕过红圈里的 ` if(sid === undefined || sid === null || !(sid < global.secrets.length && sid >= 0)`

![image-20200421224458833](image-20200421224458833.png)

利用脚本构造jwt

![image-20200421232103](20200421232103.png)

抓取包替换

![image-20200421234605518](image-20200421234605518.png)

抓取get flag包得到flag

![image-20200421234701597](image-20200421234701597.png)

## 0x03关于jwt解题思路的总结

同时关于jwt的解题有思路有4种

#### 1.修改算法为none

修改算法有两种修改的方式其中一种就是将算法就该为none.

像本题一样,后端若是支持none算法.header中的alg字段可被修改为none.去掉JWT中的signature数据（仅剩header + '.' + payload + '.'） 然后直接提交到服务端去.

#### 2.修改算法RS256为HS256

RS256是非对称加密算法，HS是对称加密算法.

如果jwt内部的函数支持的RS256算法，又同时支持HS256算法.

如果已知公钥的话，将算法改成HS256，然后后端就会用这个公钥当作密钥来加密

#### 3信息泄露

JWT是以base64编码传输的，虽然密钥不可见，但是其数据记本上是明文传输的，如果传输了重要的内容，可以base64解码然后获取其重要的信息。这里推荐网站https://jwt.io/

#### 4爆破密钥

原理就是，如果密钥比较短的话，已知加密算法，通过暴力破解的方式，可以得到其密钥.例如;通过c-jwt-cracker（https://github.com/brendan-rius/c-jwt-cracker）进行爆破。



