
title:   flask.request的内置属性总结
categories: [CTF]
tags: [python,web]

---


对于一个基于flask的web来说,Request是默认存在且有很多功能离不开Request.request对象是一个Request子类，提供了Werkzeug定义的所有属性以及一些Flask特定的属性。这导致我们有时可以控制request对象来处理一些数据.

<!-- more -->
## accept_encodings

该客户端接受的编码列表。是处理http包中的`Accept-Encoding`头的数据.

![image-20201231221711608](image-20201231221711608.png)

accept_encodings接受的数据是用list类型来保存的.list中的元素是元组存在的.

![image-20201231222115756](image-20201231222115756.png)

accept_encodings中的数据是以空格或逗号(`,`)来进行分割的.![image-20201231222535177](image-20201231222535177.png)

## accept_charsets

该客户端支持的字符集列表.是处理http包中的`Accept-Charset`头的数据。

![image-20201231223255289](image-20201231223255289.png)

accept_charsets接受的数据是用list类型来保存的.list中的元素是元组存在的.

![image-20201231223321225](image-20201231223321225.png)

accept_charsets和accept_encodings相同数据是以空格或逗号(`,`)来进行分割的.

## accept_languages

此客户端接受的语言列表。是处理http包中的`Accept-Language`头的数据。

![image-20201231224106709](image-20201231224106709.png)

accept_languages接受的数据是用list类型来保存的.list中的元素是元组存在的.

![image-20201231224141646](image-20201231224141646.png)

accept_languages数据也是以空格或逗号(`,`)来进行分割的.

## accept_mimetypes

此客户端支持作为MIMEAccept对象的mimetype列表。是处理http包中的`Accept`头的数据。

![image-20201231224846242](image-20201231224846242.png)

accept_mimetypes接受的数据是用list类型来保存的.list中的元素是元组存在的.

![image-20201231225023882](image-20201231225023882.png)

accept_mimetypes数据也是以空格或逗号(`,`)来进行分割的.

## access_route

如果存在转发的标头，则这是从客户端ip到最后一个代理服务器的所有ip地址的列表。

![image-20201231225515776](image-20201231225515776.png)

可以被`X-Real-IP`覆盖掉。但用使用Client-IP或者X-Real-IP**不能覆盖**。以逗号(`,`)来进行分割的.

![image-20201231225842253](image-20201231225842253.png)

## args

解析的URL参数。即获取以get方式提交的参数。

![image-20201231230539295](image-20201231230539295.png)

## authorization

解析形式的Authorization对象。

是处理http包中的`Authorization`头的数据。不能随意伪造。

![image-20201231231151079](image-20201231231151079.png)

## base_url

类似于url但不带查询字符串的内容

![image-20201231231742000](image-20201231231742000.png)



## cache_control

是处理http包中的`Cache-Control`头的数据。

![image-20210101104459225](image-20210101104459225.png)

cache_control接受的数据是用`dict`类型来保存的.

![image-20210101104532078](image-20210101104532078.png)

cache_control是以逗号(`,`)分割的。

![image-20210101104819616](image-20210101104819616.png)

![image-20210101104911020](image-20210101104911020.png)

## content_encoding

是处理http包中的`Content-Encoding`头的数据。

![image-20210101110051635](image-20210101110051635.png)

content_encoding接受的数据是用`str`类型来保存的.

![image-20210101110301434](image-20210101110301434.png)

content_encoding是以一个一个字符来分割的。





## content_length

是处理http包中的`Content-Length`头的数据。

![image-20210101110911675](image-20210101110911675.png)

## content_md5

是处理http包中的`Content-MD5`头的数据。

![image-20210101111258925](image-20210101111258925.png)

content_md5接受的数据是用`str`类型来保存的.

## content_type

是处理http包中的`Content-Type`头的数据。Content-Type实体标头字段指示发送给接收者的实体主体的媒体类型，或者在HEAD方法的情况下，如果请求是GET，则应发送的媒体类型。

![image-20210101111621966](image-20210101111621966.png)

content_type接受的数据是用`str`类型来保存的.

## cookies

对检索到的cookie值的只读访问权限为字典(`dict`)。是处理http包中的`Cookie`头的数据。

![image-20210101112042177](image-20210101112042177.png)

## date

是处理http包中的`Date`头的数据。其语义与RFC 822中的“原始日期”相同,不能随意修改。

![image-20210101112205964](image-20210101112205964.png)

## files

对http包中文件的处理。

## form

对http包中post参数的处理。

**![image-20210101114236684](image-20210101114236684.png)**

在get请求下这个参数无效

## headers

对http包中所有头参数的处理。

![image-20210101123732789](image-20210101123732789.png)

## host

对http包中`HOST`头参数的处理。

![image-20210101123917231](image-20210101123917231.png)

host接受的数据是用`str`类型来保存的.

## json

如果mimetype为application / json，则它将包含已解析的JSON数据。

## mimetype

类似于content_type，但没有参数（例如，没有字符集，类型等），并且总是小写.

是同时处理Content-Type头的属性.

![image-20210101134433492](image-20210101134434520.png)

mimetype是以字符串来处理但我们在控制时,只能处理Content-Type头的数据.

## mimetype_params

mimetype_params是以dict的来处理Content-Type的数据

![image-20210101134647203](image-20210101134647203.png)

## path

得到请求的路径.由url / 后的数据控制.

![image-20210101134916747](image-20210101134916747.png)

## remote_addr

客户端的远程地址。(无法伪造?)

![image-20210101135554993](image-20210101135554993.png)

## url

重建的当前URL为IRI。

![image-20201231231756221](image-20201231231756221.png)

## user_agent

是处理http包中的`User-Agent`头的数据。

![image-20210101140036906](image-20210101140036906.png)

user_agent是以元组的方式来处理数据的.

## values

同时处理get参数与post参数

![image-20210101140708664](image-20210101140708664.png)

GET方式下只处理get参数.

## 参考链接

[http头讲解](https://www.cnblogs.com/jxl1996/p/10245958.html)

[flask request讲解](https://tedboy.github.io/flask/generated/generated/flask.Request.html)