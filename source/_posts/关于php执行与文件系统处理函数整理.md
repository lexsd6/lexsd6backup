
title:  php执行与文件系统处理函数整理
categories: [CTF]
tags: [php,web]

---
最近难得有空将php中执行与文件系统处理相关常见的函数给总结一下吧。(顺便加强下记忆)
<!-- more -->


## php代码执行函数

#### eval

把字符串作为PHP代码执行(因为是一个语言构造器而不是一个函数，不能被可变函数调用。)

```php
<? php eval('code'); ?>
```

#### assert

把字符串作为PHP代码执行,在php7是一个可变函数。

```php
<? php assert('code'); ?>
```

#### preg_replace

preg_replace()函数原本是执行一个正则表达式的搜索和替换，但因为存在危险的/e修饰符，使 preg_replace() 将 replacement 参数当作 PHP 代码。（PHP 5.5.0 起， 传入 "\e" 修饰符的时候，会产生一个 E_DEPRECATED 错误； PHP 7.0.0 起，会产生 E_WARNING 错误，同时 "\e" 也无法起效。）

```php
<?php    
    preg_replace("/abc/e",'code',"php");
?>
```

#### create_function

create_function —创建一个匿名（lambda样式）函数。

```php
<?php 

$func =create_function('','code');
$func();
?>
```

#### call_user_func

call_user_func — 把第一个参数作为回调函数调用，第二个作为传入被回掉函数的参数。

```php
<?php 
call_user_func ('func','arge');
?>
```



#### call_user_func_array

调用回调函数，并把一个数组参数作为回调函数的参数

```php
<?php 
$arge[0]='arge';
call_user_func ('func',$arge);
?>
```



#### array_map

函数将用户自定义函数作用到数组中的每个值上，并返回用户自定义函数作用后的带有新值的数组。 回调函数接受的参数数目应该和传递给 array_map() 函数的数组数目一致。

```php
<?php 

$arge[0]='arge';
array_map('func',$arge);

?>
```

#### array_filter

用回调函数过滤数组中的单元

`array_filter ( array $array [, callable $callback [, int $flag = 0 ]] ) : array`

依次将 array 数组中的每个值传递到 callback 函数。如果 callback 函数返回 true，则 array 数组的当前值会被包含在返回的结果数组中。数组的键名保留不变。

```php
<?php 
$arge[0]='arge';
array_filter ('func',$arge);
?>
```



####  array_walk

array_walk() 函数对数组中的每个元素应用用户自定义函数。在函数中，数组的键名和键值是参数。(同时传两个键名和键值参数)

```php
<?php
function myfunction($value,$key)
{
echo "The key $key has the value $value<br>";
}
$a=array("a"=>"red","b"=>"green","c"=>"blue");
array_walk($a,"myfunction");
?>
```

#### usort

本函数将用用户自定义的比较函数对一个数组中的值进行排序。 如果要排序的数组需要用一种不寻常的标准进行排序，那么应该使用此函数。

```php
<?php 
$a[0]=1;
$a[1]='phpinfo()';
usort($a,'assert');
?>
```



#### uasort

uasort — 使用用户自定义的比较函数对数组中的值进行排序并保持索引关联

```php
<?php 
$a[0]=1;
$a[1]='phpinfo()';
uasort($a,'assert');
?>
```

#### FFI::cdef

创建一个新的FFI对象,可以把c语言的函数声明出来。以调用c语言system函数为例。

```python
$ffi = FFI::cdef("int system(const char *command);");//创建一个system对象
$a='ls > 1.txt';//没有回显的
$ffi->system($a);//通过$ffi去调用system函数
```



## php命令执行函数

#### system 

system — 执行外部程序，并且显示输出.如果 PHP 运行在服务器模块中， system() 函数还会尝试在每行输出完毕之后， 自动刷新 web 服务器的输出缓存。成功则返回命令输出的最后一行， 失败则返回 FALSE

```php
<?php 
system('commande')
?>
```

#### exec

exec() 执行 command 参数所指定的命令。

```php
<?php 
echo exec ('commande');
?>

```

#### shell_exec

shell_exec — 通过 shell 环境执行命令，并且将完整的输出以字符串的方式返回。反引号（''\`commande\`"）的本质是shell_exec。

(当进程执行过程中发生错误，或者进程不产生输出的情况下，都会返回 NULL)

```php
<?php 
echo shell_exec ('commande');
?>
```



#### passthru 

同 exec() 函数类似， passthru() 函数 也是用来执行外部命令（command）的。 当所执行的 Unix 命令输出二进制数据， 并且需要直接传送到浏览器的时候， 需要用此函数来替代 exec() 或 system() 函数。 常用来执行诸如 pbmplus 之类的可以直接输出图像流的命令。 通过设置 Content-type 为 image/gif， 然后调用 pbmplus 程序输出 gif 文件， 就可以从 PHP 脚本中直接输出图像到浏览器。

```php
<?php 
echo passthru('commande');
?>
```

## php对文件系统处理函数



####  ini_set

对php.ini文件里的一些对PHP_INI_USER or PHP_INI_ALL 的配置进行临时的更改.

常见的更改:

1. **include_path** :当寻找要包含的文件时，PHP会分别考虑包含路径中的每个条目。它将检查第一个路径，如果找不到，则检查下一个路径，直到找到包含的文件或返回带有E_WARNING 或的为止 E_ERROR。

2. **open_basedir**:当脚本尝试访问文件系统时，例如使用 include或fopen（），将检查文件的位置。当文件在指定的目录树之外时，PHP将拒绝访问它。(自PHP 5.2.16和5.3.4起， 用open_basedir指定的限制是目录名。以前的版本将其用作前缀。这意味着“ open_basedir = /dir/incl”还允许访问“ /dir/include”和“ /dir/incls”（如果存在）。当您只想限制对指定目录的访问时，请以斜杠结尾。例如： open_basedir = /dir/incl/)

   ```php
   <?php 
   echo ini_set('tage''vlue');
   ?>
   ```

#### set_include_path

专门设置**include_path**路径的函数。

#### chdir

将 更改当前目录。

```php
<?php 
 chdir('dir');
?>
```

#### scandir

scandir — 列出指定路径中的文件和目录

```php
<?php
scandir ( 'dir' );
?>
```

#### highlight_file 

highlight_file — 语法高亮一个文件.(可以处理协议)

```php
<?
highlight_file('file')
?>
```

#### show_source

highlight_file函数的别名，具体用法同highlight_file。

```php
<?
show_source('file')
?>
```



## 参考文献



https://www.php.net/manual/zh/ref.exec.php

https://www.cnblogs.com/-qing-/p/10819069.html