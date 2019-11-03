---
layout: post
title: ThinkCMFX 前台getshell漏洞分析
noToc: true
date: 2019-11-03 23:30:00 +0800
tags:  代码审计 PHP
cover: '../assets/' 
---

## ThinkCMFX 前台getshell漏洞分析

### 1.ThinkCMFX 前台RCE漏洞分析

## 简介

ThinkCMF是一款基于ThinkPHP+MySQL开发的中文内容管理框架。 cmfx, 在 ThinkPHP 3.2.3上，它与 ThinkCMF ThinkCMFX based相同，并且从thinkphp3抽象出了四个base Controller ，HomebaseController、AdminbaseController、AppframebaseController、MemberbaseController。

官方给出的修复结果如下

![1572421140819](C:\Users\clover\Qclover.github.io\assets\images\thinkcmf\img\1572421140819.png)

#### 漏洞成因

Thinkphp3中模板渲染经常会使用到View层中的fetch、display、assign方法，之前thinkphp3曾出现过的安全问题正是发生在这模板引擎渲染过程中所导致，如tp3.x任意文件包含正是由于在模版渲染的情况下存在任意变量覆盖所导致。 

了解了这个，看thinkcmfx从tp3.2.3抽象出来的控制类，通过调试发现传入的content进入到了HomebaseController.php的fetch中

![0](C:\Users\clover\Qclover.github.io\assets\images\thinkcmf\img\0.png)

F7跟进调用了thinkphp的controller类,然后最终调用think核心的view

![01](C:\Users\clover\Qclover.github.io\assets\images\thinkcmf\img\01.png)

在`View`类的`fetch`方法中将可控的$content直接拼接到了eval里

![1572507545397](C:\Users\clover\Qclover.github.io\assets\images\thinkcmf\img\02.png)

从`Hook::listen`一路跟下去，进入到listen方法中

![1572507685716](C:\Users\clover\Qclover.github.io\assets\images\thinkcmf\img\1572507685716.png)

![1572511491723](C:\Users\clover\Qclover.github.io\assets\images\thinkcmf\img\1572511491723.png)

在listen中可以看到将$centon传给了view_parse传入的参数$params然后进入到了exec

![1572512075436](C:\Users\clover\Qclover.github.io\assets\images\thinkcmf\img\1572512075436.png)

有插件时执行进入第二个if,直到跟踪到run

![1572789563717](C:\Users\clover\Qclover.github.io\assets\images\thinkcmf\img\1572789563717.png)

在run方法中调用think模板引擎if判断是否存在生成了模板缓存文件否则进入think->Template进行编译并加载模板文件，继续跟进fetch可控的参数名变成了`$templateFile`： 

![1572789851863](C:\Users\clover\Qclover.github.io\assets\images\thinkcmf\img\1572789851863.png)

将`$templateFile`传入了loadTemplate方法，进入loadTemplate

![1572790810031](C:\Users\clover\Qclover.github.io\assets\images\thinkcmf\img\1572790810031.png)

可以追踪到该可完全控制的变量又进入到了编译模板内容方法中，在compiler中可以发现

![1572790956162](C:\Users\clover\Qclover.github.io\assets\images\thinkcmf\img\1572790956162.png)

可控的$tmplContent直接拼接到了php代码中。

![1572791545229](C:\Users\clover\Qclover.github.io\assets\images\thinkcmf\img\1572791545229.png)

调试后如下图

![1572791907966](C:\Users\clover\Qclover.github.io\assets\images\thinkcmf\img\1572791907966.png)

编译完成后返回编译后的文件。

![1572791948820](C:\Users\clover\Qclover.github.io\assets\images\thinkcmf\img\1572791948820.png)

![1572791989805](C:\Users\clover\Qclover.github.io\assets\images\thinkcmf\img\1572791989805.png)

我们看一下`Storage::load方法干了什么：  直接进行了文件包含，就这样我们的代码就被成功执行了。 

![1572792219211](C:\Users\clover\Qclover.github.io\assets\images\thinkcmf\img\1572792219211.png)

![1572508546168](C:\Users\clover\Qclover.github.io\assets\images\thinkcmf\img\1572508546168.png)

![1572792323719](C:\Users\clover\Qclover.github.io\assets\images\thinkcmf\img\1572792323719.png)



### 2.前台任意文件上传

漏洞发生在前台\application\Asset\Controller\UeditorController.class.php中在上传图片时会进入upload->uploadimage->调用UE上传方法_ueditor_upload如下图所示

![1572771885298](C:\Users\clover\Qclover.github.io\assets\images\thinkcmf\img\1572771885298.png)

跟进_ueditor_upload该方法先后进行了设置上传信息、获取上传后缀、文件大小定义允许的后缀名和config信息再交由think的upload.这里主要看think->upload方法

![1572770326830](C:\Users\clover\Qclover.github.io\assets\images\thinkcmf\img\1572770326830.png)

而在传入upload的$config仔细查看可以发现问题若上传的后缀不在定义规定的允许的上传后缀中时返回值为null如下图所示

![1572770675990](C:\Users\clover\Qclover.github.io\assets\images\thinkcmf\img\1572770675990.png)

think的upload.class.php中upload方法如下：

```php
 public function upload($files='') {
        if('' === $files){
            $files  =   $_FILES;
        }
        if(empty($files)){
            $this->error = '没有上传的文件！';
            return false;
        }

        /* 检测上传根目录 */
        if(!$this->uploader->checkRootPath($this->rootPath)){
            $this->error = $this->uploader->getError();
            return false;
        }

        /* 检查上传目录 */
        if(!$this->uploader->checkSavePath($this->savePath)){
            $this->error = $this->uploader->getError();
            return false;
        }

        /* 逐个检测并上传文件 */
        $info    =  array();
        if(function_exists('finfo_open')){
            $finfo   =  finfo_open ( FILEINFO_MIME_TYPE );
        }
        // 对上传文件数组信息处理
        $files   =  $this->dealFiles($files);    
        foreach ($files as $key => $file) {
            $file['name']  = strip_tags($file['name']);
            if(!isset($file['key']))   $file['key']    =   $key;
            /* 通过扩展获取文件类型，可解决FLASH上传$FILES数组返回文件类型错误的问题 */
            if(isset($finfo)){
                $file['type']   =   finfo_file ( $finfo ,  $file['tmp_name'] );
            }

            /* 获取上传文件后缀，允许上传无后缀文件 */
            $file['ext']    =   pathinfo($file['name'], PATHINFO_EXTENSION);

            /* 文件上传检测 */
            if (!$this->check($file)){
                continue;
            }

            /* 获取文件hash */
            if($this->hash){
                $file['md5']  = md5_file($file['tmp_name']);
                $file['sha1'] = sha1_file($file['tmp_name']);
            }

            /* 调用回调函数检测文件是否存在 */
            $data = call_user_func($this->callback, $file);
            if( $this->callback && $data ){
                if ( file_exists('.'.$data['path'])  ) {
                    $info[$key] = $data;
                    continue;
                }elseif($this->removeTrash){
                    call_user_func($this->removeTrash,$data);//删除垃圾据
                }
            }

            /* 生成保存文件名 */
            $savename = $this->getSaveName($file);
            if(false == $savename){
                continue;
            } else {
                $file['savename'] = $savename;
            }

            /* 检测并创建子目录 */
            $subpath = $this->getSubPath($file['name']);
            if(false === $subpath){
                continue;
            } else {
                $file['savepath'] = $this->savePath . $subpath;
            }

            /* 对图像文件进行严格检测 */
            $ext = strtolower($file['ext']);
            if(in_array($ext, array('gif','jpg','jpeg','bmp','png','swf'))) {
                $imginfo = getimagesize($file['tmp_name']);
                if(empty($imginfo) /* || ($ext == 'gif' && empty($imginfo['bits'])) */){//ThinkCMF NOTE 限制太严格，以防单页gif文件无法上传
                    $this->error = '非法图像文件！';
                    continue;
                }
            }

            /* 保存文件 并记录保存成功的文件 */
            if ($this->uploader->save($file,$this->replace)) {
                unset($file['error'], $file['tmp_name']);
                $info[$key] = $file;
            } else {
                $this->error = $this->uploader->getError();
            }
        }
        if(isset($finfo)){
            finfo_close($finfo);
        }
        return empty($info) ? false : $info;
    }
```

这里对文件依次进行了检查，在文件处理处跟进通过dealFiles获取到原本的上传文件信息将文件赋给files，遍历files开始上传

![1572770799063](C:\Users\clover\Qclover.github.io\assets\images\thinkcmf\img\1572770799063.png)

调用check()对文件进行检查

![1572773876626](C:\Users\clover\Qclover.github.io\assets\images\thinkcmf\img\1572773876626.png)

![1572773992168](C:\Users\clover\Qclover.github.io\assets\images\thinkcmf\img\1572773992168.png)

可以发现对文件后缀的检查checkExt存在问题,直接返回的是文件后缀并未检查。如下图所示：

![1572771071422](C:\Users\clover\Qclover.github.io\assets\images\thinkcmf\img\1572771071422.png)这时的后缀仍然为php,往下调用getSaveName生成保存的文件名filename并拼接后缀php后返回赋给$savename

![1572771225331](C:\Users\clover\Qclover.github.io\assets\images\thinkcmf\img\1572771225331.png)

往下继续看，虽然发现又对文件ext判断一次但是显然并无影响最终执行save()

![1572775550437](C:\Users\clover\Qclover.github.io\assets\images\thinkcmf\img\1572775550437.png)

![1572775517679](C:\Users\clover\Qclover.github.io\assets\images\thinkcmf\img\1572775517679.png)

回到UeditorController.class.php中，最后将上传成功后的文件路径信息返回。

![1572775754972](C:\Users\clover\Qclover.github.io\assets\images\thinkcmf\img\1572775754972.png)

![1572775796632](C:\Users\clover\Qclover.github.io\assets\images\thinkcmf\img\1572775796632.png)






