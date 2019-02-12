---
layout: post
title:  ESPCMS前台存储xss打管理员cookie及代码执行getshell
noToc: false
date:   2019-02-01 17:30:00 +0800
tags: WEB安全 代码审计
cover: '../assets/espcms.png' 
---

## ESPCMS前台存储xss打管理员cookie及代码执行getshell

CMS版本：EspCms_P8_18101601稳定版

### 一、漏洞披露

Order.php文件

Save方法中，通过espcms_post函数中的$_POST接收订单post的数据然后交给$postvalue，然后通过espcms_db_install报该订单的数据存入数据库中返回该订单的id如下图所示

![img]({{site.baseurl}}/assets/images/espcms/图片1.png)

跟踪espcms_post函数至espcms_db.php

![img]({{site.baseurl}}/assets/images/espcms/图片2.png)

该函数对接收的值进行了addslashes过滤与处理赋于$postvalue。再通过espcms_db_install_save将$postvalue存入数据表中。同样在对商品goods的存储时最终也调用了espcms_post函数。

![img]({{site.baseurl}}/assets/images/espcms/图片3.png)

通过PHPstorm调试追踪提交订单时POST的数据，并在Save打断点调试如下：

![img]({{site.baseurl}}/assets/images/espcms/图片4.png)

![img]({{site.baseurl}}/assets/images/espcms/图片5.png)

 

Post存入数据库整个过程没有经过htmlspecialchars过滤因此提交该订单存储时可插入xss。

通过监控提交订单时的mysql处理如下：

![img]({{site.baseurl}}/assets/images/espcms/图片6.png)

将数据直接进行了存储，存于address和content值中。若在输出订单信息时，直接调用造成xss无疑。

于是找到展示order订单信息部分文件OrderMain.php，在订单输出显示信息时，通过oid调用get_order_view返回对应订单数据交予$read变量，最后通过模板将order的内容进行输出。

![img]({{site.baseurl}}/assets/images/espcms/图片7.png)

![img]({{site.baseurl}}/assets/images/espcms/图片8.png)

 

![img]({{site.baseurl}}/assets/images/espcms/图片9.png)

这是个比较严重的存储xss,通过前台可直接打后台管理员cookie更改订单等。后来发现对xss的全局处理比较有趣，对POST数据的输入输出处理先后进行了htmlspecialchar、htmlspecialchar_decode导致了对xss的处理无效，于是在该版本espcms的POST输入点均存在存储型xss。如下图所示：

**全局xss漏洞部分代码示例：**

** **

 

![img]({{site.baseurl}}/assets/images/espcms/图片10.png)

![img]({{site.baseurl}}/assets/images/espcms/图片11.png)

![img]({{site.baseurl}}/assets/images/espcms/图片12.png)

![img]({{site.baseurl}}/assets/images/espcms/图片13.png)

### 二、复现

#### 0x1:注册会员

在前台随便注册一个会员账号登入，创建一个订单进行提交：

以下是payload

![img]({{site.baseurl}}/assets/images/espcms/图片14.png)

![img]({{site.baseurl}}/assets/images/espcms/图片15.png)

 

![img]({{site.baseurl}}/assets/images/espcms/图片16.png)

![img]({{site.baseurl}}/assets/images/espcms/图片17.png)

 

![img]({{site.baseurl}}/assets/images/espcms/图片18.png)

 

#### 0x2:盗取管理员cookie

当管理员查看订单

![img]({{site.baseurl}}/assets/images/espcms/图片19.png)

 

![img]({{site.baseurl}}/assets/images/espcms/图片20.png)

 

#### 0x3:getshell

代码执行getshell比较简单~，发生在调用eval函数处理从参数获取内容时直接获取模板内容中的代码，并以通过eval函数拼接执行,只需要通过获取的cookie登录后台修改模板插入代码即可getshell。

![img]({{site.baseurl}}/assets/images/espcms/图片21.png)

![img]({{site.baseurl}}/assets/images/espcms/图片22.png)

![img]({{site.baseurl}}/assets/images/espcms/图片23.png)

![img]({{site.baseurl}}/assets/images/espcms/图片24.png)