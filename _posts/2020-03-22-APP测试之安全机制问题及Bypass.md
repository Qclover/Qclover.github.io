---
layout: post
title: APP测试之安全机制问题及Bypass
noToc: true
date: 2020-03-22 12:30:00 +0800
tags: 移动安全 漏洞挖掘
cover: '../assets/' 
---

##  APP测试之安全机制问题及Bypass

今天来讨论一个APP安全渗透测试及漏洞挖掘中遇到的一个问题，相信也会有很多师傅在挖掘漏洞中遇到以下的几种令人抓头的场景，前不久挖掘一个app又遇到了以前都遇到过此类问题，决定在此总结一下:

![image-20200322123529153]({{site.baseurl}}/assets/images/app-burp/1.png)

![image-20200322123607256]({{site.baseurl}}/assets/images/app-burp/6.png)

等等。

一般情况下在对APP测试时burp抓包需要配置代理和下载安装burp的客户端证书才可以正常的进行下一步测试，但是在HTTPS信任机制和APK自有的安全机制下测试时或许就不是那么容易了，经常会出现网络错误、抓不到包、丢包，无法正常发送请求等情况。主要可以归结为：IOS/安卓系统的固有的信任机制问题，另一方面是APK的SSL证书的绑定、SSL证书双向校验和代理检测问题。

### 系统固有的信任机制

**IOS设备上测试**

虽然安装了burp证书但是你会发现有https的数据包仍然无法抓到，仔细深究其实还是信任机制的问题，默认情况下ios系统不会对第三方安装的证书开启完全信任，由此就导致了虽然安装了证书但还是无法抓到https的包。

![image-20200316212939587]({{site.baseurl}}/assets/images/app-burp/2.png)

默认情况下IOS设备的对安装的根证书的完全信任是处于关闭状态，所以要解决以上问题，还需要将该设置为完全信任。

![image-20200316213334805]({{site.baseurl}}/assets/images/app-burp/3.png)

设置好后就可以正常抓包了。

![image-20200316213419001]({{site.baseurl}}/assets/images/app-burp/4.png)



如果排除了系统固有的信任机制问题还是无法正常抓到包这种情况下一般就属于第二种可能了----APK自有的安全机制

### APK的安全机制

https协议验证服务器身份的方式通常有三种，一是根据浏览器或者说操作系统（Android）自带的证书链；二是使用自签名证书；三是自签名证书加上SSL Pinning特性,所谓SSL pinning即证书绑定。

另外一种是双向认证，客户端与服务端分别存放不同的证书，客户端在通讯时会校验服务端的证书的一致性，反之，服务端在建立通讯前也要验证客户端证书的一致性，验证皆无问题后才建立通讯。



![image-20200322122149168]({{site.baseurl}}/assets/images/app-burp/5.png)

#### SSL pinning

​      一般情况下，关于SSL Pinning的反制，主要有两种办法，第一种是反编译APP文件，篡改内部证书信息。涉及到逆向，调试，重签名等技术，如果客户端存在壳保护、混淆、完整性自校验等防护则无法进行替换。

​      第二种是利用了Hook技术。Hook就是一个函数钩子，把程序原本要调用的函数改成另一个函数，就是对原函数的一个挂钩(hook) 。比如，客户端使用方法hostnameVerifier.verify、checkServerTrusted和checkClientTrusted对证书进行了校验,证书不对则抛出异常，停止加载页面并结束通讯。只需要Hook 证书校验失败的处理方法，让其继续加载页面并保持通讯即可。具体的SSL Pinning的反制，主要以Xposed框架和Frida框架进行Hook关键函数，从而进行数据包的截取。

针对以上情况可以总结了以下几种的具体绕过方式

1）反编译apk,得到源码编辑应用程序的Manifest文件，修改 AndroidManifest.xml，重新打包

apk反编译及打包

反编译

```java
apktool.bat d -f test.apk -o test   
apktool -f [待反编译的apk] -o [反编译之后存放文件夹]
```

打包

`apktool.bat b test`

`**java -jar .\apktool_2.3.0.jar b .\test\**`

签名

`java -jar signapk.jar testkey.x509.pem testkey.pk8 test.apk test_signed.apk `

ps:签名文件：android/build/target/product/security/

2）用自定义的CA覆盖应用程序原本的CA

3）反编译提取APK文件，注入动态库和通过Objection工具【[项目地址](https://github.com/sensepost/objection)】

也可参考roysue师傅的一篇文章[实用FRIDA进阶](https://www.anquanke.com/member/131652)[](https://www.anquanke.com/post/id/197670)

4）hook证书验证函数设置钩子--针对自定义证书的验证代码

详情针对这四种的方法有位大佬做了详细的介绍可参考[绕过安卓SSL验证证书的四种方式](https://www.freebuf.com/articles/terminal/161472.html)

除了以上修改apk验证证书逻辑重新打包的方式外，还有一种最简单的方法是使用xposed相关模块。Xposed+JustTrustMe来进行绕过。使用方法网上也已经有师傅研究过了具体可以[参考](https://xz.aliyun.com/t/6558)还有`https://www.jianshu.com/p/a818a0d0aa9f`

#### 代理检测

##### 客户端内置代理

有些APP内置了指定代理，导致开着抓包工具也无法正常抓到包。

```java
private void N(){
       Address v0=this.g();
       if(v0!=null){
       if(this.e.b().d())
       n.a(v0.getHost(),v0.getPort());
       }
       this.f();
}
```

解决：

1)直接设置代理为自己指定的代理。

比如

```java
const v0,0x22b8
sonst-string v1,"192.168.0.101"//设置为自己的代理，PORT:0x22b8=8888,IP:192.168.0.101
```



2)hook "system.setproperty" 设置代理到本地

```java
//设置代理
System.setProperty("http.proxySet","true");
System.setProperty("http.proxyHost","10.1.1.199");
System.setProperty("http.proxyPort","80");
```

##### 客户端检测是否开启代理

比如APP存在对代理的检测的代码，当存在代理检测时，这个数据包并不会通过代理发送出去。修改smail代码绕过，或者nop掉检测方法。

代码：

```java
private boolean isWifiProxy() {
    final boolean IS_ICS_OR_LATER = Build.VERSION.SDK_INT >= Build.VERSION_CODES.ICE_CREAM_SANDWICH;
    String proxyAddress;
    int proxyPort;
    if (IS_ICS_OR_LATER) {
       proxyAddress = System.getProperty("http.proxyHost");
       String portStr = System.getProperty("http.proxyPort");
       proxyPort = Integer.parseInt((portStr != null ? portStr : "-1"));
    } else {
       proxyAddress = android.net.Proxy.getHost(this);
       proxyPort = android.net.Proxy.getPort(this);
    }
    return (!TextUtils.isEmpty(proxyAddress)) && (proxyPort != -1);
  }
```

#### SSL 双向校验

问题：可拦截到包但返回异常

解决方式：bypass 双向校验

做了双向验证的apk,一般反编译后在APK的 `assets` 中就可以找到客户端证书 `.p12` 和`.cer` 的文件，而在服务端和客户端进行正常通信就需要在服务端也安装`p12` 证书,但导入时会需要一个证书密码，一般可以通过静态分析代码，搜索 `KeyStore` 或者 逆向分析客户端的`.p12` 来找到密码。

#### Sign

sign的绕过并不大了解，但是按照常规套路，就是反编译之后搜索sign/signature相关字符串，然后找到加密算法的地方，抠出来分析,再hook掉，比如系统的java.security.Signature这个接口，直接让系统获取的签名永远返回true，这样就绕过了app的签名校验了。

利用xposed可以：

```java
public void initZygote(StartupParam startupParam) throws Throwable {
     
          XposedHelpers.findAndHookMethod("java.security.Signature",null,"verify", byte[].class,new XC_MethodHook(){
             protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                 XposedBridge.log("disabled verifysignature......");
                 param.setResult(Boolean.TRUE);
             }  
        });
```

来绕过app的签名校验。有大佬师傅github给出了一键绕过App签名验证的工具，https://github.com/xxxyanchenxxx/SigKill，但是本人也没有测试过，不知道有没师傅用过。

参考：

https://xz.aliyun.com/t/6558

https://www.anquanke.com/post/id/200911

https://www.anquanke.com/post/id/200911

https://www.jianshu.com/p/a818a0d0aa9f

http://z-gelen.com/index.php/archives/68/