# VulnForum writeup

1.进入靶场[VulnForum](http://if4vo36v.ctfio.com/)

2.![image-20250210132659860](C:\Users\zheng\AppData\Roaming\Typora\typora-user-images\image-20250210132659860.png)

先看页面中内容，只发现了一个toby的id：1ac9c036aaf12a755084dc6a326ed7f5，用户和管理员的不允许的访问



3.右上角有登录窗口，尝试登录显示账户和密码组合错误，无法弱口令，查看登录数据包

![image-20250210133448336](C:\Users\zheng\AppData\Roaming\Typora\typora-user-images\image-20250210133448336.png)

发现method参数，参数值为local，可以尝试修改为remote，返回了其他内容，**获取到第一个flag**

![image-20250210133739939](C:\Users\zheng\AppData\Roaming\Typora\typora-user-images\image-20250210133739939.png)



4.并且返回了一个url，访问一次显示无效域名

![image-20250210134032819](C:\Users\zheng\AppData\Roaming\Typora\typora-user-images\image-20250210134032819.png)

5.尝试解析cname，看是否有其他域名，发现其他域名if4vo36v.vulnauth.co.uk，**获取第二个flag**

![image-20250210134516331](C:\Users\zheng\AppData\Roaming\Typora\typora-user-images\image-20250210134516331.png)



6.该系统可以处理用户登录将账号绑定到其他域名，尝试将账号绑定到http://remote-auth.if4vo36v.ctfio.com/，重新访问登录账号

![image-20250210135538074](C:\Users\zheng\AppData\Roaming\Typora\typora-user-images\image-20250210135538074.png)

6.该系统可以创建账号，也可以修改账号密码，尝试修改其他账号密码，没有数据，看是否可以账号覆盖，新建账号为第一个页面中的toby，uuid为toby的id，设置密码，再尝试登录，依然账号密码错误

![image-20250210135939562](C:\Users\zheng\AppData\Roaming\Typora\typora-user-images\image-20250210135939562.png)





7.继续拦截数据包将local改为remote，成功**获取第三个flag**

### ![image-20250210140044643](C:\Users\zheng\AppData\Roaming\Typora\typora-user-images\image-20250210140044643.png)



8.拥有用户权限，访问用户的论坛，发现两个新功能点，发表评论以及修改密码，发现john（管理员）的uuid：76887c0378ba2b80f17422fb0c0791c4

![image-20250210140336576](C:\Users\zheng\AppData\Roaming\Typora\typora-user-images\image-20250210140336576.png)



9.首先查看修改密码功能，看数据包，尝试将uuid修改管理员的uuid，无效 ，可能是cookie鉴权![image-20250210140717881](C:\Users\zheng\AppData\Roaming\Typora\typora-user-images\image-20250210140717881.png)



10.想到有个评论功能点看是否可以csrf+xss修改管理员的密码，首先获取管理员密码的url：

```
http://if4vo36v.ctfio.com/settings/password?password=123456&hash=76887c0378ba2b80f17422fb0c0791c4

```

11.尝试常见标签<a>,<img>不显示在页面上，看js尝试闭合，发现新链接[bbcode_plugin/bbcode.php at master · code-for-sites/bbcode_plugin](https://github.com/code-for-sites/bbcode_plugin/blob/master/bbcode.php)



12.尝试利用以下内容：发现只有[img]会在页面返回图片，并且抓到图片地址的数据包

```
[a]https://www.example.com[/a] [img]https://www.example.com/img.jpg[/img] [strong]test[/strong] [b]test[/b] [script]alert(true)[/script] [u]test[/u] 
```



13.所以用[img]标签看里面是否可以将修改密码的url放入，看bbcode的源代码发现以下代码

```
		if( $this->allowedTag('img') ){
			$find[] = '~\[img\](http(s)?://.*?\.(?:jpg|jpeg|gif|png))\[/img\]~s';
			$replace[] = '<img src="$1" />';
		}
```



14.发现只匹配了（.+图片后缀）就可以绕过，所以在修改密码的url后面让入新参数a=.png绕过，如下：

```
http://if4vo36v.ctfio.com/settings/password?password=123456&hash=76887c0378ba2b80f17422fb0c0791c4&a=.png
```



15.管理员访问评论区后就修改了密码，登入管理员**账号获取第四个flag**
