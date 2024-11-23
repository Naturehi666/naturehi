# Naturehi

工具使用说明
点击链接
https://github.com/Naturehi666/searchall/blob/main3.5.6/%E4%BD%BF%E7%94%A8%E8%AF%B4%E6%98%8E.md

欢迎关注我的公众号

嗨嗨安全 ---- 更多好文章等你来读

![图片](https://github.com/sujiawei00/naturahi/assets/58332933/82b33850-748d-4e03-8da0-d6552a4c91c5)

searchall3.5可以快速搜索服务器中的有关username，passsword,账号，口令的敏感信息还有浏览器的账户密码。

项目已开源，希望大家能够理解我的代码写的或许很乱，很糟糕的问题，谢谢！
欢迎批评与指正


如果你觉得这个项目对你有帮助，你可以请作者喝奶茶

![image](https://github.com/Naturehi666/searchall/assets/58332933/07759057-9072-457c-a378-5d3aab611cd1)


欢迎加入交流群！！！
![5321f5e37a3001cc55f98f4b0ea79df](https://github.com/Naturehi666/searchall/assets/58332933/2b06c0f4-02e3-4017-b441-110e1bb026c9)


如果二维码过期，添加客服拉你进群，备注searchall

![image](https://github.com/Naturehi666/searchall/assets/58332933/2d27f49f-2442-4abd-8177-bb393fad09b3)



开发者日志

5.18日 更新3.1版本

1.解决已知bug
2.增加规则库，进行过滤。
3.将扫出同一文件下的账户，密码整合到一起
4.追加时间戳。
5.search.txt 文件不在是覆盖数据，而是追加数据。


6.6日 更新3.2版本

1.解决已知bug
2.增加规则库，例如账号，密码，口令进行过滤。


6.24日 更新3.4版本

1.解决已知bug
2.识别是否安装向日葵，并自动解析历史连接记录


![image](https://github.com/Naturehi666/naturehi/assets/58332933/2a038208-c428-4b72-b823-9f51e7e2d26a)


7.12日 更新3.5版本

1.解决已知bug
2.增加读取浏览器账户，密码功能

感谢大佬！参考了大佬的工具 https://github.com/moonD4rk/HackBrowserData 集成到了一起。
![image](https://github.com/Naturehi666/naturehi/assets/58332933/62b8fb88-c986-4be5-b043-921df5ed8de8)


7.13日 更新3.5.1版本


1.解决linux输入根目录报错问题，目前已禁止根目录扫描


![image](https://github.com/Naturehi666/searchall/assets/58332933/a14f513c-3b2c-4634-b184-4af9595b8f0b)



7.14日 更新3.5.2版本


1.彻底解决linux输入根目录问题
2.解决占用cpu,内存过高等问题


![image](https://github.com/Naturehi666/searchall/assets/58332933/f4260ef6-cf01-4ad1-ad6d-3360d9e0a6ba)



![image](https://github.com/Naturehi666/searchall/assets/58332933/c708169b-56b5-4e0c-acf4-cffdf5dc8733)



7.19日 更新3.5.3版本


1.解决因线程过多导致目录扫不全问题
2.增加/var/log/secure 扫描时取出登陆成功记录
3.增加accessKeyId,accessKeySecret,jdbc匹配规则
4.增加浏览器生成的result文件夹打包功能
5.增加扫描有效文件数实时响应功能
6.增加扫描服务器中是否安装docker功能


![image](https://github.com/Naturehi666/searchall/assets/58332933/440229d6-f0c3-473f-a612-c3ed7b289400)





8.12日 更新3.5.4版本


增加 CorpId，CorpSecret，qq.im.sdkappid，qq.im.privateKey，qq.im.identifier的读取规则



![image](https://github.com/Naturehi666/searchall/assets/58332933/02f063c9-5227-4534-b654-2e93cfa62560)


9.23日 更新3.5.7版本

修改友好界面
解决已知bug

![image](https://github.com/Naturehi666/searchall/assets/58332933/5b6ed597-9996-499b-9426-0fc5666aefb9)


10.6日 更新3.5.8版本

1.解决已知bug
2.增加-e 参数拓展自定义扩展名功能，例如.java , .log 都可以
3.增加-n 参数可以只扫描指定拓展名的功能

![image](https://github.com/Naturehi666/searchall/assets/58332933/0a9a4244-8768-414a-977f-61f8bcec5670)


3.18日 更新3.5.9版本


1.解决浏览器爬取密码已知bug


![image](https://github.com/Naturehi666/searchall/assets/58332933/a29675a5-bb22-4105-afc3-2d503efd614e)





由于没有实验环境一直没有测试解决该bug，感谢CV,她她她朋友的帮忙进行测试，十分感谢！



9.4日 更新3.5.10版本

新增扫描自定义行数及文件大小功能


2024.11.23日 更新3.5.11版本

以chrome版本为 130.0.6723.70
支持最新版chrome cookie解密功能，影卷复制


鸣谢

感谢网上开源的相关项目！

免责声明

本工具仅能在取得足够合法授权的企业安全建设中使用，在使用本工具过程中，您应确保自己所有行为符合当地的法律法规。 如您在使用本工具的过程中存在任何非法行为，您将自行承担所有后果，本工具所有开发者和所有贡献者不承担任何法律及连带责任。 除非您已充分阅读、完全理解并接受本协议所有条款，否则，请您不要安装并使用本工具。 您的使用行为或者您以其他任何明示或者默示方式表示接受本协议的，即视为您已阅读并同意本协议的约束。







