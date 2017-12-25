# gofsnet
　一个用来学习IEEE 802.1X协议和drcom协议的简单项目，使用go语言。

- [English](https://github.com/artificerpi/gofsnet/blob/master/README-en.md)

## 主要知识：

- EAP (EAPOL)协议
- DRCOM 网络数据包分析
- gopacket依赖库使用

## 特点:

- [x] 跨平台（支持Windows, Linux x64 & arm等)
- [x] 只保留最基本的网络认证功能(无热点共享等限制)
- [x] 检测网络状况自动重连功能
- [x] 非明文的用户密码及简单可配置选项
- [x] 可以配置抓取认证网络包

## 测试运行环境

- Win10, Ubuntu 16.04, Raspberry Pi3
- [SCUT宿舍网络环境](https://github.com/YSunLIN/fsn_server)

## 安装使用

请先安装[winpcap](https://www.winpcap.org/)然后再运行本程序

具体请看[Wiki](https://github.com/artificerpi/gofsnet/wiki/Build-this-project)

- 如有问题请[在Issue中提出](https://github.com/artificerpi/gofsnet/issues)

**欢迎有兴趣的开发者参与其中一起学习交流**
