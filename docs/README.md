# 基于vpn和透明代理的web漏洞扫描器的实现

Transparent-Proxy-Scanner是一个基于vpn和透明代理的web漏洞扫描器，本文是vpn + 透明代理式的web漏洞扫描器的实现的简单说明，用户连接vpn后访问网站时就会把网站的请求与响应信息保存到mongodb中，然后web扫描器从数据库中读取请求信息并进行扫描。

## 架构说明
![](001.png)

## 依赖包安装

```shell

go get github.com/netxfly/Transparent-Proxy-Scanner/hyperfox
go get github.com/toolkits/slice
go get upper.io/db
go get github.com/gorilla/mux
go get menteslibres.net/gosexy/to

```