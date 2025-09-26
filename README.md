This is a project to develop a native UTF-8 capable DNS protocol. 
Goal:
To create a DNS system that natively supports UTF-8 without changing the existing DNS and its infrastructure. 

Practical application:
Clients that support uDNS communicate with the uDNS server(s) in uDNS. Because migrating all domains would be too costly, DNS queries should be forwarded to the existing DNS servers. To do this, uDNS queries are converted into normal DNS queries (UTF-8 to punny code), unless communication takes place between uDNS servers, in which case everything remains in UTF-8. 

----

这是一个开发原生支持UTF-8的DNS协议的项目。
目标：
创建一个原生支持UTF-8的DNS系统，无需改变现有DNS及其基础设施。

实际应用：
支持uDNS的客户端通过uDNS协议与uDNS服务器通信。鉴于全面迁移域名成本过高，DNS查询应转发至现有DNS服务器。为此，uDNS查询将转换为常规DNS查询（UTF-8转为Punycode），但uDNS服务器间通信仍全程保持UTF-8格式。
