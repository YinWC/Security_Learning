**Security_Learning**

项目地址：[Security_Learning](https://github.com/YinWC/Web_Security_Learning)

分享一些平时工作生活中遇到的不错的项目，包含安全的各个方面，适合安全从业者/学习者阅读

望此项目能伴随着大家的学习生活～

持续更新中~

<!-- TOC -->

- [Experience](#experience)
  - [职业规划及发展](#职业规划及发展)
  - [一些面经](#一些面经)
  - [生活](#生活)
    - [购房知识](#购房知识)
    - [其他](#其他)
- [Web Security](#web-security)
  - [企业安全建设](#企业安全建设)
  - [主机安全](#主机安全)
  - [容器安全](#容器安全)
  - [开发安全](#开发安全)
    - [SDL](#sdl)
    - [扫描器](#扫描器)
    - [蜜罐](#蜜罐)
    - [JAVA安全](#java安全)
      - [反序列](#反序列)
      - [Struct2](#struct2)
      - [JavaWeb](#javaweb)
      - [Solr](#solr)
      - [Fastjson](#fastjson)
      - [Shiro](#shiro)
      - [Jenkins](#jenkins)
      - [其他](#其他-1)
    - [Python安全](#python安全)
    - [PHP安全](#php安全)
    - [Node-js安全](#node-js安全)
  - [漏洞相关](#漏洞相关)
    - [sql注入](#sql注入)
    - [XSS跨站脚本攻击](#xss跨站脚本攻击)
    - [CSRF跨站请求伪造](#csrf跨站请求伪造)
      - [其他前端安全](#其他前端安全)
    - [SSRF服务器端请求伪造](#ssrf服务器端请求伪造)
    - [XXE(xml外部实体注入)](#xxexml外部实体注入)
    - [JSONP注入](#jsonp注入)
    - [SSTI服务器模板注入](#ssti服务器模板注入)
    - [代码执行 / 命令执行](#代码执行--命令执行)
    - [文件包含](#文件包含)
    - [文件上传 / 解析漏洞](#文件上传--解析漏洞)
    - [逻辑漏洞](#逻辑漏洞)
    - [PHP相关](#php相关)
    - [CORS漏洞](#cors漏洞)
    - [DDOS](#ddos)
    - [其他漏洞](#其他漏洞)
    - [SRC漏洞挖掘](#src漏洞挖掘)
  - [安全测试](#安全测试)
    - [信息收集](#信息收集)
    - [渗透实战](#渗透实战)
    - [渗透技巧](#渗透技巧)
      - [内网渗透](#内网渗透)
      - [WAF攻防](#waf攻防)
      - [无文件攻击](#无文件攻击)
      - [提权](#提权)
  - [安全运维](#安全运维)
  - [Others](#others)
    - [RASP](#rasp)
    - [other](#other)
- [Binary security](#binary-security)
  - [IOT Security](#iot-security)
  - [Mobile Security](#mobile-security)
    - [Frida相关文章合集](#frida相关文章合集)
    - [脱壳相关](#脱壳相关)
    - [游戏安全系列](#游戏安全系列)
    - [奇淫技巧](#奇淫技巧)
    - [比较好的前沿文章归档](#比较好的前沿文章归档)
    - [安全开发](#安全开发)
    - [逆向](#逆向)
- [CTF](#ctf)
  - [技巧总结](#技巧总结)
  - [CTF PWN](#ctf-pwn)

<!-- /TOC -->

# Experience

## 职业规划及发展

- [安全从业人员的职业规划](https://mp.weixin.qq.com/s/134C13nbVtJkg-MM0eRe8g)
- [在腾讯的八年，我的职业思考](https://yuguo.us/weblog/tencent-8-years/)
- [卓卓师傅：我在pdd的三年](https://github.com/LeadroyaL/pdd_3years)
- [程序员考公指南](https://github.com/coder2gwy/coder2gwy)
- [野生前端码农的内功修炼和自我修养笔记](https://github.com/dashnowords/blogs)

## 一些面经

- [sec-interview](https://github.com/d1nfinite/sec-interview/blob/master/README.md)
- [万字攻略，详解腾讯面试](https://mp.weixin.qq.com/s/6pEFg_OwsT6RkueE-FV6hA)
- [信息安全实习和校招的面经](https://github.com/SecYouth/sec-jobs)
- [信息安全方面面试清单](https://github.com/tiaotiaolong/sec_interview_know_list)
- [信息安全面试题汇总](https://github.com/Dollarsss/sec-interview)
- [腾讯、阿里实习移动安全面试](https://la0s.github.io/2019/05/13/chunzhao/)
- [404notfound'blog](https://4o4notfound.org/index.php/archives/183/)
- [yulige's blog](http://yulige.top/?p=685)
- [yangrz's blog](https://yangrz.github.io/blog/2016/12/15/mianshi/)

## 生活

### 购房知识

- [北京购房知识分享](https://github.com/online-books/beijing_house_knowledge)
- [上海购房知识分享](https://github.com/ayuer/shanghai_house_knowledge)
- [杭州购房知识分享](https://github.com/houshanren/hangzhou_house_knowledge)

### 其他
- [投资regular-investing-in-box](https://github.com/xiaolai/regular-investing-in-box)

# Web Security

- [Web安全学习笔记](https://websec.readthedocs.io/zh/latest/index.html)
- [Web安全研究人员是如何炼成的](https://xz.aliyun.com/t/2358#toc-0)
- [Web安全中比较好的文章](https://github.com/spoock1024/web-security)
- [Web安全攻防实战](https://github.com/hongriSec/Web-Security-Attack)

## 企业安全建设

- [企业安全建设 - 软件供应链](https://0x0d.im/archives/enterprise-security-construction-software-supply-chain.html)

## 主机安全

- [美团分布式HIDS集群架构设计](https://tech.meituan.com/2019/01/17/distributed-hids-cluster-architecture-design.html)
- [Osquery架构设计分析](https://blog.spoock.com/2018/12/29/osquery-under-the-hood/)
- [ATT&CK防御逃逸](https://paper.seebug.org/1103/#_1)
- [透过eBPF观测系统行为](https://www.bilibili.com/video/av37642583?from=search&seid=3945678335588410992)
- [Osquery官方文档](https://osquery.readthedocs.io/en/stable/)
- [利用Osquery监控反弹shell](https://clo.ng/blog/osquery_reverse_shell/)
- [安全运营流程](https://zhuanlan.zhihu.com/p/39467201)
- [Linux bash命令审计](https://mp.weixin.qq.com/s/suRCuK0ctC6F9v2dOg5Wcg)
- [Linux 提权检测](https://zgao.top/长亭实习二-linux本地提权漏洞复现与检测思路/)
- [Ali云安全告警中心检测项](https://help.aliyun.com/document_detail/180843.html?spm=5176.11065259.1996646101.searchclickresult.344a7e8fIJz6h4)
- [AgentSmith-HIDS](https://github.com/EBWi11/AgentSmith-HIDS/blob/master/doc/How-to-use-AgentSmith-HIDS-to-detect-reverse-shell/%E5%A6%82%E4%BD%95%E5%88%A9%E7%94%A8AgentSmith-HIDS%E6%A3%80%E6%B5%8B%E5%8F%8D%E5%BC%B9shell.md)
- [Elkied-HIDS](https://github.com/bytedance/Elkeid/blob/main/driver/README-zh_CN.md)
- [Yulong-HIDS](https://github.com/ysrc/yulong-hids-archived/blob/master/server/models/common.go)
- [Linux入侵检测进程创建监控](https://sq.163yun.com/blog/article/311384915510648832)
- [Linux Hook方式汇总](https://xz.aliyun.com/t/6961)

## 容器安全

- [腾讯安全:红蓝对抗中的云原生漏洞挖掘及利用实录](https://mp.weixin.qq.com/s/Aq8RrH34PTkmF8lKzdY38g)
- [k0otkit: Hack K8s in a K8s Way](https://mp.weixin.qq.com/s/H48WNRRtlJil9uLt-O9asw)
- [容器渗透工具](https://github.com/cdk-team/CDK/)
- [CIS2020-Attack-in-a-Service-Mesh-Public](https://force.tencent.com/docs/CIS2020-Attack-in-a-Service-Mesh-Public.pdf?v=1)
- [K8s渗透测试etcd的利用](https://www.cdxy.me/?p=827)
- [kubernetes集群渗透测试](https://www.freebuf.com/vuls/196993.html)

## 开发安全

- [开发人员安全指南](https://github.com/FallibleInc/security-guide-for-developers)
- [计算机编程类书籍汇总](https://github.com/justjavac/free-programming-books-zh_CN)

### SDL

- [SDL的各个阶段](https://www.jianshu.com/p/dd147e84931b)
- [SDL开发安全生命周期管理](https://www.securitypaper.org/)
- [SDL的深入探究及实践](https://pek3a.qingstor.com/community/resource/QCon2016-Beijing/SDL%E7%9A%84%E6%B7%B1%E5%85%A5%E6%8E%A2%E7%A9%B6%E5%8F%8A%E5%AE%9E%E8%B7%B5.pdf)
- [SDL探索之路](https://xz.aliyun.com/t/6625#toc-7)
- [精简版SDL落地实践](https://xz.aliyun.com/t/5656)
- [值得读的书籍securitypaper关于SDL](https://www.securitypaper.org/1.sdl%E4%BB%8B%E7%BB%8D/1-%E4%BB%80%E4%B9%88%E6%98%AFsdl/)
- [SDL建设-三方依赖库扫描系统](https://www.secpulse.com/archives/73373.html)
- [金融科技SDL安全设计checklist](https://xz.aliyun.com/t/2089)

### 扫描器

- [黑盒扫描器自研之路（一）——侃侃构架](https://milkfr.github.io/%E5%AE%89%E5%85%A8%E5%BC%80%E5%8F%91/2018/11/10/dev-black-box-scanner-1/)
- [自研之路：腾讯漏洞扫描系统的十年历程](https://security.tencent.com/index.php/blog/msg/100)
- [小米安全：漏洞扫描技巧之Web漏洞扫描器研究](https://www.freebuf.com/articles/web/212015.html)
- [携程安全自动化测试之路](https://zhuanlan.zhihu.com/p/28115732)
- [黑盒扫描器自研](https://milkfr.github.io/%E5%AE%89%E5%85%A8%E5%BC%80%E5%8F%91/2018/11/10/dev-black-box-scanner-1/)
- [漫谈漏洞扫描器的设计与开发](https://thief.one/2018/03/16/1/)
- [安全开发之扫描器迭代记：W9Scan](https://www.freebuf.com/sectool/162120.html)
- [XSS扫描器成长记](https://wemp.app/posts/e15438d4-8358-40fa-a1aa-50a6d93b4fe0)

### 蜜罐

- [蜜罐开源技术收集](https://github.com/paralax/awesome-honeypots )
- [现代蜜网，集成了多种蜜罐的安装脚本，可以快速部署、使用，也能够快速的从节点收集数据](https://github.com/threatstream/mhn )
- [T-POT，里面使用docker技术实现多个蜜罐组合，配合ELK进行研究与数据捕获](https://github.com/dtag-dev-sec/tpotce)
- [T-Pot多蜜罐平台使用心法](https://www.freebuf.com/sectool/190840.html)
- [将fork的T-POT蜜罐的一键安装脚本替换为国内加速镜像](https://github.com/n3uz/t-pot-autoinstall)
- **Web蜜罐内网监测**
  - https://github.com/micheloosterhof/cowrie py2使用ELK（ElasticSearch，LogStash，Kibana）进行数据分析，目前支持ssh，telnet，sftp等协议
  - https://github.com/mushorg/snare py3，web安全蜜罐，可克隆指定Web页面
  - https://github.com/honeynet/beeswarm py，使用agent探针与蜜罐进行实时交互来引诱攻击者
  - https://github.com/thinkst/opencanary PY2,SNMP\RDP\SAMBA蜜罐
  - https://github.com/p1r06u3/opencanary_web PY,TORNADO,内网低交互蜜罐。支持自动化安装，目前支持常见的16中协议，现为探针/蜜罐-管理的架构，可以考虑二次开发为探针-沙盒-管理的架构
  - https://github.com/p1r06u3/opencanary_web
  - https://github.com/Cymmetria 知名欺骗防御蜜罐组织。Struct、weblogic、telnet、Cisco ASA、Micros等仿真蜜罐
  - https://github.com/Cymmetria/honeycomb Cymmetria公司开源蜜罐框架，低交互
  - https://github.com/honeytrap/honeytrap 可扩展蜜罐框架，支持探针部署与高交互蜜罐
  - https://gosecure.net/2018/12/19/rdp-man-in-the-middle-smile-youre-on-camera/ RDP MITM，打造可记录图像和按键的 RDP 蜜罐（https://github.com/gosecure/pyrdp）
  
- **摄像头蜜罐**
  - https://github.com/alexbredo/honeypot-camera 摄像头蜜罐。tornado模拟WEB服务，图片代替视频，可以考虑后期多加点图片和按钮
  - https://github.com/EasyDarwin/EasyIPCamera C，RTSP服务器组件用以构建摄像头蜜罐
- **工控蜜罐**
  - https://github.com/sjhilt/GasPot 模拟油电燃气工控系统
  - https://github.com/djformby/GRFICS IoT工业仿真系统模拟框架，采用MODBUS协议对PLC虚拟机监视和控制
  - https://github.com/RabitW/IoTSecurityNAT IoT测试系统，方便快速接入各种设备，进行安全测试
  - https://github.com/mushorg/conpot 针对ICS/SCADA的低交互工控蜜罐，模拟Modbus和S7comm

### JAVA安全

- [JAVA安全SDK及编码规范](https://github.com/YinWC/rhizobia_J)
- [JAVA安全编码规范](https://github.com/momosecurity/rhizobia_J/wiki/JAVA%E5%AE%89%E5%85%A8%E7%BC%96%E7%A0%81%E8%A7%84%E8%8C%83)
- [Java代码审计系列文章](https://yinwc.github.io/2020/01/03/Java%E4%BB%A3%E7%A0%81%E5%AE%A1%E8%AE%A1/)

#### 反序列

- [Java_JSON反序列化之殇_看雪安全开发者峰会](https://github.com/shengqi158/fastjson-remote-code-execute-poc/blob/master/Java_JSON%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8B%E6%AE%87_%E7%9C%8B%E9%9B%AA%E5%AE%89%E5%85%A8%E5%BC%80%E5%8F%91%E8%80%85%E5%B3%B0%E4%BC%9A.pdf)
- [从反射链的构造看Java反序列漏洞](http://www.freebuf.com/news/150872.html)
- [Java反序列化漏洞从理解到实践](http://bobao.360.cn/learning/detail/4474.html)
- [Java 序列化与反序列化安全分析 ](http://mp.weixin.qq.com/s?__biz=MzI5ODE0ODA5MQ==&mid=2652278247&idx=1&sn=044893b732e4ffa267b00ffe1d9e4727&chksm=f7486473c03fed6525f0a869cbc4ddc03051cda92bb946377c4d831054954159542350768cf3&mpshare=1&scene=23&srcid=0919MUXFBglgDUEtLOha0wbo#rd)
- [Java-Deserialization-Cheat-Sheet](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet)
- [如何攻击Java反序列化过程](http://bobao.360.cn/learning/detail/4267.html)
- [深入理解JAVA反序列化漏洞](https://www.vulbox.com/knowledge/detail/?id=11)
- [Attacking Java Deserialization](https://nickbloor.co.uk/2017/08/13/attacking-java-deserialization/)
- [jackson反序列化详细分析](http://bobao.360.cn/learning/detail/4118.html)
- [Java安全之反序列化漏洞分析 ](https://mp.weixin.qq.com/s?__biz=MzIzMzgxOTQ5NA==&mid=2247484200&idx=1&sn=8f3201f44e6374d65589d00d91f7148e)
- [fastjson 反序列化漏洞 POC 分析 ](https://mp.weixin.qq.com/s/0a5krhX-V_yCkz-zDN5kGg)
- [Apache Commons Collections反序列化漏洞学习](http://pirogue.org/2017/12/22/javaSerialKiller/)

#### Struct2

- [Struts2 命令执行系列回顾](http://www.zerokeeper.com/vul-analysis/struts2-command-execution-series-review.html)

#### JavaWeb

**java-Web代码审计**

- [Java Web代码审计入门一周纪实：6枚CNVD通用漏洞](https://mp.weixin.qq.com/s/YvHOa9gMJpj6pne317ul0Q)
- [JAVA代码审计的一些Tips(附脚本)](https://xianzhi.aliyun.com/forum/topic/1633/)
- [Java代码审计连载之—SQL注入](https://bbs.ichunqiu.com/forum.php?mod=viewthread&tid=22170&highlight=Java%E4%BB%A3%E7%A0%81%E5%AE%A1%E8%AE%A1%E8%BF%9E%E8%BD%BD)
- [Java代码审计连载之—任意文件下载](https://bbs.ichunqiu.com/forum.php?mod=viewthread&tid=23587&highlight=Java%E4%BB%A3%E7%A0%81%E5%AE%A1%E8%AE%A1%E8%BF%9E%E8%BD%BD)
- [Java代码审计连载之—XSS](https://bbs.ichunqiu.com/forum.php?mod=viewthread&tid=22875&highlight=Java%E4%BB%A3%E7%A0%81%E5%AE%A1%E8%AE%A1%E8%BF%9E%E8%BD%BD)
- [Java代码审计连载之—添油加醋](https://bbs.ichunqiu.com/forum.php?mod=viewthread&tid=25475&highlight=Java%E4%BB%A3%E7%A0%81%E5%AE%A1%E8%AE%A1%E8%BF%9E%E8%BD%BD)
- [JAVA安全编码与代码审计.md](https://github.com/Cryin/JavaID/blob/master/JAVA%E5%AE%89%E5%85%A8%E7%BC%96%E7%A0%81%E4%B8%8E%E4%BB%A3%E7%A0%81%E5%AE%A1%E8%AE%A1.md)
- [Java代码审计PPT ](https://xianzhi.aliyun.com/forum/read/1904.html)


#### Solr

- [Skay:Apache Solr 组件安全概览](https://mp.weixin.qq.com/s/3WuWUGO61gM0dBpwqTfenQ)

#### Fastjson

- [Fastjson反序列化漏洞史](https://paper.seebug.org/1192)

#### Shiro

- [Apache Shiro反序列化识别那些事](https://mp.weixin.qq.com/s/q5sexARASK2TI6ihnRzYjg)

#### Jenkins

- [Jenkins 未授权代码执行漏洞分析](https://www.anquanke.com/post/id/86018)

#### 其他

- [关于 JNDI 注入](http://bobao.360.cn/learning/detail/4564.html)
- [层层放大java审计的攻击面 ](https://mp.weixin.qq.com/s/WT1EXEryUGGqHQpSi959xw)
- [以Java的视角来聊聊SQL注入 ](https://mp.weixin.qq.com/s?__biz=MzIzMzgxOTQ5NA==&mid=2247483954&idx=1&sn=418b7e55b16c717ee5140af990298e22&chksm=e8fe9e3bdf89172d0670690060944bf2434cc2d2e8fba4477711299a0775cf3735a2022c0778#rd)
- [站在Java的视角，深度分析防不胜防的小偷——“XSS” ](http://mp.weixin.qq.com/s?__biz=MzIzMzgxOTQ5NA==&mid=100000340&idx=1&sn=6ca4ec15ef6338daf1d4a907351d7c08&chksm=68fe9e5d5f89174b44fd0cae2e3d5c0018859d3d1dc6d60a2e16dcde34499ba224d6ea17a982#rd)
- [你的 Java web 配置安全吗？ ](https://mp.weixin.qq.com/s?__biz=MzIzMzgxOTQ5NA==&mid=100000318&idx=1&sn=9011af3e3968e0d87499605ef1a68291&chksm=68fe9e375f8917213297855bd9e1ab1203ae4c9b0b5ca351de7b2c0f7a7799bd1f4843cd13f4#rd)
- [spring任意文件读取](https://github.com/ilmila/springcss-cve-2014-3625/tree/master/src)
- [在 Runtime.getRuntime().exec(String cmd) 中执行任意shell命令的几种方法](https://mp.weixin.qq.com/s/zCe_O37rdRqgN-Yvlq1FDg)

###  Python安全

- [Python-100-Days](https://github.com/jackfrued/Python-100-Days)
- [python web 安全总结](http://bobao.360.cn/learning/detail/4522.html)
- [Defencely Clarifies Python Object Injection Exploitation](http://defencely.com/blog/defencely-clarifies-python-object-injection-exploitation/)
- [Exploiting Python Deserialization Vulnerabilities](https://crowdshield.com/blog.php?name=exploiting-python-deserialization-vulnerabilities)
- [Explaining and exploiting deserialization vulnerability with Python(EN)](https://dan.lousqui.fr/explaining-and-exploiting-deserialization-vulnerability-with-python-en.html)
- [Python PyYAML反序列化漏洞实验和Payload构造](http://www.polaris-lab.com/index.php/archives/375/)
- [Python 格式化字符串漏洞（Django为例）](https://www.leavesongs.com/PENETRATION/python-string-format-vulnerability.html)
- [format注入](http://www.venenof.com/index.php/archives/360/)
- [Be Careful with Python's New-Style String Format](http://lucumr.pocoo.org/2016/12/29/careful-with-str-format/)
- [Python urllib HTTP头注入漏洞](http://www.tuicool.com/articles/2iIj2eR)
- [Hack Redis via Python urllib HTTP Header Injection](https://security.tencent.com/index.php/blog/msg/106)
- [Python Waf黑名单过滤下的一些Bypass思路](http://www.0aa.me/index.php/archives/123/)
- [Python沙箱逃逸的n种姿势](https://mp.weixin.qq.com/s/PLI-yjqmA3gwk5w3KHzOyA)
- [利用内存破坏实现Python沙盒逃逸 ](https://mp.weixin.qq.com/s/s9fAskmp4Bb42OYsiQJFaw)
- [Python Sandbox Bypass](https://mp.weixin.qq.com/s?__biz=MzIzOTQ5NjUzOQ==&mid=2247483665&idx=1&sn=4b18de09738fdc5291634db1ca2dd55a)
- [pyt: 针对 Python 应用程序的源码静态分析工具](https://github.com/python-security/pyt)
- [Exploiting Python PIL Module Command Execution Vulnerability](http://docs.ioin.in/writeup/github.com/_neargle_PIL_RCE_By_GhostButt/index.html)
- [文件解压之过 Python中的代码执行](http://bobao.360.cn/learning/detail/4503.html)

- **爬虫系列**
  - [爬虫之从入门到精通](https://zhuanlan.zhihu.com/pachong)
  - [从零开始写Python爬虫 ](https://zhuanlan.zhihu.com/p/26673214)
  - [爬虫与反爬虫技术分析](https://blog.csdn.net/qq_25834767/article/details/104532493)
  - [漏扫动态爬虫实践](漏扫动态爬虫实践)

- **Python沙盒逃逸**
  - [Python沙盒逃逸备忘 --by K0rz3n师傅](http://www.k0rz3n.com/2018/05/04/Python%20%E6%B2%99%E7%9B%92%E9%80%83%E9%80%B8%E5%A4%87%E5%BF%98/)
  - [Python沙箱逃逸Payload收集 --by 王一航师傅](https://www.jianshu.com/p/30ece4087a8a)
  - [关于Python sec的一些简单的总结 --by Bendawang师傅](http://bendawang.site/2018/03/01/%E5%85%B3%E4%BA%8EPython-sec%E7%9A%84%E4%B8%80%E4%BA%9B%E6%80%BB%E7%BB%93/)
  - [从一个CTF题目学习Python沙箱逃逸](https://www.anquanke.com/post/id/85571)
  - [Python沙箱逃逸的n种姿势](https://xz.aliyun.com/t/52#toc-10)


### PHP安全

[PHP安全SDK及编码规范](https://github.com/momosecurity/rhizobia_P/)

###  Node-js安全

- [浅谈Node.js Web的安全问题](http://www.freebuf.com/articles/web/152891.html)
- [node.js - postgres 从注入到Getshell](https://www.leavesongs.com/PENETRATION/node-postgres-code-execution-vulnerability.html)
- [Pentesting Node.js Application : Nodejs Application Security(需翻墙)](http://www.websecgeeks.com/2017/04/pentesting-nodejs-application-nodejs.html)
- [从零开始学习渗透Node.js应用程序 ](https://bbs.ichunqiu.com/thread-21810-1-1.html?from=sec)
- [Node.js 中遇到含空格 URL 的神奇“Bug”——小范围深入 HTTP 协议](https://segmentfault.com/a/1190000012407268)

## 漏洞相关

- **开源漏洞库**
  - [2016年之前，乌云Drops文章，公开漏洞详情文章](https://wooyun.kieran.top/#!/ )
  - [2016年之前，乌云Drops文章，公开漏洞详情文章](https://wooyun.js.org/)
  - [公开漏洞详情文章](https://dvpnet.io/list/index/state/3)
  - [同程安全公开漏洞详情文章](https://sec.ly.com/bugs)
  - [中国国家工控漏洞库](http://ics.cnvd.org.cn)
  - [美国国家工控漏洞库](https://ics-cert.us-cert.gov/advisories)
  - [绿盟漏洞库，含工控](http://www.nsfocus.net/index.php?act=sec_bug)
  - [威努特工控漏洞库](http://ivd.winicssec.com/)
  - [CVE中文工控漏洞库](http://cve.scap.org.cn/view/ics)
  - [美国MITRE公司负责维护的CVE漏洞库](https://cve.mitre.org/cve/search_cve_list.html)
  - [美国Offensive Security的漏洞库](https://www.exploit-db.com)
  - [美国国家信息安全漏洞库](https://nvd.nist.gov/vuln/search)
- [一些漏洞情报的网站](https://github.com/r0eXpeR/VulnerabilityIntelligence)
- [CVE-2020:2020年的部分漏洞整理](https://github.com/r0eXpeR/CVE-2020)
- [红队中易被攻击的一些重点系统漏洞整理](https://github.com/r0eXpeR/redteam_vul)
- [白阁文库漏洞汇总](https://baizesec.github.io/bylibrary/#_10)

### sql注入
[原理-实战掌握SQL注入](https://xz.aliyun.com/t/6677)
[为什么参数化查询可以防止SQL注入?](https://www.waitalone.cn/sql-preparestatement.html)

**MySql**

- [通过MySQL LOAD DATA特性来达到任意文件读取](https://xz.aliyun.com/t/3973)
- [MySQL False 注入及技巧总结](https://www.anquanke.com/post/id/86021)
- [MySQL 注入攻击与防御](https://www.anquanke.com/post/id/85936)
- [sql注入学习总结 ](https://mp.weixin.qq.com/s?__biz=MzI5MDQ2NjExOQ==&mid=2247484372&idx=1&sn=ffcc51a88c9acf96c312421b75fc2a26&chksm=ec1e33fcdb69baea53838fd545a236c0deb8a42f3b341ee0879c9e4ac9427c2147fab95b6669#rd)
- [SQL注入防御与绕过的几种姿势](https://www.anquanke.com/post/id/86005)
- [MySQL偏门技巧](http://rcoil.me/2017/05/MySQL%E5%81%8F%E9%97%A8%E6%8A%80%E5%B7%A7/)
- [mysql注入可报错时爆表名、字段名、库名](http://www.wupco.cn/?p=4117)
- [高级SQL注入:混淆和绕过](http://www.cnblogs.com/croot/p/3450262.html)
- [Mysql约束攻击](https://ch1st.github.io/2017/10/19/Mysql%E7%BA%A6%E6%9D%9F%E6%94%BB%E5%87%BB/)
- [Mysql数据库渗透及漏洞利用总结 ](https://xianzhi.aliyun.com/forum/topic/1491/)
- [MySQL绕过WAF实战技巧 ](http://www.freebuf.com/articles/web/155570.html)
- [NetSPI SQL Injection Wiki](https://sqlwiki.netspi.com/)
- [SQL注入的“冷门姿势” ](http://www.freebuf.com/articles/web/155876.html)
- [时间延迟盲注的三种加速注入方式mysql](https://www.ch1st.cn/?p=44)
- [基于时间的高效的SQL盲注-使用MySQL的位运算符](https://xz.aliyun.com/t/3054)
- [Mysql UDF BackDoor](https://xz.aliyun.com/t/2365)
- [mysql小括号被过滤后的盲注](https://www.th1s.cn/index.php/2018/02/26/213.html)
- [SSRF To RCE in MySQL](http://docs.ioin.in/writeup/mp.weixin.qq.com/49ca504e-3b31-40ac-8591-f833086cb588/index.html)
- [MySQL-盲注浅析](http://rcoil.me/2017/11/MySQL-%E7%9B%B2%E6%B3%A8%E6%B5%85%E6%9E%90/)
- [Mysql字符编码利用技巧](https://www.leavesongs.com/PENETRATION/mysql-charset-trick.html)
- [MySQL Injection in Update, Insert and Delete](https://osandamalith.com/2017/02/08/mysql-injection-in-update-insert-and-delete/)

**MSSQL**

- [MSSQL DBA权限获取WEBSHELL的过程 ](http://fuping.site/2017/05/16/MSSQL-DBA-Permission-GET-WEBSHELL/)
- [MSSQL 注入攻击与防御](https://www.anquanke.com/post/id/86011)
- [CLR在SQL Server中的利用技术分](http://docs.ioin.in/writeup/cert.360.cn/_files_CLR_E5_9C_A8SQL_20Server_E4_B8_AD_E7_9A_84_E5_88_A9_E7_94_A8_E6_8A_80_E6_9C_AF_E5_88_86_E6_9E_90_pdf/index.pdf)
- [MSSQL不使用xp_cmdshell执行命令并获取回显的两种方法](https://zhuanlan.zhihu.com/p/33322584)

**PostgreSQL**

- [postgresql数据库利用方式 ](https://mp.weixin.qq.com/s?__biz=MzI5MDQ2NjExOQ==&mid=2247484788&idx=1&sn=8a53b1c64d864cd01bab095d97a17715&chksm=ec1e355cdb69bc4a2535bc1a053bfde3ec1838d03936ba8e44156818e91bbec9b5b04a744005#rd)
- [PostgreSQL渗透测试指南](https://www.anquanke.com/post/id/86468)
- [渗透中利用postgresql getshell ](http://www.jianfensec.com/postgresql_getshell.html)

**MongoDB**

- [十分钟看懂MongoDB攻防实战](http://www.freebuf.com/articles/database/148823.html)
- [MongoDB安全 – PHP注入检测](http://www.mottoin.com/94341.html)
- [技术分享：如何Hacking MongoDB？](https://www.freebuf.com/articles/network/101494.html)
- [MongoDB安全，php中的注入攻击](https://www.anquanke.com/post/id/84009)
- [一个MongoDB注入攻击案例分析](https://www.freebuf.com/articles/web/106085.html)

**技巧**

- [我的WafBypass之道（SQL注入篇）](https://xz.aliyun.com/t/368)
- [Bypass 360主机卫士SQL注入防御](http://www.cnblogs.com/xiaozi/p/7275134.html)
- [SQL注入之骚姿势小记](https://mp.weixin.qq.com/s/ORsciwsBGQJhFdKqceprSw)
- [CTF比赛中SQL注入的一些经验总结 ](http://www.freebuf.com/articles/web/137094.html)
- [如何绕过WAF/NGWAF的libinjection实现SQL注入](http://bobao.360.cn/learning/detail/3855.html)
- [HackMe-SQL-Injection-Challenges](https://github.com/breakthenet/HackMe-SQL-Injection-Challenges)
- [绕过WAF注入](https://bbs.ichunqiu.com/thread-25397-1-1.html?from=sec)
- [bypassGET和POST的注入防御思路分享](https://bbs.ichunqiu.com/thread-16134-1-1.html?from=sec)
- [SQL注入的常规思路及奇葩技巧 ](https://mp.weixin.qq.com/s/hBkJ1M6LRgssNyQyati1ng)
- [Beyond SQLi: Obfuscate and Bypass](https://www.exploit-db.com/papers/17934/)
- [Dnslog在SQL注入中的实战](https://www.anquanke.com/post/id/98096)
- [SQL注入：如何通过Python CGIHTTPServer绕过CSRF tokens](https://www.anquanke.com/post/id/87022)
- [BypassD盾IIS防火墙SQL注入防御（多姿势）](https://xz.aliyun.com/t/40)

**工具**

- [sqlmap自带的tamper你了解多少？ ](https://mp.weixin.qq.com/s/vEEoMacmETUA4yZODY8xMQ)
- [sqlmap的使用 ---- 自带绕过脚本tamper](https://xz.aliyun.com/t/2746)
- [使用burp macros和sqlmap绕过csrf防护进行sql注入](http://bobao.360.cn/learning/detail/3557.html)
- [sqlmap 使用总结 ](http://www.zerokeeper.com/web-security/sqlmap-usage-summary.html)
- [SQLmap tamper脚本注释](http://www.lengbaikai.net/?p=110)
- [通过Burp以及自定义的Sqlmap Tamper进行二次SQL注入](http://www.4hou.com/system/6945.html)
- [SQLMAP  JSON格式检测](https://xz.aliyun.com/t/1091)
- [记一份SQLmap使用手册小结（一）](https://xz.aliyun.com/t/3010)
- [记一份SQLmap使用手册小结（二）](https://xz.aliyun.com/t/3011)

### XSS跨站脚本攻击

- [漫谈同源策略攻防](https://www.anquanke.com/post/id/86078)
- [再谈同源策略 ](https://lightless.me/archives/review-SOP.html)
- [跨域方法总结](https://xz.aliyun.com/t/224)
- [前端安全系列（一）：如何防止XSS攻击？](https://segmentfault.com/a/1190000016551188)
- [浅谈跨站脚本攻击与防御 ](http://thief.one/2017/05/31/1/)
- [跨站的艺术-XSS入门与介绍](http://www.fooying.com/the-art-of-xss-1-introduction/)
- [DOMXSS Wiki](https://github.com/wisec/domxsswiki/wiki)
- [XSS Bypass Cookbook](https://xz.aliyun.com/t/311)
- [Content Security Policy 入门教程](https://jaq.alibaba.com/community/art/show?spm=a313e.7916646.24000001.49.ZP8rXN&articleid=518)
- [从瑞士军刀到变形金刚--XSS攻击面拓展](https://xz.aliyun.com/t/96)
- [前端防御从入门到弃坑--CSP变迁](https://paper.seebug.org/423/)
- [严格 CSP 下的几种有趣的思路（34c3 CTF）](http://www.melodia.pw/?p=935)
- [Bypassing CSP using polyglot JPEGs ](http://blog.portswigger.net/2016/12/bypassing-csp-using-polyglot-jpegs.html)
- [Bypass unsafe-inline mode CSP](http://paper.seebug.org/91/)
- [Chrome XSS Auditor – SVG Bypass](https://brutelogic.com.br/blog/chrome-xss-auditor-svg-bypass/)
- [Cross site scripting payload for fuzzing](https://xianzhi.aliyun.com/forum/read/1704.html)
- [XSS Without Dots](https://markitzeroday.com/character-restrictions/xss/2017/07/26/xss-without-dots.html)
- [Alternative to Javascript Pseudo-Protocol](http://brutelogic.com.br/blog/alternative-javascript-pseudo-protocol/)
- [不常见的xss利用探索](http://docs.ioin.in/writeup/wps2015.org/_2016_06_27__E4_B8_8D_E5_B8_B8_E8_A7_81_E7_9A_84xss_E5_88_A9_E7_94_A8_E6_8E_A2_E7_B4_A2_/index.html)
- [XSS攻击另类玩法](https://bbs.ichunqiu.com/thread-25578-1-1.html?from=sec)
- [XSS易容术---bypass之编码混淆篇-辅助脚本编写](https://bbs.ichunqiu.com/thread-17500-1-1.html?from=sec)
- [Xssing Web With Unicodes](http://blog.rakeshmane.com/2017/08/xssing-web-part-2.html)
- [Electron hack —— 跨平台 XSS ](https://mp.weixin.qq.com/s?__biz=MzU2NjE2NjIxNg==&mid=2247483756&amp;idx=1&amp;sn=96ae19e53426d5088718b6d37996e700&source=41#wechat_redirect)
- [XSS without HTML: Client-Side Template Injection with AngularJS ](http://blog.portswigger.net/2016/01/xss-without-html-client-side-template.html)
- [Modern Alchemy: Turning XSS into RCE](https://blog.doyensec.com/2017/08/03/electron-framework-security.html)
- [先知XSS挑战赛 - L3m0n Writeup](https://xz.aliyun.com/t/83)
- [SheepSec: 7 Reflected Cross-site Scripting (XSS) Examples](http://sheepsec.com/blog/7-reflected-xss.html)
- [Browser's XSS Filter Bypass Cheat Sheet](https://github.com/masatokinugawa/filterbypass/wiki/Browser's-XSS-Filter-Bypass-Cheat-Sheet)
- [妙用JavaScript绕过XSS过滤](https://www.anquanke.com/post/id/86849)
- **XSS跨站脚本检测利用**
  - [XSS Awesome系列](https://github.com/UltimateHackers/AwesomeXSS )
  - [很全面的xss工具包与资料](http://www.xss-payloads.com)
  - [XSS 漏洞Payload列表](https://github.com/ismailtasdelen/xss-payload-list)
  - [经典的xss利用框架](https://github.com/beefproject/beef)
  - [类似beef的xss利用框架](https://github.com/samdenty99/injectify)
  - [蓝莲花战队为CTF打造的xss利用框架](https://github.com/firesunCN/BlueLotus_XSSReceiver)
  - [根据特定标签生成xss payload](https://github.com/NytroRST/XSSFuzzer)
  - [余弦写的xss利用辅助工具](https://github.com/evilcos/xssor2)
  - [可识别并绕过WAF的XSS扫描工具](https://github.com/UltimateHackers/XSStrike)
  - [go,利用xss漏洞返回一个js交互shell](https://github.com/raz-varren/xsshell)
  - [利用xss漏洞返回一个js交互shell](https://github.com/UltimateHackers/JShell)
  - [一款XSS扫描器,可暴力注入参数](https://github.com/shawarkhanethicalhacker/BruteXSS)
  - [小型XSS扫描器,也可检测CRLF、XSS、点击劫持的](https://github.com/1N3/XSSTracer)
  - [PHP版本的反射型xss扫描](https://github.com/0x584A/fuzzXssPHP)
  - [批量扫描XSS的python脚本](https://github.com/chuhades/xss_scan)
  - [自动化检测页面是否存在XSS和CSRF漏洞的浏览器插件](https://github.com/BlackHole1/autoFindXssAndCsrf)
  - [使用命令行进行XSS批量检测](https://github.com/shogunlab/shuriken)
  - [支持GET、POST方式的高效XSS扫描器](https://github.com/stamparm/DSXS)
  - [kali下无法使用的话，请下载正确的PhantomJS到目录thirdparty/phantomjs/Linux](https://github.com/bsmali4/xssfork)
  - [flash xss扫描](https://github.com/riusksk/FlashScanner)
  - [针对检测网站中的反射XSS](https://github.com/Damian89/xssfinder )
  - [自动化利用XSS入侵内网](https://github.com/BlackHole1/WebRtcXSS)

### CSRF跨站请求伪造

- [Wiping Out CSRF](https://medium.com/@jrozner/wiping-out-csrf-ded97ae7e83f)
- [CSRF攻击与防御](https://www.cnblogs.com/phpstudy2015-6/p/6771239.html)
- [用代码来细说Csrf漏洞危害以及防御](https://bbs.ichunqiu.com/thread-24127-1-1.html?from=sec)
- [Cookie-Form型CSRF防御机制的不足与反思](https://www.leavesongs.com/PENETRATION/think-about-cookie-form-csrf-protected.html)
- [关于JSON CSRF的一些思考](https://mp.weixin.qq.com/s?__biz=MzIzMTc1MjExOQ==&mid=2247484126&idx=1&sn=f437882b19bed8d99d0a00938accc0c8&chksm=e89e2a06dfe9a310506419467ada63bee80f10c32267d0b11ea7d1f5491c5afdb344c5dac74e&mpshare=1&scene=23&srcid=0614BOCQBHPjaS2IOtADI3PP#rd)
- [Exploiting JSON Cross Site Request Forgery (CSRF) using Flash](http://www.geekboy.ninja/blog/exploiting-json-cross-site-request-forgery-csrf-using-flash/)
- [浅谈Session机制及CSRF攻防 ](https://mp.weixin.qq.com/s/aID_N9bgq91EM26qVSVBXw)
- [CSRF 花式绕过Referer技巧](https://www.ohlinge.cn/web/csrf_referer.html)
- [各大SRC中的CSRF技巧](http://www.freebuf.com/column/151816.html)
- [白帽子挖洞—跨站请求伪造（CSRF）篇 ](http://www.freebuf.com/column/153543.html)
- [读取型CSRF-需要交互的内容劫持](https://bbs.ichunqiu.com/thread-36314-1-1.html)

#### 其他前端安全

- [HTML中，闭合优先的神奇标签 ](https://mp.weixin.qq.com/s?__biz=MzA4MDA1NDE3Mw==&mid=2647715481&idx=1&sn=a4d930d5a944a5a6c0361a3c6c57d3d5)
- [JavaScript Dangerous Functions (Part 1) - HTML Manipulation ](http://blog.blueclosure.com/2017/09/javascript-dangerous-functions-part-1.html)
- [safari本地文件读取漏洞之扩展攻击面](http://www.wupco.cn/?p=4134)
- [利用脚本注入漏洞攻击ReactJS应用程序](http://www.freebuf.com/articles/web/144988.html)
- [当代 Web 的 JSON 劫持技巧](http://paper.seebug.org/130/?from=timeline&isappinstalled=0)
- [从微信小程序看前端代码安全](https://share.whuboy.com/weapp.html)

### SSRF服务器端请求伪造

- [SSRF安全指北](https://mp.weixin.qq.com/s/EYVFHgNClgNGrk_92PZ90A)
- [SSRF:CVE-2017-9993 FFmpeg - AVI - HLS](https://hackmd.io/p/H1B9zOg_W#)
- [SSRF（服务器端请求伪造）测试资源](https://paper.seebug.org/393/)
- [Build Your SSRF Exploit Framework SSRF](http://docs.ioin.in/writeup/fuzz.wuyun.org/_src_build_your_ssrf_exp_autowork_pdf/index.pdf)
- [SSRF攻击实例解析](http://www.freebuf.com/articles/web/20407.html)
- [SSRF漏洞分析与利用](http://www.4o4notfound.org/index.php/archives/33/)
- [SSRF漏洞的挖掘经验](https://www.secpulse.com/archives/4747.html)
- [SSRF漏洞的利用与学习](http://uknowsec.cn/posts/notes/SSRF%E6%BC%8F%E6%B4%9E%E7%9A%84%E5%88%A9%E7%94%A8%E4%B8%8E%E5%AD%A6%E4%B9%A0.html)
- [SSRF漏洞中绕过IP限制的几种方法总结](http://www.freebuf.com/articles/web/135342.html)
- [利用ssrf漏洞获取google内部的dns信息](http://bobao.360.cn/learning/detail/3566.html)
- [What is Server Side Request Forgery (SSRF)?](https://www.acunetix.com/blog/articles/server-side-request-forgery-vulnerability/)
- [Use DNS Rebinding to Bypass SSRF in Java](https://mp.weixin.qq.com/s?__biz=MzIzOTQ5NjUzOQ==&mid=2247483742&idx=1&sn=e7265d5351a6d9ed30d90be1c17be041)
- [SSRF in JAVA](https://xianzhi.aliyun.com/forum/topic/1712/)
- [DNS Rebinding技术绕过SSRF/代理IP限制](http://www.mottoin.com/95734.html)
- [Discuz ssrf漏洞利用的几个python脚本](https://phpinfo.me/2017/02/23/1438.html)
- [Discuz X系列门户文章功能SSRF漏洞挖掘与分析](http://bobao.360.cn/learning/detail/2889.html)
- [SSRF to GET SHELL](http://blog.feei.cn/ssrf/)
- [SSRF Tips](http://blog.safebuff.com/2016/07/03/SSRF-Tips/)

### XXE(xml外部实体注入)

- [一篇文章带你深入理解漏洞之 XXE 漏洞](https://xz.aliyun.com/t/3357)
- [PHP与JAVA之XXE漏洞详解与审计](https://xz.aliyun.com/t/6829#toc-1)
- [浅谈XXE漏洞攻击与防御](http://thief.one/2017/06/20/1/)
- [XXE漏洞分析](http://www.4o4notfound.org/index.php/archives/29/)
- [XML实体注入漏洞攻与防](http://www.hackersb.cn/hacker/211.html)
- [XML实体注入漏洞的利用与学习](http://uknowsec.cn/posts/notes/XML%E5%AE%9E%E4%BD%93%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E%E7%9A%84%E5%88%A9%E7%94%A8%E4%B8%8E%E5%AD%A6%E4%B9%A0.html)
- [XXE注入:攻击与防御 - XXE Injection: Attack and Prevent](http://le4f.net/post/xxe-injection-attack_and_prevent)
- [XXE (XML External Entity Injection) 漏洞实践](http://www.mottoin.com/101806.html)
- [黑夜的猎杀-盲打XXE](https://xianzhi.aliyun.com/forum/read/1837.html)
- [Hunting in the Dark - Blind XXE](https://blog.zsec.uk/blind-xxe-learning/)
- [XMLExternal Entity漏洞培训模块](https://www.sans.org/freading-room/whitepapers/application/hands-on-xml-external-entity-vulnerability-training-module-34397)
- [如何挖掘Uber网站的XXE注入漏洞](http://www.mottoin.com/86853.html)
- [XXE被提起时我们会想到什么](http://www.mottoin.com/88085.html)
- [XXE漏洞的简单理解和测试](http://www.mottoin.com/92794.html)
- [XXE漏洞攻防之我见](http://bobao.360.cn/learning/detail/3841.html)
- [XXE漏洞利用的一些技巧](http://www.91ri.org/17052.html)
- [神奇的Content-Type——在JSON中玩转XXE攻击](http://bobao.360.cn/learning/detail/360.html)
- [XXE-DTD Cheat Sheet](https://web-in-security.blogspot.jp/2016/03/xxe-cheat-sheet.html)
- [XML? Be cautious!](https://blog.pragmatists.com/xml-be-cautious-69a981fdc56a)
- [XSLT Server Side Injection Attacks](https://www.contextis.com/blog/xslt-server-side-injection-attacks)
- [Java XXE Vulnerability](https://joychou.org/web/java-xxe-vulnerability.html)
- [xml-attacks.md](https://gist.github.com/mgeeky/4f726d3b374f0a34267d4f19c9004870)

### JSONP注入

- [JSONP注入解析 ](http://www.freebuf.com/articles/web/126347.html)
- [JSONP 安全攻防技术](http://blog.knownsec.com/2015/03/jsonp_security_technic/)
- [一次关于JSONP的小实验与总结](http://www.cnblogs.com/vimsk/archive/2013/01/29/2877888.html)
- [利用JSONP跨域获取信息](https://xianzhi.aliyun.com/forum/read/1571.html)
- [关于跨域和jsonp的一些理解(新手向)](https://segmentfault.com/a/1190000009577990)
- [水坑攻击之Jsonp hijacking-信息劫持](http://www.mottoin.com/88237.html)

### SSTI服务器模板注入

- [Jinja2 template injection filter bypasses](https://0day.work/jinja2-template-injection-filter-bypasses/)
- [乱弹Flask注入](http://www.freebuf.com/articles/web/88768.html)
- [服务端模板注入攻击 （SSTI）之浅析 ](http://www.freebuf.com/vuls/83999.html)
- [Exploring SSTI in Flask/Jinja2](https://nvisium.com/blog/2016/03/09/exploring-ssti-in-flask-jinja2/)
- [Flask Jinja2开发中遇到的的服务端注入问题研究](http://www.freebuf.com/articles/web/136118.html)
- [FlaskJinja2 开发中遇到的的服务端注入问题研究 II](http://www.freebuf.com/articles/web/136180.html)
- [Exploring SSTI in Flask/Jinja2, Part II](https://nvisium.com/blog/2016/03/11/exploring-ssti-in-flask-jinja2-part-ii/)
- [Injecting Flask](https://nvisium.com/blog/2015/12/07/injecting-flask/)
- [Server-Side Template Injection: RCE for the modern webapp](https://www.blackhat.com/docs/us-15/materials/us-15-Kettle-Server-Side-Template-Injection-RCE-For-The-Modern-Web-App-wp.pdf)
- [Exploiting Python Code Injection in Web Applications](https://sethsec.blogspot.jp/2016/11/exploiting-python-code-injection-in-web.html)
- [利用 Python 特性在 Jinja2 模板中执行任意代码](http://rickgray.me/2016/02/24/use-python-features-to-execute-arbitrary-codes-in-jinja2-templates.html)
- [Python 模板字符串与模板注入](https://virusdefender.net/index.php/archives/761/)
- [Ruby ERB Template Injection](https://www.trustedsec.com/2017/09/rubyerb-template-injection/)
- [服务端模板注入攻击](https://zhuanlan.zhihu.com/p/28823933)

### 代码执行 / 命令执行

- [从PHP源码与扩展开发谈PHP任意代码执行与防御](https://blog.zsxsoft.com/post/30)
- [Command Injection/Shell Injection](https://www.exploit-db.com/docs/42593.pdf)
- [PHP Code Injection Analysis](http://www.polaris-lab.com/index.php/archives/254/)
- [	利用环境变量LD_PRELOAD来绕过php disable_function执行系统命令](http://doc.ph0en1x.com/wooyun_drops/%E5%88%A9%E7%94%A8%E7%8E%AF%E5%A2%83%E5%8F%98%E9%87%8FLD_PRELOAD%E6%9D%A5%E7%BB%95%E8%BF%87php%20disable_function%E6%89%A7%E8%A1%8C%E7%B3%BB%E7%BB%9F%E5%91%BD%E4%BB%A4.html)
- [Hack PHP mail additional_parameters](http://blog.nsfocus.net/hack-php-mail-additional_parameters/)
- [详细解析PHP mail()函数漏洞利用技巧](http://bobao.360.cn/learning/detail/3818.html)
- [在PHP应用程序开发中不正当使用mail()函数引发的血案](http://bobao.360.cn/learning/detail/3809.html)
- [BigTree CMS - Bypass CSRF filter and execute code with PHPMailer](https://www.cdxy.me/?p=765)
- [基于时间反馈的RCE](http://www.mottoin.com/97678.html)
- [正则表达式使用不当引发的系统命令执行漏洞](http://bobao.360.cn/learning/detail/3609.html)
- [命令注入突破长度限制 ](http://www.freebuf.com/articles/web/154453.html)

### 文件包含

- [php文件包含漏洞 ](https://chybeta.github.io/2017/10/08/php%E6%96%87%E4%BB%B6%E5%8C%85%E5%90%AB%E6%BC%8F%E6%B4%9E/)
- [Turning LFI into RFI](https://l.avala.mp/?p=241)
- [PHP文件包含漏洞总结](http://wooyun.jozxing.cc/static/drops/tips-3827.html)
- [常见文件包含发生场景与防御](http://bobao.360.cn/learning/detail/3873.html)
- [基于云端的本地文件包含漏洞](http://bobao.360.cn/learning/detail/3871.html)
- [zip或phar协议包含文件](https://bl4ck.in/tricks/2015/06/10/zip%E6%88%96phar%E5%8D%8F%E8%AE%AE%E5%8C%85%E5%90%AB%E6%96%87%E4%BB%B6.html)
- [文件包含漏洞 一](http://drops.blbana.cc/2016/08/12/e6-96-87-e4-bb-b6-e5-8c-85-e5-90-ab-e6-bc-8f-e6-b4-9e/)
- [文件包含漏洞 二](http://drops.blbana.cc/2016/12/03/e6-96-87-e4-bb-b6-e5-8c-85-e5-90-ab-e6-bc-8f-e6-b4-9e-ef-bc-88-e4-ba-8c-ef-bc-89/)

### 文件上传 / 解析漏洞

- [文件上传和WAF的攻与防](https://www.secfree.com/article-585.html)
- [我的WafBypass之道（upload篇）](https://xianzhi.aliyun.com/forum/read/458.html)
- [文件上传漏洞（绕过姿势） ](http://thief.one/2016/09/22/%E4%B8%8A%E4%BC%A0%E6%9C%A8%E9%A9%AC%E5%A7%BF%E5%8A%BF%E6%B1%87%E6%80%BB-%E6%AC%A2%E8%BF%8E%E8%A1%A5%E5%85%85/)
- [服务器解析漏洞 ](http://thief.one/2016/09/21/%E6%9C%8D%E5%8A%A1%E5%99%A8%E8%A7%A3%E6%9E%90%E6%BC%8F%E6%B4%9E/)
- [文件上传总结 ](https://masterxsec.github.io/2017/04/26/%E6%96%87%E4%BB%B6%E4%B8%8A%E4%BC%A0%E6%80%BB%E7%BB%93/)
- [文件上传绕过姿势总结](http://www.cnnetarmy.com/%E6%96%87%E4%BB%B6%E4%B8%8A%E4%BC%A0%E7%BB%95%E8%BF%87%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93/)
- [尽最大可能分析上传源码及漏洞利用方式](https://www.hackfun.org/pentest/make-the-most-possible-analysis-of-the-source-code-and-exploit-the-vulnerability.html)
- [从XSSer的角度测试上传文件功能](https://xianzhi.aliyun.com/forum/read/224.html)
- [代码审计之逻辑上传漏洞挖掘](http://wooyun.jozxing.cc/static/drops/papers-1957.html)
- [渗透测试方法论之文件上传](https://bbs.ichunqiu.com/thread-23193-1-1.html?from=sec)
- [关于文件名解析的一些探索](https://landgrey.me/filetype-parsing-attack/)
- [Web安全 — 上传漏洞绕过 ](http://www.freebuf.com/column/161357.html)

### 逻辑漏洞

- [A couple more common OAuth 2.0 vulnerabilities ](https://blog.avuln.com/article/4)
- [代码审计之逻辑上传漏洞挖掘](http://wooyun.jozxing.cc/static/drops/papers-1957.html)
- [逻辑至上——内含各种酷炫姿势](http://bobao.360.cn/learning/detail/3769.html)
- [Web安全测试中常见逻辑漏洞解析（实战篇）](http://www.freebuf.com/vuls/112339.html)
- [逻辑漏洞之密码重置 ](https://mp.weixin.qq.com/s/Lynmqd_ieEoNJ3mmyv9eQQ)
- [逻辑漏洞之支付漏洞](https://mp.weixin.qq.com/s/w22omfxO8vU6XzixXWmBxg)
- [逻辑漏洞之越权访问](https://mp.weixin.qq.com/s/ChiXtcrEyQeLkGOkm4PTog)
- [密码找回逻辑漏洞总结](http://wooyun.jozxing.cc/static/drops/web-5048.html)
- [一些常见的重置密码漏洞分析整理](http://wooyun.jozxing.cc/static/drops/papers-2035.html)
- [密码逻辑漏洞小总结](http://docs.ioin.in/writeup/blog.heysec.org/_archives_643/index.html)
- [漏洞挖掘之逻辑漏洞挖掘](https://bbs.ichunqiu.com/thread-21161-1-1.html)
- [tom0li: 逻辑漏洞小结](https://tom0li.github.io/2017/07/17/%E9%80%BB%E8%BE%91%E6%BC%8F%E6%B4%9E%E5%B0%8F%E7%BB%93/)

### PHP相关

**弱类型**

- [从弱类型利用以及对象注入到SQL注入](http://bobao.360.cn/learning/detail/3486.html)
- [PHP中“＝＝”运算符的安全问题](http://bobao.360.cn/learning/detail/2924.html)
- [PHP弱类型安全问题总结 ](http://blog.spoock.com/2016/06/25/weakly-typed-security/)
- [浅谈PHP弱类型安全](http://wooyun.jozxing.cc/static/drops/tips-4483.html)
- [php比较操作符的安全问题](http://wooyun.jozxing.cc/static/drops/tips-7679.html)

**随机数问题**

- [PHP mt_rand()随机数安全 ](https://mp.weixin.qq.com/s/3TgBKXHw3MC61qIYELanJg)
- [Cracking PHP rand()](http://www.sjoerdlangkemper.nl/2016/02/11/cracking-php-rand/)
- [php里的随机数](http://5alt.me/2017/06/php%E9%87%8C%E7%9A%84%E9%9A%8F%E6%9C%BA%E6%95%B0/)
- [php_mt_seed - PHP mt_rand() seed cracker](http://www.openwall.com/php_mt_seed/)
- [The GLIBC random number generator](http://www.mscs.dal.ca/~selinger/random/)
- [一道伪随机数的CTF题](https://github.com/wonderkun/CTF_web/blob/master/web500-2/writeup.pdf)

**伪协议**

- [谈一谈php://filter的妙用](www.leavesongs.com/PENETRATION/php-filter-magic.html)
- [php 伪协议](http://lorexxar.cn/2016/09/14/php-wei/)
- [利用 Gopher 协议拓展攻击面](https://blog.chaitin.cn/gopher-attack-surfaces/)
- [PHP伪协议之 Phar 协议（绕过包含）](https://www.bodkin.ren/?p=902)
- [PHP伪协议分析与应用](http://www.4o4notfound.org/index.php/archives/31/)
- [LFI、RFI、PHP封装协议安全问题学习](http://www.cnblogs.com/LittleHann/p/3665062.html)

**序列化**

- [PHP反序列化漏洞](http://bobao.360.cn/learning/detail/4122.html)
- [浅谈php反序列化漏洞 ](https://chybeta.github.io/2017/06/17/%E6%B5%85%E8%B0%88php%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/)
- [PHP反序列化漏洞成因及漏洞挖掘技巧与案例](http://bobao.360.cn/learning/detail/3193.html)

**php代码审计**

- [PHP漏洞挖掘——进阶篇](http://blog.nsfocus.net/php-vulnerability-mining/)
- [论PHP常见的漏洞](http://wooyun.jozxing.cc/static/drops/papers-4544.html)
- [浅谈代码审计入门实战：某博客系统最新版审计之旅 ](http://www.freebuf.com/articles/rookie/143554.html)
- [ctf中的php代码审计技巧](http://www.am0s.com/ctf/200.html)
- [PHP代码审计tips](http://docs.ioin.in/writeup/www.91ri.org/_15074_html/index.html)
- [代码审计之文件越权和文件上传搜索技巧](http://docs.ioin.in/writeup/blog.heysec.org/_archives_170/index.html)
- [PHP代码审计入门集合](http://wiki.ioin.in/post/group/6Rb)
- [PHP代码审计学习](http://phantom0301.cc/2017/06/06/codeaudit/)
- [PHP漏洞挖掘思路-实例](http://wooyun.jozxing.cc/static/drops/tips-838.html)
- [PHP漏洞挖掘思路-实例 第二章](http://wooyun.jozxing.cc/static/drops/tips-858.html)
- [浅谈代码审计入门实战：某博客系统最新版审计之旅 ](http://www.freebuf.com/articles/rookie/143554.html)
- [PHP 代码审计小结 (一) ](https://www.chery666.cn/blog/2017/12/11/Code-audit.html)
- [2018 PHP 应用程序安全设计指北 ](https://laravel-china.org/articles/7235/2018-php-application-security-design)

**php mail header injection**

- [What is Email Header Injection?](https://www.acunetix.com/blog/articles/email-header-injection/)
- [PHP Email Injection Example](http://resources.infosecinstitute.com/email-injection/)

**其他**

- [对于Php Shell Bypass思路总结](https://www.inksec.cn/2017/11/06/bypass_shell_4/)
- [Decrypt PHP's eval based encryption with debugger ](https://mp.weixin.qq.com/s?__biz=MzIxNjU3ODMyOQ==&mid=2247483693&idx=1&sn=ed49fc13d8e09f12d87675adff18919f)
- [Upgrade from LFI to RCE via PHP Sessions](https://www.rcesecurity.com/2017/08/from-lfi-to-rce-via-php-sessions/)
- [Xdebug: A Tiny Attack Surface](https://ricterz.me/posts/Xdebug%3A%20A%20Tiny%20Attack%20Surface)
- [Exploitable PHP functions](https://stackoverflow.com/questions/3115559/exploitable-php-functions)
- [从WordPress SQLi谈PHP格式化字符串问题](https://paper.seebug.org/386/)
- [php & apache2 &操作系统之间的一些黑魔法](http://wonderkun.cc/index.html/?p=626)
- [php内存破坏漏洞exp编写和禁用函数绕过](http://blog.th3s3v3n.xyz/2016/05/01/bin/2016-5-1-php%E5%86%85%E5%AD%98%E7%A0%B4%E5%9D%8F%E6%BC%8F%E6%B4%9Eexp%E7%BC%96%E5%86%99%E5%92%8C%E7%A6%81%E7%94%A8%E5%87%BD%E6%95%B0%E7%BB%95%E8%BF%87/)
- [挖掘PHP禁用函数绕过利用姿势](http://blog.th3s3v3n.xyz/2016/11/20/web/%E6%8C%96%E6%8E%98PHP%E7%A6%81%E7%94%A8%E5%87%BD%E6%95%B0%E7%BB%95%E8%BF%87%E5%88%A9%E7%94%A8%E5%A7%BF%E5%8A%BF/)
- [.user.ini文件构成的PHP后门](http://wooyun.jozxing.cc/static/drops/tips-3424.html)

### CORS漏洞

- [cors安全完全指南](https://xz.aliyun.com/t/2745)

### DDOS

- [DDoS攻防补遗](https://yq.aliyun.com/articles/1795)
- [反射DDOS攻击防御的一点小想法 ](http://www.freebuf.com/column/138163.html)
- [DDOS攻击方式总结](https://www.secpulse.com/archives/64088.html	)
- [DDoS防御和DDoS防护方法 你帮忙看看这7个说法靠不靠谱](http://toutiao.secjia.com/ddos-7tips)
- [DDoS防御和DDoS防护 来看个人站长、果壳网和安全公司怎么说 ](http://toutiao.secjia.com/ddos-prevention-protection)
- [DDoS防御之大流量DDoS防护方案 还有计算器估算损失](http://toutiao.secjia.com/ddos-prevention-protection-2)
- [freeBuf专栏 ](http://www.freebuf.com/author/%e9%bb%91%e6%88%88%e7%88%be)
- [遭受CC攻击的处理](http://www.xuxiaobo.com/?p=3923)

### 其他漏洞

- API安全测试
  - [API安全测试31个Tips](https://github.com/inonshk/31-days-of-API-Security-Tips)

- CDN2021完全攻击指南
  - [CDN 2021 完全攻击指南 （一）](https://www.anquanke.com/post/id/227818)
  - [CDN 2021 完全攻击指南 （二）](https://www.anquanke.com/post/id/231437)
  - [CDN 2021 完全攻击指南 （三）](https://www.anquanke.com/post/id/231441)
  - https://github.com/bin-maker/2021CDN/

-  RPO(relative path overwrite)
   - [初探 Relative Path Overwrite](https://xianzhi.aliyun.com/forum/read/1527.html?fpage=2)
   - [Detecting and exploiting path-relative stylesheet import (PRSSI) vulnerabilities](http://blog.portswigger.net/2015/02/prssi.html)
   - [RPO](http://www.thespanner.co.uk/2014/03/21/rpo/)
   - [A few RPO exploitation techniques](http://www.mbsd.jp/Whitepaper/rpo.pdf)

-   Web Cache
    - [浅析 Web Cache 欺骗攻击](http://bobao.360.cn/learning/detail/3828.html)

-  redis
   - [利用redis写webshell](https://www.leavesongs.com/PENETRATION/write-webshell-via-redis-server.html)
   - [Redis 未授权访问配合 SSH key 文件利用分析](http://blog.knownsec.com/2015/11/analysis-of-redis-unauthorized-of-expolit/)
   - [redis未授权访问漏洞利用总结](https://xianzhi.aliyun.com/forum/read/750.html)。
   - [【应急响应】redis未授权访问致远程植入挖矿脚本（防御篇） ](https://mp.weixin.qq.com/s/eUTZsGUGSO0AeBUaxq4Q2w)

- [Web之困笔记](http://www.au1ge.xyz/2017/08/09/web%E4%B9%8B%E5%9B%B0%E7%AC%94%E8%AE%B0/)
- [常见Web源码泄露总结](http://www.mottoin.com/95749.html)
- [Github信息泄露升级版案例](http://www.ms509.com/?p=718)
- [Hacking iSCSI](https://ricterz.me/posts/Hacking%20iSCSI)
- [技术详解：基于Web的LDAP注入漏洞](http://www.4hou.com/technology/9090.html)
- [未授权访问漏洞总结](https://www.secpulse.com/archives/61101.html)
- [未授权访问漏洞的检测与利用 ](https://thief.one/2017/12/08/1/)

### SRC漏洞挖掘

- [SRC漏洞挖掘实用技巧](https://xz.aliyun.com/t/6155)
- [业务漏洞挖掘笔记](https://xz.aliyun.com/t/9028)
- [一个有趣的任意密码重置](https://legoc.github.io/2020/07/07/%E4%B8%80%E4%B8%AA%E6%9C%89%E8%B6%A3%E7%9A%84%E4%BB%BB%E6%84%8F%E5%AF%86%E7%A0%81%E9%87%8D%E7%BD%AE/)
- [记一次短信验证码的"梅开五度"](https://xz.aliyun.com/t/8974)
- [挖洞经验 | 看我如何综合利用4个漏洞实现GitHub Enterprise远程代码执行 ](http://www.freebuf.com/news/142680.html)
- [来自榜一的公益SRC挖掘思路分享](https://www.freebuf.com/articles/web/265782.html)

## 安全测试

- [Web Service 渗透测试从入门到精通](http://bobao.360.cn/learning/detail/3741.html)
- [渗透标准](https://www.processon.com/view/583e8834e4b08e31357bb727)
- [Penetration Testing Tools Cheat Sheet](https://highon.coffee/blog/penetration-testing-tools-cheat-sheet/)

### 信息收集

- [OneForAll一款功能强大的子域名收集工具](https://github.com/shmilylty/OneForAll)
- [看我如何收集全网IP的whois信息 ](https://mp.weixin.qq.com/s/qz0b42DKhgo1sfitcUKhtQ)
- [浅谈Web渗透测试中的信息收集 ](http://www.freebuf.com/articles/web/142767.html)
- [渗透测试教程：如何侦查目标以及收集信息？](http://www.4hou.com/penetration/6850.html)
- [本屌的web漏洞扫描器思路 技巧总结（域名信息收集篇）](weibo.com/ttarticle/p/show?id=2309404088584863883789)
- [子域名的艺术](http://www.91ri.org/17001.html)
- [渗透测试向导之子域名枚举技术](http://www.freebuf.com/articles/network/161046.html)
- [实例演示如何科学的进行子域名收集](http://bobao.360.cn/learning/detail/4119.html)
- [【渗透神器系列】搜索引擎 ](http://thief.one/2017/05/19/1/)
- [域渗透基础简单信息收集（基础篇）](https://xianzhi.aliyun.com/forum/read/805.html)
- [内网渗透定位技术总结](http://docs.ioin.in/writeup/www.mottoin.com/_92978_html/index.html)
- [后渗透攻防的信息收集](https://www.secpulse.com/archives/51527.html)
- [安全攻城师系列文章－敏感信息收集](http://www.mottoin.com/99951.html)
- [子域名枚举的艺术](http://www.mottoin.com/101362.html)
- [论二级域名收集的各种姿势](https://mp.weixin.qq.com/s/ardCYdZzaSjvSIZiFraWGA)
- [我眼中的渗透测试信息搜集](https://xianzhi.aliyun.com/forum/read/451.html?fpage=2)
- [大型目标渗透－01入侵信息搜集](https://xianzhi.aliyun.com/forum/read/1675.html)
- [乙方渗透测试之信息收集](http://www.cnnetarmy.com/%E4%B9%99%E6%96%B9%E6%B8%97%E9%80%8F%E6%B5%8B%E8%AF%95%E4%B9%8B%E4%BF%A1%E6%81%AF%E6%94%B6%E9%9B%86/)
- [挖洞技巧：信息泄露之总结](https://www.anquanke.com/post/id/94787)


### 渗透实战

- [Splash SSRF到获取内网服务器ROOT权限](http://bobao.360.cn/learning/detail/4113.html)
- [Pivoting from blind SSRF to RCE with HashiCorp Consul](http://www.kernelpicnic.net/2017/05/29/Pivoting-from-blind-SSRF-to-RCE-with-Hashicorp-Consul.html)
- [我是如何通过命令执行到最终获取内网Root权限的 ](http://www.freebuf.com/articles/web/141579.html)
- [信息收集之SVN源代码社工获取及渗透实战](https://xianzhi.aliyun.com/forum/read/1629.html)
- [SQL注入-XXE-文件遍历漏洞组合拳渗透Deutsche Telekom](http://paper.seebug.org/256/)
- [渗透 Hacking Team](http://blog.neargle.com/SecNewsBak/drops/%E6%B8%97%E9%80%8FHacking%20Team%E8%BF%87%E7%A8%8B.html)
- [由视频系统SQL注入到服务器权限](https://bbs.ichunqiu.com/thread-25827-1-1.html?from=sec)
- [From Serialized to Shell :: Exploiting Google Web Toolkit with EL Injection](http://srcincite.io/blog/2017/05/22/from-serialized-to-shell-auditing-google-web-toolkit-with-el-injection.html)
- [浅谈渗透测试实战](http://docs.ioin.in/writeup/avfisher.win/_archives_381/index.html)
- [渗透测试学习笔记之案例一](http://avfisher.win/archives/741)
- [渗透测试学习笔记之案例二](http://avfisher.win/archives/756)
- [渗透测试学习笔记之案例四](http://avfisher.win/archives/784)
- [记一次内网渗透](http://killbit.me/2017/09/11/%E8%AE%B0%E4%B8%80%E6%AC%A1%E5%86%85%E7%BD%91%E6%B8%97%E9%80%8F/)
- 钓鱼：
  - [剑指钓鱼基建自动化的想法](https://mp.weixin.qq.com/s/5ofJ6J1KVQIvVB3dZdIVng)
  - [钓鱼框架 —— gophish](http://leuk0cyte.com/2020/11/06/%E9%92%93%E9%B1%BC%E6%A1%86%E6%9E%B6%20%E2%80%94%E2%80%94%20gophish/#%E5%8A%9F%E8%83%BD%E4%BB%8B%E7%BB%8D)
  - [如何批量发送钓鱼邮箱](https://mp.weixin.qq.com/s/8U9Nbrg0jDnTvoWxY7hAdg)
  - [钓鱼演练踩坑笔记](https://mp.weixin.qq.com/s/6mTl8C7NmsyXtOObqTNQAw)

### 渗透技巧

- [域渗透知识总结](http://echocipher.life/index.php/archives/52/)
- [Powershell攻击指南----黑客后渗透之道](https://github.com/rootclay/Powershell-Attack-Guide)
- [乙方渗透测试之Fuzz爆破](http://www.cnnetarmy.com/%E4%B9%99%E6%96%B9%E6%B8%97%E9%80%8F%E6%B5%8B%E8%AF%95%E4%B9%8BFuzz%E7%88%86%E7%A0%B4/)
- [域渗透神器Empire安装和简单使用 ](https://mp.weixin.qq.com/s/VqrUTW9z-yi3LqNNy-lE-Q)
- [如何将简单的Shell转换成为完全交互式的TTY ](http://www.freebuf.com/news/142195.html)
- [Web端口复用正向后门研究实现与防御 ](http://www.freebuf.com/articles/web/142628.html)
- [谈谈端口探测的经验与原理](http://www.freebuf.com/articles/network/146087.html)
- [端口渗透总结](http://docs.ioin.in/writeup/blog.heysec.org/_archives_577/index.html)
- [端口扫描那些事](https://mp.weixin.qq.com/s?__biz=MzI5MDQ2NjExOQ==&mid=2247484812&idx=1&sn=7d894b50b3947142fbfa3a4016f748d5&chksm=ec1e35a4db69bcb2acfe7ecb3b0cd1d366c54bfa1feaafc62c4290b3fd2eddab9aa95a98f041#rd)
- [渗透技巧——通过cmd上传文件的N种方法 ](http://blog.neargle.com/SecNewsBak/drops/%E6%B8%97%E9%80%8F%E6%8A%80%E5%B7%A7%E2%80%94%E2%80%94%E9%80%9A%E8%BF%87cmd%E4%B8%8A%E4%BC%A0%E6%96%87%E4%BB%B6%E7%9A%84N%E7%A7%8D%E6%96%B9%E6%B3%95.html)
- [域渗透TIPS：获取LAPS管理员密码 ](http://www.freebuf.com/articles/web/142659.html)
- [域渗透——Security Support Provider](http://blog.neargle.com/SecNewsBak/drops/%E5%9F%9F%E6%B8%97%E9%80%8F%E2%80%94%E2%80%94Security%20Support%20Provider.html)
- [域渗透之流量劫持](http://bobao.360.cn/learning/detail/3266.html)
- [渗透技巧——快捷方式文件的参数隐藏技巧](https://3gstudent.github.io/3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%8A%80%E5%B7%A7-%E5%BF%AB%E6%8D%B7%E6%96%B9%E5%BC%8F%E6%96%87%E4%BB%B6%E7%9A%84%E5%8F%82%E6%95%B0%E9%9A%90%E8%97%8F%E6%8A%80%E5%B7%A7/)
- [后门整理](https://bbs.ichunqiu.com/thread-25119-1-1.html?from=sec)
- [Linux后门整理合集（脉搏推荐）](https://www.secpulse.com/archives/59674.html)
- [渗透测试指南之域用户组的范围](http://www.4hou.com/penetration/7016.html)
- [Linux 端口转发特征总结 ](https://mp.weixin.qq.com/s?__biz=MzA3Mzk1MDk1NA==&mid=2651903919&idx=1&sn=686cc53137aa9e8ec323dda1e54a2c23)
- [实战 SSH 端口转发](https://www.ibm.com/developerworks/cn/linux/l-cn-sshforward/index.html)
- [多重转发渗透隐藏内网](http://bobao.360.cn/learning/detail/3545.html)
- [Linux 下多种反弹 shell 方法](http://www.03sec.com/3140.shtml)
- [linux各种一句话反弹shell总结](http://bobao.360.cn/learning/detail/4551.html)
- [php 反弹shell](http://wolvez.club/?p=458)
- [Windows域横向渗透](http://docs.ioin.in/writeup/www.mottoin.com/_89413_html/index.html)
- [A Red Teamer's guide to pivoting](https://artkond.com/2017/03/23/pivoting-guide/)
- [穿越边界的姿势 ](https://mp.weixin.qq.com/s/l-0sWU4ijMOQWqRgsWcNFA)
- [Reverse Shell Cheat Sheet](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
- [牛逼牛逼的payload和bypass总结](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [addslashes防注入的绕过案例](https://xianzhi.aliyun.com/forum/read/753.html?fpage=6)
- [浅谈json参数解析对waf绕过的影响](https://xianzhi.aliyun.com/forum/read/553.html?fpage=8)
- [使用HTTP头去绕过WAF ](http://www.sohu.com/a/110066439_468673)
- [会找漏洞的时光机: Pinpointing Vulnerabilities](https://www.inforsec.org/wp/?p=1993)

#### 内网渗透

- [内网渗透（持续更新） ](http://rcoil.me/2017/06/%E5%86%85%E7%BD%91%E6%B8%97%E9%80%8F/)
- [我所了解的内网渗透——内网渗透知识大总结](https://www.anquanke.com/post/id/92646)
- [内网端口转发及穿透](https://xianzhi.aliyun.com/forum/read/1715.html)
- [内网渗透思路整理与工具使用](http://bobao.360.cn/learning/detail/3683.html)
- [内网渗透中转发工具总结](http://blog.neargle.com/SecNewsBak/drops/%E5%86%85%E7%BD%91%E6%B8%97%E9%80%8F%E4%B8%AD%E8%BD%AC%E5%8F%91%E5%B7%A5%E5%85%B7%E6%80%BB%E7%BB%93.html)
- [内网转发的工具](https://mp.weixin.qq.com/s/EWL9-AUB_bTf7pU4S4A2zg)
- [内网转发姿势](http://www.03sec.com/3141.shtml)
- [秘密渗透内网——利用 DNS 建立 VPN 传输隧道](http://www.4hou.com/technology/3143.html)
- [利用ew轻松穿透多级目标内网](https://klionsec.github.io/2017/08/05/ew-tunnel/)
- [windows内网渗透杂谈](https://bl4ck.in/penetration/2017/03/20/windows%E5%86%85%E7%BD%91%E6%B8%97%E9%80%8F%E6%9D%82%E8%B0%88.html)
- [内网渗透随想](http://docs.ioin.in/writeup/www.91ri.org/_14390_html/index.html)
- [内网渗透思路探索之新思路的探索与验证](http://www.tuicool.com/articles/fMFB3mY)
- [内网主机发现技巧补充](http://mp.weixin.qq.com/s/l-Avt72ajCIo5GdMEwVx7A)
- [玩转Linux系统】Linux内网渗透](https://mp.weixin.qq.com/s/VJBnXq3--0HBD7eVeifOKA)
- [Cobalt strike在内网渗透中的使用 ](http://www.freebuf.com/sectool/125237.html)
- [通过双重跳板漫游隔离内网](https://xianzhi.aliyun.com/forum/read/768.html)

#### WAF攻防

- [WAF攻防研究之四个层次Bypass WAF](http://weibo.com/ttarticle/p/show?id=2309404007261092631700)
- [详谈WAF与静态统计分析](http://bobao.360.cn/learning/detail/4670.html)
- [WAF绕过参考资料](http://www.mottoin.com/100887.html)
- [浅谈WAF绕过技巧](http://www.freebuf.com/articles/web/136723.html)
- [CRLF Injection and Bypass Tencent WAF ](https://zhchbin.github.io/2016/01/31/CRLF-Injection-and-Bypass-WAF/)

#### 无文件攻击

- [无文件攻击的各种姿势](https://www.freebuf.com/column/203131.html)
- [60字节 - 无文件渗透测试实验](https://www.n0tr00t.com/2017/03/09/penetration-test-without-file.html)

#### 提权

- [提权技巧](http://www.secbox.cn/skill/5583.html)
- [linux-kernel-exploits Linux平台提权漏洞集合](https://github.com/SecWiki/linux-kernel-exploits)
- [windows-kernel-exploits Windows平台提权漏洞集合 ](https://github.com/SecWiki/windows-kernel-exploits)
- [Linux MySQL Udf 提权](http://www.91ri.org/16540.html)
- [windows提权系列上篇](http://mp.weixin.qq.com/s/uOArxXIfcI4fjqnF9BDJGA)
- [Windows提权系列中篇](https://mp.weixin.qq.com/s/ERXOLhWo0-lJbMV143I8hA)
- [获取SYSTEM权限的多种姿势](http://bobao.360.cn/learning/detail/4740.html)

## 安全运维

- [安全运维那些洞 ](https://mp.weixin.qq.com/s/5TfAF5-HR8iDA_qSIJkQ0Q)
- [美团外卖自动化业务运维系统建设](https://tech.meituan.com/digger_share.html)
- [饿了么运维基础设施进化史 ](https://mp.weixin.qq.com/s?__biz=MzA4Nzg5Nzc5OA==&mid=2651668800&idx=1&sn=615af5f120d1298475aaf4825009cb30&chksm=8bcb82e9bcbc0bff6309d9bbaf69cfc591624206b846e00d5004a68182c934dab921b7c25794&scene=38#wechat_redirect)
- [nginx配置一篇足矣](http://www.xuxiaobo.com/?p=3869)
- [Docker Remote API的安全配置 ](http://p0sec.net/index.php/archives/115/)
- [Apache服务器安全配置 ](http://foreversong.cn/archives/789)
- [IIS服务器安全配置](http://foreversong.cn/archives/803)
- [Tomcat服务器安全配置](http://foreversong.cn/archives/816)
- [互联网企业安全之端口监控 ](https://mp.weixin.qq.com/s/SJKeXegWG3OQo4r0nBs7xQ)
- [Linux应急响应姿势浅谈](http://bobao.360.cn/learning/detail/4481.html)
- [黑客入侵应急分析手工排查](https://xianzhi.aliyun.com/forum/read/1655.html)
- [企业常见服务漏洞检测&修复整理](http://www.mottoin.com/92742.html)
- [Linux基线加固](https://mp.weixin.qq.com/s/0nxiZw1NUoQTjxcd3zl6Zg)
- [Apache server security: 10 tips to secure installation](https://www.acunetix.com/blog/articles/10-tips-secure-apache-installation/)
- [Oracle数据库运维中的攻防实战（全） ](https://mp.weixin.qq.com/s/dpvBo6Bat5u4t8kSFRcv9w)
- [Linux服务器上监控网络带宽的18个常用命令](http://www.xuxiaobo.com/?p=3950)

## Others

### RASP

- [腾讯：RASP攻防 —— RASP安全应用与局限性浅析](https://security.tencent.com/index.php/blog/msg/166)
- [从0开始的PHP RASP的学习](https://xz.aliyun.com/t/7316)
- [一类PHP RASP的实现](https://c0d3p1ut0s.github.io/%E4%B8%80%E7%B1%BBPHP-RASP%E7%9A%84%E5%AE%9E%E7%8E%B0/)
- [鸟哥：taint](https://github.com/laruence/taint)


### other
- [细致分析Padding Oracle渗透测试全解析 ](http://www.freebuf.com/articles/database/150606.html)
- [Exploring Compilation from TypeScript to WebAssembly](https://medium.com/web-on-the-edge/exploring-compilation-from-typescript-to-webassembly-f846d6befc12)
- [High-Level Approaches for Finding Vulnerabilities](http://jackson.thuraisamy.me/finding-vulnerabilities.html)
- [谈谈HTML5本地存储——WebStorage](http://syean.cn/2017/08/15/%E8%B0%88%E8%B0%88HTML5%E6%9C%AC%E5%9C%B0%E5%AD%98%E5%82%A8%E2%80%94%E2%80%94WebStorage/)
- [Linux下容易被忽视的那些命令用法](https://segmentfault.com/p/1210000010668099/read)
- [各种脚本语言不同版本一句话开启 HTTP 服务器的总结](http://www.mottoin.com/94895.html)
- [WebAssembly入门：将字节码带入Web世界](http://bobao.360.cn/learning/detail/3757.html)
- [phpwind 利用哈希长度扩展攻击进行getshell](https://www.leavesongs.com/PENETRATION/phpwind-hash-length-extension-attack.html)
- [深入理解hash长度扩展攻击（sha1为例） ](http://www.freebuf.com/articles/web/69264.html)
- [Joomla 框架的程序执行流程及目录结构分析](http://bobao.360.cn/learning/detail/3909.html)
- [如何通过恶意插件在Atom中植入后门](http://bobao.360.cn/learning/detail/4268.html)


# Binary security

## IOT Security

- [物联网安全百科](https://iot-security.wiki/)
- [OWASP TOP10 物联网漏洞一览](https://xz.aliyun.com/t/2278)

## Mobile Security

### Frida相关文章合集

- [FRIDA Java Hook原理](https://mabin004.github.io/2018/07/31/Mac%E4%B8%8A%E7%BC%96%E8%AF%91Frida/)

### 脱壳相关

- [Frida主动调用脱壳](https://bbs.pediy.com/thread-260540.htm)

### 游戏安全系列

- [perfare大大 <-- 游戏安全行业先锋](https://www.perfare.net/)

### 奇淫技巧

- [反调试技术整理](https://gtoad.github.io/2017/06/25/Android-Anti-Debug/)
- [Ollvm原理](https://sq.163yun.com/blog/article/175307579596922880)

### 比较好的前沿文章归档

- [Flutter逆向工程](https://tinyhack.com/2021/03/07/reversing-a-flutter-app-by-recompiling-flutter-engine/)

### 安全开发
- [Hook框架检测](https://tech.meituan.com/2018/02/02/android-anti-hooking.html)

### 逆向

- [基础逆向教程](https://www.begin.re/)

# CTF

## 技巧总结

- [CTF线下防御战 — 让你的靶机变成“铜墙铁壁”](http://bobao.360.cn/ctf/detail/210.html)
- [ctf-wiki](https://ctf-wiki.github.io/ctf-wiki/#/introduction)
- [CTF中那些脑洞大开的编码和加密](https://www.hackfun.org/CTF/coding-and-encryption-of-those-brain-holes-in-CTF.html)
- [CTF加密与解密 ](http://thief.one/2017/06/13/1/)
- [CTF中图片隐藏文件分离方法总结](https://www.hackfun.org/CTF/summary-of-image-hiding-files-in-CTF.html)
- [Md5扩展攻击的原理和应用](http://www.freebuf.com/articles/database/137129.html)
- [CTF比赛中关于zip的总结](http://bobao.360.cn/ctf/detail/203.html)
- [十五个Web狗的CTF出题套路](http://weibo.com/ttarticle/p/show?id=2309403980950244591011)
- [CTF备忘录](https://827977014.docs.qq.com/Bt2v7IZWnYo?type=1&_wv=1&_bid=2517)
- [rcoil:CTF线下攻防赛总结](http://rcoil.me/2017/06/CTF%E7%BA%BF%E4%B8%8B%E8%B5%9B%E6%80%BB%E7%BB%93/)
- [CTF内存取证入坑指南！稳！](http://www.freebuf.com/column/152545.html)

## CTF PWN

- [PWN入门指南 CTF WIKI](https://ctf-wiki.org/pwn/readme/)
