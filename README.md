nginx tcp server
===================================  
	基于nginx的高性能的TCP服务器模块。采用协程(makecontext)实现纯异步，
	异步支持mysql,redis等常用的基于TCP的驱动。
	本模块基于nginx的stream开发。只支持1.9.x以上的版本。

* [ChangeLogs](./ChangeLogs.md "ChangeLogs")

基于协程的异步实现：
-----------------------------------
	基于协程的异步实现基本原理是：
	通过重写系统的connect,recv,send,read,write及其它相关IO函数。
	每一个请求过来时，开启一个新的协程，在这个协程中，进行新的网络
	连接时(connect)，重写的connect函数自动把socket设置为非阻塞。
	当在协程中进行读写时，如果socket未就绪(不可读或不可写)，
	重写的send,recv,read,write函数自动会挂起当前协程，
	返回到主程序处理其它请求。在挂起当前协程的同时会给
	该socket添加读或写的事件监听，当该描述符就绪时(可读或可写)，
	再唤醒之前被挂起的协程。
基本配置说明
```

stream {
	server{
		listen 2014;
		tcp_server; # 开启tcp_server模块。
		# tcp_server其它基本配置，主要是数据库，缓存等相关配置。
		appcfgfile conf/testcfg.ini;
		
		bizlog on; #打开业务日志。默认为off
		# 日志级别：error,warn,info,debug,debug2,all, 默认为info
		log_level debug; 
		# ERROR,WARN,INFO级别日志文件
		logfile  logs/test.log; 
		# DEBUG, DEBUG2级别日志文件
		debugfile logs/test.debug;

		use_async on; #是否开启异步，默认为on
		tcp_nodelay on; # 设置链接为nodelay模式, 默认为on
		so_keepalive off; # 设置链接的keepalive，默认为off

		#链接超时时间，当该链接超过该时间未有任何请求时，会关闭链接。默认为10m;
		timeout 10m; 
		# 消息接收超时时间，默认为3s
		timeout_recv 3s;
		# 消息发送超时时间，默认为2s
		timeout_send 2s;
		# 后端请求时，发送超时时间，默认为5s
		backend_timeout_send 5s;
		# 后端请求时，接收超时时间，默认为10s
		backend_timeout_recv 10s;
	}
}
```

快速起步：
-----------------------------------
    # 进入程序目录
	cd path/to/nginx-tcp/
	# 安装目录定义
	export TCP_SERVER=/usr/local/nginx-tcp-server
	# 编译程序，及Demo服务程序。
	./configure --prefix=$TCP_SERVER \
    --with-debug --without-pcre --without-http \
    --with-stream  --add-module=src/tcp_svr \
    --add-module=src/tcp_svr/demo
	make -j 4
	make install
	#拷贝测试配置。
	cp -f src/tcp_svr/demo/conf/nginx.conf $TCP_SERVER/conf/
	cp -f src/tcp_svr/demo/conf/testcfg.ini $TCP_SERVER/conf/
	#启动程序
	$TCP_SERVER/sbin/nginx
	#编译测试客户端
	cd src/tcp_svr/demo/client/
	make
	#查看测试帮助：
	./testcli -?
	>./testcli -h [host] -t [threads] -r [request count] -f [function]  -?
	>-f function: ######## functions ##########
    >      1:ADD 2:SUB 3:QUERY 4:SLEEP

	#测试之前请自行安装并启动mysql,并确保配置(testcfg.ini)正确。
	#测试累加
	./testcli -h 127.0.0.1 -t 4 -r 1000 -f 1
	#测试累减
	./testcli -h 127.0.0.1 -t 4 -r 1000 -f 2
	
	############# 测试同步与异步的差别 #############
	#测试同步的方法：
	```
	修改$TCP_SERVER/conf/nginx.conf配置：
	worker_processes  1; #确保只有一个worker.
	use_async off;		 #关闭异步
	#重启nginx
	$TCP_SERVER/sbin/nginx -s stop
	$TCP_SERVER/sbin/nginx
	#运行测试程序(-h 指定Host, -t 指定线程数，-r指定请求数，-f指定测试功能)
	./testcli -h 127.0.0.1 -t 4 -r 10 -f 4 
	#测试输出结果大概如下：
	requests,error,threads,totaltimes,  QPS
          10,    0,      4,    10.007,  1.00
	************** All Test Is OK **************
	#由于服务器是单进程，单线程并且每个请求休眠1秒。所以10个请求需要10秒完成，单进程QPS只有1。
	#(即使客户端有4个线程也是如此,测试程序超时时间为10s,太短会导致后面的请求超时)。
	#这说明在同步的情况下，进程被后端阻塞时，没有办法处理其它请求。

	#测试异步的方法：
	修改$TCP_SERVER/conf/nginx.conf配置：
	worker_processes  1; #确保只有一个worker.
	use_async on;		 #启用异步
	#重启nginx
	$TCP_SERVER/sbin/nginx -s stop
	$TCP_SERVER/sbin/nginx
	./testcli -h 127.0.0.1 -t 4 -r 10 -f 4 
	#测试输出结果大概如下：
	requests,error,threads,totaltimes,  QPS
          10,    0,      4,     3.006,  3.33
	************** All Test Is OK **************
	#服务器还是单进程，并且每个请求休眠1秒。但由于是异步的，
	# 当一个请求被后端阻塞时，还能处理其它请求。
	# (由于测试客户端是使用的同步方式，所以QPS不可能会大于线程数，
	# 如果客户端也采用异步方式，性能会更好)
	```
	

代码(demo)结构说明：
-----------------------------------
###	nginx-tcp 
	nginx的1.9.3源代码，修改了以下部分，以适应tcp_svr要求：
	1. auto/make文件修改，以支持C++。tcp_svr模块主要采用C++编写。
	
### nginx-tcp/src/tcp_svr
    tcp服务器的核心模块，实现了协程及异步IO的封装。
* ngx_log_mod.* 日志相关的处理。
* ngx_tcp_async_proc.* 异步相关的处理。
* ngx_tcp_def_protocol.* 默认的协议处理实现。(可以参考它实现自己的协议处理)
* ngx_tcp_server.h 模块头文件，相关的数据结构，函数定义在这儿。
* ngx_tcp_server_module.cpp 模块实现主文件。tcp_svr的核心逻辑在这儿。

### nginx-tcp/src/tcp_svr/demo
	一个标准的基于nginx tcp server的服务器实现，及测试客户端。
* test_protocol.h 

```
TCP服务器的一些指令头(使用框架默认定义的指定头)，指令体，命令字等。
本服务器实现采用应答式，及必须由客户端发起请求，然后服务器一定会有一个响应。
请求分为：请求头+请求体，响应为分：响应头+响应体。
请求头和响应头 必须采用固定长度，一般就是两个结构体，其中必须包含一个长度字段，及一个命令字字段。
请求体和响应体，可以是二进制格式，也可以是文本格式。具体指令体的解析是在逻辑实现代码中解析的。
```

* test_impl.*

    * test_config_t 服务器配置项定义。
    * TestContext 服务器上下文，主要进行配置解析，数据库链接池初始等服务器初始化过程。
    * TestProtocol 服务器协议处理类，继承自CDefProtocol，也可以自己实现一个协议处理类。
    * g_context_creater 重要：创建上下文，该函数会被tcp_svr框架调用。
    * g_tcp_set_callbacks 重要：设置回调的方法。主要将Demo协议处理实例及业务处理函数设置上，供框架调用。
* test_service.cpp

```
TCP服务器的逻辑实现。
主要要实现上面赋值给tcp_data->tcp_proc函数的这个业务逻辑函数：
extern int test_proc(ngx_tcp_req_t* req, ngx_tcp_rsp_t* rsp)
其实现一般是取得请求头，然后根据请求头中的指令号进行分别处理。
```
  
测试程序：nginx-tcp/src/tcp_svr/demo/client
--------------------------------------
	可以用于测试tcp_svr/demo服务的客户端工具。

基于nginx-tcp-server的Hello World程序开发
--------------------------------------
[Hello World示例开发](./HelloWorld.md "Hello World示例开发")

Authors
=======

* liuxiaojie (刘小杰)  <jie123108@163.com>


Copyright & License
===================

This module is licenced under the BSD license.

Copyright (C) 2015, by liuxiaojie (刘小杰)  <jie123108@163.com>

All rights reserved.
