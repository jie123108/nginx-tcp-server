nginx tcp server
===================================  
	基于nginx的高性能的TCP服务器模块。采用协程(makecontext)实现纯异步。
	本模块基于nginx_tcp_proxy_module修改而来，项目主页为：https://github.com/yaoweibin/nginx_tcp_proxy_module
	nginx_tcp_proxy_module是一个基于nginx的TCP代理模块。

基于协程的异步实现：
-----------------------------------
	基于协程的异步实现基本原理是这样的：
	通过重写系统的connect,recv,send,read,write及其它相关IO函数。
	每一个请求过来时，开启一个新的协程，在这个协程中，进行新网络连接时(connect)，重写的connect函数自动把socket设置为非阻塞。
	当在协程中进行读写时，如果socket未就绪(不可读或不可写)，重写的send,recv函数自动会挂起当前协程，返回到主程序处理其它请求。在挂起当前协程的同时，会给该socket添加读或写的事件监听，当该描述符就绪时(可读或可写)，再唤醒之前被挂起的协程。

通用配置说明：
-----------------------------------


测试代码编译：
-----------------------------------
	cd path/to/nginx-tcp/
	./configure --prefix=/usr/local/nginx-tcp --conf-path=conf/nginx.conf --add-module=../ngx_tcp_testsvr --with-debug --without-pcre --without-http
	make && make install
	#拷贝测试配置。
	cp ngx_tcp_testsvr/conf/nginx.conf /usr/local/nginx-tcp/conf/
	cp ngx_tcp_testsvr/conf/testcfg.ini /usr/local/nginx-tcp/conf/
	#启动程序
	/usr/local/nginx-tcp/sbin/nginx
	#编译测试客户端
	cd path/to/ngx_tcp_testsvr/client/
	make
	#查看测试帮助：
	./testcli -?
	./testcli -h [host] -t [threads] -r [request count] -f [function]  -?
	-f function: ######## functions ##########
          1:ADD 2:SUB 3:QUERY 4:SLEEP

	#测试之前请自动安装启动mysql,并确保配置正确。
	#测试累加
	./testcli -h 127.0.0.1 -t 4 -r 1000 -f 1
	#测试累减
	./testcli -h 127.0.0.1 -t 4 -r 1000 -f 2
	
	############# 测试同步与异步的差别 #############
	#测试同步的方法：
	```
	修改/usr/local/nginx-tcp/conf/nginx.conf配置：
	worker_processes  1; #确保只有一个worker.
	use_async off;		 #关闭异步
	#重启nginx
	/usr/local/nginx-tcp/sbin/nginx -s stop
	/usr/local/nginx-tcp/sbin/nginx
	./testcli -h 127.0.0.1 -t 4 -r 10 -f 4
	#测试输出结果大概如下：
	requests,error,threads,totaltimes,  QPS
    	  10,    0,      4,    10.007,1.00
	************** All Test Is OK **************
	#由于服务器是单进程，单线程并且每个请求休眠1秒。所以10个请求需要10秒完成（即使客户端有4个线程也是如此）。这说明在同步的情况下，进程被后端阻塞时，没有办法处理其它请求。

	#测试异步的方法：
	修改/usr/local/nginx-tcp/conf/nginx.conf配置：
	worker_processes  1; #确保只有一个worker.
	use_async on;		 #启用异步
	#重启nginx
	/usr/local/nginx-tcp/sbin/nginx -s stop
	/usr/local/nginx-tcp/sbin/nginx
	./testcli -h 127.0.0.1 -t 4 -r 10 -f 4
	#测试输出结果大概如下：
	requests,error,threads,totaltimes,  QPS
    	  10,    0,      4,     3.005,3.33
	************** All Test Is OK **************
	#服务器还是单进程，单线程并且每个请求休眠1秒。但由于是异步的，当一个请求被后端阻塞时，还能处理其它请求。
	
	```
	

代码结构说明：
-----------------------------------
###	nginx-tcp 
	nginx的1.2.1源代码，添加了src/tcp_async目录，里面包含了tcp服务器的核心模块，并且实现了异步。
	由于nginx默认实现中，客户端连接不能完全负载均衡(http是短连接比较多，这个问题不会很明显)，部分代码进行了修改，以适应TCP长连接的情景。

### ngx_tcp_testsvr 示例TCP服务器。
	一个标准的基于nginx tcp server的服务器实现。

### ngx_tcp_testsvr/test_protocol.h  	TCP服务器的一些指令头，指令体，命令字等。
	本服务器实现采用应答式，及必须由客户端发起请求，然后服务器一定会有一个响应。请求分为：请求头+请求体，响应为分：响应头+响应体。
	请求头和响应头 必须采用固定长度，一般就是两个结构体，其中必须包含一个长度字段，及一个命令字字段。
	请求体和响应体，可以是二进制格式，也可以是文本格式。具体指令体的解析是在逻辑实现代码中解析的。
###	ngx_tcp_testsvr/test_impl.h		 	TCP服务器的配置项，上下文定义。及请求响应指令的解析。
	配置项里面定义了常用的配置，上下文中一般定义一些需要持久保存连接，对象。
	
### ngx_tcp_testsvr/test_impl.cpp 		配置项的解析，上下文初始化，协议指令的解析，处理。
	xxx_impl.cpp中一般要设置三类回调函数。
	1. 配置项解析及上下文初始化相关函数回调：
	```
	typedef struct app_ctx_t {
		app_cfg_new_pt app_cfg_new;			//程序配置实例化
		app_cfg_init_pt app_cfg_init;		//程序配置初始化
		app_ctx_new_cb app_ctx_new;			//程序上下文实例化
		app_ctx_init_cb app_ctx_init;		//程序上下文初始化
		app_ctx_destroy_cb app_ctx_destroy;	//程序上下文销毁
		app_cfg_destroy_cb app_cfg_destroy;	//程序配置销毁
		app_exit_master_cb app_exit_master;	//master退出时调用回调
	}app_ctx_t;
	```
	设置方法为直接定义一个名为：g_app_ctx的变量：
	```
	app_ctx_t g_app_ctx ={&test_cfg_new,&test_cfg_init,&test_ctx_new, &test_ctx_init,&test_ctx_destroy, &test_cfg_destroy,NULL};
	```

	2. 协议指令解析处理相关的函数回调：
	```
	typedef struct ngx_tcp_protocol_info_s{
		uint32_t req_head_size;			//请求头大小(用于框架分配内存，接收请求头)
		uint32_t rsp_head_size;			//响应头大小(用于框架分配内存，发送响应头)
		ngx_tcp_get_req_body_size_pt get_req_body_size;	//获取请求体大小(从请求头中获取)
		ngx_tcp_get_rsp_body_size_pt get_rsp_body_size;		//获取响应体大小(从响应头中获取)
		ngx_new_req_head_pt new_req_head;				//分配请求头的空间
		ngx_new_rsp_head_pt new_rsp_head;				//分配响应头的空间
		ngx_tcp_preproc_req_header_pt preproc_req_header;	//接收完请求头之后对请求头进行处理(比如字节序转换，解密等)
		ngx_tcp_preproc_req_body_pt preproc_req_body;		//接收完请求体之后对请求体进行处理(比如字节序转换，解密等)
		ngx_tcp_preproc_rsp_header_pt preproc_rsp_header;	//发送响应头之前对响应头进行处理(比如字节序转换，加密等)
		ngx_tcp_preproc_rsp_body_pt preproc_rsp_body;		//发送响应体之前对响应体进行处理(比如字节序转换，加密等)
		ngx_tcp_free_req_pt free_req;		//释放请求相关内存
		ngx_tcp_free_rsp_pt free_rsp;		//释放响应相关内存
		ngx_tcp_debug_req_pt debug_req; 	//请求头及请求体接收完成后，进行输出打印的方法。
		ngx_tcp_debug_rsp_pt debug_rsp;	//响应头及响应体发送之前，进行输出打印的方法。
		ngx_set_rsp_code_pt set_rsp_code;		//处理函数处理完成后，将返回值设置到响应头的方法。
		ngx_tcp_debug_stats_pt debug_stats;	//请求完成后，输出请求统计信息的方法。
		ngx_tcp_req_again_pt req_again;		//当服务器接收到E_AGAIN信号后，调用的方法。
	}ngx_tcp_protocol_info_t;
	```
	3. 服务处理函数回调：
	```
	typedef int (*ngx_tcp_proc_pt)(ngx_tcp_req_t* req, ngx_tcp_rsp_t* rsp);
	```
	2与3的设置方法为实现一个设置函数，并赋值给：g_tcp_set_callbacks：
	```
	int test_set_callbacks(ngx_tcp_data_t* tcp_data){
		memcpy(&tcp_data->protocbs, &g_tcp_cbs_test, sizeof(tcp_data->protocbs));
		tcp_data->tcp_proc = &test_proc;
		return 0;
	}	
	ngx_set_callbacks_pt g_tcp_set_callbacks = &test_set_callbacks;
	```

### ngx_tcp_testsvr/test_service.cpp	TCP服务器的逻辑实现。
	主要要实现上面赋值给tcp_data->tcp_proc函数的这个业务逻辑函数：
	int test_proc(ngx_tcp_req_t* req, ngx_tcp_rsp_t* rsp);
	其实现一般是取得请求头，然后根据请求头中的指令号进行分别处理。

  
测试程序：ngx_tcp_testsvr/client
--------------------------------------
	可以用于测试ngx_tcp_testsvr服务的客户端工具。

