功能说明
--------------------------------
HelloWorld功能非常简单，客户端可以发送两个指令：
* 登录指令0x1: 输入字符串：${username}，服务器返回一串"Hello ${username},${welcome}!"字符。其中的${welcome}是从配置中读取的内容。
* 退出指令0x2: 输入字符串：${username}，服务器返回一串"Bye ${username}!"字符。
* <b>由于本示例中没有使用默认的CDefProtocol协议实现，自己重新定义了请求头，响应头，及协议处理的细节，会使代码看起来有些繁琐。如果直接继承CDefProtocol会简化很多。</b>

实现步骤
--------------------------------
##### 实现上下文HelloContext, 上下文必须实现IContext接口，包含以下函数：
* cfg_init 配置文件初始化
* ctx_init 上下文初始化，一般是进行数据库，网络链接相关的初始化
* destroy 资源销毁

实现请参见源代码中的HelloContext类。

##### 定义一个MAGIC值
    #define MAGIC 0xa0b1
    #define MAGIC_BIG 0xb1a0

##### 定义服务指令，区分不同的服务
    #define CMD_LOGIN 0x1
    #define CMD_EXIT 0x2

##### 定义错误码
    #define ERRNO_OK	0					//成功	
    #define ERRNO_SYSTEM	1				//系统错误	所有接口
    #define ERRNO_REQ_INVALID	2			//请求参数错误。	所有接口

##### 定义请求体及响应体
    #实际使用中，可能对于不同的指令，会使用不同的请求及响应体。
    typedef struct {
    	char data[4]; //这里实际长度是变长的，所以可以已经读取到\0为止。
    }hello_req_dt;
    
    typedef struct {
    	char data[4]; //这里实际长度是变长的，所以可以已经读取到\0为止。
    }hello_rsp_dt;

##### 定义请求头及响应头
* 请求头：包含magic,len,cmd，其中len是必须的，magic是为了能更方便的识别一个请求包，方便处理用的。cmd是识别不同的请求的, cmd字段也可以放到消息体当中。定义如下：
    
```
typedef struct {
	uint16_t magic; //协议识别码，为一个固定值，请求及响应均相同。
	uint32_t len; 	//指令体长度，0表示没有指令体。
	uint16_t cmd;	//指令号。
}__attribute__ ((packed)) hello_req_header_t;
```
* 响应头：包含magic,len,cmd,code。code为服务响应码。定义如下：

```
typedef struct {
	uint16_t magic; //协议识别码，为一个固定值，请求及响应均相同。
	uint32_t len; 	//指令体长度，0表示没有指令体。
	uint16_t cmd;	//指令号。
	uint16_t code;  
}__attribute__ ((packed)) hello_rsp_header_t;
```
##### 协议处理类定义
协议处理类需要实现IProtocol接口，当然也可以直接继承CDefProtocol，使用默认的实现。或者参考CDefProtocol实现自己的协议处理类。IProtocol接口定义如下：
```
class IProtocol {
public:
	// 创建请求头，必须是一个固定长度的内存(或结构体)
	virtual req_head_t* new_req_head(ngx_pool_t* pool,uint16_t* size)=0;
	// 创始响应头，必须是一个固定长度的内存(或结构体)
	virtual rsp_head_t* new_rsp_head(ngx_pool_t* pool, req_head_t* header,uint16_t* size)=0;
	// 获取请求体大小(从请求头中获取)
	virtual size_t get_req_body_size(req_head_t* header)=0;
	// 获取响应体大小(从响应头中获取)
	virtual size_t get_rsp_body_size(rsp_head_t* header)=0;

	// 接收完请求头之后对请求头进行处理(比如字节序转换，解密等)
	virtual int preproc_req_header(ngx_tcp_req_t* req)=0;
	// 接收完请求体之后对请求体进行处理(比如字节序转换，解密等)
	virtual int preproc_req_body(ngx_tcp_req_t* req)=0;
	// 发送响应头之前对响应头进行处理(比如字节序转换，加密等)
	virtual int preproc_rsp_header(ngx_tcp_rsp_t* rsp)=0;
	// 发送响应体之前对响应体进行处理(比如字节序转换，加密等)
	virtual int preproc_rsp_body(ngx_tcp_rsp_t* rsp)=0;

	// 请求头及请求体接收完成后，进行输出打印的方法。
	virtual void debug_req(ngx_tcp_req_t* req)=0;
	// 响应头及响应体发送之前，进行输出打印的方法。
	virtual void debug_rsp(ngx_tcp_rsp_t* rsp)=0;

	// 释放请求相关内存
	virtual void free_req(ngx_pool_t* pool,ngx_tcp_req_t* req)=0;
	// 释放响应相关内存
	virtual void free_rsp(ngx_pool_t* pool,ngx_tcp_rsp_t* rsp)=0;

	// 处理函数处理完成后，将返回值设置到响应头的方法。
	virtual void set_rsp_code(ngx_tcp_rsp_t* rsp, int ret)=0;
	// 请求完成后，输出请求统计信息的方法。
	virtual void debug_stats(ngx_tcp_data_t* data)=0;
	//当接收请求时，遇到TCP_AGAIN时调用的回调。
	virtual int req_again(ngx_tcp_req_t* req)=0; 
};
```
协议处理类为CHelloProtocol，可直接查看源代码，这里不列出。

##### 服务处理回调定义及实现
服务处理回调主要是取出请求头，然后根据指令号做相应的服务处理。主要代码如下：
```
int hello_proc(ngx_tcp_req_t* req, ngx_tcp_rsp_t* rsp)
{
	int ret = 0;
	hello_req_header_t* header = (hello_req_header_t*)req->req_header;

	switch(header->cmd){
	case CMD_LOGIN:
		ret = hello_login(req, rsp);
	break;
	case CMD_EXIT:
		ret = hello_exit(req, rsp);
	break;	
	default:
		ret = ERRNO_REQ_INVALID;
		NLOG_ERROR("unexpected cmd [0x%04x], ip:%V", header->cmd, &req->c->addr_text);
	}
  
	return ret;
}
#具体的业务处理函数这里不再列出，可直接参考源代码。
```

##### 设置上下文，协议处理及服务处理回调
以上定义的上下文，协议处理类及服务处理函数，需要让nginx-tcp-server框架能够调用到，这里采用回调方式：
* 实现g_context_creater函数，该函数是供nginx-tcp-server框架调用的，用于创建上面HelloContext的一个实例，该函数原型如下：

```
extern IContext* g_context_creater(ngx_conf_t *cf);
```

实现如下：
```
extern IContext* g_context_creater(ngx_conf_t *cf)
{
	IContext* context = new HelloContext(cf);
	return context;
}
```
* 实现g_tcp_set_callbacks回调，该回调函数原型如下：

```
typedef int (*ngx_set_callbacks_pt)(ngx_tcp_data_t* tcp_data);
```
实现如下：
```
# g_hello_protocol 为CHelloProtocol类的一个静态实例。
# hello_proc 为服务处理回调。
int hello_set_callbacks(ngx_tcp_data_t* tcp_data){
	tcp_data->cppcbs = (IProtocol*)&g_hello_protocol;
	tcp_data->tcp_proc = &hello_proc;
	return 0;
}
```

##### config文件编写
config文件用于把添加的源文件，依赖的第三方库添加进来。主要使用到以下几个变量：
* NGX_ADDON_SRCS 源文件添加到该变量中。
* CFLAGS 编译参数添加到该变量中。
* CORE_LIBS 链接参数添加到该变量中。

```
NGX_ADDON_SRCS="$NGX_ADDON_SRCS $ngx_addon_dir/helloworld.cpp $ngx_addon_dir/IniFile.cpp"
#由于本示例未引入第三方库，CFLAGS,CORE_LIBS都不需要定义。
```

##### 编译
```
export TCP_SERVER=/usr/local/nginx-tcp-server_hello
./configure --prefix=$TCP_SERVER \
--with-debug --without-pcre --without-http \
--with-stream  --add-module=src/tcp_svr \
--add-module=/path/to/hello-world
make -j 4
make install
```

##### 运行
* 配置nginx.conf，可参考hello-world/conf/nginx.conf配置
* 配置应用配置hellocfg.ini(由appcfgfile指令指定)。

```
[hello]
welcome=welcome to use nginx-tcp-server 2.0
```

##### 测试客户端
由于协议采用二进制，测试服务程序不能直接使用telnet, nc等方式，需要按协议实现一个测试客户端。代码请参见"client.cpp"文件。
* 编译使用 `make`
* 测试：

```
./client 127.0.0.1 2014 1 lxj
>Hello lxj,welcome to use nginx-tcp-server 2.0
./client 127.0.0.1 2014 2 lxj
>Bye lxj
./client 127.0.0.1 2014 3 lxj
error: tcp server return code:2
```

注意事项
--------------------------------
* ngx_tcp_server.h必须是第一个包含(#include)的文件，否则可能导致结构体大小不一致。

Authors
=======

* liuxiaojie (刘小杰)  <jie123108@163.com>


Copyright & License
===================

This module is licenced under the BSD license.

Copyright (C) 2015, by liuxiaojie (刘小杰)  <jie123108@163.com>

All rights reserved.
