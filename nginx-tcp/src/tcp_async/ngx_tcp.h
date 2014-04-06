
#ifndef __NGX_TCPSERVER_H__
#define __NGX_TCPSERVER_H__

#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>


typedef struct ngx_tcp_cleanup_s  ngx_tcp_cleanup_t;

/* make nginx-0.8.22+ happy */
#if defined(nginx_version) && nginx_version >= 8022
typedef ngx_addr_t ngx_peer_addr_t; 
#endif

typedef struct {
    void                  **main_conf;
    void                  **srv_conf;
} ngx_tcp_conf_ctx_t;


typedef struct {
    u_char                  sockaddr[NGX_SOCKADDRLEN];
    socklen_t               socklen;

    /* server ctx */
    ngx_tcp_conf_ctx_t     *ctx;

    unsigned                bind:1;
    unsigned                wildcard:1;
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    unsigned                ipv6only:2;
#endif
} ngx_tcp_listen_t;


typedef struct {
    ngx_tcp_conf_ctx_t    *ctx;
    ngx_str_t              addr_text;
} ngx_tcp_addr_conf_t;

typedef struct {
    in_addr_t              addr;
    ngx_tcp_addr_conf_t    conf;
} ngx_tcp_in_addr_t;


#if (NGX_HAVE_INET6)

typedef struct {
    struct in6_addr        addr6;
    ngx_tcp_addr_conf_t    conf;
} ngx_tcp_in6_addr_t;

#endif


typedef struct {
    /* ngx_tcp_in_addr_t or ngx_tcp_in6_addr_t */
    void                   *addrs;
    ngx_uint_t              naddrs;
} ngx_tcp_port_t;


typedef struct {
    int                     family;
    in_port_t               port;
    ngx_array_t             addrs;       /* array of ngx_tcp_conf_addr_t */
} ngx_tcp_conf_port_t;


typedef struct {
    struct sockaddr        *sockaddr;
    socklen_t               socklen;

    ngx_tcp_conf_ctx_t     *ctx;

    unsigned                bind:1;
    unsigned                wildcard:1;
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    unsigned                ipv6only:2;
#endif
} ngx_tcp_conf_addr_t;

typedef struct {
    in_addr_t     mask;
    in_addr_t     addr;
    ngx_uint_t    deny;      /* unsigned  deny:1; */
} ngx_tcp_access_rule_t;

typedef struct {
    ngx_array_t             servers;     /* ngx_tcp_core_srv_conf_t */
    ngx_array_t             listen;      /* ngx_tcp_listen_t */
} ngx_tcp_core_main_conf_t;

typedef struct ngx_tcp_core_srv_conf_s{
	ngx_msec_t timeout;
	ngx_msec_t timeout_recv;
	ngx_msec_t timeout_send;
	ngx_msec_t timeout_proc;
	ngx_msec_t resolver_timeout;
	ngx_msec_t backend_timeout_send;
	ngx_msec_t backend_timeout_recv;
	ngx_uint_t stack_size;
	ngx_flag_t so_keepalive;
	ngx_flag_t tcp_nodelay;
	ngx_flag_t use_async;

	ngx_flag_t log_enable;      //是否使用独立的日志文件
	ngx_flag_t log_truncate;	 //启动时清空日志文件。
	ngx_str_t logfile;		//日志文件名
	ngx_str_t debugfile;		//DEBUG日志文件
	ngx_int_t log_level;		//日志级别。
	ngx_str_t appcfgfile;
	void* appcfg;
	void* appctx;
	
	ngx_str_t               server_name;

	u_char                 *file_name;
	ngx_int_t               line;

	ngx_resolver_t         *resolver;

	/*ACL rules*/
	ngx_array_t            *rules;

	/* server ctx */
	ngx_tcp_conf_ctx_t    *ctx;
} ngx_tcp_core_srv_conf_t;

typedef struct {
    ngx_str_t              *client;
} ngx_tcp_log_ctx_t;


typedef struct {
    void                       *(*create_main_conf)(ngx_conf_t *cf);
    char                       *(*init_main_conf)(ngx_conf_t *cf, void *conf);

    void                       *(*create_srv_conf)(ngx_conf_t *cf);
    char                       *(*merge_srv_conf)(ngx_conf_t *cf, void *prev,
                                      void *conf);
} ngx_tcp_module_t;


#define NGX_TCP_MODULE         0x00504354     /* "TCP" */

#define NGX_TCP_MAIN_CONF      0x02000000
#define NGX_TCP_SRV_CONF       0x04000000


#define NGX_TCP_MAIN_CONF_OFFSET  offsetof(ngx_tcp_conf_ctx_t, main_conf)
#define NGX_TCP_SRV_CONF_OFFSET   offsetof(ngx_tcp_conf_ctx_t, srv_conf)


#define ngx_tcp_get_module_ctx(s, module)     (s)->ctx[module.ctx_index]
#define ngx_tcp_set_ctx(s, c, module)         s->ctx[module.ctx_index] = c;
#define ngx_tcp_delete_ctx(s, module)         s->ctx[module.ctx_index] = NULL;


#define ngx_tcp_get_module_main_conf(s, module)                             \
    (s)->main_conf[module.ctx_index]
#define ngx_tcp_get_module_srv_conf(s, module)  (s)->srv_conf[module.ctx_index]

#define ngx_tcp_conf_get_module_main_conf(cf, module)                       \
    ((ngx_tcp_conf_ctx_t *) cf->ctx)->main_conf[module.ctx_index]
#define ngx_tcp_conf_get_module_srv_conf(cf, module)                        \
    ((ngx_tcp_conf_ctx_t *) cf->ctx)->srv_conf[module.ctx_index]

typedef struct ngx_tcp_event_s{
	ngx_event_t ev;
	ngx_uint_t sec;
	ngx_event_handler_pt handler;
	void* args;
}ngx_tcp_event_t;

inline void ngx_tcp_event_handler_wrapper(ngx_event_t *ev);

void ngx_tcp_event_init(ngx_log_t *log, ngx_tcp_event_t* tcp_ev
		, ngx_uint_t sec, ngx_event_handler_pt handler, void* args);

void ngx_tcp_event_destroy(ngx_tcp_event_t* tcp_ev);

//void ngx_tcp_event_handler_wrapper(ngx_event_t *ev);
void ngx_tcp_event_init(ngx_log_t *log, ngx_tcp_event_t* tcp_ev
		, ngx_uint_t sec, ngx_event_handler_pt handler, void* args);
void ngx_tcp_event_destroy(ngx_tcp_event_t* tcp_ev);

extern ngx_uint_t    ngx_tcp_max_module;
extern ngx_module_t  ngx_tcp_core_module;

#endif /* _NGX_TCP_H_INCLUDED_ */
