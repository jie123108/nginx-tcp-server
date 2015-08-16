
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */
#include "ngx_tcp_server.h"
extern "C" {
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include <assert.h>
}
#include "ngx_log_mod.h"
#include "ngx_tcp_async_proc.h"
#include <algorithm>


static char* ngx_tcp_app_init(ngx_conf_t *cf, ngx_tcp_server_srv_conf_t  *cscf);
static ngx_int_t  ngx_init_process(ngx_cycle_t *cycle);
static void ngx_exit_process(ngx_cycle_t *cycle);
static void ngx_tcp_server_read_handler(ngx_event_t *rev);
void ngx_tcp_server_write_handler(ngx_event_t *wev);

static void ngx_tcp_server_set_socket_opt(
	ngx_connection_t *c, ngx_tcp_server_srv_conf_t* conf);
static void ngx_tcp_server_init_session(ngx_stream_session_t *s);

static u_char *ngx_tcp_server_log_error(ngx_log_t *log, u_char *buf,
    size_t len);

static void *ngx_tcp_server_create_srv_conf(ngx_conf_t *cf);
static char *ngx_tcp_server_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_tcp_server_on(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_tcp_server_commands[] = {

    { ngx_string("tcp_server"),
      NGX_STREAM_SRV_CONF|NGX_CONF_NOARGS,
      ngx_tcp_server_on,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("appcfgfile"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_server_srv_conf_t, appcfgfile),
      NULL },
      
    { ngx_string("so_keepalive"),
        NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_STREAM_SRV_CONF_OFFSET,
        offsetof(ngx_tcp_server_srv_conf_t, so_keepalive),
        NULL },

    { ngx_string("tcp_nodelay"),
        NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_STREAM_SRV_CONF_OFFSET,
        offsetof(ngx_tcp_server_srv_conf_t, tcp_nodelay),
        NULL },
    { ngx_string("use_async"),
        NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_STREAM_SRV_CONF_OFFSET,
        offsetof(ngx_tcp_server_srv_conf_t, use_async),
        NULL },

    { ngx_string("stack_size"),
        NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_size_slot,
        NGX_STREAM_SRV_CONF_OFFSET,
        offsetof(ngx_tcp_server_srv_conf_t, stack_size),
        NULL },

    { ngx_string("timeout"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_server_srv_conf_t, timeout),
      NULL },
    { ngx_string("timeout_recv"),
        NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_msec_slot,
        NGX_STREAM_SRV_CONF_OFFSET,
        offsetof(ngx_tcp_server_srv_conf_t, timeout_recv),
        NULL },
    { ngx_string("timeout_send"),
        NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_msec_slot,
        NGX_STREAM_SRV_CONF_OFFSET,
        offsetof(ngx_tcp_server_srv_conf_t, timeout_send),
        NULL },
    { ngx_string("backend_timeout_send"),
        NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_msec_slot,
        NGX_STREAM_SRV_CONF_OFFSET,
        offsetof(ngx_tcp_server_srv_conf_t, backend_timeout_send),
        NULL },
    { ngx_string("backend_timeout_recv"),
        NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_msec_slot,
        NGX_STREAM_SRV_CONF_OFFSET,
        offsetof(ngx_tcp_server_srv_conf_t, backend_timeout_recv),
        NULL },
      ngx_null_command
};


static ngx_stream_module_t  ngx_tcp_server_module_ctx = {
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_tcp_server_create_srv_conf,      /* create server configuration */
    ngx_tcp_server_merge_srv_conf        /* merge server configuration */
};


ngx_module_t  ngx_tcp_server_module = {
    NGX_MODULE_V1,
    &ngx_tcp_server_module_ctx,          /* module context */
    ngx_tcp_server_commands,             /* module directives */
    NGX_STREAM_MODULE,                     /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_init_process,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    ngx_exit_process,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static void ngx_tcp_timeout_handler(ngx_event_t* to_ev){
	ngx_connection_t* c = (ngx_connection_t*)to_ev->data;
	ngx_tcp_data_t* data = (ngx_tcp_data_t*)c->data;
	uint sec = ngx_time()-data->lastkeepalivetm;
	ngx_tcp_server_srv_conf_t* conf = data->conf;
	if(conf == NULL)return;
	
	uint time_diff = conf->timeout-sec*1000;
	if(time_diff < 1000){// < one second,timeout
		NLOG_DEBUG("######### client [%s] timeout #########",c->clientaddr);
		ngx_tcp_server_finalize(c);
	}else{	
		NLOG_DEBUG("######### change timeout timer (%ums) #########",time_diff);
		ngx_add_timer(&data->to_ev,time_diff);
	}
}

void ngx_tcp_first_timeout_handler(ngx_event_t* to_ev){
	ngx_connection_t* c = (ngx_connection_t*)to_ev->data;
	//ngx_tcp_data_t* data = (ngx_tcp_data_t*)c->data;
	ngx_event_del_timer(to_ev);

	NLOG_WARN("######### wait client [%s] first msg timeout #########",c->clientaddr);
	ngx_tcp_server_finalize(c);
}

static void
ngx_tcp_server_init_session(ngx_stream_session_t *s)
{
    ngx_connection_t                *c;

    ngx_tcp_server_srv_conf_t     *conf;

    c = s->connection;

    conf = (ngx_tcp_server_srv_conf_t*)ngx_stream_get_module_srv_conf(s, ngx_tcp_server_module);

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "tcp_server connection handler");

	if(c->sockaddr->sa_family==AF_INET){
		u_char* pos=NULL;
		struct sockaddr_in* sa = (struct sockaddr_in *)c->sockaddr;
		pos = ngx_sprintf(c->clientaddr, "%s",inet_ntoa(sa->sin_addr));
		ngx_sprintf(pos, ":%d", ntohs(sa->sin_port));
	}else{
		ngx_sprintf(c->clientaddr,"%.*s", c->addr_text.len, c->addr_text.data);
	}

    s->log_handler = ngx_tcp_server_log_error;

	struct sockaddr_in* lsa = (struct sockaddr_in *)c->local_sockaddr;
	ngx_tcp_data_t* data = (ngx_tcp_data_t*)NGX_TCP_PALLOC(c->pool, sizeof(ngx_tcp_data_t));
	
	c->data = data;
	data->conf = conf;
	data->status = NS_ACCEPT;
	data->lastkeepalivetm = ngx_time();
	data->listen_port = ntohs(lsa->sin_port);
	g_tcp_set_callbacks(data);
	
	
	ngx_event_t     *to_ev = &data->to_ev;
	to_ev->data = c;
	to_ev->handler = &ngx_tcp_timeout_handler;
	to_ev->timer_set = 0;
	to_ev->log = c->log;
	ngx_add_timer(to_ev, conf->timeout); 
	/**
	to_ev = &data->first_to_ev;
	to_ev->data = c;
	to_ev->handler = &ngx_tcp_first_timeout_handler;
	to_ev->timer_set = 0;
	to_ev->log = c->log;
	ngx_add_timer(to_ev, 1000); 
	**/
	//NLOG_DEBUG("[%P] %uA client %s connected to [%d]", ngx_getpid(), 
	//		c->number, (const char*)c->clientaddr, (int)data->listen_port);
	NLOG_DEBUG("[%d] %uD client  %s connected to [%d]", 
			(int)ngx_getpid(), (unsigned)c->number, (const char*)c->clientaddr, (int)data->listen_port);


    c->write->handler = ngx_tcp_server_write_handler;
    c->read->handler = ngx_tcp_server_read_handler;
	ngx_tcp_server_set_socket_opt(c, conf);
	
	if (ngx_handle_read_event(c->read, 0) != NGX_OK)
	{
		ngx_tcp_server_finalize(c);
	}

}

/**
 * recv a tcp request message
 * ret value:
 */
static NGX_RECV_STAT_T ngx_tcp_recv_msg(ngx_event_t *rev){
	if(rev->timedout){
		return RS_TIMEDOUT;
	}
	ssize_t size;
	ngx_connection_t* c = (ngx_connection_t*)rev->data;
	ngx_tcp_data_t* data = (ngx_tcp_data_t*)c->data;
	//NLOG_DEBUG("xxx ngx_tcp_recv_msg {%p} connection {%p}", data, c);
	//NLOG_DEBUG("xxx cppcbs: %p, tcp_proc: %p", data->cppcbs, data->tcp_proc);

	ngx_tcp_server_srv_conf_t* conf = (ngx_tcp_server_srv_conf_t*)data->conf;
	ngx_tcp_req_t* req_data = NULL;
	if(data->req_data == NULL){
		req_data = (ngx_tcp_req_t*)NGX_TCP_PALLOC(c->pool, sizeof(ngx_tcp_req_t));
		data->req_data = req_data;
		req_data->c = c;
		req_data->tcp_data = data;
		ngx_memset(&data->stat,0,sizeof(data->stat));
		data->stat.all = data->stat.all_begin = data->stat.recv_req =ngx_second();
		
		ngx_add_timer(rev, conf->timeout_recv);
	}else{
		req_data = data->req_data;
	}

	if(req_data->req_header == NULL){
		req_data->req_header = data->prot_new_req_head(c->pool, &req_data->req_header_size);
		req_data->header_len = 0;
	}
	NGX_RECV_STAT_T ret = RS_OK;
	do{
		size_t req_header_size = req_data->req_header_size;
		assert(req_header_size > 0);
		if(req_data->header_len < req_header_size){
			size_t rest = req_header_size-req_data->header_len;
			size = c->recv(c, (u_char*)req_data->req_header+req_data->header_len, rest);
			if(size == NGX_AGAIN){
				ret = RS_AGAIN;
				break;
			}else if(size == 0){
				ret = RS_CLOSE;
				break;
			}else if(size==NGX_ERROR){
				ret = RS_ERROR;
				char errorinfo[256];
				ngx_memzero(errorinfo, sizeof(errorinfo));
 				NLOG_WARN("recv header from %s failed! errno:%d err:%s",c->clientaddr,
						errno, strerror_r(errno, errorinfo, sizeof(errorinfo)));
				break;
			}
			
			req_data->header_len += size;
			if(req_data->header_len < req_header_size){
				ret = RS_AGAIN;
				break;
			}else{//header recv ok..
				int preret = data->prot_preproc_req_header(req_data);
				if(preret != 0){
					ret = RS_ERROR_REQ_INVALID;
					break;
				}
			}
		}

		//recv body.
		size_t req_body_size = data->prot_get_req_body_size(req_data->req_header);
		if(req_body_size <= 0){
			break;
		}

		if(req_data->body == NULL){
			req_data->body = NGX_TCP_PALLOC(c->pool, req_body_size+1);
			req_data->body_len = 0;
		}

		if(req_data->body_len < req_body_size){
			while(1){
				size_t rest = std::min(int(req_body_size-req_data->body_len), 1024*4);
				size = c->recv(c, (u_char*)req_data->body+req_data->body_len, rest);
				if(size == NGX_AGAIN){
					ret = RS_AGAIN;
					return ret; 
				}else if(size == 0){
					ret = RS_CLOSE;
					return ret; 
				}else if(size==NGX_ERROR){
					ret = RS_ERROR;
					char errorinfo[256];
					ngx_memzero(errorinfo, sizeof(errorinfo));
					NLOG_ERROR("recv body from %s failed! errno:%d err:%s",c->clientaddr,
							errno, strerror_r(errno, errorinfo, sizeof(errorinfo)));
					return ret; 
				}
				
				req_data->body_len += size;
				if(req_data->body_len >=req_body_size){
					break;
				}
				if((size_t)size < rest){
					break;
				}
				
			}
			
			if(req_data->body_len < req_body_size){
				return RS_AGAIN;
			}

			int preret = data->prot_preproc_req_body(req_data);
			if(preret != 0){
				ret = RS_ERROR_REQ_INVALID;
				break;
			}
		}

	}while(0);
	
	return ret;
}

static void ngx_tcp_proc_sync(ngx_tcp_data_t* data){
	int ret = 0;
	ngx_connection_t* c = data->req_data->c;
	data->stat.proc = ngx_second();
	ret = data->tcp_proc(data->req_data,data->rsp_data);
	data->stat.proc = ngx_second()-data->stat.proc;
	data->stat.code = ret;
	data->prot_set_rsp_code(data->rsp_data, ret);
	//log_ADDR(data->rsp_data);
	data->status = NS_SEND; 

	#if 1
	c->write->active = 0;
	c->write->ready = 0;
	//NLOG_DEBUG("data {0x%08x} status:%d",data, data->status);
	c->write->handler = &ngx_tcp_server_write_handler;
	ret = ngx_handle_write_event(c->write, 0);
	if(ret != NGX_OK)
	{
	    NLOG_ERROR("ngx_hendle_write_event: %d", ret);
	    ngx_tcp_server_finalize(c);
	    data->status = NS_CLOSE;
	}
	#else
	ngx_tcp_send_rsp_data(c->write);
	#endif
	data->stat.all_end = ngx_second();
	data->stat.all = data->stat.all_end-data->stat.all_begin;
	data->prot_debug_stats(data);

	if(data->req_data != NULL){
		data->prot_free_req(c->pool, data->req_data);
		data->req_data = NULL;
	}
	
}

static void ngx_tcp_server_read_handler(ngx_event_t *rev)
{
	ngx_int_t ret=0;
	ngx_connection_t    *c;
	c = (ngx_connection_t*)rev->data;
	ngx_tcp_data_t* data = (ngx_tcp_data_t*)c->data;
	data->lastkeepalivetm = ngx_time();
	switch(data->status){
	case NS_ACCEPT:
	case NS_RECV:
	case NS_DONE:
		data->status = NS_RECV;
	break;
	case NS_PROC:
		NLOG_WARN("on [proc] status, find a read event, proc_begin:%.4f cur:%.4f, cli:%s", 
			 	data->stat.all_begin, ngx_second(),c->clientaddr);
		return;
	case NS_SEND:
		c->error = 1;
		ngx_tcp_server_finalize(c);
		data->status = NS_CLOSE;
		NLOG_WARN("on [send] status, find a read event, proc_begin:%.4f cur:%.4f, cli:%s", 
				data->stat.all_begin, ngx_second(),c->clientaddr);
		return; 
	break;
	case NS_CLOSE:
		NLOG_ERROR(" ns_close status, cli:%s", c->clientaddr);
	break;
	}
	
	NGX_RECV_STAT_T rs = ngx_tcp_recv_msg(rev);
	switch(rs){
	case RS_AGAIN:
		ret = data->prot_req_again(data->req_data);
		if(ret != 0){
			c->error = 1;
			//NLOG_DEBUG("client %s close socked!", c->clientaddr);
			ngx_tcp_server_finalize(c);
			data->status = NS_CLOSE;
			data->stat.all_end = ngx_second();
			data->stat.all = data->stat.all_end-data->stat.all_begin;
			data->stat.recv_req= ngx_second()-data->stat.recv_req;
		}

		return;
	break;
	case RS_ERROR:
	case RS_ERROR_REQ_INVALID:
	case RS_TIMEDOUT:
	{
		c->error = 1;
		if(rs == RS_ERROR){
			//char errorinfo[256];
			//ngx_memzero(errorinfo, sizeof(errorinfo));
			//NLOG_ERROR("recv message from %s failed! errno:%d err:%s",c->clientaddr,
			//	errno, strerror_r(errno, errorinfo, sizeof(errorinfo)));
		}else if(rs == RS_ERROR_REQ_INVALID){
			NLOG_WARN("recv invalid message from %s !",c->clientaddr);
		}else if(rs == RS_TIMEDOUT){
			NLOG_WARN("recv message from %s timedout!", c->clientaddr);
		}
		//ngx_tcp_close_connection(c);
		data->status = NS_CLOSE;
		data->stat.all_end = ngx_second();
		data->stat.all = data->stat.all_end-data->stat.all_begin;
		data->stat.recv_req= ngx_second()-data->stat.recv_req;
	}
	case RS_CLOSE:
		c->error = 1;
		//NLOG_DEBUG("client %s close socked!", c->clientaddr);
		data->status = NS_CLOSE;
		data->stat.all_end = ngx_second();
		data->stat.all = data->stat.all_end-data->stat.all_begin;
		data->stat.recv_req= ngx_second()-data->stat.recv_req;
		ngx_tcp_server_finalize(c);
	break;
	case RS_OK:
	{	
		data->prot_debug_req(data->req_data);
		
		ngx_del_timer(rev);
		if(data->rsp_data != NULL){
			NLOG_ERROR("### data->rsp_data != NULL ###");
			data->prot_free_rsp(c->pool, data->rsp_data);
			data->rsp_data = NULL;
		}

		data->stat.recv_req= ngx_second()-data->stat.recv_req;

		data->status = NS_PROC;
		data->rsp_data = (ngx_tcp_rsp_t*)NGX_TCP_PALLOC(c->pool, sizeof(ngx_tcp_rsp_t));
		data->rsp_data->rsp_header = data->prot_new_rsp_head(c->pool, 
					data->req_data->req_header, &data->rsp_data->rsp_header_size); 
		data->rsp_data->c = c;
		data->rsp_data->tcp_data = data;
		data->rsp_data->isbigendian = data->req_data->isbigendian;
		data->rsp_data->rsp_send_times = 0;
		data->rsp_data->rsp_chain = NULL;
		data->rsp_data->rsp_rest = NULL;

		if(data->conf->use_async){
			ngx_tcp_proc_async(data);
		}else{
			ngx_tcp_proc_sync(data);
		}
	} 
	break;
	default:
		NLOG_WARN("############## un processed status[%d] ###############", data->status);
	}
}


ngx_chain_t* ngx_tcp_send_chain(ngx_connection_t    *c,ngx_chain_t* chain){
	int i;
	//NLOG_DEBUG("c->send_chain:0x%08x", (int)c->send_chain);
	ngx_chain_t* rest = chain;
	for(i=0;i < 200; i++){
		rest = c->send_chain(c, rest, 1024*4);
		if(rest == NGX_CHAIN_ERROR ||rest == NULL){
			return rest;
		}else{
			NLOG_DEBUG("###### send resp to [%s] uncomplete rest:0x%016x####", 
				c->clientaddr, (long long int)rest);
		}
	}
	//if(i == 2000){
	//	NLOG_ERROR("Send Response To [%s] not complete!", c->clientaddr);
	//}
	
	return rest;
}

static void ngx_tcp_server_empty_write_handler(ngx_event_t *wev){
	//log_INFO("############## empty write handler #############");
}

void ngx_tcp_server_write_handler(ngx_event_t *wev)
{
	ngx_connection_t    *c;
	c = (ngx_connection_t*)wev->data;
	ngx_tcp_data_t* data = (ngx_tcp_data_t*)c->data;

	//NLOG_DEBUG("data {%p} fd:%d ready:%d active:%d", data, (int)c->fd, wev->ready,wev->active);
	if(data->status!=NS_SEND){
		if(data->status == NS_DONE) return;
		NLOG_ERROR("data {0x%08x} invalid status [%d] fd:%d ", 
					(long)data, data->status, c->fd);
		
		if(ngx_handle_write_event(wev, 0) != NGX_OK)
		{
			NLOG_ERROR("ngx_handle_write_event error!");
			ngx_tcp_server_finalize(c);
			data->status = NS_CLOSE;
		}
		//NLOG_DEBUG("after handle write event: data {0x%08x} fd:%d ready:%d active:%d", (long)data, c->fd, wev->ready,wev->active);
	
		return;
	}
	
	do{
		if(data->rsp_data == NULL){
			NLOG_ERROR("###### rsp data is null! ######");
			break;
		}else{
			//NLOG_DEBUG("fd[%d] data {0x%08x} write response rsp header:0x%08x, body:0x%08x", 
			//c->fd, (long)data,  (long)rsp->rsp_header, (long)rsp->body);
		}

		ngx_tcp_rsp_t* rsp = (ngx_tcp_rsp_t*)data->rsp_data;
		if(rsp->rsp_chain == NULL){
			size_t rsp_body_size = 0;
			ngx_chain_t* header = rsp->rsp_chain = rsp->rsp_rest =
					(ngx_chain_t*)NGX_TCP_PALLOC(c->pool, sizeof(ngx_chain_t));

			data->prot_debug_rsp(data->rsp_data);

			rsp_body_size = data->prot_get_rsp_body_size(rsp->rsp_header);
			
			data->prot_preproc_rsp_header(rsp);
			header->buf = (ngx_buf_t*)NGX_TCP_PALLOC(c->pool, sizeof(ngx_buf_t));
			header->buf->pos = header->buf->start = (u_char*)rsp->rsp_header;
			header->buf->last = header->buf->end = 
				(u_char*)header->buf->pos + data->rsp_data->rsp_header_size;
			header->buf->memory = 1;

			if(rsp->body != NULL){
				ngx_chain_t* body = NULL;
				data->prot_preproc_rsp_body(rsp);
				
				header->next = body = (ngx_chain_t*)NGX_TCP_PALLOC(c->pool, sizeof(ngx_chain_t));
				body->buf = (ngx_buf_t*)NGX_TCP_PALLOC(c->pool, sizeof(ngx_buf_t));	
				body->buf->pos = body->buf->start = (u_char*)rsp->body;
				body->buf->last = body->buf->end = 
					(u_char*)body->buf->pos + rsp_body_size;
				body->buf->memory = 1;
				
				body->buf->last_buf = 1;
				body->buf->last_in_chain = 1;
				body->next = NULL;
			}else{
				header->buf->last_buf = 1;
				header->buf->last_in_chain = 1;
				header->next = NULL;
			}
		}
		
		ngx_add_timer(wev,data->conf->timeout_send);
		data->stat.send_rsp = ngx_second();
		rsp->rsp_rest = ngx_tcp_send_chain(c, rsp->rsp_rest);
		data->stat.send_rsp = ngx_second()-data->stat.send_rsp;
		rsp->rsp_send_times++;
		ngx_del_timer(wev);
		wev->handler = &ngx_tcp_server_empty_write_handler;
		if(rsp->rsp_rest == NULL){//send success!
			//NLOG_DEBUG("send response success!");
		}else if(rsp->rsp_rest == NGX_CHAIN_ERROR){
			c->error = 1;
			NLOG_ERROR("send resp to[%s] failed!", c->clientaddr);
			ngx_tcp_server_finalize(c);
		}else{//发送不完整。
			//c->error = 1;
			//ngx_tcp_close_connection(c);
			if(rsp->rsp_send_times < 100){
				NLOG_WARN("Send Response To [%s] not complete! times: %d", 
						c->clientaddr, rsp->rsp_send_times);
				c->write->active = 0;
				c->write->ready = 0;
				wev->handler = &ngx_tcp_server_write_handler;
				int ret = ngx_handle_write_event(c->write, 0);
				if(ret == NGX_OK)
				{
					return;		
				}
				else
				{
				    NLOG_ERROR("ngx_hendle_write_event: %d", ret);
					ngx_tcp_server_finalize(c);
				    data->status = NS_CLOSE;
					break;
				}
			}else{
				c->error = 1;
				NLOG_ERROR("Send Response To [%s] failed! times:%d",
					c->clientaddr,
					rsp->rsp_send_times);
				ngx_tcp_server_finalize(c);
			}
		}
		data->status = NS_DONE;		
	}while(0);

	if(data->rsp_data != NULL){
		if(data->rsp_data->rsp_chain != NULL){
			ngx_chain_t* chain = data->rsp_data->rsp_chain;
			data->rsp_data->rsp_chain = NULL;
			while(chain != NULL){
				if(chain->buf != NULL){
					NGX_TCP_PFREE(c->pool,chain->buf);
				}
				ngx_chain_t* next = chain->next;
				NGX_TCP_PFREE(c->pool, chain);
				chain = next;
			}
		}
		data->prot_free_rsp(c->pool, data->rsp_data);
		data->rsp_data = NULL;
	}
}


void ngx_tcp_server_finalize(ngx_connection_t *c)
{

    //ngx_log_debug1(ngx_NLOG_DEBUG_STREAM, c->log, 0,"finalize connection: %i", rc);

	ngx_pool_t  *pool = c->pool;
	if(c->data != NULL){
		ngx_tcp_data_t* data = (ngx_tcp_data_t*)c->data;
		if(data->to_ev.timer_set){
			ngx_del_timer(&data->to_ev);
		}
		if(data != NULL){
			if(data->req_data != NULL){
				data->prot_free_req(c->pool, data->req_data);
				data->req_data = NULL;
			}
			if(data->rsp_data != NULL){
				data->prot_free_rsp(c->pool, data->rsp_data);
				data->rsp_data = NULL;
			} 
			if(data->userdata != NULL){
				NGX_TCP_PFREE(pool, data->userdata);
			}
			
			NGX_TCP_PFREE(pool, data);
		}
		c->data = NULL;
	}
	
    ngx_stream_close_connection(c);
}

static void ngx_tcp_server_set_socket_opt(
	ngx_connection_t *c, ngx_tcp_server_srv_conf_t* conf)
{
    int keepalive;
    int tcp_nodelay;

    if (conf->so_keepalive)
    {
        keepalive = 1;

        if (setsockopt(c->fd, SOL_SOCKET, SO_KEEPALIVE,
                       (const void *) &keepalive, sizeof(int)) == -1)
        {
            ngx_log_error(NGX_LOG_ALERT, c->log, ngx_socket_errno,
                          "setsockopt(SO_KEEPALIVE) failed");
        }
    }

    if (conf->tcp_nodelay)
    {
        tcp_nodelay = 1;
        if (setsockopt(c->fd, IPPROTO_TCP, TCP_NODELAY,
                       (const void *) &tcp_nodelay, sizeof(int))
            == -1)
        {
            ngx_log_error(NGX_LOG_ALERT, c->log, ngx_socket_errno,
                          "setsockopt(TCP_NODELAY) failed");
        }

        c->tcp_nodelay = NGX_TCP_NODELAY_SET;
    }
}


static u_char *
ngx_tcp_server_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char                 *p;
    ngx_stream_session_t   *s;

    s = (ngx_stream_session_t*)log->data;


    p = buf;
    p = ngx_snprintf(p, len,
                     ", bytes from/to client:%O/%O",
                     s->received, s->connection->sent);

    return p;
}


static void *
ngx_tcp_server_create_srv_conf(ngx_conf_t *cf)
{
    ngx_tcp_server_srv_conf_t  *conf;

    conf = (ngx_tcp_server_srv_conf_t*)ngx_pcalloc(cf->pool, sizeof(ngx_tcp_server_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->timeout = NGX_CONF_UNSET_MSEC;
    conf->timeout_recv = NGX_CONF_UNSET_MSEC;
    conf->timeout_send = NGX_CONF_UNSET_MSEC;
    conf->stack_size = NGX_CONF_UNSET_MSEC;
    conf->so_keepalive = NGX_CONF_UNSET;
    conf->tcp_nodelay = NGX_CONF_UNSET;
    conf->use_async = NGX_CONF_UNSET;
	conf->backend_timeout_send = NGX_CONF_UNSET_MSEC;
	conf->backend_timeout_recv = NGX_CONF_UNSET_MSEC;

    return conf;
}


static char *
ngx_tcp_server_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_tcp_server_srv_conf_t *prev = (ngx_tcp_server_srv_conf_t*)parent;
    ngx_tcp_server_srv_conf_t *conf = (ngx_tcp_server_srv_conf_t*)child;

    ngx_conf_merge_msec_value(conf->timeout, prev->timeout, 1000*60*10);
    ngx_conf_merge_msec_value(conf->timeout_recv, prev->timeout_recv, 1000*3);
    ngx_conf_merge_msec_value(conf->timeout_send, prev->timeout_send, 1000*2);
    ngx_conf_merge_msec_value(conf->backend_timeout_send, prev->backend_timeout_send, 1000*5);
    ngx_conf_merge_msec_value(conf->backend_timeout_recv, prev->backend_timeout_recv, 1000*10);
    
    ngx_conf_merge_size_value(conf->stack_size, prev->stack_size, 1024*128);
    ngx_conf_merge_value(conf->so_keepalive, prev->so_keepalive, 0);
    ngx_conf_merge_value(conf->tcp_nodelay, prev->tcp_nodelay, 1);
    ngx_conf_merge_value(conf->use_async, prev->use_async, 1);


    return ngx_tcp_app_init(cf, conf);;
}


static char *
ngx_tcp_server_on(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_core_srv_conf_t  *cscf;

    cscf = (ngx_stream_core_srv_conf_t*)ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_core_module);

    cscf->handler = ngx_tcp_server_init_session;

    return NGX_CONF_OK;
}

static char* ngx_tcp_app_init(ngx_conf_t *cf, ngx_tcp_server_srv_conf_t  *conf)
{	
	
	printf("nginx version [%s %s],tcp mod: %s\n", __DATE__, __TIME__,
				conf->use_async?"async":"sync");

	NLOG_INFO("nginx version [%s %s],tcp mod: %s", __DATE__, __TIME__,
				conf->use_async?"async":"sync");
	cf->cycle->conf_ctx[ngx_tcp_server_module.index] = (void***)conf;

	
	char config[512];
	ngx_memset(config,0,sizeof(config));
	ngx_conf_full_name(cf->cycle, &conf->appcfgfile, 0);	
	snprintf(config,sizeof(config), "%.*s",(int)conf->appcfgfile.len,conf->appcfgfile.data);
	conf->appctx = g_context_creater(cf);
	if(conf->appctx != NULL){
		if(conf->appctx->cfg_init(config,conf)!=NGX_OK){
			return (char*)NGX_CONF_ERROR;
		}
	}
		
   	return NGX_CONF_OK;
}

static ngx_int_t  ngx_init_process(ngx_cycle_t *cycle)
{
	//printf("########### init_process ###############\n");
	ngx_tcp_server_srv_conf_t* conf =  (ngx_tcp_server_srv_conf_t*)ngx_get_conf(cycle->conf_ctx, ngx_tcp_server_module);
	if(conf->appctx != NULL){
		if(conf->appctx->ctx_init(cycle) == NGX_ERROR){
			return NGX_ERROR;
		}
	}
	
	return 0;
}

static void ngx_exit_process(ngx_cycle_t *cycle)
{
	ngx_tcp_server_srv_conf_t* conf =  (ngx_tcp_server_srv_conf_t*)ngx_get_conf(cycle->conf_ctx, ngx_tcp_server_module);
	if(conf->appctx != NULL){
		conf->appctx->destroy(cycle);
		delete conf->appctx; 
		conf->appctx = NULL;
	}
} 

void* ngx_tcp_palloc(ngx_pool_t* pool, size_t size,const char* file, int line){
	void* p = ngx_calloc(size, pool->log);
	return p;
}

void *ngx_tcp_realloc(ngx_pool_t *pool, void* p, size_t size,const char* file, int line)
{
	return realloc(p, size);
}

ngx_int_t ngx_tcp_pfree(ngx_pool_t *pool, void *p,const char* file, int line){
	ngx_free(p);
	return 0; 
}
