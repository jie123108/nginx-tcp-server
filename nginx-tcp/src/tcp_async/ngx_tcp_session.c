#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include "ngx_tcp_session.h"
#include "ngx_tcp.h"
#include "ngx_tcp_log.h"
#include "ngx_tcp_async_proc.h"
#include <errno.h>
#include <string.h>

#define TCP_MIN(a,b) ((a)<(b)?(a):(b))

ngx_int_t ngx_tcp_access_handler(ngx_connection_t *c,ngx_tcp_core_srv_conf_t     *cscf) ;
static void ngx_tcp_set_conn_socket(ngx_connection_t *c,ngx_tcp_core_srv_conf_t  *cscf) ;
static void ngx_tcp_server_read_handler(ngx_event_t *rev);
//static void ngx_tcp_server_write_handler(ngx_event_t *wev) ;
//static void ngx_tcp_send_rsp_data(ngx_event_t* wev);

void ngx_tcp_timeout_handler(ngx_event_t* to_ev){
	ngx_connection_t* c = (ngx_connection_t*)to_ev->data;
	ngx_tcp_data_t* data = (ngx_tcp_data_t*)c->data;
	uint sec = ngx_time()-data->lastkeepalivetm;
	ngx_tcp_core_srv_conf_t* tcsf = data->conf;
	if(tcsf == NULL)return;
	
	uint time_diff = tcsf->timeout-sec*1000;
	if(time_diff < 1000){// < one second,timeout
		LOG_DEBUG("######### client [%V] timeout #########", &c->addr_text);
		ngx_tcp_close_connection(c);
	}else{	
		LOG_DEBUG("######### change timeout timer (%ums) #########",time_diff);
		ngx_add_timer(&data->to_ev,time_diff);
	}
}

void ngx_tcp_first_timeout_handler(ngx_event_t* to_ev){
	ngx_connection_t* c = (ngx_connection_t*)to_ev->data;
	//ngx_tcp_data_t* data = (ngx_tcp_data_t*)c->data;
	ngx_event_del_timer(to_ev);

	LOG_WARN("######### wait client [%V] first msg timeout #########", &c->addr_text);
	ngx_tcp_close_connection(c);
}


void ngx_tcp_init_connection(ngx_connection_t *c)
{
	ngx_uint_t            i;
	ngx_tcp_port_t       *port;
	struct sockaddr      *sa;
	struct sockaddr_in   *sin;
	ngx_tcp_log_ctx_t    *ctx;
	ngx_tcp_in_addr_t    *addr;
	ngx_tcp_addr_conf_t  *addr_conf;
	ngx_tcp_core_srv_conf_t     *cscf;
#if (NGX_HAVE_INET6)
	struct sockaddr_in6  *sin6;
	ngx_tcp_in6_addr_t   *addr6;
#endif


	/* find the server configuration for the address:port */

	/* AF_INET only */

	port = (ngx_tcp_port_t*)c->listening->servers;

	if (port->naddrs > 1)
	{
		/*
		 * There are several addresses on this port and one of them
		 * is the "*:port" wildcard so getsockname() is needed to determine
		 * the server address.
		 *
		 * AcceptEx() already gave this address.
		 */

		if (ngx_connection_local_sockaddr(c, NULL, 0) != NGX_OK)
		{
		    ngx_tcp_close_connection(c);
		    return;
		}

		sa = c->local_sockaddr;

		switch (sa->sa_family)
		{

#if (NGX_HAVE_INET6)
		    case AF_INET6:
		        sin6 = (struct sockaddr_in6 *) sa;

		        addr6 = port->addrs;

		        /* the last address is "*" */

		        for (i = 0; i < port->naddrs - 1; i++)
		        {
		            if (ngx_memcmp(&addr6[i].addr6, &sin6->sin6_addr, 16) == 0)
		            {
		                break;
		            }
		        }

		        addr_conf = &addr6[i].conf;

		        break;
#endif

		    default: /* AF_INET */
		        sin = (struct sockaddr_in *) sa;

		        addr = (ngx_tcp_in_addr_t*)port->addrs;

		        /* the last address is "*" */

		        for (i = 0; i < port->naddrs - 1; i++)
		        {
		            if (addr[i].addr == sin->sin_addr.s_addr)
		            {
		                break;
		            }
		        }

		        addr_conf = &addr[i].conf;

		        break;
		}
	}
	else
	{
		switch (c->local_sockaddr->sa_family)
		{

#if (NGX_HAVE_INET6)
		    case AF_INET6:
		        addr6 = port->addrs;
		        addr_conf = &addr6[0].conf;
		        break;
#endif

		    default: /* AF_INET */
		        addr = (ngx_tcp_in_addr_t*)port->addrs;
		        addr_conf = &addr[0].conf;
		        break;
		}
	}

	if(c->sockaddr->sa_family==AF_INET){
		//u_char* pos=NULL;
		//struct sockaddr_in* sa = (struct sockaddr_in *)c->sockaddr;
		//pos = ngx_sprintf(c->clientaddr, "%s",inet_ntoa(sa->sin_addr));
		//ngx_sprintf(pos, ":%d", ntohs(sa->sin_port));
	}else{
		//ngx_sprintf(c->clientaddr,"%.*s", c->addr_text.len, c->addr_text.data);
	}

	cscf = (ngx_tcp_core_srv_conf_t*)ngx_tcp_get_module_srv_conf(addr_conf->ctx, ngx_tcp_core_module);
	if(ngx_tcp_access_handler(c, cscf) == NGX_ERROR)
	{
	    ngx_tcp_close_connection(c);
	    return;
	}  


	struct sockaddr_in* lsa = (struct sockaddr_in *)c->local_sockaddr;
	ngx_tcp_data_t* data = (ngx_tcp_data_t*)NGX_TCP_PALLOC(c->pool, sizeof(ngx_tcp_data_t));
	//LOG_DEBUG("new tcp data {0x%08x}", (long)data);
	c->data = data;
	data->conf = cscf;
	data->status = NS_ACCEPT;
	data->lastkeepalivetm = ngx_time();
	data->listen_port = ntohs(lsa->sin_port);
	g_tcp_set_callbacks(data);
	
	ngx_event_t     *to_ev = &data->to_ev;
	to_ev->data = c;
	to_ev->handler = &ngx_tcp_timeout_handler;
	to_ev->timer_set = 0;
	to_ev->log = c->log;
	ngx_add_timer(to_ev, cscf->timeout); 
	/*
	to_ev = &data->first_to_ev;
	to_ev->data = c;
	to_ev->handler = &ngx_tcp_first_timeout_handler;
	to_ev->timer_set = 0;
	to_ev->log = c->log;
	ngx_add_timer(to_ev, 1000); 
	*/
	LOG_DEBUG("[%d] client %V connected to [%d]", (int)ngx_getpid(),  
	         &c->addr_text, data->listen_port);
	//LOG_DEBUG("[%d] %u client %V connected to [%d], conns: %d/%d", ngx_getpid(), c->number,
	//         &c->addr_text, data->listen_port, ngx_process_conn->conns, ngx_conn_sum->conn_sum);

	ctx = (ngx_tcp_log_ctx_t*)ngx_palloc(c->pool, sizeof(ngx_tcp_log_ctx_t));
	if (ctx == NULL)
	{
		ngx_tcp_close_connection(c);
		return;
	}

	ctx->client = &c->addr_text;

	c->log->connection = c->number;
	c->log->handler = ngx_tcp_log_error;
	c->log->data = ctx;
	c->log->action = (char*)"nginx tcp module init connection";

	c->log_error = NGX_ERROR_INFO;

	c->write->handler = ngx_tcp_server_write_handler;
	c->read->handler = ngx_tcp_server_read_handler;
	ngx_tcp_set_conn_socket(c,cscf);

	//LOG_INFO("ngx_linux_sendfile_chain addr: 0x%08x", (int)&ngx_linux_sendfile_chain);
	//LOG_INFO("ngx_writev_chain:0x%08x", (int)&ngx_writev_chain);
	//LOG_INFO("ngx_aio_write_chain:0x%08x", (int)&ngx_aio_write_chain);

	if (ngx_handle_read_event(c->read, 0) != NGX_OK)
	{
		ngx_tcp_close_connection(c);
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
	ngx_tcp_core_srv_conf_t* conf = (ngx_tcp_core_srv_conf_t*)data->conf;
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
		req_data->req_header = data->protocbs.new_req_head(c->pool);
		req_data->header_len = 0;
	}
	NGX_RECV_STAT_T ret = RS_OK;
	do{
		size_t req_header_size = data->protocbs.req_head_size;
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
 				LOG_WARN("recv header from %V failed! errno:%d err:%s",&c->addr_text,
						errno, strerror_r(errno, errorinfo, sizeof(errorinfo)));
				break;
			}
			
			req_data->header_len += size;
			if(req_data->header_len < req_header_size){
				ret = RS_AGAIN;
				break;
			}else{//header recv ok..
				if(data->protocbs.preproc_req_header != NULL){
					int preret = data->protocbs.preproc_req_header(req_data);
					if(preret != 0){
						ret = RS_ERROR_REQ_INVALID;
						break;
					}
				}
			}
		}

		//recv body.
		size_t req_body_size = data->protocbs.get_req_body_size(req_data->req_header);
		if(req_body_size <= 0){
			break;
		}

		if(req_data->body == NULL){
			req_data->body = NGX_TCP_PALLOC(c->pool, req_body_size+1);
			req_data->body_len = 0;
		}

		if(req_data->body_len < req_body_size){
			while(1){
				size_t rest = TCP_MIN(req_body_size-req_data->body_len, 1024*4);
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
					LOG_ERROR("recv body from %s failed! errno:%d err:%V",&c->addr_text,
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

			if(data->protocbs.preproc_req_body != NULL){
				int preret = data->protocbs.preproc_req_body(req_data);
				if(preret != 0){
					ret = RS_ERROR_REQ_INVALID;
					break;
				}
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
	data->protocbs.set_rsp_code(data->rsp_data, ret);
	//LOG_ADDR(data->rsp_data);
	data->status = NS_SEND; 

	#if 1
	c->write->active = 0;
	c->write->ready = 0;
	//LOG_DEBUG("data {0x%08x} status:%d",data, data->status);
	c->write->handler = &ngx_tcp_server_write_handler;
	ret = ngx_handle_write_event(c->write, 0);
	if(ret != NGX_OK)
	{
	    LOG_ERROR("ngx_hendle_write_event: %d", ret);
	    ngx_tcp_close_connection(c);
	    data->status = NS_CLOSE;
	}
	#else
	ngx_tcp_send_rsp_data(c->write);
	#endif
	data->stat.all_end = ngx_second();
	data->stat.all = data->stat.all_end-data->stat.all_begin;
	if(data->protocbs.debug_stats != NULL){
		data->protocbs.debug_stats(data);
	}

	if(data->req_data != NULL){
		data->protocbs.free_req(c->pool, data->req_data);
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
		LOG_WARN("unexpected status [proc],proc_begin:%.4f cur:%.4f, cli:%V", 
			 	data->stat.all_begin, ngx_second(),&c->addr_text);
		return;
	case NS_SEND:
		c->error = 1;
		ngx_tcp_close_connection(c);
		data->status = NS_CLOSE;
		LOG_WARN("unexpected status [send], proc_begin:%.4f cur:%.4f, cli:%V", 
				data->stat.all_begin, ngx_second(),&c->addr_text);
		return; 
	break;
	case NS_CLOSE:
		LOG_ERROR(" ns_close status, cli:%V", &c->addr_text);
	break;
	}
	
	NGX_RECV_STAT_T rs = ngx_tcp_recv_msg(rev);
	switch(rs){
	case RS_AGAIN:
		if(data->protocbs.req_again != NULL){
			ret = data->protocbs.req_again(data->req_data);
			if(ret != 0){
				c->error = 1;
				//LOG_DEBUG("client %s close socked!", c->clientaddr);
				ngx_tcp_close_connection(c);
				data->status = NS_CLOSE;
				data->stat.all_end = ngx_second();
				data->stat.all = data->stat.all_end-data->stat.all_begin;
				data->stat.recv_req= ngx_second()-data->stat.recv_req;
			}
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
			//LOG_ERROR("recv message from %s failed! errno:%d err:%s",c->clientaddr,
			//	errno, strerror_r(errno, errorinfo, sizeof(errorinfo)));
		}else if(rs == RS_ERROR_REQ_INVALID){
			LOG_WARN("recv invalid message from %V !", &c->addr_text);
		}else if(rs == RS_TIMEDOUT){
			LOG_WARN("recv message from %V timedout!", &c->addr_text);
		}
		//ngx_tcp_close_connection(c);
		data->status = NS_CLOSE;
		data->stat.all_end = ngx_second();
		data->stat.all = data->stat.all_end-data->stat.all_begin;
		data->stat.recv_req= ngx_second()-data->stat.recv_req;
	}
	case RS_CLOSE:
		c->error = 1;
		//LOG_DEBUG("client %s close socked!", c->clientaddr);
		data->status = NS_CLOSE;
		data->stat.all_end = ngx_second();
		data->stat.all = data->stat.all_end-data->stat.all_begin;
		data->stat.recv_req= ngx_second()-data->stat.recv_req;
		ngx_tcp_close_connection(c);
	break;
	case RS_OK:
	{	
		if(data->protocbs.debug_req != NULL){
			data->protocbs.debug_req(data->req_data);
		}
		
		ngx_del_timer(rev);
		if(data->rsp_data != NULL){
			LOG_ERROR("### data->rsp_data != NULL ###");
			data->protocbs.free_rsp(c->pool, data->rsp_data);
			data->rsp_data = NULL;
		}

		data->stat.recv_req= ngx_second()-data->stat.recv_req;

		data->status = NS_PROC;
		data->rsp_data = (ngx_tcp_rsp_t*)NGX_TCP_PALLOC(c->pool, sizeof(ngx_tcp_rsp_t));
		data->rsp_data->rsp_header = data->protocbs.new_rsp_head(c->pool, data->req_data->req_header);
		data->rsp_data->c = c;
		data->rsp_data->tcp_data = data;
		data->rsp_data->isbigendian = data->req_data->isbigendian;
		data->rsp_data->rsp_send_times = 0;
		data->rsp_data->rsp_chain = NULL;
		data->rsp_data->rsp_rest = NULL;

#ifdef NOT_USE_ASYNC
		ngx_tcp_proc_sync(data);
#else
		if(data->conf->use_async){
			ngx_tcp_proc_async(data);
		}else{
			ngx_tcp_proc_sync(data);
		}
#endif 
	} 
	break;
	default:
		LOG_WARN("############## un processed status[%d] ###############", data->status);
	}
}


ngx_chain_t* ngx_tcp_send_chain(ngx_connection_t    *c,ngx_chain_t* chain){
	int i;
	//LOG_DEBUG("c->send_chain:0x%08x", (int)c->send_chain);
	ngx_chain_t* rest = chain;
	for(i=0;i < 200; i++){
		rest = c->send_chain(c, rest, 1024*4);
		if(rest == NGX_CHAIN_ERROR ||rest == NULL){
			return rest;
		}else{
			LOG_DEBUG("###### send resp to [%V] uncomplete rest:%p####", 
				&c->addr_text, rest);
		}
	}
	//if(i == 2000){
	//	LOG_ERROR("Send Response To [%s] not complete!", c->clientaddr);
	//}
	
	return rest;
}

static void ngx_tcp_server_empty_write_handler(ngx_event_t *wev){
	//LOG_INFO("############## empty write handler #############");
}

void ngx_tcp_server_write_handler(ngx_event_t *wev)
{
	ngx_connection_t    *c;
	c = (ngx_connection_t*)wev->data;
	ngx_tcp_data_t* data = (ngx_tcp_data_t*)c->data;

	//LOG_DEBUG("data {0x%08x} fd:%d ready:%d active:%d", (int)data, c->fd, wev->ready,wev->active);
	if(data->status!=NS_SEND){
		if(data->status == NS_DONE) return;
		LOG_ERROR("data {0x%08x} invalid status [%d] fd:%d ", 
					(long)data, data->status, c->fd);
		
		if(ngx_handle_write_event(wev, 0) != NGX_OK)
		{
			LOG_ERROR("ngx_handle_write_event error!");
			ngx_tcp_close_connection(c);
			data->status = NS_CLOSE;
		}
		//LOG_DEBUG("after handle write event: data {0x%08x} fd:%d ready:%d active:%d", (long)data, c->fd, wev->ready,wev->active);
	
		return;
	}
	
	do{
		if(data->rsp_data == NULL){
			LOG_ERROR("###### rsp data is null! ######");
			break;
		}else{
			//LOG_DEBUG("fd[%d] data {0x%08x} write response rsp header:0x%08x, body:0x%08x", 
			//c->fd, (long)data,  (long)rsp->rsp_header, (long)rsp->body);
		}

		ngx_tcp_rsp_t* rsp = (ngx_tcp_rsp_t*)data->rsp_data;
		if(rsp->rsp_chain == NULL){
			size_t rsp_body_size = 0;
			ngx_chain_t* header = rsp->rsp_chain = rsp->rsp_rest =
					(ngx_chain_t*)NGX_TCP_PALLOC(c->pool, sizeof(ngx_chain_t));

			if(data->protocbs.debug_rsp != NULL){
				data->protocbs.debug_rsp(data->rsp_data);
			}

			rsp_body_size = data->protocbs.get_rsp_body_size(rsp->rsp_header);
			
			//LOG_ADDR(header);
			//LOG_ADDR(header->buf);
			//LOG_ADDR(rsp->rsp_header);
			if(data->protocbs.preproc_rsp_header != NULL){
				data->protocbs.preproc_rsp_header(rsp);
			}		
			header->buf = (ngx_buf_t*)NGX_TCP_PALLOC(c->pool, sizeof(ngx_buf_t));
			header->buf->pos = header->buf->start = (u_char*)rsp->rsp_header;
			header->buf->last = header->buf->end = 
				(u_char*)header->buf->pos + data->protocbs.rsp_head_size;
			header->buf->memory = 1;

			if(rsp->body != NULL){
				ngx_chain_t* body = NULL;
				if(data->protocbs.preproc_rsp_body != NULL){
					data->protocbs.preproc_rsp_body(rsp);
				}
				
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
			//LOG_DEBUG("send response success!");
		}else if(rsp->rsp_rest == NGX_CHAIN_ERROR){
			c->error = 1;
			LOG_ERROR("send resp to[%V] failed!", &c->addr_text);
			ngx_tcp_close_connection(c);
		}else{//发送不完整。
			//c->error = 1;
			//ngx_tcp_close_connection(c);
			if(rsp->rsp_send_times < 100){
				LOG_WARN("Send Response To [%V] not complete! times: %d", 
						&c->addr_text, rsp->rsp_send_times);
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
				    LOG_ERROR("ngx_hendle_write_event: %d", ret);
					ngx_tcp_close_connection(c);
				    data->status = NS_CLOSE;
					break;
				}
			}else{
				c->error = 1;
				LOG_ERROR("Send Response To [%V] failed! times:%d",
					&c->addr_text,
					rsp->rsp_send_times);
				ngx_tcp_close_connection(c);
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
		data->protocbs.free_rsp(c->pool, data->rsp_data);
		data->rsp_data = NULL;
	}
}

static void
ngx_tcp_set_conn_socket(ngx_connection_t *c,ngx_tcp_core_srv_conf_t  *cscf)
{
    int                       keepalive;
    int                       tcp_nodelay;

    if (cscf->so_keepalive)
    {
        keepalive = 1;

        if (setsockopt(c->fd, SOL_SOCKET, SO_KEEPALIVE,
                       (const void *) &keepalive, sizeof(int)) == -1)
        {
            ngx_log_error(NGX_LOG_ALERT, c->log, ngx_socket_errno,
                          "setsockopt(SO_KEEPALIVE) failed");
        }
    }

    if (cscf->tcp_nodelay)
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


// void ngx_tcp_close_connection(ngx_connection_t *c)

void ngx_tcp_close_connection_(ngx_connection_t *c, const char* func, int line)
{

#if (NGX_STAT_STUB)
	(void) ngx_atomic_fetch_add(ngx_stat_active, -1);
#endif

	c->destroyed = 1;
	
	ngx_pool_t  *pool = c->pool;
	if(c->data != NULL){
		ngx_tcp_data_t* data = (ngx_tcp_data_t*)c->data;
		if(data->to_ev.timer_set){
			ngx_del_timer(&data->to_ev);
		}
		if(data != NULL){
			if(data->req_data != NULL){
				data->protocbs.free_req(c->pool, data->req_data);
				data->req_data = NULL;
			}
			if(data->rsp_data != NULL){
				data->protocbs.free_rsp(c->pool, data->rsp_data);
				data->rsp_data = NULL;
			} 
			if(data->userdata != NULL){
				NGX_TCP_PFREE(pool, data->userdata);
			}
			
			NGX_TCP_PFREE(pool, data);
		}
		c->data = NULL;
	}
	
	ngx_close_connection(c);

	LOG_DEBUG("[%d] close client [%V] connection in [%s:%d]", 
			ngx_getpid(), &c->addr_text, func, line);
	//LOG_DEBUG("[%d] close client [%V] connection, conns:%d/%d", ngx_getpid(), &c->addr_text,
	//		ngx_process_conn->conns, ngx_conn_sum->conn_sum);

	ngx_destroy_pool(pool);
}


u_char *
ngx_tcp_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char              *p;
    ngx_tcp_log_ctx_t   *ctx;

    if (log->action)
    {
        p = ngx_snprintf(buf, len, " while %s", log->action);
        len -= p - buf;
        buf = p;
    }

    ctx = (ngx_tcp_log_ctx_t*)log->data;

    p = ngx_snprintf(buf, len, ", client: %V", ctx->client);
    len -= p - buf;
    buf = p;

    return p;
}


ngx_int_t ngx_tcp_access_handler(ngx_connection_t *c,ngx_tcp_core_srv_conf_t     *cscf)
{
    ngx_uint_t                   i;
    struct sockaddr_in          *sin;
    ngx_tcp_access_rule_t       *rule;

    if (cscf->rules == NULL)
    {
        return NGX_DECLINED;
    }

    /* AF_INET only */

    if (c->sockaddr->sa_family != AF_INET)
    {
        return NGX_DECLINED;
    }

    sin = (struct sockaddr_in *) c->sockaddr;

    rule = (ngx_tcp_access_rule_t*)cscf->rules->elts;
    for (i = 0; i < cscf->rules->nelts; i++)
    { 
        if ((sin->sin_addr.s_addr & rule[i].mask) == rule[i].addr)
        {
            if (rule[i].deny)
            {
                LOG_WARN("deny client [%s]", inet_ntoa(sin->sin_addr));
                return NGX_ERROR;
            }

            return NGX_OK;
        }
    }

    return NGX_DECLINED;
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

//#include "impl/def_impl.c"

