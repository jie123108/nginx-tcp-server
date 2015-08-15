#ifndef __BASELIB_MYSQL_POOL_H__
#define __BASELIB_MYSQL_POOL_H__
#include "ngx_log_mod.h"
#include "ConnPool.h"
#include <errmsg.h>
#include <assert.h>
#include <mysqld_error.h>
#include <mysql.h>
#include "IniFile.h"

#ifndef DEFINED_MYSQL_CONFIG_T
typedef struct mysql_config_t{
	char host[64];
	int port;
	char database[64];
	char username[64];
	char password[64];
	int conns;//最大连接数。
	int timeout; //超时时间(秒)，默认1
}mysql_config_t;
#endif

#define DEF_MYSQL_SECTION  "mysql"

inline bool mysql_config_read(CIniFile* pIniConfig, mysql_config_t* pconfig, const char* section)
{
	memset(pconfig,0, sizeof(mysql_config_t));
	if(section == NULL){
		section = DEF_MYSQL_SECTION;
	}
		
	string tmp = pIniConfig->GetValue(section, "host", "127.0.0.1");
	strncpy(pconfig->host, tmp.c_str(), sizeof(pconfig->host));

	pconfig->port = pIniConfig->GetValueI(section, "port", 3306);

	tmp = pIniConfig->GetValue(section, "username", "root");
	strncpy(pconfig->username, tmp.c_str(), sizeof(pconfig->username));

	tmp = pIniConfig->GetValue(section, "password", "");
	strncpy(pconfig->password, tmp.c_str(), sizeof(pconfig->password));

	tmp = pIniConfig->GetValue(section, "database", "mysql");
	strncpy(pconfig->database, tmp.c_str(), sizeof(pconfig->database));

	pconfig->conns = pIniConfig->GetValueI(section, "conns", 1);

	pconfig->timeout = pIniConfig->GetValueI(section, "timeout", 1);
	
	return true;

}


inline void* mysql_new_cb(void* args){
	return mysql_init(NULL);
}

inline int mysql_connect_cb(void* conn,void* args)
{
	MYSQL* mysql = (MYSQL*)conn;
	int ret = 0;
	mysql_config_t* c = (mysql_config_t*)args;
	int recon = 1;

	if(c->timeout >0){
		mysql_options(mysql, MYSQL_OPT_CONNECT_TIMEOUT, (char *)&c->timeout);
	}
	
	mysql_options(mysql, MYSQL_OPT_RECONNECT, (char *)&recon);
	if((mysql=mysql_real_connect(mysql, c->host, c->username,c->password, c->database, c->port, 
			NULL, CLIENT_MULTI_STATEMENTS|CLIENT_MULTI_RESULTS)) == NULL){//连接失败
		NLOG_ERROR("use user '%s' Connect To Mysql %s:%d/%s failed! err: %s", 
						c->username, c->host, c->port, c->database,
						mysql_error(mysql));
		ret = -1;
	}else{
		//mysql_query(mysql, "set names utf8");
		ret = mysql_set_character_set(mysql, "utf8");
		if(ret != 0){
			NLOG_ERROR("mysql_set_character_set(utf8) failed! ret=%d", ret);
		}
	}

	return ret;
}

inline int mysql_reconnect_cb(void* conn,void* args)
{
	MYSQL* mysql = (MYSQL*)conn;
	return mysql_ping(mysql);
}

inline int mysql_close_cb(void* conn)
{
	return 0;
}

inline int mysql_test_close_cb(void* conn){ //测试是否需要关闭连接(在连接出错的情况下) 0:不需要关闭，1:需要关闭
	MYSQL* mysql = (MYSQL*)conn;
	int err = mysql_errno(mysql);
	if(err == CR_SERVER_GONE_ERROR || err == ER_QUERY_INTERRUPTED
		|| err == CR_SERVER_LOST){
		return 1;
	}
	return 0;
}
inline void mysql_free_cb(void* conn){
	if(conn != NULL){
		MYSQL* mysql = (MYSQL*)conn;
		mysql_close(mysql);	
	}
}

inline conn_pool_t* mysql_pool_new(int size,mysql_config_t* config)
{

	conn_cb_t cbs ={&mysql_new_cb,
					&mysql_free_cb,
					&mysql_connect_cb,
					&mysql_close_cb,
					&mysql_test_close_cb};
	return conn_pool_new(size, 1, &cbs, config);
}

inline void mysql_pool_free(conn_pool_t* pool)
{
	conn_pool_free(pool);
}

inline MYSQL* mysql_pool_get(conn_pool_t* pool)
{
	return (MYSQL*)conn_pool_get(pool);
}

inline int mysql_pool_put(conn_pool_t* pool, MYSQL* conn, int real_close=0)
{
	return conn_pool_put(pool, conn,real_close);
}

/**
 * 连接池是否可用。(有一个连接可用就表示可用，如果所有连接都不可用，表示不可用)
 * 1:表示是活的，0:表示已经死了。
 */
inline int mysql_pool_alived(conn_pool_t* pool){
	int i, isalived=0;
	for(i=0;i<pool->size; i++){
		MYSQL* mysql = mysql_pool_get(pool);
		if(mysql != NULL){
			if(mysql_ping(mysql) == 0){
				isalived = 1;
			}
			mysql_pool_put(pool, mysql);
			if(isalived) break;
		}
	}

	return isalived;
}

#endif

