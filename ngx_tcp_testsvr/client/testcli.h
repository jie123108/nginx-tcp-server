#ifndef __MSG_ONLINE_CLI_H__
#define __MSG_ONLINE_CLI_H__
#include "../mylib/Sockcli.h"
#include "../test_protocol.h"

#define ERRNO_SOCK_ERR 100 //ÍøÂç´íÎó¡£



int cli_test_init(client_ctx_t* ctx);
int cli_test_add(client_ctx_t* ctx, int n, int* result);
int cli_test_sub(client_ctx_t* ctx, int n, int* result);
int cli_test_query(client_ctx_t* ctx, int* result);
int cli_test_sleep(client_ctx_t* ctx, int second);

#endif
