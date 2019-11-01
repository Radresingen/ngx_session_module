#ifndef _NGX_HTTP_SESSION_WORKER_PROCESS_H_INCLUDED_
#define _NGX_HTTP_SESSION_WORKER_PROCESS_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


ngx_int_t ngx_http_session_worker_process_init(ngx_cycle_t *cycle);
void ngx_http_session_worker_process_exit(ngx_cycle_t *cycle);

ngx_int_t ngx_http_session_handler(ngx_http_request_t *r);

#endif /* _NGX_HTTP_session_WORKER_PROCESS_H_INCLUDED_ */
