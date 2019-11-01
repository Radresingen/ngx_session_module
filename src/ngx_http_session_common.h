#ifndef _NGX_HTTP_SESSION_COMMON_H_INCLUDED_
#define _NGX_HTTP_SESSION_COMMON_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>


#define SESSION_ID_MAX_LEN               10
#define NGX_HTTP_SESSION_NR_BUCKETS      107

typedef struct {
    ngx_uint_t       nr_requests;
    ngx_uint_t       bytes_in;
    ngx_uint_t       bytes_out;
    ngx_uint_t       total_latency_ms;
    ngx_uint_t       total_upstream_latency_ms;
} ngx_http_session_stats_t;

#endif /* _NGX_HTTP_SESSION_COMMON_H_INCLUDED_ */
