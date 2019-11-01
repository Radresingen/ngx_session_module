#ifndef _NGX_HTTP_SESSION_HASH_H_INCLUDED_
#define _NGX_HTTP_SESSION_HASH_H_INCLUDED_

#include "ngx_http_session_module.h"
#include <ngx_config.h>
#include <ngx_core.h>


typedef struct {
    ngx_array_t       **buckets;
    ngx_uint_t        size;
    ngx_slab_pool_t   *pool;
} ngx_http_session_hash_t;


ngx_int_t ngx_http_session_hash_init(ngx_http_session_hash_t *hash,
        ngx_uint_t nr_buckets, ngx_pool_t *pool,ngx_cycle_t *cycle);

ngx_int_t ngx_http_session_hash_add(ngx_http_session_hash_t *hash,ngx_uint_t key, u_char *name, size_t len,ngx_http_request_t *r);

void * ngx_http_session_hash_find(ngx_http_session_hash_t *hash,ngx_uint_t key, u_char *name, size_t len,ngx_http_request_t *r);

#endif /* _NGX_HTTP_session_HASH_H_INCLUDED_ */
