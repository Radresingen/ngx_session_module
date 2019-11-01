#ifndef _NGX_HTTP_SESSION_MODULE_H_INCLUDED_
#define _NGX_HTTP_SESSION_MODULE_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define DEFAULT_INDEX -128

typedef struct {
    ngx_str_t       session_id;
    ngx_int_t       index;
    ngx_shm_zone_t *shm_zone;
    //worker processler için shared memory zone
    ngx_shm_zone_t *shm_zone_workers;   
} ngx_http_session_loc_conf_t;

typedef struct {
    ngx_flag_t      enable;
    ngx_str_t       log;
    time_t          interval;
    ngx_flag_t      perturb;
} ngx_http_session_main_conf_t;

typedef struct {
	ngx_uint_t		session_id_count;
} ngx_http_session_shm_ctx;

extern ngx_module_t ngx_http_session_module;

#endif /* _NGX_HTTP_SESSION_MODULE_H_INCLUDED_ */
