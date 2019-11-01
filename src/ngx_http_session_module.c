#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_session_hash.h"
#include "ngx_http_session_common.h"
#include "ngx_http_session_module.h"
#include "ngx_http_session_worker_process.h"

static ngx_int_t ngx_http_session_init(ngx_conf_t *cf);

static ngx_int_t ngx_http_session_process_init(ngx_cycle_t *cycle);
static void ngx_http_session_process_exit(ngx_cycle_t *cycle);

static void *ngx_http_session_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_session_init_main_conf(ngx_conf_t *cf, void *conf);

static void *ngx_http_session_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_session_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static char *ngx_http_session_set_session_id(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_http_session_init_zone(ngx_shm_zone_t *shm_zone, void *data);
static ngx_int_t ngx_http_session_init_worker_zone(ngx_shm_zone_t *shm_zone, void *data);

static char *ngx_http_sample_module_command(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_command_t  ngx_http_session_commands[] = {
    { ngx_string("http_session"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_session_main_conf_t, enable),
      NULL},
    { ngx_string("http_session_id"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
                        |NGX_CONF_TAKE1,
      ngx_http_session_set_session_id,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},
    { ngx_string("http_session_interval"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_session_main_conf_t, interval),
      NULL},
    { ngx_string("http_session_perturb"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_session_main_conf_t, perturb),
      NULL},
     { ngx_string("http_session_stats"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_sample_module_command,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
    { ngx_string("http_session_log"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_session_main_conf_t, log),
      NULL},
      
    ngx_null_command
};


static ngx_http_module_t  ngx_http_session_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_http_session_init,               /* postconfiguration */
    ngx_http_session_create_main_conf,   /* create main configuration */
    ngx_http_session_init_main_conf,     /* init main configuration */
    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */
    ngx_http_session_create_loc_conf,    /* create location configuration */
    ngx_http_session_merge_loc_conf      /* merge location configuration */
};


ngx_module_t ngx_http_session_module = {
    NGX_MODULE_V1,
    &ngx_http_session_ctx,               /* module context */
    ngx_http_session_commands,           /* module directives */
    NGX_HTTP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    ngx_http_session_process_init,       /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    ngx_http_session_process_exit,       /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_session_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt              *h;
    ngx_http_core_main_conf_t        *cmcf;
    ngx_http_session_main_conf_t  *amcf;

    amcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_session_module);
    if (!amcf->enable) {
        return NGX_OK;
    }

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_session_handler;

    return NGX_OK;
}


static ngx_int_t
ngx_http_session_process_init(ngx_cycle_t *cycle)
{
    return ngx_http_session_worker_process_init(cycle);
}


static void
ngx_http_session_process_exit(ngx_cycle_t *cycle)
{
	return ngx_http_session_worker_process_exit(cycle);
}


static void *
ngx_http_session_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_session_main_conf_t  *amcf;

    amcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_session_main_conf_t));
    if (amcf == NULL) {
        return NULL;
    }

    amcf->enable = NGX_CONF_UNSET;
    amcf->interval = NGX_CONF_UNSET;
    amcf->perturb = NGX_CONF_UNSET;

    return amcf;
}


static char *
ngx_http_session_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_session_main_conf_t *amcf = conf;

    if (amcf->enable == NGX_CONF_UNSET) {
      amcf->enable = 0;
    }
    if (amcf->interval == NGX_CONF_UNSET) {
      amcf->interval = 60;
    }
    if (amcf->perturb == NGX_CONF_UNSET) {
      amcf->perturb = 0;
    }
    
    return NGX_CONF_OK;
}


static void *
ngx_http_session_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_session_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_session_loc_conf_t));
    if(conf == NULL) {
        return NULL;
    }

    return conf;
}


static char *
ngx_http_session_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_shm_zone_t *shm_zone;
    ngx_shm_zone_t *shm_zone_worker;
    ngx_str_t *shm_name;
    ngx_str_t *shm_name_worker;
    ngx_http_session_loc_conf_t *prev = parent;
    ngx_http_session_loc_conf_t *conf = child;

    ngx_conf_merge_str_value(conf->session_id, prev->session_id, "default");
    if (conf->index == 0) { // session_id is not set in current location
        conf->index = prev->index;
    }

	shm_name = ngx_palloc(cf->pool, sizeof *shm_name);
  shm_name->len = sizeof("shared_memory") - 1;
  shm_name->data = (unsigned char *) "shared_memory";
  shm_zone = ngx_shared_memory_add(cf, shm_name, 8 * ngx_pagesize, &ngx_http_session_module);

 	if(shm_zone == NULL){
    return NGX_CONF_ERROR;
 	}
  //worker shared memory initialization
  shm_name_worker = ngx_palloc(cf->pool, sizeof *shm_name_worker);
  shm_name_worker->len = sizeof("shared_memory_workers") - 1;
  shm_name_worker->data = (unsigned char *)"shared_memory_workers";
  shm_zone_worker = ngx_shared_memory_add(cf, shm_name_worker, 1024 * ngx_pagesize, &ngx_http_session_module);

  shm_zone->init = ngx_http_session_init_zone;
  shm_zone_worker->init = ngx_http_session_init_worker_zone;

  conf->shm_zone = shm_zone;
  conf->shm_zone_workers = shm_zone_worker;

	ngx_conf_merge_ptr_value(conf->shm_zone, prev->shm_zone, NULL);
  ngx_conf_merge_ptr_value(conf->shm_zone_workers, prev->shm_zone_workers, NULL);
    return NGX_CONF_OK;
}

static char *
ngx_http_session_set_session_id(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_session_loc_conf_t *alcf = conf;
    ngx_str_t                 *value;

    value = cf->args->elts;

    if (value[1].data[0] == '$') {
        value[1].len--;
        value[1].data++;

        alcf->index = ngx_http_get_variable_index(cf, &value[1]);
        if (alcf->index == NGX_ERROR) {
            return NGX_CONF_ERROR;
        }
        alcf->session_id = value[1];
        return NGX_CONF_OK;
    }

    alcf->session_id = value[1];
    alcf->index = DEFAULT_INDEX;
    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_session_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
	ngx_slab_pool_t                *shpool;
	ngx_http_session_shm_ctx	   *reqn;
	
   if (data) { 
                shm_zone->data = data;
                return NGX_OK;
    }
        
    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
	reqn = ngx_slab_alloc(shpool, sizeof(*reqn));

	reqn->session_id_count = 0;
	shm_zone->data = reqn;          
    return NGX_OK;
}

static ngx_int_t
ngx_http_session_init_worker_zone(ngx_shm_zone_t *shm_zone, void *data)
{
	ngx_slab_pool_t                *shpool;
    ngx_http_session_hash_t        *hash;

   //bir önceki cycle ın shared zone nunu tekrar kullanıyorsan return et 
   if (data) { 
                shm_zone->data = data;
                return NGX_OK;
    }
    //ilk önce hash_t struct ı için shared memoryden yer alıyoruz    
    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
	hash = ngx_slab_alloc(shpool, sizeof(*hash));

    hash->size = NGX_HTTP_SESSION_NR_BUCKETS;
    hash->pool = shpool;
    hash->buckets = ngx_slab_alloc(shpool,sizeof(ngx_array_t *) * hash->size);
        
    shm_zone->data = hash;          
    return NGX_OK;
}


static ngx_int_t
ngx_http_sample_handler(ngx_http_request_t *r)
{
  	ngx_atomic_int_t           accepted, handled, active, request, reading, writing,waiting;
    ngx_uint_t                  nsessionID;
	ngx_shm_zone_t              *shm_zone;
  	ngx_http_session_loc_conf_t *lccf;
  	
    accepted = *ngx_stat_accepted;
    handled  = *ngx_stat_handled;
    active   = *ngx_stat_active;
    request  = *ngx_stat_requests;
    reading  = *ngx_stat_reading;
    writing  = *ngx_stat_writing;
    waiting  = *ngx_stat_waiting;
    
  	lccf = ngx_http_get_module_loc_conf(r, ngx_http_session_module);

  	shm_zone = lccf->shm_zone;
    nsessionID = ((ngx_http_session_shm_ctx *)shm_zone->data)->session_id_count;

   
  	char ngx_hello_world[512];
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "BEFORE SPRINTF");
  	sprintf(ngx_hello_world,"VERSION 1.1\nACCEPTED: %u\nHANDLED: %u\nACTIVE: %u\nREQUEST: %u\nREADING: %u\nWRITING: %u\nWAITING: %u\nNUMBER OF SESSIONS: %u\n",accepted
      ,handled,active,request,reading,writing,waiting,nsessionID);
  	//u_char *ngx_hello_world = (u_char *) "Hello World!";
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "AFTER SPRINTF");
  	
  	size_t sz = ngx_strlen(ngx_hello_world);

	r->headers_out.content_type.len = ngx_strlen("text/html") - 1;
	r->headers_out.content_type.data = (u_char *) "text/html";
	r->headers_out.status = NGX_HTTP_OK;
	r->headers_out.content_length_n = sz;
	ngx_http_send_header(r);

	ngx_buf_t    *b;
	ngx_chain_t   *out;

	b = ngx_calloc_buf(r->pool);

	out = ngx_alloc_chain_link(r->pool);

	out->buf = b;
	out->next = NULL;

	b->pos = (u_char *) ngx_hello_world;
	b->last = (u_char *) ngx_hello_world + sz;
	b->memory = 1;
	b->last_buf = 1;

	return ngx_http_output_filter(r, out);
} 
  	


static char *
ngx_http_sample_module_command(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_sample_handler;

    return NGX_CONF_OK;
}
