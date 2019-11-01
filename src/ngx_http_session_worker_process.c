#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_upstream.h>
#include <nginx.h>

#include <unistd.h>
#include <syslog.h>
#include <sys/file.h>

#include "ngx_http_session_hash.h"
#include "ngx_http_session_module.h"
#include "ngx_http_session_common.h"
#include "ngx_http_session_worker_process.h"

static time_t worker_process_timer_interval;    /* In seconds */
static ngx_flag_t worker_process_timer_perturb;

static ngx_event_t                  write_out_ev;
static ngx_uint_t                   *isfinded = NULL;
static ngx_int_t                    ngx_http_session_old_time = 0;
static ngx_int_t                    ngx_http_session_new_time = 0;
static ngx_str_t                    ngx_http_session_log;
static ngx_fd_t                     ngx_http_session_log_fd = NGX_INVALID_FILE;
static u_char                       *ngx_http_session_title = (u_char *)"Ngxsession";
static ngx_http_session_hash_t      *hash;



static void worker_process_alarm_handler(ngx_event_t *ev);
//static ngx_str_t *get_session_id(ngx_http_request_t *r);


ngx_int_t
ngx_http_session_worker_process_init(ngx_cycle_t *cycle)
{
    ngx_int_t                       rc;
    ngx_time_t                      *time;
    ngx_http_session_main_conf_t    *amcf;
    



    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cycle->log, 0,"http session init worker");

    amcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_session_module);
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cycle->log, 0,"http session init worker1");
    if (!amcf->enable) {
        return NGX_OK;
    }
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cycle->log, 0,"http session init worker2");
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cycle->log, 0,"http session init worker3");
    time = ngx_timeofday();
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cycle->log, 0,"http session init worker4");
    ngx_http_session_old_time = time->sec;
    ngx_http_session_new_time = time->sec;
    ngx_http_session_log = amcf->log;
    worker_process_timer_interval = amcf->interval;
    worker_process_timer_perturb = amcf->perturb;
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cycle->log, 0,"http session init worker5");
    openlog((char *)ngx_http_session_title, LOG_NDELAY, LOG_SYSLOG);
    syslog(LOG_INFO, "pid:%i|Process:init", ngx_getpid());
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cycle->log, 0,"http session init worker6");
    //rc = ngx_http_session_hash_init(hash, NGX_HTTP_SESSION_NR_BUCKETS, cycle->pool, cycle);
    if (rc != NGX_OK) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cycle->log, 0,"http session init worker >> session_hash_init PROBLEM");
        return rc;
    }
    
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cycle->log, 0,"http session init worker << finished");
    return NGX_OK;
}


void ngx_http_session_worker_process_exit(ngx_cycle_t *cycle)
{
    ngx_http_session_main_conf_t *amcf;

    amcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_session_module);

    if (!amcf->enable) {
        return;
    }

    

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, cycle->log, 0,"http session worker process exit pid: %i",ngx_getpid());
}

ngx_int_t
ngx_http_session_handler(ngx_http_request_t *r)
{
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "process id : %i",getpid());
    //ngx_str_t      *session_id;
    ngx_uint_t                          key;
    ngx_uint_t                          status;
    ngx_uint_t                          *status_array;
    ngx_uint_t                          ses_flag=0;
    ngx_http_session_loc_conf_t         *lccf;
    ngx_shm_zone_t                      *shm_zone_worker;
    
    lccf = ngx_http_get_module_loc_conf(r,ngx_http_session_module);

  	shm_zone_worker = lccf->shm_zone_workers;

    hash = shm_zone_worker->data;

 	char *sidf;
	char * sesid;
	ngx_str_t	sessionID;
	ngx_uint_t   i=0;
 	
     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "TEST");
     
 	//if(ngx_strstr(r->uri.data,"m3u8") != NULL){
	    
        if (r->args.data != NULL) {
		    sidf = ngx_strstr(r->args.data, "SessionID=");
		    if(sidf != NULL){
		 	    /*for (i = 0; i < 24; i++) {
			        sesid[i] = *(sidf + 10 + i);
			    }*/
                char * firstchar = sidf;
                while(*(sidf+10) != ' ' && *(sidf + 10) != '&'){
                    sidf++;
                    i++;
                }
                int k;
                sesid = malloc((i+1)*sizeof(char));
                for(k=0;k<i;k++){
                    sesid[k] = *(firstchar + 10 + k);
                }
                sesid[i] = '\0';
                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "pointer to char array suc");
                ngx_str_set(&sessionID, sesid);
                sessionID.len = i -1;
	 		    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "SESID: %s LEN: %i", sessionID.data, sessionID.len);
                 ses_flag = 1;
		    }


            
	    }
    //}

    ngx_time_t * time = ngx_timeofday();

    //session_id = get_session_id(r);

    ngx_uint_t req_latency_ms = (time->sec * 1000 + time->msec) - (r->start_sec * 1000 + r->start_msec);

    // following magic airlifted from ngx_http_upstream.c:4416-4423
    ngx_uint_t upstream_req_latency_ms = 0;
    ngx_http_upstream_state_t  *state;

    if (r->upstream_states != NULL && r->upstream_states->nelts != 0) {
        state = r->upstream_states->elts;
        if (state[0].status) {
            // not even checking the status here...
			#if (nginx_version < 1009000)
			upstream_req_latency_ms = (state[0].response_sec * 1000 + state[0].response_msec);
			#else
			upstream_req_latency_ms = state[0].response_time;
			#endif
        }
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "before pointer");
    ngx_str_t *sessionptr = &sessionID;
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "after pointer");
    //ngx_str_set(sessionptr,sessionID.data);
    if(i == 0 ){
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "LEN ERROR %i i %i",sessionID.len,i);
        sessionptr = NULL;
        goto END;
    }
    // TODO: key should be cached to save CPU time
    else{
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "LEN %s",sessionptr->data);
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "LEN %i",sessionptr->len);
    }
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "sessionPTR to function data : %s len %i",sessionID.data,sessionID.len);
    key = ngx_hash_key_lc(sessionptr->data, sessionptr->len);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "KEY %i",key);
    if(ses_flag){
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "go to hash find %i",sessionID.len);
            isfinded = ngx_http_session_hash_find(hash,key, sessionID.data, sessionID.len,r);
            ses_flag = 0;
        }
    else{
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "go to end ");
        goto END;
    }

    if (isfinded == NULL && sessionptr != NULL) {           
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"http session worker going to hash_add %i",sessionID.len);
        ngx_http_session_hash_add(hash,key, sessionID.data, sessionID.len,r);
        
    }

    if (r->err_status) {
        status = r->err_status;
    } else if (r->headers_out.status) {
        status = r->headers_out.status;
    } else {
        status = 0;
    }

    
    //////////////////////////////////////////////////////////////////////////////////
  	//ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"requested path: %s", r->uri.data);
                           
	//////////////////////////////////////////////////////////////////////////////////
END:
    sessionID.len = 0;
	return NGX_OK;
}




static void
worker_process_alarm_handler(ngx_event_t *ev)
{
    ngx_time_t  *time;
    ngx_msec_t   next;

    time = ngx_timeofday();

    ngx_http_session_old_time = ngx_http_session_new_time;
    ngx_http_session_new_time = time->sec;

    if (ngx_http_session_log.len) {
        ngx_http_session_log_fd = ngx_open_file(ngx_http_session_log.data, NGX_FILE_APPEND, NGX_FILE_CREATE_OR_OPEN, NGX_FILE_DEFAULT_ACCESS);
        if (ngx_http_session_log_fd == NGX_INVALID_FILE) {
            syslog(LOG_INFO, "Invalid file: %s", ngx_http_session_log.data);
        }
        if (flock(ngx_http_session_log_fd, LOCK_EX|LOCK_NB) == -1) {
            return; // In the unlikely case that the lock cannot be obtained we will try again on the next alarm
        }
    }

    //ngx_http_session_hash_iterate(&stats_hash, worker_process_write_out_stats, NULL, NULL);

    if (ngx_http_session_log_fd != NGX_INVALID_FILE) {
        ngx_close_file(ngx_http_session_log_fd);
        ngx_http_session_log_fd = NGX_INVALID_FILE;
    }

    if (ngx_exiting || ev == NULL)
        return;

    next = (ngx_msec_t)worker_process_timer_interval * 1000;

    ngx_add_timer(ev, next);
}


static ngx_str_t *
get_session_id(ngx_http_request_t *r)
{
    ngx_http_session_loc_conf_t  *alcf;
    ngx_http_variable_value_t       *vv;
    static ngx_str_t session_id;

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_session_module);

    if (alcf->index > 0) {
        vv = ngx_http_get_indexed_variable(r, alcf->index);

        if ((vv != NULL) && (!vv->not_found)) {
            session_id.len = vv->len;
            session_id.data = vv->data;
            return &session_id;
        }
    }
    
    return &alcf->session_id;
}
