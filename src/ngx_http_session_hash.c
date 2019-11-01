#include <ngx_config.h>
#include <ngx_core.h>


#include "ngx_http_session_hash.h"
#include "ngx_http_session_common.h"

typedef struct {
    ngx_time_t       *time_to_live;
    ngx_uint_t       ignore;
    u_char           len;
    u_char           *name;
} ngx_http_session_hash_elt_t;

void * ngx_array_session_push(ngx_array_t *a);
ngx_int_t
ngx_http_session_hash_init(ngx_http_session_hash_t *hash,
        ngx_uint_t nr_buckets, ngx_pool_t *pool,ngx_cycle_t *cycle)
{
    hash->size = nr_buckets;
    hash->pool = pool;
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cycle->log, 0,"http session hash init1");
    hash->buckets = ngx_pcalloc(pool, sizeof(ngx_array_t *) * hash->size);
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cycle->log, 0,"http session hash init2");
    if (hash->buckets == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cycle->log, 0,"http session hash init3");
        return NGX_ERROR;
    }
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cycle->log, 0,"http session hash init4");
    return NGX_OK;
}

ngx_int_t
ngx_http_session_hash_add(ngx_http_session_hash_t *hash,ngx_uint_t key, u_char *name, size_t len,ngx_http_request_t *r)
{

    ngx_array_t                 *bucket;
    ngx_http_session_hash_elt_t *elt;
    ngx_http_session_hash_elt_t *elts;
    ngx_http_session_loc_conf_t *lccf;
    ngx_shm_zone_t              *shm_zone_worker;
    void *data;
    ngx_time_t *time_to_live;
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"http session hash add function start ");
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"http session hash add function GET LOC CONF ");

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"http session hash add function GET BUCKET ");
    bucket = hash->buckets[key % hash->size];
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"http session hash add function hash->buckets[key % hash->size] ptr : %p",&(hash->buckets[key % hash->size]));
    if (bucket == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"http session hash add function BUCKET NULL ");
        bucket = ngx_slab_alloc(hash->pool,sizeof(ngx_array_t));
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"http session hash add function PALLOC FOR BUCKET PTR : %p ",bucket);
        if (bucket == NULL) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"http session hash add function cannot alloc for bucket NGX ERROR");
            return NGX_ERROR;
        }

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"http session hash add function ngx_array_init");

        //ARRAY INIT FUNCTION OVERWRITE
        bucket->nelts = 0;
        bucket->size = sizeof(ngx_http_session_hash_elt_t);
        bucket->nalloc = 64;
        bucket->pool = hash->pool;

        bucket->elts = ngx_slab_alloc(hash->pool, 64 * sizeof(ngx_http_session_hash_elt_t));
        if (bucket->elts == NULL) {
            return NGX_ERROR;
        }
        //ARRAY INIT FUNCTION OVERWRITE END
        /*if (ngx_array_init(bucket, hash->pool, 64, sizeof(ngx_http_session_hash_elt_t))
            != NGX_OK)
        {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"http session hash add function bucket array init ERROR bucketptr : %p hash->pool ptr: %p",bucket,hash->pool);
            return NGX_ERROR;
        }*/

        hash->buckets[key % hash->size] = bucket;
        
    }
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"http session hash add function PUSH ELT TO BUCKET ");

    elt = ngx_array_session_push(bucket);
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"http session hash add function checking elt is null ");
    if (elt == NULL){
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"http session hash add function ELT NULL ERROR ");
        return NGX_ERROR;
    }

        
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"http session hash add function PALLOC FOR DATA ");
    data = ngx_slab_alloc(hash->pool, len+2);
    time_to_live = ngx_slab_alloc(hash->pool, sizeof(ngx_time_t ));
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"http session hash add function COPY NAME TO DATA MEMCPY ");
    ngx_memcpy(data, name, len+1);
    elt->name = data;
    elt->len = len;
    elt->ignore = 0;
    *time_to_live = *(ngx_timeofday());
    elt->time_to_live = time_to_live ;
    return NGX_OK;
}

void *
ngx_http_session_hash_find(ngx_http_session_hash_t *hash,ngx_uint_t key, u_char *name, size_t len,ngx_http_request_t *r)
{
    ngx_uint_t                  bucket_index=0;
    ngx_uint_t                  i, j,new_element = 0;
    ngx_array_t                 *bucket;
    ngx_http_session_hash_elt_t *elt;
    ngx_http_session_hash_elt_t *elts;
    ngx_shm_zone_t              *shm_zone;
    ngx_shm_zone_t              *shm_zone_worker;
    ngx_http_session_loc_conf_t *lccf;
    ngx_uint_t                  session_count;
    ngx_uint_t                  search_flag = 1;
    ngx_uint_t                  str_compare = 0;


    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"http session hash find session : %s",name);
    lccf = ngx_http_get_module_loc_conf(r, ngx_http_session_module);

  	shm_zone = lccf->shm_zone;
    shm_zone_worker = lccf->shm_zone_workers;

    //((ngx_http_session_shm_ctx *)shm_zone->data)->session_id_count
    //sessionCountları sıfırla
    session_count = ((ngx_http_session_shm_ctx *)shm_zone->data)->session_id_count;
    bucket = hash->buckets[key % hash->size];
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"http session hash where i am ");
    if (bucket == NULL) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"http session hash add find session_count incremented sescount: %i + 1 HASH(NAME) : %s",session_count,name);
        session_count++;
        
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"http session hash find bucket null");
        new_element = 1;
        goto CLEAN;
BACK:
        ((ngx_http_session_shm_ctx *)shm_zone->data)->session_id_count = session_count;
        new_element = 0;
        return NULL;
    }

    for (i=0; i<bucket->nelts; i++) {
        elts = (ngx_http_session_hash_elt_t *)bucket->elts;
        elt = &elts[i];

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"http session hash in bucket ses: %s compared ses: %s ",elt->name,name);
        for (j = 0; j<len; j++) {
            if (name[j] != elt->name[j]) {
                if(((ngx_timeofday())->sec - (elt->time_to_live->sec)) > 15 && elt->ignore == 0){
                        ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"TIME DIFFERENCE SYSTEM (%i) - HASH(%i) : %i IGNORE: %i",(ngx_timeofday())->sec,elt->time_to_live->sec,ngx_timeofday()->sec - elt->time_to_live->sec,elt->ignore);
                        elt->ignore = 1;
                        if(session_count !=0){
                            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"http session hash find session_count dec sescount: %i + 1 HASH(NAME): %s",session_count,elt->name);
                            session_count -=1;
                        }
                        
                }
                
                str_compare = 1;
                break;
            }
        }           
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"STR COMPARE %i",str_compare);        
        if(str_compare == 0){
            //if it is finded update the time to live value
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"session_count ADD TIME DIFFERENCE SYSTEM (%i) - HASH(%i)",ngx_timeofday()->sec,elt->time_to_live->sec);
            if(((ngx_timeofday())->sec - (elt->time_to_live->sec)) > 15 && elt->ignore == 1){
                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"http session hash find session_count incremented sescount: %i + 1 HASH(%i)",session_count,elt->name);
                session_count +=1;
            }
            ngx_log_debug5(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"session_count ADD TIME DIFFERENCE SYSTEM (%i) - HASH(%i) : %i IGNORE: %i HASH(NAME) : %s before ignore=1",ngx_timeofday()->sec,elt->time_to_live->sec,(ngx_timeofday())->sec - elt->time_to_live->sec,elt->ignore,elt->name); 
            elt->ignore = 0;
            *(elt->time_to_live) = *(ngx_timeofday());
            ngx_log_debug5(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"session_count ADD TIME DIFFERENCE SYSTEM (%i) - HASH(%i) : %i IGNORE: %i HASH(NAME) : %s after ignore=1",ngx_timeofday()->sec,elt->time_to_live->sec,(ngx_timeofday())->sec - elt->time_to_live->sec,elt->ignore,elt->name);
            search_flag = 0;
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"http session hash finded %s",elt->name);        
        }
        str_compare = 0;
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"STR COMPARE after if %i",str_compare);
    }
    //look for other buckets if ttl is larger than 15 than update the active sessionIDS
CLEAN:

    

    for(bucket_index=0;bucket_index<NGX_HTTP_SESSION_NR_BUCKETS;bucket_index++){
        bucket = hash->buckets[bucket_index];
        //dont check the same bucket again !=key
        if(bucket != NULL && bucket_index != (key % hash->size)){
            for (i=0; i<bucket->nelts; i++) {
                
                elts = (ngx_http_session_hash_elt_t *)bucket->elts;
                elt = &elts[i];

                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"http session hash in bucket checking ses: %s ttl: %i",elt->name,elt->time_to_live->sec);
                if(((ngx_timeofday())->sec - (elt->time_to_live->sec)) > 15 && elt->ignore == 0){
                    ngx_log_debug5(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"session_count TIME DIFFERENCE SYSTEM (%i) - HASH(%i) : %i IGNORE: %i HASH(NAME) : %s",ngx_timeofday()->sec,elt->time_to_live->sec,ngx_timeofday()->sec - elt->time_to_live->sec,elt->ignore,elt->name);
                    elt->ignore = 1;
                    ngx_log_debug5(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"session_count TIME DIFFERENCE SYSTEM (%i) - HASH(%i) : %i IGNORE: %i HASH(NAME) : %s after ignore=1",ngx_timeofday()->sec,elt->time_to_live->sec,(ngx_timeofday())->sec - elt->time_to_live->sec,elt->ignore,elt->name);
                    if(session_count != 0){ 
                        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"http session hash session_count dec : %i - 1 HASH NAME: %s",session_count,elt->name);
                        session_count -=1;
                    }    
                }
            }
        }
    }
    if(new_element){
        goto BACK;
    }
    if(!search_flag){
        ((ngx_http_session_shm_ctx *)shm_zone->data)->session_id_count = session_count;
        return elt->name;
    }
    
    // +1 because of newly added node
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"http session hash session_count incremented : %i + 1 HASH(NAME): %s",session_count,name);
    session_count +=1;
    ((ngx_http_session_shm_ctx *)shm_zone->data)->session_id_count = session_count;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"http session hash didnt finded returning NULL sessionID= %s",name);


    
    return NULL;
}
//FUNCTION OVERWRITE NGX_ARRAY_PUSH
void * ngx_array_session_push(ngx_array_t *a)
 {
     void                *elt, *new;
     size_t              size;
     ngx_slab_pool_t     *p;
 
     if (a->nelts == a->nalloc) {
 
         /* the array is full */
 
         size = a->size * a->nalloc;
 
         p = a->pool;
 
         if ((u_char *) a->elts + size == p->last
             && p->last + a->size <= p->end)
         {
             /*
              * the array allocation is the last in the pool
              * and there is space for new allocation
              */
 
             p->last += a->size;
             a->nalloc++;
 
         } else {
             /* allocate a new array */
 
             new = ngx_slab_alloc(p, 2 * size);
            if (new == NULL) {
                 return NULL;
             }
 
             ngx_memcpy(new, a->elts, size);
             a->elts = new;
             a->nalloc *= 2;
         }
     }
 
     elt = (u_char *) a->elts + a->size * a->nelts;
     a->nelts++;
 
     return elt;
}

