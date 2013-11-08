#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


// refenrence from modules/ngx_http_access_module.c

/*

 this module only works in server block
 config like followes:
 {
	portal_deny ug1 app1;
	portal_allow ug2 app2;
	portal_default on/off;
 }

*/

static char* ngx_http_permit_load(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char* ngx_http_permit_url(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char* ngx_http_permit_default(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_permit_init(ngx_conf_t *cf);
static void* ngx_http_permit_create_srv_conf(ngx_conf_t *cf);
static char* ngx_http_permit_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_permition_handler(ngx_http_request_t *r);

typedef struct {
	ngx_str_t usergroup;
	ngx_str_t app;
	ngx_uint_t permit;      /* default deny 0 accept 1 */
} ngx_http_permit_public_t;

typedef struct {
	ngx_str_t username;
	ngx_str_t url;
} ngx_http_permit_private_t;

typedef struct {

	ngx_array_t      *public_rules; 
	ngx_hash_combined_t public_hash;
	ngx_hash_keys_arrays_t *public_keys;

	ngx_array_t      *private_rules; 
	ngx_hash_combined_t private_hash;
	ngx_hash_keys_arrays_t *private_keys;

	ngx_uint_t default_permit;
} ngx_http_permit_srv_conf_t;

static ngx_command_t  ngx_http_permit_commands[] = {
	{ ngx_string("portal_allow"),
		NGX_HTTP_SRV_CONF|NGX_CONF_TAKE2,
		ngx_http_permit_load,
		NGX_HTTP_SRV_CONF_OFFSET,
		0,
		NULL },
	{ ngx_string("portal_deny"),
		NGX_HTTP_SRV_CONF|NGX_CONF_TAKE2,
		ngx_http_permit_load,
		NGX_HTTP_SRV_CONF_OFFSET,
		0,
		NULL },
	{ ngx_string("portal_url"),
		NGX_HTTP_SRV_CONF|NGX_CONF_TAKE2,
		ngx_http_permit_url,
		NGX_HTTP_SRV_CONF_OFFSET,
		0,
		NULL },
	{ ngx_string("portal_default"),
		NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
		ngx_http_permit_default,
		NGX_HTTP_SRV_CONF_OFFSET,
		0,
		NULL },
};

static ngx_http_module_t  ngx_http_permit_module_ctx = {
	NULL,                                  /* preconfiguration */
	ngx_http_permit_init,                  /* postconfiguration */

	NULL,                                  /* create main configuration */
	NULL,                                  /* init main configuration */

	ngx_http_permit_create_srv_conf,      /* create server configuration */
	ngx_http_permit_merge_srv_conf,       /* merge server configuration */

	NULL,								 /* create location configuration */
	NULL						         /* merge location configuration */
};


ngx_module_t  ngx_http_permit_module = {
	NGX_MODULE_V1,
	&ngx_http_permit_module_ctx,           /* module context */
	ngx_http_permit_commands,              /* module directives */
	NGX_HTTP_MODULE,                       /* module type */
	NULL,                                  /* init master */
	NULL,                                  /* init module */
	NULL,                                  /* init process */
	NULL,                                  /* init thread */
	NULL,                                  /* exit thread */
	NULL,                                  /* exit process */
	NULL,                                  /* exit master */
	NGX_MODULE_V1_PADDING
};


static char* 
ngx_http_permit_default(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_permit_srv_conf_t *pscf = conf;
	ngx_str_t *value;
	value = cf->args->elts;


	printf("default %s\n",value[1].data);

	if(value[1].len==2 && ngx_strcmp(value[1].data, "on") == 0) {
		pscf->default_permit = 1; 
	}
	else {
		pscf->default_permit = 0; 
	}

	return NGX_CONF_OK;
}


/*

	portal_url bbs bbs.neusoft.com

*/

static char *
ngx_http_permit_url(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_permit_srv_conf_t *pscf =conf;
	ngx_str_t *value;
	ngx_http_permit_private_t *rule;
	int ret;

	value = cf->args->elts;

	if (pscf->private_keys == NULL) {
		pscf->private_keys = ngx_pcalloc(cf->temp_pool, sizeof(ngx_hash_keys_arrays_t));
		if (pscf->private_keys == NULL) {      
			return NGX_CONF_ERROR;         
		}

		pscf->private_keys->pool = cf->pool;   
		pscf->private_keys->temp_pool = cf->pool;

		if (ngx_hash_keys_array_init(pscf->private_keys, NGX_HASH_SMALL) != NGX_OK) {
			return NGX_CONF_ERROR;         
		}
	}

	if (pscf->private_rules == NULL) {
		pscf->private_rules = ngx_array_create(cf->pool, 4, sizeof(ngx_http_permit_private_t));
		if (pscf->private_rules == NULL) {
			return NGX_CONF_ERROR;
		}
	}

	ngx_str_t *u = ngx_palloc(cf->pool, sizeof(ngx_str_t));
	if (u == NULL) {
		return NGX_CONF_ERROR;     
	}

	*u = value[1];

	ret = ngx_hash_add_key(pscf->private_keys, &(value[2]), u, NGX_HASH_WILDCARD_KEY);

	printf("ngx_hash_add_key rc %d\n",ret);
	if(ret != NGX_OK) return NGX_CONF_ERROR;

	rule = ngx_array_push(pscf->private_rules);
	if (rule == NULL) {
		return NGX_CONF_ERROR;
	}

	printf("private %s %s %s\n",value[0].data,value[1].data,value[2].data);
	rule->username= value[1]; 
	rule->url = value[2]; 

	return NGX_CONF_OK;
}

static char *
ngx_http_permit_load(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_permit_srv_conf_t *pscf = conf;
	ngx_str_t *value;
	ngx_http_permit_public_t   *rule;
	int ret;

	value = cf->args->elts;

	if (pscf->public_rules == NULL) {
		pscf->public_rules = ngx_array_create(cf->pool, 4, sizeof(ngx_http_permit_public_t));
		if (pscf->public_rules == NULL) {
			return NGX_CONF_ERROR;
		}
	}

	rule = ngx_array_push(pscf->public_rules);
	if (rule == NULL) {
		return NGX_CONF_ERROR;
	}

	if(value[0].len==12) {
		//portal_allow
		rule->permit = 1;
	}
	else {
		//portal_deny
		rule->permit = 0;
	}

	rule->usergroup= value[1]; 
	rule->app = value[2]; 
	printf("rule %s %s %d\n",rule->usergroup.data,rule->app.data,rule->permit);

	if (pscf->public_keys == NULL) {
		pscf->public_keys = ngx_pcalloc(cf->temp_pool, sizeof(ngx_hash_keys_arrays_t));
		if (pscf->public_keys == NULL) {      
			return NGX_CONF_ERROR;         
		}

		pscf->public_keys->pool = cf->pool;   
		pscf->public_keys->temp_pool = cf->pool;

		if (ngx_hash_keys_array_init(pscf->public_keys, NGX_HASH_SMALL) != NGX_OK) {
			return NGX_CONF_ERROR;         
		}
	}


	ngx_str_t *u = ngx_palloc(cf->pool, sizeof(ngx_str_t));
	if (u == NULL) {
		return NGX_CONF_ERROR;     
	}

	//*u = value[1];
	u->len = value[1].len + 2;
	u->data = ngx_pcalloc(cf->pool,u->len);
	if(u->data) {
		ngx_snprintf(u->data,u->len,"%s#%d",value[1].data,rule->permit);
	}
	else {
		return NGX_CONF_ERROR;
	}

	printf("u data %d %s\n",u->len,u->data);

	ret = ngx_hash_add_key(pscf->public_keys, &(value[2]), u, NGX_HASH_WILDCARD_KEY);

	printf("ngx_hash_add_key rc %d\n",ret);
	if(ret != NGX_OK) return NGX_CONF_ERROR;




	return NGX_CONF_OK;
}


static void *
ngx_http_permit_create_srv_conf(ngx_conf_t *cf)
{
	ngx_http_permit_srv_conf_t *pscf;

	pscf = ngx_pcalloc(cf->pool, sizeof(ngx_http_permit_srv_conf_t));
	if (pscf == NULL) {
		return NULL;
	}

	return pscf;
}


static char *
ngx_http_permit_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_permit_srv_conf_t *prev = parent;
	ngx_http_permit_srv_conf_t *conf = child;
	ngx_http_permit_public_t *rule;
	ngx_hash_init_t  hash;
	int i=0;


	ngx_conf_merge_uint_value(conf->default_permit,
	                              prev->default_permit, 1);

	printf("in merge num %d %d\n",conf->public_rules->nelts,conf->private_rules->nelts);
	if (conf->public_rules == NULL) {
		conf->public_rules = prev->public_rules;
	}

	if(conf && conf->public_rules) {
		rule = conf->public_rules->elts;
		for (i = 0; i < conf->public_rules->nelts; i++) {
			printf("in merge %d %s %s %d\n",i,rule[i].usergroup.data,rule[i].app.data,rule[i].permit);
		}
	}
	if(conf->public_keys == NULL ) {
		conf->public_hash = prev->public_hash;
		printf("return ok\n");
		return NGX_CONF_OK;
	}

	hash.key = ngx_hash_key_lc;
	hash.max_size = 2048; /* TODO: referer_hash_max_size; */
	hash.bucket_size = 64; /* TODO: referer_hash_bucket_size; */
	hash.name = "sslvpn_public";
	hash.pool = cf->pool;

	printf("before merge hash\n");
	if (conf->public_keys->keys.nelts) {
		hash.hash = &conf->public_hash.hash;
		hash.temp_pool = NULL;

		if (ngx_hash_init(&hash, conf->public_keys->keys.elts, conf->public_keys->keys.nelts)
				!= NGX_OK)
		{
			return NGX_CONF_ERROR;
		}
	}

	if (conf->public_keys->dns_wc_head.nelts) {

/*
		ngx_qsort(conf->keys->dns_wc_head.elts,
				(size_t) conf->keys->dns_wc_head.nelts,
				sizeof(ngx_hash_key_t),
				ngx_http_cmp_referer_wildcards);
*/

		hash.hash = NULL;
		hash.temp_pool = cf->temp_pool;

		if (ngx_hash_wildcard_init(&hash, conf->public_keys->dns_wc_head.elts,
					conf->public_keys->dns_wc_head.nelts)
				!= NGX_OK)
		{
			return NGX_CONF_ERROR;
		}

		conf->public_hash.wc_head = (ngx_hash_wildcard_t *) hash.hash;
	}

	if (conf->public_keys->dns_wc_tail.nelts) {

/*
		ngx_qsort(conf->keys->dns_wc_tail.elts,
				(size_t) conf->keys->dns_wc_tail.nelts,
				sizeof(ngx_hash_key_t),
				ngx_http_cmp_referer_wildcards);
*/

		hash.hash = NULL;
		hash.temp_pool = cf->temp_pool;

		if (ngx_hash_wildcard_init(&hash, conf->public_keys->dns_wc_tail.elts,
					conf->public_keys->dns_wc_tail.nelts)
				!= NGX_OK)
		{
			return NGX_CONF_ERROR;
		}

		conf->public_hash.wc_tail = (ngx_hash_wildcard_t *) hash.hash;
	}

	conf->public_keys = NULL;

//========================================================================================================

	if (conf->private_rules == NULL) {
		conf->private_rules = prev->private_rules;
	}

	ngx_http_permit_private_t *private;
	if(conf && conf->private_rules) {
		private = conf->private_rules->elts;
		for (i = 0; i < conf->private_rules->nelts; i++) {
			printf("in merge %d %s %s\n",i,private[i].username.data,private[i].url.data);
		}
	}
	if(conf->private_keys == NULL ) {
		conf->private_hash = prev->private_hash;
		return NGX_CONF_OK;
	}

	hash.key = ngx_hash_key_lc;
	hash.max_size = 2048; /* TODO: referer_hash_max_size; */
	hash.bucket_size = 64; /* TODO: referer_hash_bucket_size; */
	hash.name = "sslvpn_private";
	hash.pool = cf->pool;

	printf("before merge hash\n");
	if (conf->private_keys->keys.nelts) {
		hash.hash = &conf->private_hash.hash;
		hash.temp_pool = NULL;

		if (ngx_hash_init(&hash, conf->private_keys->keys.elts, conf->private_keys->keys.nelts)
				!= NGX_OK)
		{
			return NGX_CONF_ERROR;
		}
	}

	if (conf->private_keys->dns_wc_head.nelts) {

/*
		ngx_qsort(conf->keys->dns_wc_head.elts,
				(size_t) conf->keys->dns_wc_head.nelts,
				sizeof(ngx_hash_key_t),
				ngx_http_cmp_referer_wildcards);
*/

		hash.hash = NULL;
		hash.temp_pool = cf->temp_pool;

		if (ngx_hash_wildcard_init(&hash, conf->private_keys->dns_wc_head.elts,
					conf->private_keys->dns_wc_head.nelts)
				!= NGX_OK)
		{
			return NGX_CONF_ERROR;
		}

		conf->private_hash.wc_head = (ngx_hash_wildcard_t *) hash.hash;
	}

	if (conf->private_keys->dns_wc_tail.nelts) {

/*
		ngx_qsort(conf->keys->dns_wc_tail.elts,
				(size_t) conf->keys->dns_wc_tail.nelts,
				sizeof(ngx_hash_key_t),
				ngx_http_cmp_referer_wildcards);
*/

		hash.hash = NULL;
		hash.temp_pool = cf->temp_pool;

		if (ngx_hash_wildcard_init(&hash, conf->private_keys->dns_wc_tail.elts,
					conf->private_keys->dns_wc_tail.nelts)
				!= NGX_OK)
		{
			return NGX_CONF_ERROR;
		}

		conf->private_hash.wc_tail = (ngx_hash_wildcard_t *) hash.hash;
	}

	conf->private_keys = NULL;

	return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_permit_init(ngx_conf_t *cf)
{
	ngx_http_handler_pt        *h; 
	ngx_http_core_main_conf_t  *cmcf;  

	cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

	h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
	if (h == NULL) {
		return NGX_ERROR;
	}

	*h = ngx_http_permition_handler;

	return NGX_OK;
}

static ngx_int_t
ngx_http_permition_handler(ngx_http_request_t *r)
{
	ngx_http_permit_srv_conf_t *pscf;
	ngx_http_permit_public_t *rule;
	ngx_http_permit_private_t *pri;
	ngx_uint_t i;
	//ngx_str_t mm=ngx_string("www.baidu.com");
	ngx_uint_t key;
	ngx_str_t *value;
	ngx_str_t host;

	pscf = ngx_http_get_module_srv_conf(r, ngx_http_permit_module);
	rule = pscf->public_rules->elts;

#if 1
	//get host
	printf("uri %.*s\n",r->uri.len,r->uri.data);
	if(r->uri.data) {

		u_char ch_host[240] = {0,};
		ngx_int_t ret;

		ret = sscanf(r->uri.data,"/sslvpn/%*[^/]/%239[^/]/",ch_host);
		if(ret != 1) return NGX_ERROR;

		host.len = strlen(ch_host);
		host.data = ngx_pcalloc(r->pool,host.len);
		if(host.data) {
			ngx_memcpy(host.data,ch_host,host.len);
		}
		else {
			return NGX_ERROR;
		}

		printf("in permition host %s\n",host.data);
		
	}
#endif


	//get username/group

	key=0;
	for(i=0;i<host.len;i++) {
		key = ngx_hash(key, (host.data)[i]);
	}

	//match private
	value = ngx_hash_find_combined(&pscf->private_hash, key, host.data, host.len);

	if(value==NULL) {
		printf("private hash not found\n");
	}
	else {
		printf("private hash found %s\n",value->data);
	}

	//match public
	value = ngx_hash_find_combined(&pscf->public_hash, key, host.data, host.len);

	if(value==NULL) {
		printf("public hash not found\n");
	}
	else {
		printf("public hash found %.*s\n",value->len,value->data);
	}

	//match default

	printf("permit default %d\n",pscf->default_permit);

/*
	pri = pscf->private_rules->elts;
	for (i = 0; i < pscf->private_rules->nelts; i++) {
		printf("in permit %d %s %s\n",i,pri[i].username.data,pri[i].url.data);
	}
*/

	return NGX_DECLINED;
}
