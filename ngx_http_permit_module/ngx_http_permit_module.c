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
} ngx_http_permit_rule_t;

typedef struct {
	ngx_array_t      *rules; 
	ngx_uint_t default_permit;
	ngx_hash_combined_t hash;
	ngx_hash_keys_arrays_t *keys;
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
	ngx_int_t rc;
	u_char *data;

	if(pscf->keys == NULL) {
		pscf->keys = ngx_pcalloc(cf->temp_pool, sizeof(ngx_hash_keys_arrays_t));

		if(pscf->keys==NULL) {
			return NGX_CONF_ERROR;
		}

		pscf->keys->pool = cf->pool;
		pscf->keys->temp_pool = cf->pool;
		if (ngx_hash_keys_array_init(pscf->keys, NGX_HASH_SMALL) != NGX_OK) {
			return NGX_CONF_ERROR;
		}
	}


	value = cf->args->elts;


	if(value[1].len==0||value[2].len==0) {
		return NGX_CONF_ERROR;
	}

	data = ngx_pcalloc(cf->pool,value[1].len+1);
	ngx_snprintf(data, value[1].len+1, "%s",value[1].data);
	rc = ngx_hash_add_key(pscf->keys, value+2, data, NGX_HASH_WILDCARD_KEY);

	if (rc == NGX_OK) {
		return NGX_CONF_OK;
	}
	else {
		return NGX_CONF_ERROR;
	}
}

static char *
ngx_http_permit_load(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	
	ngx_http_permit_srv_conf_t *pscf = conf;
	ngx_str_t *value;
	ngx_http_permit_rule_t   *rule;

	value = cf->args->elts;

	if (pscf->rules == NULL) {
		pscf->rules = ngx_array_create(cf->pool, 4, sizeof(ngx_http_permit_rule_t));
		if (pscf->rules == NULL) {
			return NGX_CONF_ERROR;
		}
	}

	rule = ngx_array_push(pscf->rules);
	if (rule == NULL) {
		return NGX_CONF_ERROR;
	}

	printf("permit load %s  %s %s\n",value[0].data,value[1].data,value[2].data);
	rule->usergroup= value[1]; 
	rule->app = value[2]; 
	if(value[0].len==12) {
		//portal_allow
		rule->permit = 1;
	}
	else {
		//portal_allow
		rule->permit = 0;
	}

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
	ngx_http_permit_rule_t *rule;
	ngx_hash_init_t  hash;
	int i=0;

	if (conf->rules == NULL) {
		conf->rules = prev->rules;
	}

	ngx_conf_merge_uint_value(conf->default_permit,
	                              prev->default_permit, 1);


	//printf("in merge num %d\n",conf->rules->nelts);

	if(conf && conf->rules) {
		rule = conf->rules->elts;
		for (i = 0; i < conf->rules->nelts; i++) {
			printf("in merge %d %s %s %d\n",i,rule[i].usergroup.data,rule[i].app.data,rule[i].permit);
		}
	}
	if(conf->keys == NULL ) {
		conf->hash = prev->hash;
		return NGX_CONF_OK;
	}

	hash.key = ngx_hash_key_lc;
	hash.max_size = 2048; /* TODO: referer_hash_max_size; */
	hash.bucket_size = 64; /* TODO: referer_hash_bucket_size; */
	hash.name = "sslvpn";
	hash.pool = cf->pool;

	printf("before merge hash\n");
	if (conf->keys->keys.nelts) {
		hash.hash = &conf->hash.hash;
		hash.temp_pool = NULL;

		if (ngx_hash_init(&hash, conf->keys->keys.elts, conf->keys->keys.nelts)
				!= NGX_OK)
		{
			return NGX_CONF_ERROR;
		}
	}

	if (conf->keys->dns_wc_head.nelts) {

/*
		ngx_qsort(conf->keys->dns_wc_head.elts,
				(size_t) conf->keys->dns_wc_head.nelts,
				sizeof(ngx_hash_key_t),
				ngx_http_cmp_referer_wildcards);
*/

		hash.hash = NULL;
		hash.temp_pool = cf->temp_pool;

		if (ngx_hash_wildcard_init(&hash, conf->keys->dns_wc_head.elts,
					conf->keys->dns_wc_head.nelts)
				!= NGX_OK)
		{
			return NGX_CONF_ERROR;
		}

		conf->hash.wc_head = (ngx_hash_wildcard_t *) hash.hash;
	}

	if (conf->keys->dns_wc_tail.nelts) {

/*
		ngx_qsort(conf->keys->dns_wc_tail.elts,
				(size_t) conf->keys->dns_wc_tail.nelts,
				sizeof(ngx_hash_key_t),
				ngx_http_cmp_referer_wildcards);
*/

		hash.hash = NULL;
		hash.temp_pool = cf->temp_pool;

		if (ngx_hash_wildcard_init(&hash, conf->keys->dns_wc_tail.elts,
					conf->keys->dns_wc_tail.nelts)
				!= NGX_OK)
		{
			return NGX_CONF_ERROR;
		}

		conf->hash.wc_tail = (ngx_hash_wildcard_t *) hash.hash;
	}

	conf->keys = NULL;

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
	ngx_http_permit_rule_t *rule;
	ngx_uint_t i;
	//ngx_str_t mm=ngx_string("www.baidu.com");
	ngx_str_t mm=ngx_string("bbs.neusoft.com");
	ngx_uint_t key;
	u_char *value;

	pscf = ngx_http_get_module_srv_conf(r, ngx_http_permit_module);
	rule = pscf->rules->elts;

	if(pscf->default_permit) {
		for (i = 0; i < pscf->rules->nelts; i++) {
			printf("in permit %d %s %s %d\n",i,rule[i].usergroup.data,rule[i].app.data,rule[i].permit);
		}
	}
	else {
		printf("deny\n");
	}


	key=0;
	for(i=0;i<mm.len;i++) {
		key = ngx_hash(key, mm.data[i]);
	}


	printf("key %u\n",key);

	 value = ngx_hash_find_combined(&pscf->hash, key, mm.data, mm.len);

	 if(value==NULL) {
		printf("hash not found\n");
	 }
	 else {
		printf("hash found %s\n",value);
	 }



	return NGX_DECLINED;

}
