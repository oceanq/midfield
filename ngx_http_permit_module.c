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
static char* ngx_http_permit_default(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_permit_init(ngx_conf_t *cf);
static void* ngx_http_permit_create_srv_conf(ngx_conf_t *cf);
static char* ngx_http_permit_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child);
static void* ngx_http_permit_create_loc_conf(ngx_conf_t *cf);
static char* ngx_http_permit_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_permition_handler(ngx_http_request_t *r);

typedef struct {
	ngx_str_t usergroup;
	ngx_str_t app;
	ngx_uint_t permit;      /* default deny 0 accept 1 */
	ngx_flag_t enable;
} ngx_http_permit_rule_t;

typedef struct {
	ngx_list_t *rules;
	ngx_uint_t default_permit;
} ngx_http_permit_srv_conf_t;

typedef struct {
	ngx_uint_t enable;
} ngx_http_permit_loc_conf_t;

static ngx_command_t  ngx_http_permit_commands[] = {
	{ ngx_string("portal_allow"),
		NGX_HTTP_SRV_CONF|NGX_CONF_TAKE2,
		ngx_http_permit_load,
		NGX_HTTP_SRV_CONF_OFFSET,
		offsetof(ngx_http_permit_srv_conf_t,rules),
		NULL },
	{ ngx_string("portal_deny"),
		NGX_HTTP_SRV_CONF|NGX_CONF_TAKE2,
		ngx_http_permit_load,
		NGX_HTTP_SRV_CONF_OFFSET,
		offsetof(ngx_http_permit_srv_conf_t,rules),
		NULL },
	{ ngx_string("portal_default"),
		NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_flag_slot,
		NGX_HTTP_SRV_CONF_OFFSET,
		offsetof(ngx_http_permit_srv_conf_t,default_permit),
		NULL },
	{ ngx_string("permit_enable"),
		NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_flag_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_permit_loc_conf_t,enable),                                                                              
		NULL},
};

static ngx_http_module_t  ngx_http_permit_module_ctx = {
	NULL,                                  /* preconfiguration */
	ngx_http_permit_init,                  /* postconfiguration */

	NULL,                                  /* create main configuration */
	NULL,                                  /* init main configuration */

	ngx_http_permit_create_srv_conf,      /* create server configuration */
	ngx_http_permit_merge_srv_conf,       /* merge server configuration */

	ngx_http_permit_create_loc_conf,	/* create location configuration */
	ngx_http_permit_merge_loc_conf,	    /* merge location configuration */
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


/*

	portal_url bbs bbs.neusoft.com

*/

static char *
ngx_http_permit_load(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_permit_srv_conf_t *pscf = conf;
	ngx_str_t *value;
	ngx_http_permit_rule_t   *rule;
	int ret;

	value = cf->args->elts;

	if(pscf->rules == NULL) {
		pscf->rules = ngx_list_create(cf->pool, 4, sizeof(ngx_http_permit_rule_t));
		if (pscf->rules == NULL) {
			return NGX_CONF_ERROR;
		}
	}

	rule = ngx_list_push(pscf->rules);
	if (rule == NULL) {
		return NGX_ERROR;
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

	return NGX_CONF_OK;
}

static void *
ngx_http_permit_create_loc_conf(ngx_conf_t *cf)
{
	ngx_http_permit_loc_conf_t *plcf;

	plcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_permit_loc_conf_t));
	if (plcf == NULL) {
		return NULL;
	}
	plcf->enable = NGX_CONF_UNSET;

	return plcf;
}

static char *
ngx_http_permit_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_permit_loc_conf_t *prev = parent;
	ngx_http_permit_loc_conf_t *conf = child;

	ngx_conf_merge_uint_value(conf->enable,
	                              prev->enable, 0);
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
	pscf->default_permit = NGX_CONF_UNSET;

	return pscf;
}


static char *
ngx_http_permit_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_permit_srv_conf_t *prev = parent;
	ngx_http_permit_srv_conf_t *conf = child;

	ngx_conf_merge_uint_value(conf->default_permit,
	                              prev->default_permit, 1);

	if (conf->rules == NULL) {
		conf->rules = prev->rules;
	}

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
	ngx_http_permit_loc_conf_t *plcf;
	ngx_http_permit_rule_t *rule;
	ngx_list_part_t *p ; 
	ngx_uint_t i,j;
	u_char *cookie;
	u_char *start,*user,*group;
	group = NULL;

	pscf = ngx_http_get_module_srv_conf(r, ngx_http_permit_module);
	plcf = ngx_http_get_module_loc_conf(r, ngx_http_permit_module);

	if(plcf->enable==0) return NGX_OK;
	else {
		/*	get appname from url
			https://192.168.224.128/secret/appname/00/uggc/xd.arhfbsg.pbz/
			appname may have been encoded
		*/


		u_char *app;
		u_char *url;
		ngx_int_t count = 0;

		url = ngx_pnalloc(r->pool, r->uri.len+1);
		if(url==NULL) {
			return NGX_ERROR;
		}
		memset(url,0,r->uri.len+1);
		ngx_memcpy(url, r->uri.data, r->uri.len);

		app = strtok(url,"/");
		while(app) {
			count++;
			if(count>=2) break;
			/*
				0-->prefix secret
				1-->appname not used
			*/
			app = strtok(NULL,"/");
		}

		if(count>=2) {
			/*
			   get usergroup,username from cookie
			   set-cookie when login successed
			 */

			ngx_list_part_t *part;
			ngx_table_elt_t *header;

			part = &r->headers_in.headers.part;
			header = part->elts;

			for(i=0;;i++){
				if (i >= part->nelts) {
					if (part->next == NULL) {
						break;
					}

					part = part->next;
					header = part->elts;
					i = 0;
				}

				if(!strcasecmp(header[i].key.data,"cookie")) {
					cookie = ngx_pcalloc(r->pool,header[i].value.len+1);
					if(cookie==NULL) {
						return NGX_HTTP_FORBIDDEN;
					}
					memset(cookie,0,header[i].value.len+1);
					ngx_memcpy(cookie,header[i].value.data,header[i].value.len);

					group = NULL;
					start = strtok(cookie,";");
					while(start) {
						user = strstr(start,"sslvpndata=");
						if(user) {
							group = strstr(start,"#");
							if(group) {
								*group='\0';
								group +=1;
								user+=strlen("sslvpndata=");
								printf("app %s user %s group %s\n",app,user,group);

								//check groupname and appname, if appname == username means this app is self defined 
								p = &(pscf->rules->part);
								rule = p->elts;
								for (j = 0; j< p->nelts; j++) {
									if(!strcmp(rule[j].usergroup.data,"any")) {
										//group any
										if(!strcmp(rule[j].app.data,"any")||!strcmp(rule[j].app.data,app)) break; 
									}
									else if(!strcmp(rule[j].app.data,"any")) {
										//app any
										if(!strcmp(rule[j].usergroup.data,group)) break; 
									}
									else {
										if(!strcmp(rule[j].usergroup.data,group) && !strcmp(rule[j].app.data,app)) {
											break;
										}
									}
								}
								if(j>=p->nelts) {
									//maybe self defined
									if(!strcmp(app,user)) return NGX_OK;
									else {
										if(pscf->default_permit) return NGX_OK;
										else return NGX_HTTP_FORBIDDEN;
									}
								}
								else {
									printf("%s %s %d\n",rule[j].usergroup.data,rule[j].app.data,rule[j].permit);
									if(rule[j].permit) return NGX_OK;
									else return NGX_HTTP_FORBIDDEN;
								}
							}
							else {
								return NGX_HTTP_FORBIDDEN;
							}
						}
						start = strtok(NULL,";");
					}
					if(!group) return NGX_HTTP_FORBIDDEN;
					break;
				}
			}
			//not found cookie
			if(!group) return NGX_HTTP_FORBIDDEN;

		}
		else {
			// no app name forbid/ok both fine
			return NGX_OK;
		}
	}
	return NGX_OK;
}
