
/*
 * Copyright (C) Igor Sysoev
 */

#define __USE_GNU
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_queue.h>
#include <ngx_channel.h>
#include <ngx_process_cycle.h>
#include <string.h>
#include <stdio.h>
#include <libxml/HTMLparser.h>
#include <ctype.h>
#include "zlib.h"

//#define DELTA 19
#define BLOCK_SZ 4096
#define LEN_QUEUE 30
#define OVECCOUNT 30    /* should be a multiple of 3 */
#define ngx_strcasestr(s1, s2)  strcasestr((const char *) s1, (const char *) s2)
#define ngx_strcasecmp(s1, s2)  strcasecmp((const char *) s1, (const char *) s2)

static void *ngx_http_html_create_conf(ngx_conf_t *cf);
static char *ngx_http_html_merge_conf(ngx_conf_t *cf,void *parent, void *child);
static ngx_int_t ngx_http_html_filter_init(ngx_conf_t *cf);

ngx_user_session *head=NULL;
service *service_head=NULL;
ngx_str_t jslib_str;

typedef struct
{
	ngx_flag_t               enable;
} ngx_http_html_loc_conf_t;

typedef struct
{
	ngx_http_request_t *r;
	u_char *begin;				//where to match url
	u_char *tag_start;
	u_char *tag_end;
	u_char *jslib_pos;
	ngx_chain_t *out;			//out chains
	htmlParserCtxtPtr  ctxt;
	ngx_str_t buf;				//whole response buf
	unsigned int size;			//current size
	ngx_int_t content_type;
	unsigned int req_len;
	unsigned int content_len;

} ngx_http_html_ctx_t;

enum content_type {
	T_OTHER=-1,
	T_HTML,
	T_JS,
	T_CSS,
	T_INIT
};


static ngx_command_t  ngx_http_html_filter_commands[] = {

	{ ngx_string("html_filter"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
		ngx_conf_set_flag_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_html_loc_conf_t,enable),
		NULL},

	ngx_null_command
};

static ngx_http_module_t  ngx_http_html_filter_module_ctx = {
	NULL,                                  /* preconfiguration */
	ngx_http_html_filter_init,              /* postconfiguration */

	NULL,                                  /* create main configuration */
	NULL,                                  /* init main configuration */

	NULL,                                  /* create server configuration */
	NULL,                                  /* merge server configuration */

	ngx_http_html_create_conf,              /* create location configuration */
	ngx_http_html_merge_conf                /* merge location configuration */
};


ngx_module_t  ngx_http_html_filter_module = {
	NGX_MODULE_V1,
	&ngx_http_html_filter_module_ctx,       /* module context */
	ngx_http_html_filter_commands,          /* module directives */
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

static void StartElement(void *, const xmlChar *, const xmlChar **);
static void EndElement(void *, const xmlChar *);
static void Comment(void *, const xmlChar *);
static void CdataBlock(void *, xmlChar *, int);

static htmlSAXHandler saxHandler =
{
	NULL,
	NULL,
	NULL,
	NULL,                     
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	StartElement,
	EndElement,
	NULL,
	NULL,
	NULL,
	NULL,
	Comment,
	NULL,
	NULL/*errorDebug*/,
	NULL/*fatalErrorDebug*/,
	NULL,
	CdataBlock,
	NULL
};

static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;

char *url_key_lst[]={"href","action","src","background","codebase","lowsrc","cite"};

char *css_pattern = "url\\([\"\']?([^()\"\']*)[\"\']?\\)|@import\\s*[\"\']([^\"\']*)[\"\']";
pcre *css_re = NULL;
int css_erroffset;
const char *css_error;

//attent to source not included
char *js_pattern = "([A-Za-z_][_\\w]*)\\.(open|write|writeln|setAttribute|showModalDialog|showModelessDialog|navigate)\\s*\\(|([A-Za-z_][_\\w\\.]*)\\.(href|src|action|background|lowsrc|useMap|longDesc|cite|codeBase|location|host|hostname|pathname|innerHTML|search|protocol|cookie|domain|)\\s*=\\s*([^=][^;\\r\\n}]*)";
pcre *js_re = NULL;
int js_erroffset;
const char *js_error;


static int
ngx_append_buf_to_chain(ngx_http_html_ctx_t *ctx, ngx_buf_t *b)
{

	ngx_chain_t *c,*tmp;
	c = ngx_alloc_chain_link(ctx->r->pool);
	if(c==NULL) return NGX_ERROR;

	c->buf = b;
	c->next=NULL;

	if(ctx->out) {
		for(tmp=ctx->out;tmp;tmp=tmp->next) {
			if(tmp->next==NULL) {
				tmp->next=c;
				break;
			}
		}
	}
	else {
		ctx->out=c;
	}

	return NGX_OK;
}


/*
	malloc buf point to the pos and last, append the node to ctx->out
*/

static int ngx_append_chain(ngx_http_html_ctx_t* ctx,u_char* pos,u_char* last, int flag)
{

	ngx_buf_t *b;
	ngx_chain_t *c,*tmp;

	//printf("in chain\n%.*s\n",last-pos,pos);

	if(pos>=last) return NGX_ERROR;

	b = ngx_create_temp_buf(ctx->r->pool,last-pos);
	if(b==NULL) return NGX_ERROR;

	c = ngx_alloc_chain_link(ctx->r->pool);
	if(c==NULL) return NGX_ERROR;

	ngx_memcpy(b->pos, pos, last-pos);
	b->last = b->pos+(last-pos);
	b->temporary = 1;
	b->memory = 1;
	b->last_buf = flag;

	c->buf = b;
	c->next=NULL;

	if(ctx->out) {
		for(tmp=ctx->out;tmp;tmp=tmp->next) {
			if(tmp->next==NULL) {
				tmp->next=c;
				break;
			}
		}
	}
	else {
		ctx->out=c;
	}

	return NGX_OK;
}

#define NGX_TR_URL(start_u,end_u) \
	do {\
		u_char *tmp; \
		for(tmp=start_u;tmp<end_u;tmp++){ \
			if(*tmp=='?') break; \
			if(*tmp>='A' && *tmp<='Z'){ \
				*tmp=((*tmp+DELTA-'A')%26+'A'); \
			} \
			if(*tmp>='a' && *tmp<='z'){ \
				*tmp=((*tmp+DELTA-'a')%26+'a'); \
			} \
		} \
	}while(0)

/*
	null may be not error;
*/
static ngx_buf_t*
ngx_encode_url(ngx_http_request_t *r,u_char *start,u_char *end)
{
	
	u_char *ch,*ch_end;
	ngx_uint_t len,size=0;
	ngx_buf_t *b = NULL;

	if(ngx_strstr(start,http_proto_str.data)==start) {
		//ch = start+sizeof("http://");
		ch = start+http_proto_str.len;
		ch_end = memchr(ch,'/',end-ch);
		if(ch_end) {
			//len = sizeof("/sslvpn/http/") + (ch_end-ch-1) + (end-ch_end-1);
			len = http_prefix_str.len + (ch_end-ch) + (end-ch_end) +1;
			b = ngx_create_temp_buf(r->pool,len);
			if(b==NULL) return NULL;
			NGX_TR_URL(ch_end+1,end);
			size = snprintf((char*)b->pos,len,"/sslvpn/http/%.*s/%.*s",ch_end-ch,ch,end-ch_end-1,ch_end+1);
			goto good;
		}
		else {
			//<a href="http://news.baidu.com">
			len = http_prefix_str.len + (end-ch) +1;
			b = ngx_create_temp_buf(r->pool,len);
			if(b==NULL) return NULL;
			size = snprintf((char*)b->pos,len,"/sslvpn/http/%.*s/",end-ch,ch);
			goto good;
		}
	}
	else if(ngx_strstr(start,https_proto_str.data)==start) {
		//ch = start+sizeof("http://");
		ch =  start + https_proto_str.len;
		ch_end = memchr(ch,'/',end-ch);
		if(ch_end) {
			//len = sizeof("/sslvpn/https/") + (ch_end-ch-1) + (end-ch_end-1);
			len = https_prefix_str.len + (ch_end-ch) + (end-ch_end) +1;
			b = ngx_create_temp_buf(r->pool,len);
			if(b==NULL) return NULL;
			NGX_TR_URL(ch_end+1,end);
			size = snprintf((char*)b->pos,len,"/sslvpn/https/%.*s/%.*s",ch_end-ch,ch,end-ch_end-1,ch_end+1);
			goto good;
		}
	}
	else if(*start=='/') {
		if(ngx_strstr(r->uri.data,http_prefix_str.data)) {
			//ch = r->uri.data + sizeof("/sslvpn/http/")-1;
			ch = r->uri.data + http_prefix_str.len;
			ch_end = memchr(ch,'/',end-ch);
			if(ch_end) {
				//len = sizeof("/sslvpn/http/") + (ch_end-ch) + (end-start);
				len = http_prefix_str.len + (ch_end-ch) + (end-start)+1;
				b = ngx_create_temp_buf(r->pool,len);
				if(b==NULL) return NULL;
				NGX_TR_URL(start,end);
				size = snprintf((char*)b->pos,len,"/sslvpn/http/%.*s%.*s",ch_end-ch,ch,end-start,start);
				goto good;
			}
		}
		else if(ngx_strstr(r->uri.data,https_prefix_str.data)) {
			//ch = r->uri.data + sizeof("/sslvpn/https/")-1;
			ch = r->uri.data + https_prefix_str.len;
			ch_end = memchr(ch,'/',end-ch);
			if(ch_end) {
				len = https_prefix_str.len + (ch_end-ch) + (end-start) +1;
				b = ngx_create_temp_buf(r->pool,len);
				if(b==NULL) return NULL;
				NGX_TR_URL(start,end);
				size = snprintf((char*)b->pos,len,"/sslvpn/https/%.*s%.*s",ch_end-ch,ch,end-start,start);
				goto good;
			}
		}
		else {
			// uri.data does't start with /sslvpn/http/ /sslvpn/https/
			return NULL;
		}
	}
	else {
		NGX_TR_URL(start,end);
		//printf("relative :%.*s\n",end-start,start);
		//ngx_append_chain(ctx,start,end,0);
		return NULL;
	}

good:
	b->last = b->pos+size;
	b->temporary = 1;
	b->memory = 1;
	b->last_buf = 0;
	//printf("url %.*s\n",b->last-b->pos,b->pos);

	return b;

}

static u_char*
ngx_search_js_end(u_char *start,u_char *current,u_char *last)
{
	/*	
	 match " ' () [] {}
	 end :
		;---> aa.src=mm;
		\n---> aa.src=mm
			   bb.action=dd
		}-----> function mm () { cc.href=gg}
	
		but attention to escape char
	*/

	u_char *ch;
	int s_quote=0;
	int d_quote=0;
	int parentheses=0;
	int bracket=0;
	int brace=0;

	ch = start;
	while(ch<current) {

		switch(*ch) {

			case '"':
				d_quote++;
				break;
			case '\'':
				s_quote++;
				break;
			case '(':
				parentheses++;
				break;
			case ')':
				parentheses--;
				break;
			case '[':
				bracket++;
				break;
			case ']':
				bracket--;
				break;
			case '{':
				brace++;
				break;
			case '}':
				brace--;
				break;
			default:
				break;

		}
		ch++;
	}

	if(d_quote%2==0 && s_quote%2==0 && parentheses==0 && bracket==0 && brace==0) return current;
	
	ch = current;
	while(ch<last) {
		switch(*ch) {

			case '"':
				d_quote++;
				break;
			case '\'':
				s_quote++;
				break;
			case '(':
				parentheses++;
				break;
			case ')':
				parentheses--;
				break;
			case '[':
				bracket++;
				break;
			case ']':
				bracket--;
				break;
			case '{':
				brace++;
				break;
			case '}':
				brace--;
				break;
			case '\n':
			case ';':
				if(d_quote%2==0 && s_quote%2==0 && parentheses==0 && bracket==0 && brace==0) return current;
				break;
			default:
				break;

		}
		ch++;
	}

	return NULL;
		
}

/*
	update url in buf (start+len), and append them to ctx->out
	flag:0--text block in html, 1--file
*/
static ngx_int_t
ngx_update_js(ngx_http_html_ctx_t* ctx,u_char *start,int len,int flag)
{
	char* subject;
	int subject_length,rc;
	int ovector[OVECCOUNT];
	ngx_buf_t *b;

	subject = (char*) start;
	subject_length = len;

	//printf("js subject %.*s\n",len,start);

	rc = pcre_exec(
			js_re,                   /* the compiled pattern */
			NULL,                 /* no extra data - we didn't study the pattern */
			subject,              /* the subject string */
			subject_length,       /* the length of the subject */
			0,                    /* start at offset 0 in the subject */
			0,                    /* default options */
			ovector,              /* output vector for substring information */
			OVECCOUNT);           /* number of elements in the output vector */
	
	if (rc < 0)
	{
		switch(rc)
		{
			case PCRE_ERROR_NOMATCH: break;
									 /*
									  *     Handle other special cases if you like
									  *         */
			default: printf("Matching error %d\n", rc); break;
		}

		// don't free, will be userd forever
		//pcre_free(re);     /* Release memory used for the compiled pattern */
		return 1;
	}

	if (rc == 0) rc = OVECCOUNT/3;

	if(ovector[0]>=len) return 1;


	if(*(subject+ovector[1]-1)=='(') {

		ngx_append_chain(ctx,ctx->begin,(u_char*)subject+ovector[2],0);
		ctx->begin = (u_char*)subject+ovector[5];
		int size = 24+ovector[3]-ovector[2]+ovector[5]-ovector[4];
		b = ngx_create_temp_buf(ctx->r->pool,size);
		if(b==NULL) return 1;
		int sz = snprintf((char*)b->pos,size,"neti_jslib_handle(%.*s, \"%.*s\")",ovector[3]-ovector[2],subject+ovector[2],ovector[5]-ovector[4],subject+ovector[4]);
		b->last=b->pos+sz;
		ngx_append_chain(ctx,b->pos,b->last,0);
	}
	else {
		//printf("assign: neti_jslib_assign(%.*s, \"%.*s\",%.*s)\n",ovector[7]-ovector[6],subject+ovector[6],ovector[9]-ovector[8],subject+ovector[8],ovector[11]-ovector[10],subject+ovector[10]);
		ngx_append_chain(ctx,ctx->begin,(u_char*)subject+ovector[6],0);
		ctx->begin = ngx_search_js_end((u_char*)subject+ovector[10],(u_char*)subject+ovector[11],(u_char*)subject+len);
		int size = 25+ovector[7]-ovector[6]+ovector[9]-ovector[8]+(ctx->begin-(u_char*)subject)-ovector[10]; 
		b = ngx_create_temp_buf(ctx->r->pool,size);
		if(b==NULL) return 1;
		int sz = snprintf((char*)b->pos,size,"neti_jslib_assign(%.*s, \"%.*s\",%.*s)",ovector[7]-ovector[6],subject+ovector[6],ovector[9]-ovector[8],subject+ovector[8],(ctx->begin-(u_char*)subject)-ovector[10],subject+ovector[10]);
		b->last=b->pos+sz;
		ngx_append_chain(ctx,b->pos,b->last,0);
	}


	for (;;)
	{
		int options = 0;                 /* Normally no options */
		int start_offset = ovector[1];   /* Start at end of previous match */

		if (ovector[0] == ovector[1])
		{
			if (ovector[0] == subject_length) break;
			options = PCRE_NOTEMPTY_ATSTART | PCRE_ANCHORED;
		}

		rc = pcre_exec(
				js_re,                   /* the compiled pattern */
				NULL,                 /* no extra data - we didn't study the pattern */
				subject,              /* the subject string */
				subject_length,       /* the length of the subject */
				start_offset,         /* starting offset in the subject */
				options,              /* options */
				ovector,              /* output vector for substring information */
				OVECCOUNT);           /* number of elements in the output vector */

		if (rc == PCRE_ERROR_NOMATCH)
		{
			if (options == 0) break;
			ovector[1] = start_offset + 1;
			continue;    /* Go round the loop again */
		}

		if (rc < 0)
		{
			goto END;
		}

		if (rc == 0) rc = OVECCOUNT/3;
		if(ovector[0]>=len) return 1;

		if(*(subject+ovector[1]-1)=='(') {
			//printf("function: neti_jslib_handle(%.*s, \"%.*s\")\n",ovector[3]-ovector[2],subject+ovector[2],ovector[5]-ovector[4],subject+ovector[4]);

			ngx_append_chain(ctx,ctx->begin,(u_char*)subject+ovector[2],0);
			ctx->begin = (u_char*)subject+ovector[5];
			unsigned int size = 24+ovector[3]-ovector[2]+ovector[5]-ovector[4];
			b = ngx_create_temp_buf(ctx->r->pool,size);
			if(b==NULL) return 1;
			int sz = snprintf((char*)b->pos,size,"neti_jslib_handle(%.*s, \"%.*s\")",ovector[3]-ovector[2],subject+ovector[2],ovector[5]-ovector[4],subject+ovector[4]);
			b->last=b->pos+sz;
			ngx_append_chain(ctx,b->pos,b->last,0);

		}
		else {
			//printf("assign: neti_jslib_assign(%.*s, \"%.*s\",%.*s)\n",ovector[7]-ovector[6],subject+ovector[6],ovector[9]-ovector[8],subject+ovector[8],ovector[11]-ovector[10],subject+ovector[10]);
			ngx_append_chain(ctx,ctx->begin,(u_char*)subject+ovector[6],0);
			ctx->begin = ngx_search_js_end((u_char*)subject+ovector[10],(u_char*)subject+ovector[11],(u_char*)subject+len);
			int size = 25+ovector[7]-ovector[6]+ovector[9]-ovector[8]+(ctx->begin-(u_char*)subject)-ovector[10]; 
			b = ngx_create_temp_buf(ctx->r->pool,size);
			if(b==NULL) return 1;
			int sz = snprintf((char*)b->pos,size,"neti_jslib_assign(%.*s, \"%.*s\",%.*s)",ovector[7]-ovector[6],subject+ovector[6],ovector[9]-ovector[8],subject+ovector[8],(ctx->begin-(u_char*)subject)-ovector[10],subject+ovector[10]);
			b->last=b->pos+sz;
			ngx_append_chain(ctx,b->pos,b->last,0);
		}

	}

END:

	return 0;
}

/*
	update url in buf (start+len), and append them to ctx->out
	flag:0--text block in html, 1--file
*/


static ngx_int_t
ngx_update_css(ngx_http_html_ctx_t* ctx,u_char *start,int len,int flag)
{
	char* subject;
	int subject_length,rc;
	int ovector[OVECCOUNT];
	ngx_buf_t *b;


	subject = (char*) start;
	subject_length = len;

	rc = pcre_exec(
			css_re,                   /* the compiled pattern */
			NULL,                 /* no extra data - we didn't study the pattern */
			subject,              /* the subject string */
			subject_length,       /* the length of the subject */
			0,                    /* start at offset 0 in the subject */
			0,                    /* default options */
			ovector,              /* output vector for substring information */
			OVECCOUNT);           /* number of elements in the output vector */
	
	if (rc < 0)
	{
		switch(rc)
		{
			case PCRE_ERROR_NOMATCH: break;
									 /*
									  *     Handle other special cases if you like
									  *         */
			default: printf("Matching error %d\n", rc); break;
		}

		// don't free, will be userd forever
		//pcre_free(re);     /* Release memory used for the compiled pattern */
		return 1;
	}

	if (rc == 0) rc = OVECCOUNT/3;

	ngx_append_chain(ctx,ctx->begin,(u_char*)subject+ovector[2*rc-2],0);
	ctx->begin = (u_char*)subject+ovector[2*rc-1];
	//printf("css %.*s\n",ovector[2*rc-1]-ovector[2*rc-2],subject+ovector[2*rc-2]);
	b = ngx_encode_url(ctx->r,(u_char*)subject+ovector[2*rc-2],ctx->begin);
	if(b) ngx_append_buf_to_chain(ctx,b);
	else ngx_append_chain(ctx,(u_char*)subject+ovector[2*rc-2],ctx->begin,0); 
	//ngx_append_chain(ctx,(u_char*)subject+ovector[2*rc-2],ctx->begin,0); // part of value


	for (;;)
	{
	int options = 0;                 /* Normally no options */
		int start_offset = ovector[1];   /* Start at end of previous match */

		if (ovector[0] == ovector[1])
		{
			if (ovector[0] == subject_length) break;
			options = PCRE_NOTEMPTY_ATSTART | PCRE_ANCHORED;
		}

		rc = pcre_exec(
				css_re,                   /* the compiled pattern */
				NULL,                 /* no extra data - we didn't study the pattern */
				subject,              /* the subject string */
				subject_length,       /* the length of the subject */
				start_offset,         /* starting offset in the subject */
				options,              /* options */
				ovector,              /* output vector for substring information */
				OVECCOUNT);           /* number of elements in the output vector */

		if (rc == PCRE_ERROR_NOMATCH)
		{
			if (options == 0) break;
			ovector[1] = start_offset + 1;
			continue;    /* Go round the loop again */
		}

		if (rc < 0)
		{
			goto END;
		}

		if (rc == 0) rc = OVECCOUNT/3;

		ngx_append_chain(ctx,ctx->begin,(u_char*)subject+ovector[2*rc-2],0);
		ctx->begin = (u_char*)subject+ovector[2*rc-1];
		//printf("css %.*s\n",ovector[2*rc-1]-ovector[2*rc-2],subject+ovector[2*rc-2]);
		b = ngx_encode_url(ctx->r,(u_char*)subject+ovector[2*rc-2],ctx->begin);
		if(b) ngx_append_buf_to_chain(ctx,b);
		else ngx_append_chain(ctx,(u_char*)subject+ovector[2*rc-2],ctx->begin,0);
		//ngx_append_chain(ctx,(u_char*)subject+ovector[2*rc-2],ctx->begin,0); // part of value

	}

END:

	return 0;
}

/*
 * ----------------------------------------------------------
 * input   : ngx_http_html_ctx_t *ctx,xmlChar *name,xmlChar **attrs
 * output  : none
 * Descrip : find all urls and replace them            
 * ----------------------------------------------------------
 */

static void StartElement(void *voidContext, const xmlChar *name, const xmlChar **attrs)
{
	ngx_http_html_ctx_t *ctx;
	char* content_pos;
	char* tmp;
	char* attribute_pos;
	char* value_pos;
	char* tag_pos;
	char* end_pos;
	int i,j;
	int refresh_flag=0;
	int content_flag=0;
	int url_key_len;
	ngx_buf_t *b;

	ctx = (ngx_http_html_ctx_t *)voidContext;

	if(ctx->jslib_pos) {

		if(!ngx_strcasecmp(name,"html")) {
			//just update jslib_pos
			tag_pos = ngx_strcasestr(ctx->begin,"<html");
			if(tag_pos) {
				end_pos = ngx_strchr(tag_pos,'>');
				if(end_pos) {
					ctx->jslib_pos = end_pos; 
				}
			}
		}
		else if(!ngx_strcasecmp(name,"head")) {
			//insert neti_def.js here
			tag_pos = ngx_strcasestr(ctx->begin,"<head");
			if(tag_pos) {
				end_pos = ngx_strchr(tag_pos,'>');
				if(end_pos) {
					ctx->jslib_pos = end_pos; 
					printf("in head\n");
					ngx_append_chain(ctx,ctx->begin,end_pos+1,0);
					ngx_append_chain(ctx,jslib_str.data,jslib_str.data+jslib_str.len,0);
					//insert neti_def.js here
					ctx->begin = end_pos + 1;
					ctx->jslib_pos = NULL;
				}
			}
		}
		else {
			printf("in else\n");
			// insert neti_def.js to ctx->jslib_pos
			ngx_append_chain(ctx,ctx->begin,ctx->jslib_pos+1,0);
			ngx_append_chain(ctx,jslib_str.data,jslib_str.data+jslib_str.len,0);
			//insert neti_def.js here
			ctx->begin = ctx->jslib_pos + 1;
			ctx->jslib_pos = NULL;
		}
	}
	if(!ngx_strcasecmp(name,"script")) {
		ctx->tag_start = ngx_strcasestr(ctx->begin,(u_char*)name);
		if(ctx->tag_start) {
			ctx->tag_start = ngx_strchr(ctx->tag_start,'>');
		}
	}
	else if(!ngx_strcasecmp(name,"style")) {
		ctx->tag_start = ngx_strcasestr(ctx->begin,(u_char*)name);
		if(ctx->tag_start) {
			ctx->tag_start = ngx_strchr(ctx->tag_start,'>');
		}
	}

	if(attrs==NULL) return;
	url_key_len=sizeof(url_key_lst)/sizeof(u_char*);

	if(!ngx_strcmp(name,"meta")) {
		tmp = ngx_strcasestr(ctx->begin,(u_char*)name);
		if(tmp) {
			/*
			   for meta
			   <meta http-equiv="refresh" content="0;url=http://a.b.c/index.php?sid=a7"/>
			   <meta http-equiv="refresh" content="0;http://a.b.c/index.php?sid=a7"/>
			   <meta content="0;url=http://a.b.c/index.php?sid=a7" http-equiv="refresh"/>
			   <meta content="0;http://a.b.c/index.php?sid=a7" http-equiv="refresh"/>
			 */
		
			for(i=0;attrs[i];i=i+2) {
				char* meta_url_start;
				if(!ngx_strcmp(attrs[i],"http-equiv") && !ngx_strcmp(attrs[i+1],"refresh")) {
					refresh_flag = 1;
				}
				else if(!ngx_strcmp(attrs[i],"content") && attrs[i+1] && ngx_strlen(attrs[i+1]) > 0) {
					content_flag = 1;
				}
				if(refresh_flag && content_flag) {
					content_pos=ngx_strstr(tmp,(u_char*)attrs[i+1]);
					if(content_pos) {
						meta_url_start=ngx_strchr(content_pos,';');
						if(meta_url_start) {
							meta_url_start = meta_url_start +1;
							ngx_append_chain(ctx,ctx->begin,(u_char*)meta_url_start,0); //the part before url value
							ctx->begin=(u_char*)content_pos+ngx_strlen(attrs[i+1]);
							b = ngx_encode_url(ctx->r,(u_char*)meta_url_start,ctx->begin);
							if(b) ngx_append_buf_to_chain(ctx,b);
							else ngx_append_chain(ctx,(u_char*)meta_url_start,ctx->begin,0);
							//ngx_append_chain(ctx,(u_char*)meta_url_start,ctx->begin,0); // part of value
						}
					}
				}
			}
		}
		else {
			return ;
		}
	}

	//for(i=0;attrs[i];i=i+2){  
	for(i=0;attrs[i];i=i+2){  
		if(!attrs[i]) break;
		for(j=0;j<url_key_len;j++) {
			if(!ngx_strcmp(attrs[i],url_key_lst[j])) {
				tag_pos = ngx_strstr(ctx->begin,(u_char*)name);
				if(tag_pos) {
					attribute_pos = ngx_strstr(tag_pos,(u_char*)attrs[i]);
					if(attribute_pos) {
						value_pos = ngx_strstr(attribute_pos,(u_char*)attrs[i+1]);
						if(value_pos) {
							ngx_append_chain(ctx,ctx->begin,(u_char*)value_pos,0); //the part before url value
							ctx->begin=(u_char*)value_pos+ngx_strlen(attrs[i+1]);
							b = ngx_encode_url(ctx->r,(u_char*)value_pos,ctx->begin);
							if(b) ngx_append_buf_to_chain(ctx,b);
							else ngx_append_chain(ctx,(u_char*)value_pos,ctx->begin,0); 
							//ngx_append_chain(ctx,(u_char*)value_pos,ctx->begin,0); // part of value
							break;
						}
					}
				}
			}
		}
		if(j>=url_key_len) {
			//attributes include url but need special deal
			if(!ngx_strcmp(attrs[i],"style")) {
				/*
				  style="background-image: url('images/button_search.gif'); 
				  style="@import url('images/button_search.gif'); 
				*/
				char* style_tmp;
				style_tmp = ngx_strstr(ctx->begin,(u_char*)attrs[i+1]);
				if(style_tmp) {
					char* style_url;
					u_char* url_start;
					u_char* url_end;
					char* quote_ch;
					u_char* style_end;

					style_url=ngx_strstr((u_char*)style_tmp,"url(");
					if(style_url) {

						quote_ch=style_url+4;
						style_end=(u_char*)style_tmp+ngx_strlen(attrs[i+1]);

						while((u_char*)quote_ch<style_end && isspace(*quote_ch)) quote_ch++;
						url_start=(u_char*)quote_ch+1;

						if(*quote_ch!='\'' && *quote_ch!='"') {
							// url(images/mm.gif)
							url_end=memchr(url_start,')',(u_char*)style_tmp+ngx_strlen(attrs[i+1])-url_start);
							if(url_end) {
								ngx_append_chain(ctx,ctx->begin,url_start,0); //the part before url value
								ctx->begin=url_end;
								b = ngx_encode_url(ctx->r,url_start,ctx->begin);
								if(b) ngx_append_buf_to_chain(ctx,b);
								else ngx_append_chain(ctx,url_start,ctx->begin,0);
								//ngx_append_chain(ctx,url_start,ctx->begin,0); // part of value
							}
						}
						else {
							// url("images/mm.gif")

							url_end=memchr(url_start,*quote_ch,(u_char*)style_tmp+ngx_strlen(attrs[i+1])-url_start);
							if(url_end) {
								ngx_append_chain(ctx,ctx->begin,url_start,0); //the part before url value
								ctx->begin=url_end;
								b = ngx_encode_url(ctx->r,url_start,ctx->begin);
								if(b) ngx_append_buf_to_chain(ctx,b);
								else ngx_append_chain(ctx,url_start,ctx->begin,0); 
								//ngx_append_chain(ctx,url_start,ctx->begin,0); // part of value
							}
						}
					}
				}
			}
			else if(ngx_strstr(attrs[i],"on")) {
				//js hook
				tmp = ngx_strstr(ctx->begin,attrs[i+1]);
				if(tmp) {
					ngx_append_chain(ctx,ctx->begin,(u_char*)tmp,0); //the part before url value
					ctx->begin=(u_char*)tmp+ngx_strlen(attrs[i+1]);
					ngx_update_js(ctx,(u_char*)tmp,ngx_strlen(attrs[i+1]),0);
					break;
				}
			}
			else {
				continue;
			}
		}
	}

	return;
}
/*
 * ----------------------------------------------------------
 * input   : void *voidContext, const xmlChar *name
 * output  : none
 * Descrip : if css or js end,save before infor and call pcre            
 * ----------------------------------------------------------
 */
static void EndElement(void *voidContext, const xmlChar *name)
{
	ngx_http_html_ctx_t *ctx;

	ctx = (ngx_http_html_ctx_t *)voidContext;
	if(ctx->tag_start) {
		//printf(" name %s tag start %x\n",name,ctx->tag_start);
		if(!ngx_strcasecmp(name,"script")) {
			ctx->tag_end = ngx_strcasestr(ctx->tag_start,"</script");
			if(ctx->tag_end) {
				//printf("end element %.*s\n",ctx->tag_end-ctx->tag_start,ctx->tag_start);
				ngx_update_js(ctx,ctx->tag_start,ctx->tag_end-ctx->tag_start,0);
			}
		}
		else if(!ngx_strcasecmp(name,"style")) {
			ctx->tag_end = ngx_strcasestr(ctx->tag_start,"</style");
			if(ctx->tag_end) {
				//printf("end element %.*s\n",ctx->tag_end-ctx->tag_start,ctx->tag_start);
				ngx_update_css(ctx,ctx->tag_start,ctx->tag_end-ctx->tag_start,0);
			}
		}
		else {
			printf("end name %s\n",name);
		}
	}
	ctx->tag_start = NULL;
	ctx->tag_end = NULL;
	return;
}
/*
 * ----------------------------------------------------------
 * input   : void *voidContext, const xmlChar *name
 * output  : none
 * Descrip : if has comment,jump it            
 * ----------------------------------------------------------
 */
static void Comment(void *voidContext, const xmlChar *chars)
{
//	printf("in Comment\n");
	return;
}

/*
 * ----------------------------------------------------------
 * input   : void *voidContext, const xmlChar *name
 * output  : none
 * Descrip : if css or js end,save before infor and call pcre            
 * ----------------------------------------------------------
 */
#define HTML_BUF_SIZE 1024
static void CdataBlock(void *voidContext, xmlChar *chars, int length)
{
	return;
}

static void
ngx_init_pcre()
{
	if(css_re == NULL) {

		pcre_malloc = malloc;
		pcre_free = free;

		css_re = pcre_compile(
				css_pattern,              /* the pattern */
				0,                    /* default options */
				&css_error,               /* for error message */
				&css_erroffset,           /* for error offset */
				NULL);                /* use default character tables */

		if (css_re == NULL)
		{
			printf("css pcre_compile error %d:%s\n",css_erroffset, css_error);
			//ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,"css pcre_compile error %d:%s\n",erroffset, error);
			return ;
		}

	}

	if(js_re == NULL ) {

		pcre_malloc = malloc;
		pcre_free = free;

		js_re = pcre_compile(
				js_pattern,              /* the pattern */
				0,                    /* default options */
				&js_error,               /* for error message */
				&js_erroffset,           /* for error offset */
				NULL);                /* use default character tables */

		if (js_re == NULL)
		{
			printf("js pcre_compile error %d:%s\n",js_erroffset, js_error);
			//ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,"css pcre_compile error %d:%s\n",erroffset, error);
			return ;
		}
	}
}

/*
	0--html
	1--js
	2--css
	-1--other,keep unchanged
*/

static ngx_int_t
ngx_detect_content_type(ngx_http_request_t *r,ngx_chain_t *in)
{
	u_char *ch;
	ngx_chain_t *tmp;

	if(!r->headers_out.content_type.data) {
		return T_OTHER;
	}

	if(ngx_strcasestr(r->headers_out.content_type.data,"text/html") ||
		ngx_strcasestr(r->headers_out.content_type.data,"text/htm") ||
		ngx_strcasestr(r->headers_out.content_type.data,"text/xml")) {

		for(tmp=in;tmp;tmp=tmp->next) {
			ch = tmp->buf->pos;
			while(ch<tmp->buf->last && isspace(*ch)) ch++;
			if(ch>=tmp->buf->last) continue;
			if(*ch=='<') {
				return T_HTML;
			} 
			else {
				return T_JS;
			}
		}

		return T_OTHER;

	}
	else if (ngx_strcasestr(r->headers_out.content_type.data,"text/javascript") ||
			ngx_strcasestr(r->headers_out.content_type.data,"application/javascript") ||
			ngx_strcasestr(r->headers_out.content_type.data,"application/x-javascript"))
	{
		return T_JS;
	}
	else if (ngx_strcasestr(r->headers_out.content_type.data,"text/css"))
	{
		return T_CSS;
	}
	else {
		printf("type %d\n",T_OTHER);
		return T_OTHER;
	}

	return T_OTHER;

}


/*
 * ----------------------------------------------------------
 * input   : ngx_http_request_t *r
 * output  : none
 * return  : next header filter
 * Descrip : header filter
 * ----------------------------------------------------------
 */
static ngx_int_t
ngx_http_html_header_filter(ngx_http_request_t *r)
{
	ngx_http_html_ctx_t        *ctx;
	ngx_http_html_loc_conf_t *slcf;


	//printf("uri %.*s \n",r->uri.len,r->uri.data);

	if(r->headers_out.status == NGX_HTTP_MOVED_TEMPORARILY) {
#if 1 
		unsigned int i;
		ngx_list_part_t *part;
		ngx_table_elt_t *header;
		part = &r->headers_out.headers.part;  
		header = part->elts;
		for (i=0;;i++)
		{  
			if (i >= part->nelts) 
			{
				if (part->next == NULL)        
				{
					break;
				}
				part = part->next;
				header = part->elts;           
				i = 0;            
			}
			if (header[i].key.data && !ngx_strcasecmp("Location",header[i].key.data)) {
				//printf("key %s value %s\n",header[i].key.data,header[i].value.data);
				ngx_buf_t *b;
				b = ngx_encode_url(r,header[i].value.data,header[i].value.data+header[i].value.len);
				if(b==NULL) return ngx_http_next_header_filter(r);
				header[i].value.len = b->last-b->pos; 
				header[i].value.data = b->pos;
				return ngx_http_next_header_filter(r);

			}
		}

#endif
		return ngx_http_next_header_filter(r);
	}


	if (r->headers_out.status != NGX_HTTP_OK || r != r->main) {
		//printf("status %d\n",r->headers_out.status);
		return ngx_http_next_header_filter(r);
	}

	slcf = ngx_http_get_module_loc_conf(r, ngx_http_html_filter_module);
	if(slcf == NULL) {
		return NGX_ERROR;
	}
	if(slcf->enable == 0) return ngx_http_next_header_filter(r);



	ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_html_ctx_t));
	if (ctx == NULL)
	{
		return NGX_ERROR;
	}
	ngx_http_set_ctx(r, ctx, ngx_http_html_filter_module);

	ctx->r=r;
	ctx->size=0;
	ctx->req_len = 0;
	ctx->content_type=T_INIT;

	if(r->headers_out.content_length_n>0) {
		ctx->content_len = r->headers_out.content_length_n;
		ctx->buf.len=r->headers_out.content_length_n;
		//no matter malloc failed or not, ngx_http_next_header_filter and malloc again in 
		ctx->buf.data=ngx_pcalloc(r->pool,ctx->buf.len);
		if(ctx->buf.data==NULL) {
			printf("data malloc error\n");
			ctx->buf.len=0;
		}
	}
	else {
		//malloc data chain by chain
		ctx->content_len=0;
		ctx->buf.len=BLOCK_SZ;
		ctx->buf.data=ngx_pcalloc(r->pool,ctx->buf.len);
		if(ctx->buf.data==NULL) {
			printf("data malloc error\n");
			ctx->buf.len=0;
		}
	}

	r->main_filter_need_in_memory = 1;
	ngx_http_clear_content_length(r);
	ngx_http_clear_accept_ranges(r);


	return ngx_http_next_header_filter(r);
}


/*
 * ----------------------------------------------------------
 * input   : ngx_http_request_t *r,ngx_chain_t *in
 * output  : none
 * return  : next body filter
 * Descrip : htmlbody filter
 * ----------------------------------------------------------
 */
static ngx_int_t
ngx_http_html_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
	ngx_chain_t *tmp;
	unsigned int len=0;
	int last_flag=0;
	ngx_http_html_ctx_t     *ctx;
	int ret;
	ngx_http_html_loc_conf_t *slcf;

	slcf = ngx_http_get_module_loc_conf(r, ngx_http_html_filter_module);
	if(slcf == NULL) {
		return NGX_ERROR;
	}

	if(slcf->enable == 0) return ngx_http_next_body_filter(r, in);

	ctx = ngx_http_get_module_ctx(r, ngx_http_html_filter_module);
	if (ctx == NULL)
	{
		return ngx_http_next_body_filter(r, in);
	}
	if(ctx->content_type == T_INIT) {
		ctx->content_type = ngx_detect_content_type(r,in);
	}
	if(ctx->content_type == T_OTHER) return ngx_http_next_body_filter(r, in);

	for(tmp=in;tmp;tmp=tmp->next) {
		len=tmp->buf->last-tmp->buf->pos;
		ctx->req_len += len;
		//printf("len %d %.*s\n",len,len,tmp->buf->pos);
		if(ctx->size+len>ctx->buf.len) {
			//malloc
			u_char *chunk;
			ctx->buf.len += ctx->buf.len;
			chunk=ngx_pcalloc(r->pool,ctx->buf.len);
			if(chunk==NULL) { 
				printf("chunk malloc error\n");
				return ngx_http_next_body_filter(r, NULL);
			}
			printf("not enough\n");
			if(ctx->buf.data) {
				ngx_memcpy(chunk,ctx->buf.data,ctx->size);
				ngx_memcpy(chunk+ctx->size,tmp->buf->pos,len);
			}
			else {
				ngx_memcpy(chunk,tmp->buf->pos,len);
			}
			ctx->buf.data = chunk;
			ctx->size = ctx->buf.len;
		}
		else {
			//enough
			ngx_memcpy(ctx->buf.data+ctx->size,tmp->buf->pos,len);
			ctx->size+=len;
		}

		tmp->buf->pos = tmp->buf->last;
		tmp->buf->recycled = 0;

		if(tmp->buf->last_buf) last_flag=1;
		if(tmp->next==NULL) break;
	}

	if(last_flag==0) {
		ret = ngx_http_next_body_filter(r, NULL);
		return ret;
	}
	/*
	ngx_append_chain(ctx,ctx->buf.data,ctx->buf.data+ctx->size,1);
	ret = ngx_http_next_body_filter(r, ctx->out);

	return ret;
	*/

	//detect content-type html/js/css
	if(ctx->buf.data == NULL) { 
		return NGX_ERROR;
	}

	ctx->begin=ctx->buf.data;
	ctx->jslib_pos = ctx->buf.data;
	if(ctx->content_type==T_HTML) {
		if (ctx->ctxt == NULL) {
			ctx->ctxt = htmlCreatePushParserCtxt(&saxHandler, ctx, "", 0, "", 
					XML_CHAR_ENCODING_NONE);
					//xmlDetectCharEncoding(ctx->buf.data,ctx->size));
		}
		ret = htmlParseChunk(ctx->ctxt, (char*)ctx->buf.data, ctx->size, 1);
		htmlParseChunk(ctx->ctxt, "", 0, 1);
		htmlFreeParserCtxt(ctx->ctxt);


		ngx_append_chain(ctx,ctx->begin,ctx->buf.data+ctx->size,1);
		return ngx_http_next_body_filter(r, ctx->out);
	}
	else if(ctx->content_type==T_JS) {
		ngx_update_js(ctx,ctx->buf.data,ctx->size,1);
		ngx_append_chain(ctx,ctx->begin,ctx->buf.data+ctx->size,1);
		return ngx_http_next_body_filter(r, ctx->out);
	}
	else if(ctx->content_type==T_CSS) {
		ngx_update_css(ctx,ctx->buf.data,ctx->size,1);
		ngx_append_chain(ctx,ctx->begin,ctx->buf.data+ctx->size,1);
		return ngx_http_next_body_filter(r, ctx->out);
	}
	else {
		return ngx_http_next_body_filter(r, in);
	}

	return ngx_http_next_body_filter(r, ctx->out);
}

/*
 * ----------------------------------------------------------
 * input   : ngx_conf_t *cf
 * output  : none
 * return  : NGX_CONF_OK or NGX_CONF_ERROR
 * Descrip : get html enable flag
 * ----------------------------------------------------------
 */
static void *
ngx_http_html_create_conf(ngx_conf_t *cf)
{
	ngx_http_html_loc_conf_t  *slcf;
	ngx_int_t len;

	ngx_init_pcre();

	ngx_str_set(&jslib_str,"\n<script type=\"text/javascript\" src=\"/js/neti_def.js\"></script>\n");

	slcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_html_loc_conf_t));
	if (slcf == NULL)
	{
		return NULL;
	}

	slcf->enable = NGX_CONF_UNSET;
	return slcf;
}

/*
 * ----------------------------------------------------------
 * input   : ngx_conf_t *cf,void *parent, void *child
 * output  : none
 * return  : NGX_CONF_OK or NGX_CONF_ERROR
 * Descrip : merge urlmap
 * ----------------------------------------------------------
 */
	static char *
ngx_http_html_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_html_loc_conf_t *prev = parent;
	ngx_http_html_loc_conf_t *conf = child;

	ngx_conf_merge_value(conf->enable, prev->enable, 0);
	//ngx_conf_merge_str_value(conf->html_url, prev->html_url, "");
	//ngx_conf_merge_value(conf->timeout, prev->timeout, NGX_CONF_UNSET);

	return NGX_CONF_OK;
}

/*
 * ----------------------------------------------------------
 * input   : ngx_conf_t *cf
 * output  : none
 * return  : NGX_OK
 * Descrip : init html filter
 * ----------------------------------------------------------
 */
	static ngx_int_t
ngx_http_html_filter_init(ngx_conf_t *cf)
{
	ngx_http_next_header_filter = ngx_http_top_header_filter;
	ngx_http_top_header_filter = ngx_http_html_header_filter;

	ngx_http_next_body_filter = ngx_http_top_body_filter;
	ngx_http_top_body_filter = ngx_http_html_body_filter;

	return NGX_OK;
}
