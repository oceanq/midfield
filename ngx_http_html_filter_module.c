
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

#define DELTA 19
#define BLOCK_SZ 4096
#define LEN_QUEUE 30
#define OVECCOUNT 30    /* should be a multiple of 3 */
#define ngx_strcasestr(s1, s2)  strcasestr((const char *) s1, (const char *) s2)

static void *ngx_http_html_create_conf(ngx_conf_t *cf);
static char *ngx_http_html_merge_conf(ngx_conf_t *cf,void *parent, void *child);
static ngx_int_t ngx_http_html_filter_init(ngx_conf_t *cf);

ngx_user_session *head=NULL;
service *service_head=NULL;

typedef struct
{
	ngx_flag_t               enable;
} ngx_http_html_loc_conf_t;

typedef struct
{
	ngx_http_request_t *r;
	htmlParserCtxtPtr  ctxt;
	ngx_str_t buf;				//whole response buf
	unsigned int size;			//current size
	u_char *begin;				//where to match url
	ngx_chain_t *out;			//out chains
	ngx_chain_t *busy;
	ngx_int_t type;				//update in StartElement for CdataBlock
	unsigned int req_len;
	unsigned int content_len;

} ngx_http_html_ctx_t;

enum content_type {
	T_OTHER=-1,
	T_HTML,
	T_JS,
	T_CSS
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


static void ngx_encode_url(u_char *start,u_char *end)
{
	u_char *tmp;

	//printf("encoded start:%.*s\n",end-start,start);

	for(tmp=start;tmp<end;tmp++){
		if(*tmp>='A' && *tmp<='Z'){
			*tmp=((*tmp+DELTA-'A')%26+'A');
		}
		if(*tmp>='a' && *tmp<='z'){
			*tmp=((*tmp+DELTA-'a')%26+'a');
		}
	}
	//printf("encoded end:%.*s\n",end-start,start);
}


static void ngx_decode_url(u_char *start,u_char *end)
{
	u_char *tmp;

	for(tmp=start;tmp<end;tmp++){
		if(*tmp>='A' && *tmp<='Z'){
			*tmp=((*tmp-DELTA-'A')%26+'A');
		}
		if(*tmp>='a' && *tmp<='z'){
			*tmp=((*tmp-DELTA-'a')%26+'a');
		}
	}

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

	if(*(subject+ovector[1]-1)=='(') {

		ngx_append_chain(ctx,ctx->begin,(u_char*)subject+ovector[2],0);
		ctx->begin = (u_char*)subject+ovector[5];
		int size = 24+ovector[3]-ovector[2]+ovector[5]-ovector[4];
		b = ngx_create_temp_buf(ctx->r->pool,size);
		if(b==NULL) return 1;
		snprintf((char*)b->pos,size,"neti_jslib_handle(%.*s, \"%.*s\")",ovector[3]-ovector[2],subject+ovector[2],ovector[5]-ovector[4],subject+ovector[4]);
		b->last=b->pos+size;
		ngx_append_chain(ctx,b->pos,b->last,0);
	}
	else {
		//printf("assign: neti_jslib_assign(%.*s, \"%.*s\",%.*s)\n",ovector[7]-ovector[6],subject+ovector[6],ovector[9]-ovector[8],subject+ovector[8],ovector[11]-ovector[10],subject+ovector[10]);
		ngx_append_chain(ctx,ctx->begin,(u_char*)subject+ovector[6],0);
		ctx->begin = ngx_search_js_end((u_char*)subject+ovector[10],(u_char*)subject+ovector[11],(u_char*)subject+len);
		int size = 25+ovector[7]-ovector[6]+ovector[9]-ovector[8]+(ctx->begin-(u_char*)subject)-ovector[10]; 
		b = ngx_create_temp_buf(ctx->r->pool,size);
		if(b==NULL) return 1;
		snprintf((char*)b->pos,size,"neti_jslib_assign(%.*s, \"%.*s\",%.*s)",ovector[7]-ovector[6],subject+ovector[6],ovector[9]-ovector[8],subject+ovector[8],(ctx->begin-(u_char*)subject)-ovector[10],subject+ovector[10]);
		b->last=b->pos+size;
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

		if(*(subject+ovector[1]-1)=='(') {
			//printf("function: neti_jslib_handle(%.*s, \"%.*s\")\n",ovector[3]-ovector[2],subject+ovector[2],ovector[5]-ovector[4],subject+ovector[4]);

			ngx_append_chain(ctx,ctx->begin,(u_char*)subject+ovector[2],0);
			ctx->begin = (u_char*)subject+ovector[5];
			unsigned int size = 24+ovector[3]-ovector[2]+ovector[5]-ovector[4];
			b = ngx_create_temp_buf(ctx->r->pool,size);
			if(b==NULL) return 1;
			snprintf((char*)b->pos,size,"neti_jslib_handle(%.*s, \"%.*s\")",ovector[3]-ovector[2],subject+ovector[2],ovector[5]-ovector[4],subject+ovector[4]);
			b->last=b->pos+size;
			ngx_append_chain(ctx,b->pos,b->last,0);

		}
		else {
			//printf("assign: neti_jslib_assign(%.*s, \"%.*s\",%.*s)\n",ovector[7]-ovector[6],subject+ovector[6],ovector[9]-ovector[8],subject+ovector[8],ovector[11]-ovector[10],subject+ovector[10]);
			ngx_append_chain(ctx,ctx->begin,(u_char*)subject+ovector[6],0);
			ctx->begin = ngx_search_js_end((u_char*)subject+ovector[10],(u_char*)subject+ovector[11],(u_char*)subject+len);
			int size = 25+ovector[7]-ovector[6]+ovector[9]-ovector[8]+(ctx->begin-(u_char*)subject)-ovector[10]; 
			b = ngx_create_temp_buf(ctx->r->pool,size);
			if(b==NULL) return 1;
			snprintf((char*)b->pos,size,"neti_jslib_assign(%.*s, \"%.*s\",%.*s)",ovector[7]-ovector[6],subject+ovector[6],ovector[9]-ovector[8],subject+ovector[8],(ctx->begin-(u_char*)subject)-ovector[10],subject+ovector[10]);
			b->last=b->pos+size;
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
	ngx_encode_url((u_char*)subject+ovector[2*rc-2],ctx->begin);
	ngx_append_chain(ctx,(u_char*)subject+ovector[2*rc-2],ctx->begin,0); // part of value


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
		ngx_encode_url((u_char*)subject+ovector[2*rc-2],ctx->begin);
		ngx_append_chain(ctx,(u_char*)subject+ovector[2*rc-2],ctx->begin,0); // part of value

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
#define KEYNAME_LEN 32
#define neti_js_lib_str "<script type=\"text/javascript\" src=\"/js/neti_def.js\"></script>\n"
#define comment_str "<!--nothing-->"

ngx_buf_t* js_lib_buf;

static void StartElement(void *voidContext, const xmlChar *name, const xmlChar **attrs)
{
	ngx_http_html_ctx_t *ctx;
	//u_char* content_pos;
	char* content_pos;
	//u_char* tmp;
	char* tmp;
	//u_char* attribute_pos;
	char* attribute_pos;
	char* value_pos;
	//u_char* tag_pos;
	char* tag_pos;
	int i,j;
	int refresh_flag=0;
	int content_flag=0;
	int url_key_len;

	ctx = (ngx_http_html_ctx_t *)voidContext;

	if(!ngx_strcmp(name,"script")) {
		ctx->type=T_JS;
	}
	else if(!ngx_strcmp(name,"style")) {
		ctx->type=T_CSS;
	}
	else {
		ctx->type=T_OTHER;
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
							ngx_encode_url((u_char*)meta_url_start,ctx->begin);
							ngx_append_chain(ctx,(u_char*)meta_url_start,ctx->begin,0); // part of value
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
							ngx_encode_url((u_char*)value_pos,ctx->begin);
							ngx_append_chain(ctx,(u_char*)value_pos,ctx->begin,0); // part of value
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
								ngx_encode_url(url_start,ctx->begin);
								ngx_append_chain(ctx,url_start,ctx->begin,0); // part of value
							}
						}
						else {
							// url("images/mm.gif")

							url_end=memchr(url_start,*quote_ch,(u_char*)style_tmp+ngx_strlen(attrs[i+1])-url_start);
							if(url_end) {
								ngx_append_chain(ctx,ctx->begin,url_start,0); //the part before url value
								ctx->begin=url_end;
								ngx_encode_url(url_start,ctx->begin);
								ngx_append_chain(ctx,url_start,ctx->begin,0); // part of value
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
//	printf("in EndElement\n");
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
	ngx_http_html_ctx_t *ctx;
	char* tag_end;
	//u_char* tag_end;

	ctx = (ngx_http_html_ctx_t *)voidContext;

	if(ctx->type==T_OTHER) {
		return;
	}
	else if(ctx->type==T_JS) {
		tag_end = ngx_strstr(ctx->begin,"</script");
		if(tag_end) {
			ngx_update_js(ctx,(u_char*)(tag_end-length),length,0);
		}
		else {
			printf("js tag text matched error\n");
		}

	}
	else if(ctx->type==T_CSS) {

		tag_end = ngx_strstr(ctx->begin,"</style");
		if(tag_end) {
			ngx_update_css(ctx,(u_char*)(tag_end-length),length,0);
		}
		else {
			printf("css tag text matched error\n");
		}
	}
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
ngx_detect_content_type(ngx_http_html_ctx_t *ctx)
{
	ngx_http_request_t *r=ctx->r;
	u_char *ch=ctx->buf.data;
	u_char *end=ctx->buf.data+ctx->size;

	if(!r->headers_out.content_type.data) return T_OTHER;

	if(ngx_strcasestr(r->headers_out.content_type.data,"text/html") ||
		ngx_strcasestr(r->headers_out.content_type.data,"text/htm") ||
		ngx_strcasestr(r->headers_out.content_type.data,"text/xml")) {

		while(ch<end && isspace(*ch)) ch++;

		//if first non-space char is '<', it's probally a html
		if(*ch=='<') {
			return T_HTML;
		} 
		else {
			//may be js
			return T_JS;
		}

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


	printf("uri %.*s content-length %d\n",r->uri.len,r->uri.data,r->headers_out.content_length_n);
	if (r->headers_out.status != NGX_HTTP_OK || r != r->main) {
		return ngx_http_next_header_filter(r);
	}

	slcf = ngx_http_get_module_loc_conf(r, ngx_http_html_filter_module);
	if(slcf == NULL) {
		return NGX_ERROR;
	}
	if(slcf->enable == 0) return ngx_http_next_header_filter(r);

#if 0 
	int i;
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
		printf("key %s value %d\n",header[i].key.data,header[i].value.data);
	}

#endif


	ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_html_ctx_t));
	if (ctx == NULL)
	{
		return NGX_ERROR;
	}
	ngx_http_set_ctx(r, ctx, ngx_http_html_filter_module);

	ctx->r=r;
	ctx->size=0;
	ctx->type=T_OTHER;
	ctx->req_len = 0;
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
	int  content_type;
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

	printf("uri %.*s\n",r->uri.len,r->uri.data);
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

	printf("last flag %d\n",last_flag);
	if(last_flag==0) {
		ret = ngx_http_next_body_filter(r, NULL);
		printf("ret %d\n",ret);
		return ret;
	}
	/*
	ngx_append_chain(ctx,ctx->buf.data,ctx->buf.data+ctx->size,1);
	ret = ngx_http_next_body_filter(r, ctx->out);

	return ret;
	*/

	printf("last flag %d req len %d\n",last_flag,ctx->req_len);
	//detect content-type html/js/css
	if(ctx->buf.data == NULL) { 
		printf("ctx->buf null\n");
		return NGX_ERROR;
	}
	content_type = ngx_detect_content_type(ctx);
	ctx->begin=ctx->buf.data;
	if(content_type==T_HTML) {
		if (ctx->ctxt == NULL) {
			ctx->ctxt = htmlCreatePushParserCtxt(&saxHandler, ctx, "", 0, "", 
					xmlDetectCharEncoding(ctx->buf.data,ctx->size));
		}
		ret = htmlParseChunk(ctx->ctxt, (char*)ctx->buf.data, ctx->size, 1);

		ngx_append_chain(ctx,ctx->begin,ctx->buf.data+ctx->size,0);
		ngx_append_chain(ctx,js_lib_buf->pos,js_lib_buf->last,1);
		return ngx_http_next_body_filter(r, ctx->out);
	}
	else if(content_type==T_JS) {
		printf("get js\n");
		ngx_update_js(ctx,ctx->buf.data,ctx->size,1);
		ngx_append_chain(ctx,ctx->begin,ctx->buf.data+ctx->size,1);
		return ngx_http_next_body_filter(r, ctx->out);
	}
	else if(content_type==T_CSS) {
		printf("get css\n");
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

	len = strlen(neti_js_lib_str);

	js_lib_buf = ngx_create_temp_buf(cf->pool,len);
	if(js_lib_buf == NULL) return NULL;



	ngx_memcpy(js_lib_buf->pos, neti_js_lib_str, len);
	js_lib_buf->last = js_lib_buf->pos+len;   
	js_lib_buf->temporary = 1;
	js_lib_buf->memory = 1;          
	js_lib_buf->last_buf = 1;


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
