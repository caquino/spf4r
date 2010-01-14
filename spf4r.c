#include "ruby.h"
#include <stdlib.h>  
#include <sys/types.h>
#include <unistd.h>
#include <netinet/in.h>
#include <spf2/spf.h>
#include <stdio.h>

static VALUE
t_query (VALUE self, VALUE map)
{
	int retcode = SPF_RESULT_PASS;
	SPF_server_t *spf_server = NULL;
	SPF_request_t *spf_request = NULL;
	SPF_response_t *spf_response = NULL;
	SPF_response_t *spf_response_2mx = NULL;

	char * ip = STR2CSTR (rb_hash_aref (map,rb_str_new2 ("client_address")));
	char * helo = STR2CSTR (rb_hash_aref (map,rb_str_new2 ("helo_name")));
	char * sender = STR2CSTR (rb_hash_aref (map,rb_str_new2 ("sender")));
	char * recipient = STR2CSTR (rb_hash_aref (map,rb_str_new2 ("recipient")));

	spf_server = SPF_server_new (SPF_DNS_CACHE, 0);
	if (spf_server == NULL) rb_raise (rb_eRuntimeError,  "can't initialize SPF library");

	spf_request = SPF_request_new (spf_server);

	if (SPF_request_set_ipv4_str (spf_request, ip)) rb_raise (rb_eTypeError, "error, invalid IP address");

	if (SPF_request_set_helo_dom (spf_request, helo)) rb_raise (rb_eTypeError, "error, invalid helo domain");

	if (SPF_request_set_env_from (spf_request, sender)) rb_raise (rb_eTypeError, "error, invalid envelope from address");

	SPF_request_query_mailfrom (spf_request, &spf_response);

	if (SPF_response_result (spf_response) != SPF_RESULT_PASS)
	{
		SPF_request_query_rcptto (spf_request, &spf_response_2mx, recipient);

		if (SPF_response_result (spf_response_2mx) == SPF_RESULT_PASS)
		{
			return INT2NUM(SPF_RESULT_PASS);
		}

		retcode = SPF_response_result (spf_response);
	} 
	SPF_server_free(spf_server);

	return INT2NUM(retcode);
}


VALUE cSPF;  

void
Init_spf4r()
{
	cSPF = rb_define_class("SPF", rb_cHash);
	rb_define_method (cSPF,"query", t_query, 1);

	rb_define_const (cSPF,"SPF_RESULT_PASS",INT2NUM(SPF_RESULT_PASS));
	rb_define_const (cSPF,"SPF_RESULT_FAIL",INT2NUM(SPF_RESULT_FAIL));
	rb_define_const (cSPF,"SPF_RESULT_SOFTFAIL",INT2NUM(SPF_RESULT_SOFTFAIL));
	rb_define_const (cSPF,"SPF_RESULT_NEUTRAL",INT2NUM(SPF_RESULT_NEUTRAL));
	rb_define_const (cSPF,"SPF_RESULT_NONE",INT2NUM(SPF_RESULT_NONE));
	rb_define_const (cSPF,"SPF_RESULT_TEMPERROR",INT2NUM(SPF_RESULT_TEMPERROR));
	rb_define_const (cSPF,"SPF_RESULT_PERMERROR",INT2NUM(SPF_RESULT_PERMERROR));
	rb_define_const (cSPF,"SPF_RESULT_INVALID",INT2NUM(SPF_RESULT_INVALID)); 
}
