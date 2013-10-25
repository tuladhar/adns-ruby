/*
 * Ruby interface to GNU adns asynchronous DNS client library.
 * Copyright (C) 2013 Purushottam Tuladhar <purshottam.tuladhar@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <adns.h>
#include <ruby.h>

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <netinet/in.h>

#define VERSION			"0.3"
#define CSTR2STR(cstr)	((cstr) ? rb_str_new2(cstr) : rb_str_new2(""))
#define CSTR2SYM(cstr)	(rb_str_intern(CSTR2STR(cstr)))
#define CHECK_TYPE(v,t) (Check_Type(v, t))
#define DEFAULT_DIAG_FILEMODE "w"

typedef struct {
    adns_state ads;
    FILE *diagfile;
} rb_adns_state_t;

typedef struct {
    adns_query adq;
    rb_adns_state_t *rb_ads_r;
    VALUE answer;
} rb_adns_query_t;

static VALUE mADNS;					/* ADNS */
static VALUE mADNS__cState;    		/* ADNS::State */
static VALUE mADNS__cQuery;    		/* ADNS::Query */
static VALUE mADNS__mRR;            /* ADNS::RR */
static VALUE mADNS__mStatus;        /* ADNS::Status */
static VALUE mADNS__mIF;         	/* ADNS::IF */
static VALUE mADNS__mQF;         	/* ADNS::QF */
static VALUE mADNS__eError;         /* ADNS::Error */
static VALUE mADNS__eLocalError;    /* ADNS::LocalError */
static VALUE mADNS__eRemoteError;   /* ADNS::RemoteError */
static VALUE mADNS__eQueryError;    /* ADNS::QueryError */
static VALUE maDNS__ePermanentError;/* ADNS::PermanentError */
static VALUE mADNS__eNotReadyError; /* ADNS::NotReadyError */

static void adns_select_timeout(rb_adns_state_t *rb_ads_r, double t)
{
   /*
	* select call on adns query IO rather than file descriptors.
	*/
	struct timeval **tv_mod = NULL, tv_buf, timeout, now;
	int nfds, maxfds = 0;
	fd_set rfds, wfds, efds;
	int ecode;

	timeout.tv_sec = t;
	timeout.tv_usec = 0;
	ecode = gettimeofday(&now, NULL);
	if (ecode == -1)
		rb_raise(mADNS__eError, strerror(ecode));
	FD_ZERO(&rfds); FD_ZERO(&wfds); FD_ZERO(&efds);
	adns_beforeselect(rb_ads_r->ads, &maxfds, &rfds, &wfds, &efds,
					  tv_mod, &tv_buf, &now);
	ecode = select(maxfds, &rfds, &wfds, &efds, &timeout);
	if (ecode == -1)
		rb_raise(mADNS__eError, strerror(ecode));
	ecode = gettimeofday(&now, NULL);
	if (ecode == -1)
		rb_raise(mADNS__eError, strerror(ecode));
	adns_afterselect(rb_ads_r->ads, maxfds, &rfds, &wfds, &efds, &now);
}

/*
 * call-seq: status_to_s(status) => String
 *
 * Convert adns status code to string representation.
 */
static VALUE mADNS__status_to_s(VALUE self, VALUE a1)
{
	adns_status status;
	const char *s;
    
	CHECK_TYPE(a1, T_FIXNUM);
    status = FIX2INT(a1);
	s = adns_strerror(status);
	return CSTR2STR(s);
}

/*
 * call-seq: status_to_ss(status) => String
 *
 * Convert adns status code to short abbreviation string representation.
 */
static VALUE mADNS__status_to_ss(VALUE self, VALUE a1)
{
	adns_status status;
	const char *s;
    
	CHECK_TYPE(a1, T_FIXNUM);
    status = FIX2INT(a1);
	s = adns_errabbrev(status);
	return CSTR2STR(s);
}

void __rdata_modify(VALUE data)
{
    struct RData *data_r = (struct RData *)data;
	long data_len = sizeof(data_r->data);
    VALUE *ptr = ALLOC_N(VALUE, data_len);
    MEMCPY(ptr, data_r->data, VALUE, data_len);
}
#define RDATA_MODIFY(d) (__rdata_modify(d))

static VALUE parse_adns_rr_addr(adns_rr_addr *addr_r)
{
	const char *addr_str = inet_ntoa(addr_r->addr.inet.sin_addr);
	if (!addr_str)
		return CSTR2STR("");
	else
		return CSTR2STR(addr_str);
}

static VALUE parse_adns_rr_hostaddr(adns_rr_hostaddr *hostaddr_r)
{
	VALUE rb_hostaddr = rb_hash_new();
	VALUE host_k = CSTR2SYM("host");
    VALUE host_v = CSTR2STR(hostaddr_r->host);
	VALUE status_k = CSTR2SYM("status");
    VALUE status_v = INT2FIX(hostaddr_r->astatus);
	VALUE addrs_k = CSTR2SYM("addr");
    VALUE addrs_v = rb_ary_new();
	int idx;
    
	if (hostaddr_r->naddrs > 0)
		for (idx=0; idx < hostaddr_r->naddrs; idx++)
			rb_ary_store(addrs_v, idx, parse_adns_rr_addr(hostaddr_r->addrs+idx));

	rb_hash_aset(rb_hostaddr, host_k, host_v);
	rb_hash_aset(rb_hostaddr, status_k, status_v);
	rb_hash_aset(rb_hostaddr, addrs_k, addrs_v);

	return rb_hostaddr;
}


static VALUE parse_adns_rr_soa(adns_rr_soa *soa_r)
{
    VALUE rb_soa = rb_hash_new();
    VALUE mname_k 	= CSTR2SYM("mname");
    VALUE mname_v   = CSTR2STR(soa_r->mname);
    VALUE rname_k	= CSTR2SYM("rname");
    VALUE rname_v	= CSTR2STR(soa_r->rname);
    VALUE serial_k	= CSTR2SYM("serial");
    VALUE serial_v  = INT2FIX(soa_r->serial);
    VALUE refresh_k = CSTR2SYM("refresh");
    VALUE refresh_v = INT2FIX(soa_r->refresh);
    VALUE retry_k	= CSTR2SYM("retry");
    VALUE retry_v = INT2FIX(soa_r->retry);
    VALUE minimum_k = CSTR2SYM("minimum");
    VALUE mimimum_v = INT2FIX(soa_r->minimum);
    
	rb_hash_aset(rb_soa, mname_k, mname_v);
	rb_hash_aset(rb_soa, rname_k, rname_v);
	rb_hash_aset(rb_soa, serial_k, serial_v);
	rb_hash_aset(rb_soa, refresh_k, refresh_v);
	rb_hash_aset(rb_soa, retry_k, retry_v);
	rb_hash_aset(rb_soa, minimum_k, mimimum_v);

	return rb_soa;
}


static VALUE parse_adns_rr_srv(adns_rr_srvraw *srvraw_r, adns_rr_srvha *srvha_r)
{
	VALUE rb_srv = rb_hash_new();
	VALUE priority_k = CSTR2SYM("priority"), priority_v;
	VALUE weight_k = CSTR2SYM("weight"), weight_v;
	VALUE port_k = CSTR2SYM("port"), port_v;
	VALUE host_k = CSTR2SYM("host"), host_v;
	VALUE addrs_k = CSTR2SYM("addrs"), addrs_v;
	
	if (srvraw_r)
	{
		priority_v = INT2FIX(srvraw_r->priority);
		weight_v = INT2FIX(srvraw_r->weight);
		port_v = INT2FIX(srvraw_r->port);
		host_v = CSTR2STR(srvraw_r->host);
		rb_hash_aset(rb_srv, host_k, host_v);
	}
	else if (srvha_r)
	{
		priority_v = INT2FIX(srvha_r->priority);
		weight_v = INT2FIX(srvha_r->weight);
		port_v = INT2FIX(srvha_r->port);
		addrs_v = parse_adns_rr_hostaddr(&srvha_r->ha);
		rb_hash_aset(rb_srv, addrs_k, addrs_v);
	}

	rb_hash_aset(rb_srv, priority_k, priority_v);
	rb_hash_aset(rb_srv, weight_k, weight_v);
	rb_hash_aset(rb_srv, port_k, port_v);

	return rb_srv;
}


static VALUE parse_adns_answer(adns_answer *answer_r)
{
	VALUE rb_answer = rb_ary_new2(answer_r->nrrs);;
	adns_rrtype t = answer_r->type & adns_rrt_typemask;
	adns_rrtype t_dref = answer_r->type & adns__qtf_deref;
    int idx, ecode;
	
	if (answer_r->nrrs == 0)
    /* something went wrong! */
		return rb_answer;

	for (idx=0; idx < answer_r->nrrs; idx++)
	{
		VALUE v; /* record specific value */
        
		/* A, ADDR RECORD */
		if (t == adns_r_a)
			if (t_dref)
				v = parse_adns_rr_addr(answer_r->rrs.addr+idx);
			else
			{
				const char *addr_buf;
				struct in_addr *inaddr_r = answer_r->rrs.inaddr+idx;
				addr_buf = inet_ntoa(*inaddr_r);
				if (ecode)
					v = CSTR2STR("");
				else
					v = CSTR2STR(addr_buf);
			}
		/* NS, NS_RAW RECORD */
            else if (t == adns_r_ns_raw)
                if (t_dref)
                    v = parse_adns_rr_hostaddr(answer_r->rrs.hostaddr+idx);
                else
                    v = CSTR2STR(answer_r->rrs.str[idx]);
		/* CNAME, PTR, PTR_RAW RECORD */
                else if (t == adns_r_cname ||
                         t == adns_r_ptr ||
                         t == adns_r_ptr_raw)
                    v = CSTR2STR(answer_r->rrs.str[idx]);
		/* SOA, SOA_RAW RECORD */
                else if (t == adns_r_soa_raw)
                    v = parse_adns_rr_soa(answer_r->rrs.soa+idx);
		/* HINFO RECORD */
                else if (t == adns_r_hinfo)
                {
                    adns_rr_intstrpair *intstrpair_r = answer_r->rrs.intstrpair+idx;
                    const char *str1 = intstrpair_r->array[0].str;
                    const char *str2 = intstrpair_r->array[1].str;
                    v = rb_ary_new();
                    VALUE v1 = rb_ary_new();
                    VALUE v2 = rb_ary_new();
                    
                    rb_ary_store(v1, 0, INT2FIX(intstrpair_r->array[0].i));
                    rb_ary_store(v1, 1, str1 ? CSTR2STR(str1) : CSTR2STR(""));
                    rb_ary_store(v2, 0, INT2FIX(intstrpair_r->array[1].i));
                    rb_ary_store(v2, 1, str2 ? CSTR2STR(str2) : CSTR2STR(""));
                    rb_ary_store(v, 0, v1);
                    rb_ary_store(v, 1, v2);
                }
		/* MX, MX_RAW RECORD */
                else if (t == adns_r_mx_raw)
                {
                    v = rb_hash_new();
                    VALUE preference_k = CSTR2SYM("preference"), preference_v;
                    
                    if (t_dref) {
                        adns_rr_inthostaddr *inthostaddr_r = answer_r->rrs.inthostaddr+idx;
                        preference_v = INT2FIX(inthostaddr_r->i);
                        v = parse_adns_rr_hostaddr(&inthostaddr_r->ha);
                    } else {
                        adns_rr_intstr *intstr_r = answer_r->rrs.intstr+idx;
                        preference_v = INT2FIX(intstr_r->i);
                        VALUE host_k = CSTR2SYM("host");
                        VALUE host_v = CSTR2STR(intstr_r->str);
                        rb_hash_aset(v, host_k, host_v);
                    }
                    rb_hash_aset(v, preference_k, preference_v);
                }
		/* TXT RECORD */
                else if (t == adns_r_txt)
                {
                    adns_rr_intstr *intstr_r = answer_r->rrs.manyistr[idx];
                    v = CSTR2STR(intstr_r->str);
                }
		/* RP RP_RAW RECORD */
                else if (t == adns_r_rp)
                {
                    adns_rr_strpair *strpair_r = answer_r->rrs.strpair+idx;
                    v = rb_ary_new2(2);
                    rb_ary_store(v, 0, CSTR2STR(strpair_r->array[0]));
                    rb_ary_store(v, 1, CSTR2STR(strpair_r->array[1]));
                }
		/* SRV, SRV_RAW RECORD */
                else if (t == adns_r_srv)
                {
                    if (t_dref) {
                        adns_rr_srvraw *srvraw_r = answer_r->rrs.srvraw+idx;
                        v = parse_adns_rr_srv(srvraw_r, NULL);
                    } else {
                        adns_rr_srvha *srvha_r = answer_r->rrs.srvha+idx;
                        v = parse_adns_rr_srv(NULL, srvha_r);
                    }
                }
		/* UNKNOWN RECORD */
                else
                    v = rb_hash_new();
		/* push value to answer array */
        rb_ary_store(rb_answer, idx, v);
	}
	return rb_answer;
}

static VALUE cQuery_init(VALUE self)
{
	return self;
}

static void cQuery_mark(void *ptr)
{
	rb_adns_query_t *rb_adq_r = (rb_adns_query_t *)ptr;
	rb_gc_mark(rb_adq_r->answer);
}

static void cQuery_free(void *ptr)
{
	rb_adns_query_t *rb_adq_r = (rb_adns_query_t *)ptr;
	rb_adq_r->rb_ads_r = NULL;
	rb_adq_r->adq = NULL;
	rb_adq_r->answer = Qnil;
	(void) free(rb_adq_r);
}

/*
 * call-seq: check => Hash or raises ADNS::NotReadyError
 *
 * Check pending asynchronous request and retrieve answer or raises ADNS::NotReadyError, if request is still pending.
 */
static VALUE cQuery_check(VALUE self)
{
    rb_adns_query_t *rb_adq_r;
    adns_answer *answer_r;
    int ecode;
	
    Data_Get_Struct(self, rb_adns_query_t, rb_adq_r);
	if (rb_adq_r->answer != Qnil)
		return rb_adq_r->answer;
	if (!rb_adq_r->adq)
		rb_raise(mADNS__eQueryError, "invalid query");
	ecode = adns_check(rb_adq_r->rb_ads_r->ads, &rb_adq_r->adq, &answer_r, NULL);
	if (ecode)
    {
		if (ecode == EWOULDBLOCK)
			rb_raise(mADNS__eNotReadyError, strerror(ecode));
		else
        {
			rb_adq_r->adq = NULL;
			rb_raise(mADNS__eError, strerror(ecode));
		}
	}
	rb_adq_r->answer = rb_hash_new();
	rb_hash_aset(rb_adq_r->answer, CSTR2SYM("type"), INT2FIX(answer_r->type));
	rb_hash_aset(rb_adq_r->answer, CSTR2SYM("owner"), CSTR2STR(answer_r->owner));
	rb_hash_aset(rb_adq_r->answer, CSTR2SYM("status"), INT2FIX(answer_r->status));
	rb_hash_aset(rb_adq_r->answer, CSTR2SYM("expires"), INT2FIX(answer_r->expires));
	rb_hash_aset(rb_adq_r->answer, CSTR2SYM("answer"), parse_adns_answer(answer_r));
	rb_adq_r->adq = NULL; /* mark query as completed, thus making it invalid */
	return rb_adq_r->answer;
}

/*
 * call-seq: wait() => Hash
 *
 * Wait until answer is received.
 */
static VALUE cQuery_wait(int argc, VALUE argv[], VALUE self)
{
    rb_adns_query_t *rb_adq_r;
    adns_answer *answer_r;
    int ecode;
	
    Data_Get_Struct(self, rb_adns_query_t, rb_adq_r);
	if (rb_adq_r->answer != Qnil)
		return rb_adq_r->answer;
	if (!rb_adq_r->adq)
		rb_raise(mADNS__eQueryError, "query invalidated");
	ecode = adns_wait(rb_adq_r->rb_ads_r->ads, &rb_adq_r->adq, &answer_r, NULL);
	if (ecode)
	{
		rb_adq_r->adq = NULL;
		rb_adq_r->answer = Qnil;
		rb_raise(mADNS__eError, strerror(ecode));
	}
	rb_adq_r->answer = rb_hash_new();
	rb_hash_aset(rb_adq_r->answer, CSTR2SYM("type"), INT2FIX(answer_r->type));
	rb_hash_aset(rb_adq_r->answer, CSTR2SYM("owner"), CSTR2STR(answer_r->owner));
	rb_hash_aset(rb_adq_r->answer, CSTR2SYM("status"), INT2FIX(answer_r->status));
	rb_hash_aset(rb_adq_r->answer, CSTR2SYM("expires"), INT2FIX(answer_r->expires));
	rb_hash_aset(rb_adq_r->answer, CSTR2SYM("answer"), parse_adns_answer(answer_r));
	rb_adq_r->adq = NULL;
	return rb_adq_r->answer;
}

/*
 * call-seq: cancel() => nil
 *
 * Cancel current pending asynchronous request.
 */
static VALUE cQuery_cancel(VALUE self)
{
	rb_adns_query_t *rb_adq_r;
	int ecode;
    
	Data_Get_Struct(self, rb_adns_query_t, rb_adq_r);
	if (!rb_adq_r->adq)
		rb_raise(mADNS__eQueryError, "query invalidated");
	(void) adns_cancel(rb_adq_r->adq);
	cQuery_free((void *)rb_adq_r);
	return Qnil;
}


/*
 * call-seq: submit(domain, type[, qflags]) => ADNS::Query instance
 *
 * Submit asynchronous request to resolve domain <domain> of record type <type> using optional query flags <qflags>.
 */
static VALUE cState_submit(int argc, VALUE argv[], VALUE self)
{
	rb_adns_query_t *rb_adq_r = ALLOC(rb_adns_query_t);
    const char *owner;
    adns_rrtype type;
	adns_queryflags qflags = adns_qf_owner;
	VALUE query; /* return instance */
	int ecode;
    
    Data_Get_Struct(self, rb_adns_state_t, rb_adq_r->rb_ads_r);
	if (argc < 2)
		rb_raise(rb_eArgError, "wrong number of arguments (%d for 2)", argc);
	else if (argc > 3)
		rb_raise(rb_eArgError, "excess number of arguments (%d for 3)", argc);		
    CHECK_TYPE(argv[0], T_STRING); /* DOMAIN */
    CHECK_TYPE(argv[1], T_FIXNUM); /* RR */
    if (argc == 3)
        CHECK_TYPE(argv[2], T_FIXNUM); /* QFlags */
	owner = STR2CSTR(argv[0]);
	type = FIX2INT(argv[1]);
    if (argc == 3)
        qflags |= FIX2INT(argv[2]);
    rb_adq_r->answer = Qnil;
    query = Data_Wrap_Struct(mADNS__cQuery, cQuery_mark, cQuery_free, rb_adq_r);
    ecode = adns_submit(rb_adq_r->rb_ads_r->ads, owner, type, qflags, (void *)query, &rb_adq_r->adq);
	if (ecode)
		rb_raise(mADNS__eError, strerror(ecode));
	rb_obj_call_init(query, 0, 0);
    return query;
}

/*
 * call-seq: submit_reverse(ipaddr, type[, qflags])	=> ADNS::Query object
 *
 * Submit asynchronous request to reverse lookup address <ipaddr> using optional query flags <qflags>.
 * Note: <type> can only be ADNS::RR::PTR or ADNS::RR::PTR_RAW  
 */
static VALUE cState_submit_reverse(int argc, VALUE argv[], VALUE self)
{
	VALUE query; /* return instance */
	rb_adns_query_t *rb_adq_r = ALLOC(rb_adns_query_t);
	const char *owner;
    struct sockaddr_in addr;
    adns_rrtype type;
	adns_queryflags qflags = adns_qf_owner;
	int idx, ecode;
    
	if (argc < 2)
		rb_raise(rb_eArgError, "wrong number of arguments (%d for 2)", argc);
	if (argc > 3)
		rb_raise(rb_eArgError, "excess number of arguments (%d for 2)", argc);
    CHECK_TYPE(argv[0], T_STRING);
    CHECK_TYPE(argv[1], T_FIXNUM);
    if (argc == 3)
    	CHECK_TYPE(argv[2], T_FIXNUM);
	owner = STR2CSTR(argv[0]);
	type = FIX2INT(argv[1]);
	if (argc == 3)
		qflags |= FIX2INT(argv[2]);
	switch(type)
	{
		case adns_r_ptr:
		case adns_r_ptr_raw:
			break;
		default:
    		rb_raise(rb_eArgError, "invalid record type (PTR or PTR_RAW record expected)");
	}
	addr.sin_family = AF_INET;
	ecode = inet_aton(owner, &addr.sin_addr);
	if (ecode == -1)
		rb_raise(mADNS__eQueryError, "invalid ip address");
    Data_Get_Struct(self, rb_adns_state_t, rb_adq_r->rb_ads_r);
    rb_adq_r->answer = Qnil;
    query = Data_Wrap_Struct(mADNS__cQuery, cQuery_mark, cQuery_free, rb_adq_r);
    rb_obj_call_init(query, 0, 0);
    ecode = adns_submit_reverse(rb_adq_r->rb_ads_r->ads, (struct sockaddr *) &addr,
								type, qflags, (void *)query, &rb_adq_r->adq);
	if (ecode)
		rb_raise(mADNS__eError, strerror(ecode));
    return query;
}

/*
 * call-seq: submit_reverse_any(ip_addr, type[, qflags])	=> ADNS::Query instance
 * 
 * Submit asynchronous request to reverse lookup address <ipaddr> using optional query flags <qflags>.
 * Note: <type> can any resource record.  
 */
static VALUE cState_submit_reverse_any(int argc, VALUE argv[], VALUE self)
{
	VALUE query; /* return instance */
	rb_adns_query_t *rb_adq_r = ALLOC(rb_adns_query_t);
	const char *owner;
	struct sockaddr_in addr;
	const char *zone; /* in-addr.arpa or any other reverse zones */
    adns_rrtype type = adns_r_none;
	adns_queryflags qflags = adns_qf_owner;
	int idx, ecode;
   
    Data_Get_Struct(self, rb_adns_state_t, rb_adq_r->rb_ads_r);
	if (argc < 3)
		rb_raise(rb_eArgError, "wrong number of arguments (%d for 3)", argc);
    if (argc > 4)
    	rb_raise(rb_eArgError, "excess number of arguments (%d for 4)", argc);
    CHECK_TYPE(argv[0], T_STRING); /* IP */
    CHECK_TYPE(argv[1], T_STRING); /* Zone */
    CHECK_TYPE(argv[2], T_FIXNUM); /* RR */
	if (argc == 4)
		CHECK_TYPE(argv[3], T_FIXNUM); /* )); */
    owner = STR2CSTR(argv[0]);
    zone = STR2CSTR(argv[1]);
	type = FIX2INT(argv[2]);
    if (argc == 4)
    	qflags |= FIX2INT(argv[3]);
	addr.sin_family = AF_INET;
	ecode = inet_aton(owner, &addr.sin_addr);
	if (ecode == 0)
		rb_raise(mADNS__eQueryError, "invalid ip address");
	rb_adq_r->answer = Qnil;
	query = Data_Wrap_Struct(mADNS__cQuery, cQuery_mark, cQuery_free, rb_adq_r);
	rb_obj_call_init(query, 0, 0);
    ecode = adns_submit_reverse_any(rb_adq_r->rb_ads_r->ads, (struct sockaddr*)&addr,
    								zone, type, qflags, (void *)query, &rb_adq_r->adq);
	if (ecode)
		rb_raise(mADNS__eError, strerror(ecode));
    return query;
}

/*
 * call-seq: completed()	=> Array
 *
 * Returns an array of all the completed (ADNS::Query) queries submitted using ADNS::State.submit_*() methods.
 */
static VALUE cState_completed_queries(int argc, VALUE argv[], VALUE self)
{
	VALUE a1, query_list = rb_ary_new();
	VALUE query_ctx; /* ADNS::Query context passed from one of the submit_* */
    rb_adns_state_t *rb_ads_r;
	rb_adns_query_t *rb_adq_r;
    adns_query adq;
    adns_answer *answer_r;
    double timeout;
    int ecode;

   	if (argc == 1)
   	{
		a1 = argv[0];
		CHECK_TYPE(a1, T_FLOAT);
   	}
   	else
		a1 = rb_float_new(0.0);
    timeout = (double) RFLOAT_VALUE(a1);
    Data_Get_Struct(self, rb_adns_state_t, rb_ads_r);
	(void) adns_select_timeout(rb_ads_r, timeout);
    for (adns_forallqueries_begin(rb_ads_r->ads);
         (adq = adns_forallqueries_next(rb_ads_r->ads, 0)) != 0;)
    {
        ecode = adns_check(rb_ads_r->ads, &adq, &answer_r, (void **)&query_ctx);
        if (ecode)
            if (ecode == EWOULDBLOCK)
                continue;
		Data_Get_Struct(query_ctx, rb_adns_query_t, rb_adq_r);
		rb_adq_r->answer = rb_hash_new();
		rb_hash_aset(rb_adq_r->answer, CSTR2SYM("type"), INT2FIX(answer_r->type));
		rb_hash_aset(rb_adq_r->answer, CSTR2SYM("owner"), CSTR2STR(answer_r->owner));
		rb_hash_aset(rb_adq_r->answer, CSTR2SYM("status"), INT2FIX(answer_r->status));
		rb_hash_aset(rb_adq_r->answer, CSTR2SYM("expires"), INT2FIX(answer_r->expires));
		rb_hash_aset(rb_adq_r->answer, CSTR2SYM("answer"), parse_adns_answer(answer_r));
		rb_adq_r->adq = NULL;
		free(answer_r);
    	rb_ary_push(query_list, query_ctx);
    }
    return query_list;
}

/*
 * call-seq: synchronous(domain, type[, qflags]) => Hash
 *
 * Submit synchronous request to resolve domain <domain> of record type <type> using optional query flags <qflags>.
 */
static VALUE cState_synchronous(int argc, VALUE argv[], VALUE self)
{
	VALUE answer = rb_hash_new(); /* return instance */
	rb_adns_state_t *rb_ads_r;
	adns_answer *answer_r;
	adns_queryflags qflags = adns_qf_owner;
	adns_rrtype type = adns_r_none;
	const char *owner;
	int ecode;
    
	Data_Get_Struct(self, rb_adns_state_t, rb_ads_r);
    if (argc < 2)
    	rb_raise(rb_eArgError, "wrong number of arguments (%d for 2)", argc);
    if (argc > 3)
    	rb_raise(rb_eArgError, "excess number of arguments (%d for 3)", argc);
    CHECK_TYPE(argv[0], T_STRING); /* DOMAIN */
    CHECK_TYPE(argv[1], T_FIXNUM); /* RR */
    if (argc == 3)
        CHECK_TYPE(argv[2], T_FIXNUM); /* QFlags */
	owner = STR2CSTR(argv[0]);
	type = FIX2INT(argv[1]);
    if (argc == 3)
        qflags |= FIX2INT(argv[2]);
	ecode = adns_synchronous(rb_ads_r->ads, owner, type, qflags, &answer_r);
	if (ecode)
		rb_raise(mADNS__eError, adns_strerror(ecode));
	/* populate return hash */
	rb_hash_aset(answer, CSTR2SYM("type"), INT2FIX(answer_r->type));
	rb_hash_aset(answer, CSTR2SYM("owner"), CSTR2STR(answer_r->owner));
	rb_hash_aset(answer, CSTR2SYM("status"), INT2FIX(answer_r->status));
	rb_hash_aset(answer, CSTR2SYM("expires"), INT2FIX(answer_r->expires));
	rb_hash_aset(answer, CSTR2SYM("answer"), Qnil);
	if (answer_r->nrrs == 0)
		return answer;
	else
		rb_hash_aset(answer, CSTR2SYM("answer"), parse_adns_answer(answer_r));
	return answer;
}

/*
 * call-seq: global_system_failure() => nil
 *
 * Call this function, If serious problem(s) occurs with adns library.
 * All currently outstanding queries will be made to fail with ADNS::Status::SystemFail
 * status code and adns library will close any stream sockets it has open since inception.
 */
static VALUE cState_global_system_failure(VALUE self)
{
	rb_adns_state_t *rb_ads_r;
	Data_Get_Struct(self, rb_adns_state_t, rb_ads_r);
	(void) adns_globalsystemfailure(rb_ads_r->ads);
	return Qnil;
}

static VALUE cState_initialize(int argc, VALUE argv[], VALUE self)
{
	return self;
}

static void cState_free(void *ptr)
{
	rb_adns_state_t *rb_ads_r = (rb_adns_state_t *) ptr;
    (void) adns_finish(rb_ads_r->ads);
    if (rb_ads_r->diagfile)
    	(void) fclose(rb_ads_r->diagfile);
	free(rb_ads_r);
}

static void cState_mark(void *ptr)
{
	return;
}

/*
 * call-seq: new([iflags, filename, filemode])	=> ADNS::State object
 *
 * Create new ADNS::State object and initialize adns library using optional initialization
 * flags <iflags>, debug log to filename <filename> (*only available if ADNS::IF::DEBUG flag is given*),
 * debug log filemode <filemode>.
 */
static VALUE cState_new(int argc, VALUE argv[], VALUE self)
{
    VALUE state; /* return instance */
    rb_adns_state_t *rb_ads_r = ALLOC(rb_adns_state_t);
    rb_ads_r->ads = NULL;
    rb_ads_r->diagfile = NULL;
	adns_initflags iflags = adns_if_none;
    const char *fname, *fmode;
	
	if (argc > 3)
		rb_raise(rb_eArgError, "excess number of arguments (%d for 3)", argc);
	if (argc >= 1)
	{
        CHECK_TYPE(argv[0], T_FIXNUM);
        iflags |= FIX2INT(argv[0]);
    	if (argc >= 2)
    	{
        	CHECK_TYPE(argv[1], T_STRING);
        	fname = STR2CSTR(argv[1]);
    		if (argc == 3)
    		{
        		CHECK_TYPE(argv[2], T_STRING);
        		fmode = STR2CSTR(argv[2]);
			} else
				fmode = DEFAULT_DIAG_FILEMODE;
    		rb_ads_r->diagfile = fopen(fname, fmode);
    		if (!rb_ads_r->diagfile)
        		rb_raise(rb_eIOError, "%s - %s", strerror(errno), fname);
		}
	}
    adns_init(&rb_ads_r->ads, iflags, rb_ads_r->diagfile);
    state = Data_Wrap_Struct(mADNS__cState, cState_mark, cState_free, rb_ads_r);
    rb_obj_call_init(state, 0, 0);
    return state;
}

/*
 * call-seq: new2(configtext, [iflags, filename, filemode])	=> ADNS::State object
 *
 * Create new ADNS::State object and initialize adns library using resolve.conf style
 * configuration text and optional initialization
 * flags <iflags>, debug log to filename <filename> (*only available if ADNS::IF::DEBUG flag is given*),
 * debug log filemode <filemode>.
 */
static VALUE cState_new2(int argc, VALUE argv[], VALUE self)
{
    VALUE state; /* return instance */
    rb_adns_state_t *rb_ads_r = ALLOC(rb_adns_state_t);
    rb_ads_r->ads = NULL;
    rb_ads_r->diagfile = NULL;
	adns_initflags iflags = adns_if_none;
    const char *fname, *fmode, *cfgtxt;
	
	if (argc > 4)
		rb_raise(rb_eArgError, "excess number of arguments (%d for 3)", argc);
	if (argc >= 1)
	{
        CHECK_TYPE(argv[0], T_STRING);
        cfgtxt = STR2CSTR(argv[0]);
        if (argc >= 2)
        {
        	CHECK_TYPE(argv[1], T_FIXNUM);
        	iflags |= FIX2INT(argv[1]);
    	}
    	if (argc >= 3)
    	{
        	CHECK_TYPE(argv[2], T_STRING);
        	fname = STR2CSTR(argv[2]);
    		if (argc == 4)
    		{
        		CHECK_TYPE(argv[3], T_STRING);
        		fmode = STR2CSTR(argv[3]);
			} else
				fmode = DEFAULT_DIAG_FILEMODE;
    		rb_ads_r->diagfile = fopen(fname, fmode);
    		if (!rb_ads_r->diagfile)
        		rb_raise(rb_eIOError, "%s - %s", strerror(errno), fname);
		}
	}
    adns_init_strcfg(&rb_ads_r->ads, iflags, rb_ads_r->diagfile, cfgtxt);
    state = Data_Wrap_Struct(mADNS__cState, cState_mark, cState_free, rb_ads_r);
    rb_obj_call_init(state, 0, 0);
    return state;
}

/*
 * call-seq: finish() => nil
 *
 * Finish all the outstanding queries associated with the ADNS::State instance.
 */
static VALUE cState_finish(VALUE self)
{
	rb_adns_state_t *rb_ads_r;
	Data_Get_Struct(self, rb_adns_state_t, rb_ads_r);
	(void) adns_finish(rb_ads_r->ads);
	return Qnil;
}

/*
 * = ADNS Module
 *
 * === Classes
 * * ADNS::State
 * * ADNS::Query
 * * ADNS::Error
 * * ADNS::LocalError
 * * ADNS::RemoteError
 * * ADNS::QueryError
 * * ADNS::NotReadyError
 *
 * === Class methods
 * * ADNS::status_to_s
 * * ADNS::status_to_ss
 *
 * === Modules
 * * ADNS::RR		- resource record types constant collection module.
 * * ADNS::QF		- adns query flags constant collection module.
 * * ADNS::IF		- adns initialization flags constant collections module.
 * * ADNS::Status	- adns status code constant collection module.
 *
 * === Usage Example
 * ==== Asynchronous
 * require 'rubygems';
 * require 'adns';
 * require 'pp';
 * adns = ADNS::State.new();
 * query = adns.submit("rubygems.org", ADNS::RR:NS);
 * pp query.wait();
 *
 * ==== Synchronous
 * require 'rubygems'
 * require 'adns';
 * require 'pp';
 * adns = ADNS::State.new();
 * pp adns.synchronous('rubygems', ADNS::RR::MX);
 *
 */
void Init_adns(void)
{
   /*
    * Document-module: ADNS
    * ADNS module provides bindings to GNU adns resolver library.
    */
	mADNS = rb_define_module("ADNS");
	rb_define_module_function(mADNS, "status_to_s", mADNS__status_to_s, 1);
	rb_define_module_function(mADNS, "status_to_ss", mADNS__status_to_ss, 1);
    rb_define_const(mADNS, "VERSION", CSTR2STR(VERSION));

   /*
    * Document-class: ADNS::State
    * ADNS::State class defines asychronous/synchronous methods to submit/check the query.
    */
    mADNS__cState = rb_define_class_under(mADNS, "State", rb_cObject);
    rb_define_module_function(mADNS__cState, "new", cState_new, -1);
    rb_define_module_function(mADNS__cState, "new2", cState_new2, -1);
    rb_define_method(mADNS__cState, "initialize", cState_initialize, -1);
    rb_define_method(mADNS__cState, "synchronous", cState_synchronous, -1);
    rb_define_method(mADNS__cState, "submit", cState_submit, -1);
    rb_define_method(mADNS__cState, "submit_reverse", cState_submit_reverse, -1);
    rb_define_method(mADNS__cState, "submit_reverse_any", cState_submit_reverse_any, -1);
    rb_define_method(mADNS__cState, "completed_queries", cState_completed_queries, -1);
    rb_define_method(mADNS__cState, "global_system_failure", cState_global_system_failure, -1);
 
   /*
    * Document-class: ADNS::Query
    * ADNS::Query class defines asychronous/synchronous methods to check the query
    * submitted using one of the ADNS::State.submit* methods.
    */
    mADNS__cQuery = rb_define_class_under(mADNS, "Query", rb_cObject);
    rb_define_method(mADNS__cQuery, "initialize", cQuery_init, 0);
	rb_define_method(mADNS__cQuery, "check", cQuery_check, 0);
	rb_define_method(mADNS__cQuery, "wait", cQuery_wait, -1);
	rb_define_method(mADNS__cQuery, "cancel", cQuery_cancel, 0);
    
   /*
    * Document-module: ADNS::RR
    * Module defines collection of adns resource records.
    */
    mADNS__mRR = rb_define_module_under(mADNS, "RR");
	rb_define_const(mADNS__mRR, "UNKNOWN",	INT2FIX(adns_r_unknown));
	rb_define_const(mADNS__mRR, "NONE",		INT2FIX(adns_r_none));
	rb_define_const(mADNS__mRR, "A",		INT2FIX(adns_r_a));   
	rb_define_const(mADNS__mRR, "NS_RAW",	INT2FIX(adns_r_ns_raw)); 
	rb_define_const(mADNS__mRR, "NS",		INT2FIX(adns_r_ns));
	rb_define_const(mADNS__mRR, "CNAME",	INT2FIX(adns_r_cname));
	rb_define_const(mADNS__mRR, "SOA_RAW",	INT2FIX(adns_r_soa_raw));
	rb_define_const(mADNS__mRR, "SOA",		INT2FIX(adns_r_soa));
	rb_define_const(mADNS__mRR, "PTR_RAW",  INT2FIX(adns_r_ptr_raw));
	rb_define_const(mADNS__mRR, "PTR",		INT2FIX(adns_r_ptr));
	rb_define_const(mADNS__mRR, "HINFO",	INT2FIX(adns_r_hinfo));
	rb_define_const(mADNS__mRR, "MX_RAW",	INT2FIX(adns_r_mx_raw));
	rb_define_const(mADNS__mRR, "MX",		INT2FIX(adns_r_mx));
	rb_define_const(mADNS__mRR, "TXT",		INT2FIX(adns_r_txt));
	rb_define_const(mADNS__mRR, "RP_RAW",	INT2FIX(adns_r_rp_raw));
	rb_define_const(mADNS__mRR, "RP",		INT2FIX(adns_r_rp));
    rb_define_const(mADNS__mRR, "SRV",      INT2FIX(adns_r_srv));
    rb_define_const(mADNS__mRR, "SRV_RAW",  INT2FIX(adns_r_srv_raw));

   /*
    * Document-module: ADNS::Status
    * Module defines collection of adns status code.
    */
	mADNS__mStatus = rb_define_module_under(mADNS, "Status");
    rb_define_const(mADNS__mStatus, "OK", INT2FIX(adns_s_ok));

    // ADNS::LocalError
    rb_define_const(mADNS__mStatus, "NoMemory",       	   INT2FIX(adns_s_nomemory));
    rb_define_const(mADNS__mStatus, "UnknownRRType",  	   INT2FIX(adns_s_unknownrrtype));
    rb_define_const(mADNS__mStatus, "SystemFail",     	   INT2FIX(adns_s_systemfail));
    
    // ADNS::RemoteError
    rb_define_const(mADNS__mStatus, "Timeout",			   INT2FIX(adns_s_timeout));
	rb_define_const(mADNS__mStatus, "AllServFail",         INT2FIX(adns_s_allservfail));
	rb_define_const(mADNS__mStatus, "NoRecurse",           INT2FIX(adns_s_norecurse));
	rb_define_const(mADNS__mStatus, "InvalidResponse",     INT2FIX(adns_s_invalidresponse));
	rb_define_const(mADNS__mStatus, "UnknownFormat",       INT2FIX(adns_s_unknownformat));
	rb_define_const(mADNS__mStatus, "RcodeServFail",       INT2FIX(adns_s_rcodeservfail));
	rb_define_const(mADNS__mStatus, "RcodeFormatError",    INT2FIX(adns_s_rcodeformaterror));
	rb_define_const(mADNS__mStatus, "RcodeNotImplemented", INT2FIX(adns_s_rcodenotimplemented));
	rb_define_const(mADNS__mStatus, "RcodeRefused",        INT2FIX(adns_s_rcoderefused));
	rb_define_const(mADNS__mStatus, "RcodeUnknown",        INT2FIX(adns_s_rcodeunknown));
	rb_define_const(mADNS__mStatus, "Inconsistent",        INT2FIX(adns_s_inconsistent));
	rb_define_const(mADNS__mStatus, "ProhibitedCNAME",     INT2FIX(adns_s_prohibitedcname));
	rb_define_const(mADNS__mStatus, "AnswerDomainInvalid", INT2FIX(adns_s_answerdomaininvalid));
	rb_define_const(mADNS__mStatus, "InvalidData",         INT2FIX(adns_s_invaliddata));
    
    // ADNS::QueryError
	rb_define_const(mADNS__mStatus, "QueryDomainWrong",    INT2FIX(adns_s_querydomainwrong));
	rb_define_const(mADNS__mStatus, "QueryDomainInvalid",  INT2FIX(adns_s_querydomaininvalid));
	rb_define_const(mADNS__mStatus, "QueryDomainTooLong",  INT2FIX(adns_s_querydomaintoolong));
	
    // ADNS::PermanentError
    rb_define_const(mADNS__mStatus, "NXDomain",            INT2FIX(adns_s_nxdomain));
	rb_define_const(mADNS__mStatus, "NoData",              INT2FIX(adns_s_nodata));
    
   /*
    * Document-module: ADNS::IF
    * Module defines collection of adns init flags.
    */
	mADNS__mIF = rb_define_module_under(mADNS, "IF");
	rb_define_const(mADNS__mIF, "NONE",	    	INT2FIX(adns_if_none));
 	rb_define_const(mADNS__mIF, "NOENV",	    INT2FIX(adns_if_noenv));
	rb_define_const(mADNS__mIF, "NOERRPRINT",  	INT2FIX(adns_if_noerrprint));
	rb_define_const(mADNS__mIF, "NOSERVWarn",  	INT2FIX(adns_if_noserverwarn));
	rb_define_const(mADNS__mIF, "DEBUG",       	INT2FIX(adns_if_debug));
	rb_define_const(mADNS__mIF, "LOGPID",      	INT2FIX(adns_if_logpid));
	rb_define_const(mADNS__mIF, "NOAUTOSYS",   	INT2FIX(adns_if_noautosys));
	rb_define_const(mADNS__mIF, "EINTR",	    INT2FIX(adns_if_eintr));
	rb_define_const(mADNS__mIF, "NOSIGPIPE",   	INT2FIX(adns_if_nosigpipe));
	rb_define_const(mADNS__mIF, "CHECKC_ENTEX", INT2FIX(adns_if_checkc_entex));
	rb_define_const(mADNS__mIF, "CHECKC_FREQ",	INT2FIX(adns_if_checkc_freq));

   /*
    * Document-module: ADNS::QF
    * Module defines collection of adns query flags.
    */
    mADNS__mQF = rb_define_module_under(mADNS, "QF");
	rb_define_const(mADNS__mQF, "NONE",		    	INT2FIX(adns_qf_none));
	rb_define_const(mADNS__mQF, "SEARCH",		    INT2FIX(adns_qf_search));
	rb_define_const(mADNS__mQF, "USEVC",		    INT2FIX(adns_qf_usevc));
	rb_define_const(mADNS__mQF, "OWNER",		    INT2FIX(adns_qf_owner));
	rb_define_const(mADNS__mQF, "QUOTEOK_QUERY",	INT2FIX(adns_qf_quoteok_query));
	rb_define_const(mADNS__mQF, "QUOTEOK_CNAME",	INT2FIX(adns_qf_quoteok_cname));
	rb_define_const(mADNS__mQF, "QUOTEOK_ANSHOST",	INT2FIX(adns_qf_quoteok_anshost));
	rb_define_const(mADNS__mQF, "QUOTEFAIL_CNAME",	INT2FIX(adns_qf_quotefail_cname));
	rb_define_const(mADNS__mQF, "CNAME_LOOSE",	    INT2FIX(adns_qf_cname_loose));
	rb_define_const(mADNS__mQF, "CNAME_FORBID",    	INT2FIX(adns_qf_cname_forbid));

	/*
	 * Document-class: ADNS::Error
	 */
	mADNS__eError		  = rb_define_class_under(mADNS, "Error", rb_eException);
	/*
	 * Document-class: ADNS::LocalError
	 */	
	mADNS__eLocalError	  = rb_define_class_under(mADNS, "LocalError", mADNS__eError);
	/*
	 * Document-class: ADNS::RemoteError
	 */
	mADNS__eRemoteError	  = rb_define_class_under(mADNS, "RemoteError",	mADNS__eError);
	/*
	 * Document-class: ADNS::QueryError
	 */
	mADNS__eQueryError	  = rb_define_class_under(mADNS, "QueryError", mADNS__eError);
	/*
	 * Document-class: ADNS::PermanentError
	 */    
    maDNS__ePermanentError = rb_define_class_under(mADNS, "PermanentError", mADNS__eError);
	/*
	 * Document-class: ADNS::NotReadyError
	 */	
	mADNS__eNotReadyError  = rb_define_class_under(mADNS, "NotReadyError", mADNS__eError);
}
