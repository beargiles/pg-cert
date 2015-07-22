/*
 * This file is released under the PostgreSQL license by its author,
 * Bear Giles <bgiles@coyotesong.com>
 *
 *************************************************************************
 *
 * This file contains general utilities. Some of this would be better handled
 * by macros (for type safety) but the macro ## substitution isn't working
 * as expected.
 *
 *************************************************************************/
#include <stdio.h>
#include <time.h>
#include "postgres.h"
#include "fmgr.h"
#include "pgtime.h"
#include "funcapi.h"
#include "utils/timestamp.h"
#include <postgresql/internal/c.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/pem.h>

#define DATE_LEN 128

PG_MODULE_MAGIC;


/*
 * Convert string to X.
 */
void * pgx_X_from_string(const char *txt,
		void * (*new_object)(void),
		int (*read)(BIO *, void **, pem_password_cb *, void *)) {
    BIO *inp;
	void *x;
	int r;

	x = new_object();
    inp = BIO_new_mem_buf((char *) txt, strlen(txt));

    if ((r = read(inp, &x, 0, NULL)) == NULL) {
            ereport(ERROR,
                (errcode(ERRCODE_DATA_CORRUPTED), errmsg("%s:%d: unable to retrieve data (%d) 1", __FILE__, __LINE__, ERR_get_error())));
    }
    
    BIO_free(inp);

    return x;
}

/*
 * Convert bytea to X.
 */
void * pgx_X_from_bytea(const bytea *raw,
		void * *(new_object)(void),
		int (*d2i)(BIO *, void **)) {
    BIO *bio;
	void *x;
	int r;

    bio = BIO_new_mem_buf(VARDATA(raw), VARSIZE(raw) - VARHDRSZ);
    BIO_set_close(bio, BIO_NOCLOSE);
	x = new_object();

    if ((r = d2i(bio, &x)) == NULL) {
        ereport(ERROR,
                (errcode(ERRCODE_DATA_CORRUPTED), errmsg("%s:%d: unable to retrieve data (%d) 2", __FILE__, __LINE__, ERR_get_error())));
    }

    BIO_free(bio);

    return x;
}

/**
 * Convert X to string.
 */
char * pgx_X_to_string(const void *x, int(*f)(BIO *, const void *)) {
    BIO *bio = BIO_new(BIO_s_mem());
    int len;
    char *ptr, *result;
    int r;

	if ((r = f(bio, x)) != 1) {
        ereport(ERROR,
                (errcode(ERRCODE_DATA_CORRUPTED), errmsg("%s:%d: unable to retrieve data", __FILE__, __LINE__)));
    }

    if ((len = BIO_get_mem_data(bio, &ptr)) < 0) {
        elog(WARNING, "openssl error %d", ERR_get_error());
    }

    result = palloc(len + 1);
    strncpy(result, ptr, len);
    result[len] = '\0';
    BIO_free(bio);

    return result;
}

/**
 * Convert X to bytea
 */
bytea *pgx_X_to_bytea(const void *x, int(*i2d)(BIO *, const void *)) {
    BIO *bio = BIO_new(BIO_s_mem());
    int len;
    bytea *result;
    char *ptr;
    int r;

	if ((r = i2d(bio, x)) != 1) {
        ereport(ERROR,
                (errcode(ERRCODE_DATA_CORRUPTED), errmsg("%s:%d: unable to retrieve data", __FILE__, __LINE__)));
	}

    if ((len = BIO_get_mem_data(bio, &ptr)) < 0) {
        elog(WARNING, "openssl error %d", ERR_get_error());
    }

    result = (bytea *) palloc(len + 1 + VARHDRSZ);
    memcpy(VARDATA(result), ptr, len);
    SET_VARSIZE(result, len + VARHDRSZ);
    BIO_free(bio);

    return result;
}

/*************************************************************************/

/**
 * Convert ASN1_TIME object to PostgreSQL timestamp.
 */
int asn1Time_to_timestamp(ASN1_TIME *asn1, Timestamp *dt) {
    BIO *bio;
    char buf[DATE_LEN];
    struct tm tm;
    struct pg_tm pgtm;
    int r;

    // extract 'not before' date
    bio = BIO_new(BIO_s_mem());
    if ((r = ASN1_TIME_print(bio, asn1)) <= 0) {
        BIO_free(bio);
        ereport(ERROR,
                (errcode(ERRCODE_DATA_CORRUPTED), errmsg("unable to retrieve timestamp")));
        return 1;
    }

    // convert 'not before' date
    if ((r = BIO_gets(bio, buf, DATE_LEN)) <= 0) {
        BIO_free(bio);
        ereport(ERROR,
                (errcode(ERRCODE_DATA_CORRUPTED), errmsg("unable to create ISO-8601 timestamp")));
        return 1;
    }

    BIO_free(bio);

    memset(&tm, 0, sizeof(struct tm));
    strptime(buf, "%b %d %T %Y %z", &tm);
    
    pgtm.tm_sec = tm.tm_sec;
    pgtm.tm_min = tm.tm_min;
    pgtm.tm_hour = tm.tm_hour;
    pgtm.tm_mday= tm.tm_mday;
    pgtm.tm_mon= tm.tm_mon + 1;
    pgtm.tm_year = tm.tm_year + 1900;
    pgtm.tm_wday= tm.tm_wday;
    pgtm.tm_yday = tm.tm_yday;
    pgtm.tm_isdst = tm.tm_isdst;
    pgtm.tm_gmtoff = 0;
    pgtm.tm_zone = "UTC";

    tm2timestamp(&pgtm, 0, NULL, dt);
    
    return 0;
}

/*************************************************************************/

/**
 * Convert BIGNUM to bytea. (Copied from pg-bignum)
 */
bytea * bignum_to_bytea(BIGNUM *bn) {
    int len;
    bytea *results;

    // create bytea results.
    len = BN_num_bytes(bn);
    results = (bytea *) palloc(len + 1 + VARHDRSZ);
    *VARDATA(results) = BN_is_negative(bn) ? 0x01 : 0x00;
    BN_bn2bin(bn, (unsigned char *) VARDATA(results) + 1);
    SET_VARSIZE(results, len + 1 + VARHDRSZ);

    return results;
}