/*
 * This file is released under the PostgreSQL license by its author,
 * Bear Giles <bgiles@coyotesong.com>
 *
 *************************************************************************
 *
 * This file contains functions that implement X.509 digital certificate
 * request functionality. Few people will care about this unless they're
 * running a certificate authority.
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
#include <openssl/x509.h>
#include <openssl/pem.h>

#include "certs.h"

X509_REQ * x509_req_from_string(const char *txt) {
	return (X509_REQ *) pgx_X_from_string(txt, X509_REQ_new, PEM_read_bio_X509_REQ);
}

X509_REQ * x509_req_from_bytea(const bytea *raw) {
	return (X509_REQ *) pgx_X_from_bytea(raw, X509_REQ_new, d2i_X509_REQ_bio);
}

char * x509_req_to_string(const X509_REQ *req) {
	return pgx_X_to_string(req, PEM_write_bio_X509_REQ);
}

bytea * x509_req_to_bytea(const X509_REQ *req) {
	return pgx_X_to_bytea(req, i2d_X509_REQ_bio);
}

/*************************************************************************/

/*
 * Code fragment that reads certificate request
 */
#define READ_CERT_REQ(idx) \
	{ \
		bytea *raw = PG_GETARG_BYTEA_P(idx); \
    	if (raw == NULL || VARSIZE(raw) == VARHDRSZ) { \
        	PG_RETURN_NULL(); \
    	} \
		\
    	req = x509_req_from_bytea(raw); \
    	if (req == NULL) { \
       		ereport(ERROR, \
                (errcode(ERRCODE_DATA_CORRUPTED), errmsg( \
                        "unable to decode X509_REQ record"))); \
		} \
    }


/*************************************************************************/

/*
 * Wrappers for OpenSSL 'x509_req' functions.
 */

#define NAME_LEN 1000

/*
 * Read PEM format.
 */
PG_FUNCTION_INFO_V1(pgx_x509_req_in);

Datum pgx_x509_req_in(PG_FUNCTION_ARGS) {
	char *txt;
	X509_REQ *req;
	bytea *result;

    // check for null input
    txt = PG_GETARG_CSTRING(0);
    if (txt == NULL || strlen(txt) == 0) {
        PG_RETURN_NULL();
    }

    // write X509_REQ cert into buffer
    req = x509_req_from_string(txt);
    if (req == NULL) {
        ereport(ERROR,
                (errcode(ERRCODE_DATA_CORRUPTED), errmsg(
                        "unable to decode X509_REQ record")));
        PG_RETURN_NULL();
    }

    result = x509_req_to_bytea(req);
    X509_REQ_free(req);

    // return bytea
    PG_RETURN_BYTEA_P(result);
}

/*
 * Write PEM format.
 */
PG_FUNCTION_INFO_V1(pgx_x509_req_out);

Datum pgx_x509_req_out(PG_FUNCTION_ARGS) {
    bytea *raw;
    char *result;
    X509_REQ *req;

    // check for null value.
    raw = PG_GETARG_BYTEA_P(0);
    if (raw == NULL || VARSIZE(raw) == VARHDRSZ) {
        PG_RETURN_NULL();
    }

    // write X509_REQ into buffer
    req = x509_req_from_bytea(raw);
    result = x509_req_to_string(req);
    X509_REQ_free(req);

    PG_RETURN_CSTRING(result);
}

