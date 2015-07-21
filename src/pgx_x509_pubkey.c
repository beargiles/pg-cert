/*
 * This file is released under the PostgreSQL license by its author,
 * Bear Giles <bgiles@coyotesong.com>
 *
 *************************************************************************
 *
 * This file contains functions that implement X.509 digital certificate
 * public keys. They are related EVP_PKEY and PKEY types. 
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

X509_PUBKEY * x509_pubkey_from_string(const char *txt) {
	return (X509_PUBKEY *) pgx_X_from_string(txt, X509_PUBKEY_new, PEM_read_bio_PUBKEY);
}

X509_PUBKEY * x509_pubkey_from_bytea(const bytea *raw) {
	return (X509_PUBKEY *) pgx_X_from_bytea(raw, X509_PUBKEY_new, d2i_PUBKEY_bio);
}

char * x509_pubkey_to_string(const X509_PUBKEY *cert) {
	return pgx_X_to_string(cert, PEM_write_bio_PUBKEY);
}

bytea * x509_pubkey_to_bytea(const X509_PUBKEY *cert) {
	return pgx_X_to_bytea(cert, i2d_PUBKEY_bio);
}

/*************************************************************************/

/*
 * Code fragment that reads certificate
 */
#define READ_PUBKEY(idx) \
	{ \
		bytea *raw = PG_GETARG_BYTEA_P(idx); \
    	if (raw == NULL || VARSIZE(raw) == VARHDRSZ) { \
        	PG_RETURN_NULL(); \
    	} \
		\
    	cert = x509_pubkey_from_bytea(raw); \
    	if (cert == NULL) { \
       		ereport(ERROR, \
                (errcode(ERRCODE_DATA_CORRUPTED), errmsg( \
                        "unable to decode X509 public key record"))); \
		} \
    }


/*************************************************************************/

/*
 * Wrappers for OpenSSL 'X509_PUBKEY' functions.
 */

#define NAME_LEN 1000

/*
 * Read PEM format.
 */
PG_FUNCTION_INFO_V1(pgx_x509_pubkey_in);

Datum pgx_x509_pubkey_in(PG_FUNCTION_ARGS) {
	char *txt;
	X509_PUBKEY *key;
	bytea *result;

    // check for null input
    txt = PG_GETARG_CSTRING(0);
    if (txt == NULL || strlen(txt) == 0) {
        PG_RETURN_NULL();
    }

    // write X509_PUBKEY into buffer
    key = x509_pubkey_from_string(txt);
    if (key == NULL) {
        ereport(ERROR,
                (errcode(ERRCODE_DATA_CORRUPTED), errmsg(
                        "unable to decode X509_PUBKEY record")));
        PG_RETURN_NULL();
    }

    result = x509_pubkey_to_bytea(key);
    X509_PUBKEY_free(key);

    // return bytea
    PG_RETURN_BYTEA_P(result);
}

/*
 * Write PEM format.
 */
PG_FUNCTION_INFO_V1(pgx_x509_pubkey_out);

Datum pgx_x509_pubkey_out(PG_FUNCTION_ARGS) {
    bytea *raw;
    char *result;
    X509_PUBKEY *key;

    // check for null value.
    raw = PG_GETARG_BYTEA_P(0);
    if (raw == NULL || VARSIZE(raw) == VARHDRSZ) {
        PG_RETURN_NULL();
    }

    // write X509_PUBKEY into buffer
    key = x509_pubkey_from_bytea(raw);
    result = x509_pubkey_to_string(key);
    X509_PUBKEY_free(key);

    PG_RETURN_CSTRING(result);
}

