/*
 * This file is released under the PostgreSQL license by its author,
 * Bear Giles <bgiles@coyotesong.com>
 *
 *************************************************************************
 *
 * This file contains functions that implement DSA key functionality.
 * Multiple DSA keys can be quickly generated from a single set of DSA
 * parameters.
 *
 *************************************************************************
 *
 * ENGINE notes: can use DSA_new_method(ENGINE *) instead of DSA_new().
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
#include <openssl/dsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include "certs.h"

// static function since d2i.. is a macro
static int local_d2i_DSAparams_bio(BIO *bp, DSA **x) {
	return d2i_DSAparams_bio(bp, x);
}

// static function since i2d.. is a macro.
static int local_i2d_DSAparams_bio(BIO *bp, const DSA *x) {
	return i2d_DSAparams_bio(bp, x);
}

DSA * dsa_params_from_string(const char *txt) {
	return (DSA *) pgx_X_from_string(txt, DSA_new, PEM_read_bio_DSAparams);
}

DSA * dsa_params_from_bytea(const bytea *raw) {
	return (DSA *) pgx_X_from_bytea(raw, DSA_new, local_d2i_DSAparams_bio);
}

char * dsa_params_to_string(const DSA *params) {
	return pgx_X_to_string(params, PEM_write_bio_DSAparams);
}

bytea * dsa_params_to_bytea(const DSA *params) {
	return pgx_X_to_bytea(params, local_i2d_DSAparams_bio);
}

/*************************************************************************/

/*
 * Code fragment that reads dsa parameters
 */
#define READ_DSA_PARAMS(idx) \
	{ \
		bytea *raw = PG_GETARG_BYTEA_P(idx); \
    	if (raw == NULL || VARSIZE(raw) == VARHDRSZ) { \
        	PG_RETURN_NULL(); \
    	} \
		\
    	params = dsa_params_from_bytea(raw); \
    	if (params == NULL) { \
       		ereport(ERROR, \
                (errcode(ERRCODE_DATA_CORRUPTED), errmsg( \
                        "unable to decode DSAparams record"))); \
		} \
    }


/*************************************************************************/

/*
 * Wrappers for OpenSSL 'dsa_param' functions.
 */

/**
 * Read PEM format.
 */
PG_FUNCTION_INFO_V1(pgx_dsa_params_in);

Datum pgx_dsa_params_in(PG_FUNCTION_ARGS) {
	char *txt;
	DSA *params;
	bytea *result;

    // check for null input
    txt = PG_GETARG_CSTRING(0);
    if (txt == NULL || strlen(txt) == 0) {
        PG_RETURN_NULL();
    }

    // apps.c:load_key
    // apps.c: X509_NAME *parse_name()...
    // int bio_to_mem(unsigned char ** out, int maxlen, BIO *in)

    // write DSAparams into buffer
    params = dsa_params_from_string(txt);
    if (params == NULL) {
        ereport(ERROR,
                (errcode(ERRCODE_DATA_CORRUPTED), errmsg(
                        "unable to decode DSAparams record")));
        PG_RETURN_NULL();
    }

    result = dsa_params_to_bytea(params);
    DSA_free(params);

    // return bytea
    PG_RETURN_BYTEA_P(result);
}

/**
 * Write PEM format.
 */
PG_FUNCTION_INFO_V1(pgx_dsa_params_out);

Datum pgx_dsa_params_out(PG_FUNCTION_ARGS) {
    bytea *raw;
    char *result;
    DSA *params;

    // check for null value.
    raw = PG_GETARG_BYTEA_P(0);
    if (raw == NULL || VARSIZE(raw) == VARHDRSZ) {
        PG_RETURN_NULL();
    }

    // write DSAparams into buffer
    params = dsa_params_from_bytea(raw);
    result = dsa_params_to_string(params);
    DSA_free(params);

    PG_RETURN_CSTRING(result);
}

/**
 * Get size of DSA parameters.
 */
PG_FUNCTION_INFO_V1(pgx_dsa_size_dsa_params);

Datum pgx_dsa_size_dsa_params(PG_FUNCTION_ARGS) {
    int bits;
    char *result;
    DSA *params;

    READ_DSA_PARAMS(0);

    bits = DSA_size(params);
    DSA_free(params);

    PG_RETURN_CSTRING(bits);
}

/**
 * Generate a new set of DSA parameters.
 */
PG_FUNCTION_INFO_V1(pgx_dsa_generate_dsa_params);

Datum pgx_dsa_generate_dsa_params(PG_FUNCTION_ARGS) {
    int bits;
    bytea *result;
    DSA *params;
    const unsigned char seed[32];
    int r;

    // check for null value.
    bits = PG_GETARG_INT32(0);
    if (bits < 1024) {
        bits = 1024;
    }

    RAND_bytes(seed, sizeof(seed));

    params = DSA_new();
    r = DSA_generate_parameters_ex(params, bits, seed, sizeof(seed), NULL, NULL, NULL);
    if (r != 1) {
        elog(WARNING, "openssl error: %d", ERR_get_error(r));
        DSA_free(params);
        PG_RETURN_NULL();
    }

    // write DSAparams into buffer
    result = dsa_params_to_bytea(params);
    DSA_free(params);

    PG_RETURN_BYTEA_P(result);
}


/**
 * Generate a new DSA keypair.
 */
//PG_FUNCTION_INFO_V1(pgx_dsa_generate_dsa_keypair);

Datum pgx_dsa_generate_dsa_keypair(PG_FUNCTION_ARGS) {
    DSA *params;

    READ_DSA_PARAMS(0);

    // new key replaces params.
    DSA_generate_key(params);
    // result = dsa_to_string(params);
    DSA_free(params);

    PG_RETURN_NULL();
}
 