/*
 * This file is released under the PostgreSQL license by its author,
 * Bear Giles <bgiles@coyotesong.com>
 *
 *************************************************************************
 *
 * This file contains functions that implement X.509 digital certificate
 * functionality. 
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

X509 * x509_from_string(const char *txt) {
	return (X509 *) pgx_X_from_string(txt, X509_new, PEM_read_bio_X509);
}

X509 * x509_from_bytea(const bytea *raw) {
	return (X509 *) pgx_X_from_bytea(raw, X509_new, d2i_X509_bio);
}

char * x509_to_string(const X509 *cert) {
	return pgx_X_to_string(cert, PEM_write_bio_X509);
}

bytea * x509_to_bytea(const X509 *cert) {
	return pgx_X_to_bytea(cert, i2d_X509_bio);
}

/*************************************************************************/

/*
 * Code fragment that reads certificate
 */
#define READ_CERT(idx) \
	{ \
		bytea *raw = PG_GETARG_BYTEA_P(idx); \
    	if (raw == NULL || VARSIZE(raw) == VARHDRSZ) { \
        	PG_RETURN_NULL(); \
    	} \
		\
    	cert = x509_from_bytea(raw); \
    	if (cert == NULL) { \
       		ereport(ERROR, \
                (errcode(ERRCODE_DATA_CORRUPTED), errmsg( \
                        "unable to decode X509 record"))); \
		} \
    }


/*************************************************************************/

// for valuable hints see: https://zakird.com/2013/10/13/certificate-parsing-with-openssl/

//X509_check_ca(cert) - returns int (0 = false, > 0 valid)
// SPKAC - Netscape extension used by some CAs.
// X509_extract_key
// X509_name_cmp
// X509_get_signature_type

// X509_get_X509_PUBKEY
// X509_verify(X509 *, EVP_PKEY *)

// X509_sign(X509, PKEY, MD)
// X509_sign_ctx(X509, EVP_MD_CTX)
// ulong X509_NAME_hash(X509_NAME *)

// X509_pubkey_digest(X509, EVP_MD, unsigned char *md, unsigned int *len)
// X509_digest(X509, EVP_MD, unsigned char *, unsigned int *len)
// X509_REQ_digest
// X509_NAME_digest

// PKEY * X509_PUBKEY_get(X509_PUBKEY *)
// i2d_PUBKEY
// d2i PUBKEY

// X509_NAME_set(X509_NAME **, X509_NAME *)

// int X509_alias_set1(X509 *, unsigned char *name, int len)
// int X509_keyid_set1(X509 *, unsigned char *id, int len);
// X509_TRUST_set
// X509_add1_trust_object
// X509_add1_reject_object
// X509_trust_clear(X509 *)
// X509_reject_clear(X509 *)

// X509 *X509_dup(X509)
// X509_REQ *X509_to_X509_REQ(
// X509 *X509_REQ_to_X509(

/*
 * Wrappers for OpenSSL 'x509' functions.
 */

#define NAME_LEN 1000

/*
 * Read PEM format.
 */
PG_FUNCTION_INFO_V1(pgx_x509_in);

Datum pgx_x509_in(PG_FUNCTION_ARGS) {
	char *txt;
	X509 *x509;
	bytea *result;

    // check for null input
    txt = PG_GETARG_CSTRING(0);
    if (txt == NULL || strlen(txt) == 0) {
        PG_RETURN_NULL();
    }

    // write X509 cert into buffer
    x509 = x509_from_string(txt);
    if (x509 == NULL) {
        ereport(ERROR,
                (errcode(ERRCODE_DATA_CORRUPTED), errmsg(
                        "unable to decode X509 record")));
        PG_RETURN_NULL();
    }

    result = x509_to_bytea(x509);
    X509_free(x509);

    // return bytea
    PG_RETURN_BYTEA_P(result);
}

/*
 * Write PEM format.
 */
PG_FUNCTION_INFO_V1(pgx_x509_out);

Datum pgx_x509_out(PG_FUNCTION_ARGS) {
    bytea *raw;
    char *result;
    X509 *cert;

    // check for null value.
    raw = PG_GETARG_BYTEA_P(0);
    if (raw == NULL || VARSIZE(raw) == VARHDRSZ) {
        PG_RETURN_NULL();
    }

    // write X509 cert into buffer
    cert = x509_from_bytea(raw);
    result = x509_to_string(cert);
    X509_free(cert);

    PG_RETURN_CSTRING(result);
}

/*************************************************************************/

/*
 * Get basic (minimal) information about a certificate
 */
PG_FUNCTION_INFO_V1(pgx_x509_get_basic_info);

Datum pgx_x509_get_basic_info(PG_FUNCTION_ARGS) {
    TupleDesc tupdesc;
    HeapTuple tuple;
    bytea *raw;
    X509 *cert;
    char **values;
    X509_NAME *name;
    char buffer[NAME_LEN];
    BIGNUM *bn;
    Timestamp dt;

    // Build a tuple descriptor for our result type
    if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
         ereport(ERROR,
             (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                      errmsg("function returning record called in context that cannot accept type record")));

    // check for null value.
    raw = PG_GETARG_BYTEA_P(0);
    if (raw == NULL || VARSIZE(raw) == VARHDRSZ) {
        PG_RETURN_NULL();
    }

    cert = x509_from_bytea(raw);
    if (cert == NULL) {
        ereport(ERROR,
                (errcode(ERRCODE_DATA_CORRUPTED), errmsg(
                        "unable to decode X509 record")));
    }
    
    values = palloc(5 * sizeof (char *));
    
    // get serial number. (to be fixed...)
    bn = ASN1_INTEGER_to_BN(X509_get_serialNumber(cert), NULL);
    //result = bignum_to_bytea(bn);
    values[0] = pstrdup("1");
    BN_free(bn);

    // get not-before
    values[1] = (char *) timestamptz_to_str(asn1Time_to_timestamp(X509_get_notBefore(cert), &dt));

    // get not-after
    values[2] = (char *) timestamptz_to_str(asn1Time_to_timestamp(X509_get_notAfter(cert), &dt));
    
    // get issuer
    name = X509_get_issuer_name(cert);
    X509_NAME_oneline(name, buffer, NAME_LEN);
    buffer[NAME_LEN-1] = '\0';
    values[3] = pstrdup(buffer);
    
    // get subject
    name = X509_get_subject_name(cert);
    X509_NAME_oneline(name, buffer, NAME_LEN);
    buffer[NAME_LEN-1] = '\0';
    values[4] = pstrdup(buffer);

    // to add: basic constraint, public key.

    X509_free(cert);

    tuple = BuildTupleFromCStrings(TupleDescGetAttInMetadata(tupdesc), values);
    PG_RETURN_DATUM(HeapTupleGetDatum(tuple));
}

        
/*************************************************************************/

/*
 * Get certificate version number. Should always be '3'.
 */
PG_FUNCTION_INFO_V1(pgx_x509_get_version);

Datum pgx_x509_get_version(PG_FUNCTION_ARGS) {
    X509 *cert;
    int version;

	READ_CERT(0);

    version = X509_get_version(cert);
    X509_free(cert);

    PG_RETURN_INT32(version);
}

/*************************************************************************/

/*
 * Get certificate serial number.
 */
PG_FUNCTION_INFO_V1(pgx_x509_get_serial_number);

Datum pgx_x509_get_serial_number(PG_FUNCTION_ARGS) {
    bytea *result;
    BIGNUM *bn;
    X509 *cert;

	READ_CERT(0);

    bn = ASN1_INTEGER_to_BN(X509_get_serialNumber(cert), NULL);
    result = bignum_to_bytea(bn);
    BN_free(bn);
    X509_free(cert);

    PG_RETURN_BYTEA_P(result);
}

/*************************************************************************/

/*
 * Get certificate 'not before' timestamp.
 */
PG_FUNCTION_INFO_V1(pgx_x509_get_not_before);

Datum pgx_x509_get_not_before(PG_FUNCTION_ARGS) {
    X509 *cert;
    Timestamp dt;

	READ_CERT(0);

    asn1Time_to_timestamp(X509_get_notBefore(cert), &dt);

    X509_free(cert);
    
    PG_RETURN_TIMESTAMPTZ(dt);
}

/*************************************************************************/

/*
 * Get certificate 'not after' timestamp.
 */
PG_FUNCTION_INFO_V1(pgx_x509_get_not_after);

Datum pgx_x509_get_not_after(PG_FUNCTION_ARGS) {
    X509 *cert;
    Timestamp dt;

	READ_CERT(0);

    asn1Time_to_timestamp(X509_get_notAfter(cert), &dt);

    X509_free(cert);
    
    PG_RETURN_TIMESTAMPTZ(dt);
}

/*************************************************************************/

/*
 * Get certificate 'issuer'.
 */
PG_FUNCTION_INFO_V1(pgx_x509_get_issuer);

Datum pgx_x509_get_issuer(PG_FUNCTION_ARGS) {
    X509 *cert;
    X509_NAME *name;
    char buffer[NAME_LEN];

	READ_CERT(0);
    
    name = X509_get_issuer_name(cert);
    
    X509_NAME_oneline(name, buffer, NAME_LEN);
    buffer[NAME_LEN-1] = '\0';

    //X509_NAME_free(name);
    X509_free(cert);
    
    PG_RETURN_CSTRING(pstrdup(buffer));
}

/*************************************************************************/

/*
 * Get certificate 'subject'.
 */
PG_FUNCTION_INFO_V1(pgx_x509_get_subject);

Datum pgx_x509_get_subject(PG_FUNCTION_ARGS) {
    X509 *cert;
    X509_NAME *name;
    char buffer[NAME_LEN];

	READ_CERT(0);
    
    name = X509_get_subject_name(cert);
    
    X509_NAME_oneline(name, buffer, NAME_LEN);
    buffer[NAME_LEN-1] = '\0';

    //X509_NAME_free(name);
    X509_free(cert);
    
    PG_RETURN_CSTRING(pstrdup(buffer));
}

/*************************************************************************/

/*
 * Get certificate 'public key'.
 */
PG_FUNCTION_INFO_V1(pgx_x509_get_public_key);

Datum pgx_x509_get_public_key(PG_FUNCTION_ARGS) {
    X509 *cert;
    X509_PUBKEY *key;
    bytea *result;

    READ_CERT(0);
    
    key = X509_get_pubkey(cert);
    result = x509_pubkey_to_bytea;
    X509_PUBKEY_free(key);
    X509_free(cert);
    
    PG_RETURN_BYTEA_P(result);
}
