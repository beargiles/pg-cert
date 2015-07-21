/*
 * This file is released under the PostgreSQL license by its author,
 * Bear Giles <bgiles@coyotesong.com>
 */
#ifndef _CERTS_H
#define _CERTS_H

extern void *pgx_X_from_string(const char *txt,
    void * (*new_object)(void),
    int (*read)(BIO *, void **, pem_password_cb *, void *));
        
extern void *pgx_X_from_bytea(const bytea *raw,
    void * *(new_object)(void),
    int (*d2i)(BIO *, void **));
        
extern char *pgx_X_to_string(const void *x, int(*f)(BIO *, const void *));

extern bytea *pgx_X_to_bytea(const void *x, int(*i2d)(BIO *, const void *));

//
// X.509 certificates
//
extern X509 *x509_from_string(const char *txt);
extern X509 *x509_from_bytea(const bytea *raw);
extern char *x509_to_string(const X509 *cert);
extern bytea *x509_to_bytea(const X509 *cert);

//
// X.509 certificate public keys
//
extern X509_PUBKEY *x509_pubkey_from_string(const char *txt);
extern X509_PUBKEY *x509_pubkey_from_bytea(const bytea *raw);
extern char *x509_pubkey_to_string(const X509_PUBKEY *cert);
extern bytea *x509_pubkey_to_bytea(const X509_PUBKEY *cert);

//
// X.509 certificate requests
//
extern X509_REQ *x509_req_from_string(const char *txt);
extern X509_REQ *x509_req_from_bytea(const bytea *raw);
extern char *x509_req_to_string(const X509_REQ *cert);
extern bytea *x509_req_to_bytea(const X509_REQ *cert);

extern bytea *bignum_to_bytea(BIGNUM *bn);
extern int asn1Time_to_timestamp(ASN1_TIME *asn1, Timestamp *dt);

#endif