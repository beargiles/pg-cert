--
-- This file is released under the PostgreSQL license by its author,
-- Bear Giles <bgiles@coyotesong.com>
--
-- ---------------------------------------------------------------------------------
--
-- Author: Bear Giles <bgiles@coyotesong.com>
-- Created at: 2015-07-19 14:03:05 -0600
--
-- ---------------------------------------------------------------------------------

CREATE EXTENSION IF NOT EXISTS bignum;

--
-- Create type: X.509 digital certificate
--
CREATE TYPE cert;

CREATE OR REPLACE FUNCTION cert_in(cstring) RETURNS cert
AS 'cert', 'pgx_x509_in'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION cert_out(cert) RETURNS CSTRING
AS 'cert', 'pgx_x509_out'
LANGUAGE C IMMUTABLE STRICT;

CREATE TYPE cert (
    INPUT   = cert_in,
    OUTPUT  = cert_out
);

-- ---------------------------------------------------------------------------------

--
-- Create type: X.509 digital certificate public key
--
CREATE TYPE pubkey;

CREATE OR REPLACE FUNCTION pubkey_in(cstring) RETURNS pubkey
AS 'cert', 'pgx_x509_pubkey_in'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION pubkey_out(pubkey) RETURNS CSTRING
AS 'cert', 'pgx_x509_pubkey_out'
LANGUAGE C IMMUTABLE STRICT;

CREATE TYPE pubkey (
    INPUT   = pubkey_in,
    OUTPUT  = pubkey_out
);

-- ---------------------------------------------------------------------------------

--
-- Create type: X.509 digital certificate request
--
CREATE TYPE cert_req;

CREATE OR REPLACE FUNCTION cert_req_in(cstring) RETURNS cert_req
AS 'cert', 'pgx_x509_req_in'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION cert_req_out(cert_req) RETURNS CSTRING
AS 'cert', 'pgx_x509_req_out'
LANGUAGE C IMMUTABLE STRICT;

CREATE TYPE cert_req (
    INPUT   = cert_req_in,
    OUTPUT  = cert_req_out
);

-- ---------------------------------------------------------------------------------

--
-- Create type: mandatory information in digital certificate.
--
CREATE TYPE basic_cert_info AS (
   serial     bignum,
   not_before TIMESTAMP,
   not_after  TIMESTAMP,
   issuer     text,
   subject    text
-- basic_constraint bool
-- public_key key
);

--
-- Create accessor for the basic properties.
--
CREATE OR REPLACE FUNCTION get_basic_info(cert) RETURNS basic_cert_info
AS 'cert', 'pgx_x509_get_basic_info'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION get_version(cert) RETURNS int
AS 'cert', 'pgx_x509_get_version'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION get_serial_number(cert) RETURNS bignum
AS 'cert', 'pgx_x509_get_serial_number'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION get_not_before(cert) RETURNS TIMESTAMP
AS 'cert', 'pgx_x509_get_not_before'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION get_not_after(cert) RETURNS TIMESTAMP
AS 'cert', 'pgx_x509_get_not_after'
LANGUAGE C IMMUTABLE STRICT;

--
-- FIXME: these hould return distinguished names, not strings.
--
CREATE OR REPLACE FUNCTION get_issuer(cert) RETURNS TEXT
AS 'cert', 'pgx_x509_get_issuer'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION get_subject(cert) RETURNS TEXT
AS 'cert', 'pgx_x509_get_subject'
LANGUAGE C IMMUTABLE STRICT;

--
-- Get public key associated with certificate
--
CREATE OR REPLACE FUNCTION get_public_key(cert) RETURNS pubkey
AS 'cert', 'pgx_x509_get_public_key'
LANGUAGE C IMMUTABLE STRICT;
