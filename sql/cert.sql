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
-- Create type
--
CREATE TYPE cert;

CREATE OR REPLACE FUNCTION cert_in(cstring) RETURNS cert
AS 'pg_x509', 'pgx_x509_in'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION cert_out(cert) RETURNS CSTRING
AS 'pg_x509', 'pgx_x509_out'
LANGUAGE C IMMUTABLE STRICT;

CREATE TYPE cert (
    INPUT   = cert_in,
    OUTPUT  = cert_out
);

--
-- Create accessor for the basic properties.
--
CREATE OR REPLACE FUNCTION get_version(cert) RETURNS int
AS 'pg_x509', 'pgx_x509_get_version'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION get_serial_number(cert) RETURNS bignum
AS 'pg_x509', 'pgx_x509_get_serial_number'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION get_not_before(cert) RETURNS TIMESTAMP
AS 'pg_x509', 'pgx_x509_get_not_before'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION get_not_after(cert) RETURNS TIMESTAMP
AS 'pg_x509', 'pgx_x509_get_not_after'
LANGUAGE C IMMUTABLE STRICT;

--
-- FIXME: these hould return distinguished names, not strings.
--
CREATE OR REPLACE FUNCTION get_issuer(cert) RETURNS TEXT
AS 'pg_x509', 'pgx_x509_get_issuer'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION get_subject(cert) RETURNS TEXT
AS 'pg_x509', 'pgx_x509_get_subject'
LANGUAGE C IMMUTABLE STRICT;

