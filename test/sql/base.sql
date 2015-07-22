\set ECHO none
BEGIN;
\i sql/cert.sql
\set ECHO all

create table certs (
	cert cert
);

-- these are Thawte and Verisign CA certs.
insert into certs values (
cert('-----BEGIN CERTIFICATE-----
MIIDEzCCAnygAwIBAgIBATANBgkqhkiG9w0BAQQFADCBxDELMAkGA1UEBhMCWkEx
FTATBgNVBAgTDFdlc3Rlcm4gQ2FwZTESMBAGA1UEBxMJQ2FwZSBUb3duMR0wGwYD
VQQKExRUaGF3dGUgQ29uc3VsdGluZyBjYzEoMCYGA1UECxMfQ2VydGlmaWNhdGlv
biBTZXJ2aWNlcyBEaXZpc2lvbjEZMBcGA1UEAxMQVGhhd3RlIFNlcnZlciBDQTEm
MCQGCSqGSIb3DQEJARYXc2VydmVyLWNlcnRzQHRoYXd0ZS5jb20wHhcNOTYwODAx
MDAwMDAwWhcNMjAxMjMxMjM1OTU5WjCBxDELMAkGA1UEBhMCWkExFTATBgNVBAgT
DFdlc3Rlcm4gQ2FwZTESMBAGA1UEBxMJQ2FwZSBUb3duMR0wGwYDVQQKExRUaGF3
dGUgQ29uc3VsdGluZyBjYzEoMCYGA1UECxMfQ2VydGlmaWNhdGlvbiBTZXJ2aWNl
cyBEaXZpc2lvbjEZMBcGA1UEAxMQVGhhd3RlIFNlcnZlciBDQTEmMCQGCSqGSIb3
DQEJARYXc2VydmVyLWNlcnRzQHRoYXd0ZS5jb20wgZ8wDQYJKoZIhvcNAQEBBQAD
gY0AMIGJAoGBANOkUG7I/1Zr5s9dtuoMaHVHoqrC2oQl/Kj0R1HahbUgdJSGHg91
yekIYfUGbTBuFRkC6VLAYttNmZ7iagxEOM3+vuNkCXDF/rFrKbYvScg71CcEJRCX
L+eQbcAoQpnXTEPew/UhbVSfXcNY4cDk2VuwuNy0e982OsK1ZiIS1ocNAgMBAAGj
EzARMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAB/pMaVz7lcxG
7oWDTSEwjsrZqG9JGubaUeNgcGyEYRGhGshIPllDfU+VPaGLtwtimHp1it2ITk6e
QNuozDJ0uW8NxuOzRAvZim+aKZuZGCg70eNAKJpaPNW15yAbi8qkq43pUdniTCxZ
qdq5snUb9kLy78fyGPmJvKP/iiMucEc=
-----END CERTIFICATE-----')),
(cert('-----BEGIN CERTIFICATE-----
MIICPDCCAaUCED9pHoGc8JpK83P/uUii5N0wDQYJKoZIhvcNAQEFBQAwXzELMAkG
A1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMTcwNQYDVQQLEy5DbGFz
cyAxIFB1YmxpYyBQcmltYXJ5IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MB4XDTk2
MDEyOTAwMDAwMFoXDTI4MDgwMjIzNTk1OVowXzELMAkGA1UEBhMCVVMxFzAVBgNV
BAoTDlZlcmlTaWduLCBJbmMuMTcwNQYDVQQLEy5DbGFzcyAxIFB1YmxpYyBQcmlt
YXJ5IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MIGfMA0GCSqGSIb3DQEBAQUAA4GN
ADCBiQKBgQDlGb9to1ZhLZlIcfZn3rmN67eehoAKkQ76OCWvRoiC5XOooJskXQ0f
zGVuDLDQVoQYh5oGmxChc9+0WDlrbsH2FdWoqD+qEgaNMax/sDTXjzRniAnNFBHi
TkVWaR94AoDa3EeRKbs2yWNcxeDXLYd7obcysHswuiovMaruo2fa2wIDAQABMA0G
CSqGSIb3DQEBBQUAA4GBAFgVKTk8d6PaXCUDfGD67gmZPCcQcMgMCeazh88K4hiW
NWLMv5sneYlfycQJ9M61Hd8qveXbhpxoJeUwfLaJFf5n0a3hUKw8fGJLj7qE1xIV
Gx/KXQ/BUpQqEZnae88MNhPVNdwQGVnqlMEAv3WP2fr9dgTbYruQagPZRjXZ+Hxb
-----END CERTIFICATE-----'));


select * from certs;

--
-- get certificate version. should always be 3 but older certs
-- may be other values.
--
select get_version(cert) from certs;

--
-- get basic information about the certificates.
--
select get_serial_number(cert), get_not_before(cert), 
	get_not_after(cert), get_issuer(cert), get_subject(cert) from certs;

--
-- get public key associated with the certificates.
--
-- select get_public_key(cert) from certs;

-- select get_basic_info(cert) from certs;

--
-- store DSA parameters
--
create table dp (
	d	dsa_params
);

insert into dp values('-----BEGIN DSA PARAMETERS-----
MIIBHwKBgQCGIeexFs4ojvI/P2XCJITgkQUj290g3b0XEkp52bA7TzGisr/yclgo
gQaNgOMFl1ihZsb9+TXQ6EVuOjU9kRxg+q8RiOlBfjfECG4iHPJCZkCSlq3Ru/q8
G6MstbYd1JFs+3EnhRUzBbYzsJVRxRK2aWVPpBK9eO0KO7/XpoyPoQIVANxy/fCk
2GZ1obvQ/Tb9yJ8VxZXlAoGBAIMqIgE3BBxOlWPiwPMA9hZrYO9j14ocktABqM/q
+HkZt/+79Prkep2obLgWfxcSUmb7VvtBoazAa5Ru14xvz16TUXj4wFJ+0MVsCI2c
o2RDrQCDKFh0pUITewdUXQfADJLq/kgeSJYwHg3YTDeWNlvvxEQnQvAFQfX6dX+w
ZpE+
-----END DSA PARAMETERS-----');

select d, size(d) from dp;


-- get dsa parameters
select generate_dsa_params(1024);
ROLLBACK;
