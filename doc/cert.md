cert
====

Synopsis
--------

This extension adds native support for X509 digital certificates. Only OpenSSL format
is supported at the moment but other formats should be easy to add.

Description
-----------

This is very preliminary work that is not intended for production use. Much more
functionality has been prototyped but not yet merged.

The biggest change is that the issuer and subject will become LDAP names (or something similar).
That type will itself convert to the expected strings but it will give us a lot more flexibility
in the meanwhile.


Usage
-----

You can create a digital certificate as a column type and populate it with a standard
OpenSSL digital certificate.

```{sql}
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
```

We can now query basic information about the certificate.

```{sql}
select get_serial_number(cert), get_not_before(cert), 
    get_not_after(cert), get_issuer(cert), get_subject(cert) from certs;
           get_serial_number            |      get_not_before      |      get_not_after       |       get_issuer       |      get_subject       
----------------------------------------+--------------------------+--------------------------+------------------------+------------------------
 1                                      | Thu Aug 01 00:00:00 1996 | Thu Dec 31 23:59:59 2020 | C=ZA/ST=Western Cape/L | C=ZA/ST=Western Cape/L
 84287173645887463140025226144593929437 | Mon Jan 29 00:00:00 1996 | Wed Aug 02 23:59:59 2028 | C=US/O=VeriSign, Inc./ | C=US/O=VeriSign, Inc./
(2 rows)
```


Support
-------

  There is issues tracker? Github? Put this information here.

Author
------

Bear Giles <bgiles@coyotesong.com>

Copyright and License
---------------------

Copyright (c) 2015 Bear Giles <bgiles@coyotesong.com>

