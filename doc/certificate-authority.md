Introduction to Certificate Authorities
=======================================

Synopsis
--------

Registration Authority (RA)
---------------------------

The registration authority is responsible for collecting and verifying information
from candidates for digital certificates. Public RAs for individuals might require:

* a valid email address
* a valid credit card
* a copy of a driver's license or passport page

Public RAs for companies might require verification of business license and
incorporation documents.

Internal RAs, e.g., for employees or students, will probably be tied to internal
systems. Digital certificates play well with LDAP / Active Directory systems since
they use the same distinguished names. (Both are elements of the X.500 directory
standard.)

Registration authorities are also responsible for approving, denying, and revoking
digital certificates. This could be automatic (e.g., credit card charge went through,
employee record found in Active Directory) or it could require manual intervention.

Certificate Authority (CA)
--------------------------

The confusingly named certificate authority has two responsiblities: signing
digital certificates and maintaining the confidentially of the required private keys.
This is often performed in dedicated hardware.

This project allows it to be done in the database server.

For the most part the certificate authority should simply sign certificates. There
is one exception - digital certificates may specify policies and a CA may either
modify the certificate as required (e.g., shorted the 'valid for' period) or refuse
it outright (e.g., the key length is too small).

Certificate Repository (Repository)
-----------------------------------

The certificate repository is responsible for making certificates and certificate
revocation lists (CRLs) available. There are a half dozen or so search criteria specified
by RFC XXXX so the database underlying the repository should include indexes on these
criteria.

Certificate Lifecycle
---------------------

Certificates have a well-defined life cycle.

* PENDING. All completed certificate requests received by the RA start life in PENDING state.

* APPROVED. The certificate request has been approved by the RA and is passed to the CA to
be signed.

* REJECTED. The certificate request has been rejected by the RA and no further action will
be taken.

* SIGNED. The approved certificate request has been signed by the CA and passed to the repository
for publication.

* EXPIRED. The certificate has expired.

* REVOKED. The certificate has been revoked by either the subject or the RA. This could
happen if the private key has been compromised, the employee left the company, etc.

* NOT-YET-VALID. The certificate is signed but not yet valid.

PostgreSQL Extensions
---------------------

The CERT PostgreSQL extension implements the bottom tier of a CA and repository. It is a C extension.

The CA PostgreSQL extension implements the middle tier of a CA and repository.

No PostgreSQL extension exists for the top tier of a repository since it requires an HTTP,
FTP and/or web service server.

Author
------

Bear Giles <bgiles@coyotesong.com>

Copyright and License
---------------------

Copyright (c) 2015 Bear Giles <bgiles@coyotesong.com>

