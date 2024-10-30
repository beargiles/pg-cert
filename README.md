# pg-cert - PostgreSQL Server extension for Digital Certificates

This repository contains a PostgreSQL Server extension for digital certificates.

It started as part of an effort to clean up prior work going back to the late '90s
but I got side-tracked and never came back to it since I felt the needs and
available technologies had changed. E.g., with the 'pl/java' plugin I could
implement the same functionality in java using BouncyCastle.

Two things have changed since then. The first is that PostgreSQL has had support
for 'Foreign Data Wrappers' (FDW) for some time. This would be a natural encapsulation
of on-prem keystores. As of the last time I checked the 'pl/java' extension doesn't
support FDW but I thought I might be able to contribute a read-only implementation
of one.

The second is that I've had some growing concern about a mismatch between this
and the current implementation of the 'pl/java' extension. The latter isn't incorrect -
far from it - but it's probably not a good match for my goals here.


## Updated Goals

The updated goals are:

- remove deprecated libssl calls
- support additional UDTs and related UDFs
- add pkcs12/p12 FDW
- add 'live' tests using java + testcontainers (uses docker)


### Source code organization

With the addition of the live tests there will be a slight modification to the
source code layout. It will be modified to match the layout used by maven:

  - src:
    - main:
      - c:
      - java:
      - resouces:
        - sql:
    - test:
      - c:
      - java:
      - resources:
        - sql:

This is a slight annoyance but I think it will be easier to maintain.

## Legacy read.me

A long description

To build it, just do this:

    make
    make installcheck
    make install

If you encounter an error such as:

    "Makefile", line 8: Need an operator

You need to use GNU make, which may well be installed on your system as
`gmake`:

    gmake
    gmake install
    gmake installcheck

If you encounter an error such as:

    make: pg_config: Command not found

Be sure that you have `pg_config` installed and in your path. If you used a
package management system such as RPM to install PostgreSQL, be sure that the
`-devel` package is also installed. If necessary tell the build process where
to find it:

    env PG_CONFIG=/path/to/pg_config make && make installcheck && make install

And finally, if all that fails (and if you're on PostgreSQL 8.1 or lower, it
likely will), copy the entire distribution directory to the `contrib/`
subdirectory of the PostgreSQL source tree and try it there without
`pg_config`:

    env NO_PGXS=1 make && make installcheck && make install

If you encounter an error such as:

    ERROR:  must be owner of database regression

You need to run the test suite using a super user, such as the default
"postgres" super user:

    make installcheck PGUSER=postgres

Once cert is installed, you can add it to a database. If you're running
PostgreSQL 9.1.0 or greater, it's a simple as connecting to a database as a
super user and running:

    CREATE EXTENSION cert;

If you've upgraded your cluster to PostgreSQL 9.1 and already had cert
installed, you can upgrade it to a properly packaged extension with:

    CREATE EXTENSION cert FROM unpackaged;

For versions of PostgreSQL less than 9.1.0, you'll need to run the
installation script:

    psql -d mydb -f /path/to/pgsql/share/contrib/cert.sql

If you want to install cert and all of its supporting objects into a specific
schema, use the `PGOPTIONS` environment variable to specify the schema, like
so:

    PGOPTIONS=--search_path=extensions psql -d mydb -f cert.sql

Dependencies
------------
The `cert` data type has no dependencies other than PostgreSQL.

Copyright and License
---------------------

Copyright (c) 2015 The maintainer's name.

