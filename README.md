## Description:
adtool is a unix command line utility for Active Directory administration.  Features include user and group creation, deletion, modification, password setting and directory query and search capabilities.

## System requirements:
adtool requires LDAP libraries to be installed (www.openldap.org).  To use secure (ldaps://) connections OpenLDAP has to have been built with SSL support.  SSL support is required for the password setting feature to work.

## Installation:
```
tar zxvf adtools-1.x.tar.gz
cd adtools-1.x
./configure
make
make install
```

Configure options: `--prefix=install_path`, `--with-ldap=/openldap_install_prefix`

## Configuration:
An example configuration file is installed to {prefix}/etc/adtool.cfg.dist.  Rename this to adtool.cfg and edit as appropriate.  Alternatively, command line options can be used.

## Usage:
```
> adtool list ou=user,dc=example,dc=com
CN=allusers,OU=user,DC=example,DC=com
OU=finance,OU=user,DC=example,DC=com
OU=administration,OU=user,DC=example,DC=com

> adtool oucreate marketing ou=user,dc=example,dc=com
> adtool useradd jsmith ou=marketing,ou=user,dc=example,dc=com
> adtool setpass jsmith banana
> adtool unlock jsmith
> adtool groupadd allusers jsmith
> adtool attributereplace jsmith telephonenumber 123
> adtool attributereplace jsmith mail jsmith@example.com
```

See the adtool man page for more info


