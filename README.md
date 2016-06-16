# Dovecot authentication module for apache

 as dovecot can have many different authentication backends and exposes 
 itself as authentication source trough dovecot-auth client socket (which example
 configuration can be found bellow). This module enables you to authenticate
 users against it using basic authentication. To compile you can use provided Makefile,
 or if you have problems with detected paths autoconf configure script should help you.

 **Always enable authentication over SSL as basic authentication by design is cleartext (base64 encoded only)**

## example dovecot configuration
```
  socket listen {
    #master {
      # Master socket provides access to userdb information. It's typically
      # used to give Dovecot's local delivery agent access to userdb so it
      # can find mailbox locations.
      #path = /var/run/dovecot/auth-master
      #mode = 0600
      # Default user/group is the one who started dovecot-auth (root)
      #user =
      #group =
    #}
    client {
      # The client socket is generally safe to export to everyone. Typical
      # use
      # is to export it to your SMTP server so it can do SMTP AUTH lookups
      # using it.
      path = /var/run/dovecot/auth-client
      mode = 0666
    }
  }

```
Example configuration of apache2 server can be found in "example.conf" file
in same directory. Currently there is possibility to chain it with other
authentication mechanisms but that will / should be discussed anyway.

## example apache2 configuration
```
<Directory "/srv/www/htdocs">
        AuthType Basic
        AuthName "My dovecot authenticated place"
        AuthBasicProvider dovecot
        AuthDovecotAuthSocket /var/run/dovecot/auth-client
        AuthDovecotTimeout 5
        AuthDovecotAuthoritative On
        Require valid-user
        Options Indexes FollowSymLinks
        AllowOverride AuthConfig
        Order allow,deny
        Allow from all
</Directory>
```
