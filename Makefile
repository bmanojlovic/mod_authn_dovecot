CFLAGS=-I/usr/include/apache2 -g -O2
LDFLAGS=
all: apache_module

standalone_client:
	gcc -ggdb -g -Wall -o client client.c -lglib-2.0 -I/usr/include/glib-2.0 -I/usr/lib64/glib-2.0/include

testcase:
	gcc -ggdb -g -Wall -o proba proba.c -lglib-2.0 -I/usr/include/glib-2.0 -I/usr/lib64/glib-2.0/include
	gcc -ggdb -g -Wall -o apr_proba apr_proba.c $(CFLAGS) -DLINUX -D_REENTRANT -D_GNU_SOURCE -pthread -I/usr/include/apr-1 -DLINUX -D_REENTRANT -D_GNU_SOURCE -pthread -I/usr/include/apr-1 -lapr-1 -lrt -lpthread -ldl -laprutil-1 -lldap -llber -lexpat -lapr-1 -lrt -lpthread -ldl

apache_module:
	/usr/bin/apxs -c mod_authn_dovecot.c

install:
	/usr/bin/apxs -i -a mod_authn_dovecot.la
clean:
	-rm -rf .libs/ mod_authn_dovecot.la mod_authn_dovecot.lo mod_authn_dovecot.slo client proba apr_proba config.log config.status
