all: standalone_client testcase apache_module

a:	apache_module
standalone_client:
	cc -ggdb -g -Wall -o client client.c `pkg-config glib-2.0 --cflags --libs`
testcase:
	cc -ggdb -g -Wall -o proba proba.c `pkg-config glib-2.0 --cflags --libs`
	cc -ggdb -g -Wall -o apr_proba apr_proba.c -I/usr/include/apache2  -I/usr/include/apr-1 -lapr-1 -laprutil-1
apache_module:
	/usr/sbin/apxs2 -c mod_authn_dovecot.c

install: all
	sudo /usr/sbin/apxs2 -i -a mod_authn_dovecot.la
clean:
	rm -rf .libs/ mod_authn_dovecot.la mod_authn_dovecot.lo mod_authn_dovecot.slo client proba apr_proba
