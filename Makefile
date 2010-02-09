all:
	cc -o proba proba.c  -I/usr/include/glib-2.0 -I/usr/lib64/glib-2.0/include -lglib-2.0
	cc -ggdb -g -Wall -o client client.c `pkg-config glib-2.0 --cflags --libs`
	/usr/sbin/apxs2 -c mod_authn_dovecot.c

install:
	sudo /usr/sbin/apxs2 -i -a mod_authn_dovecot.la
clean:
	rm -rf .libs/ mod_authn_dovecot.la mod_authn_dovecot.lo mod_authn_dovecot.slo client proba mod_authn_dovecot.pidb
