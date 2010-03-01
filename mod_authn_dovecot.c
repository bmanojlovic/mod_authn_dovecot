/*  
 Copyright 2010 Boris Manojlovic <boris@steki.net>
 Licensed under the Apache License, Version 2.0 (the "License"); 
 you may not use this file except in compliance with the License. 
 You may obtain a copy of the License at
 
 	 http://www.apache.org/licenses/LICENSE-2.0 
 
 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 See the License for the specific language governing permissions and 
 limitations under the License. 
*/

#include "apr_strings.h"

#include "ap_config.h"
#include "ap_provider.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "mod_auth.h"

#include <unistd.h>
#include <stdio.h>

#include "apr_base64.h"		// base64 encode

// What has been implemented
/*
"S:" = What dovecot-auth is writing...
"C:" = What we should write for succesfull auth...

S:MECH <TAB> PLAIN <TAB> plaintext <NEWLINE>
S:MECH <TAB> LOGIN <TAB> plaintext <NEWLINE>
S:VERSION <TAB> 1 <TAB> 0 <NEWLINE>
S:SPID <TAB> 3924 <NEWLINE>
S:CUID <TAB> 3032 <NEWLINE>
S:DONE <NEWLINE>

// handshake
C:VERSION <TAB> 1 <TAB> 0 <NEWLINE>
C:CPID <TAB> <MY_PID> <NEWLINE>

// authorization step
// resp is base64("\0user:\0password")
C:AUTH <TAB> 1 <TAB> PLAIN <TAB> service=apache <TAB> nologin <TAB> lip=127.0.0.1 <TAB> rip=10.10.10.1 <TAB> secured <TAB> resp=AGpvaG5kb2UAcGFzc3dvcmQ== <NEWLINE>

// on successs this should be output
S:OK <TAB> 1 <TAB> user=johndoe  <NEWLINE>
*/

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#define BUFFMAX 8192
// Supported version of dovecot auth protocol
#define AUTH_PROTOCOL_MAJOR_VERSION 1
#define AUTH_PROTOCOL_MINOR_VERSION 1
#define AUTH_MECHANISM "PLAIN"

// Apache configuration variables
typedef struct {
	char *dovecotauthsocket;
	int dovecotauthtimeout;
	int authoritative;
} authn_dovecot_config_rec;

// struct which defines current state of connection to dovecot auth socket
struct connection_state {
	int version_ok;
	int mech_available;
	int hshake_done;
	int authenticated;
	int handshake_sent;
};

/* proto */
int sock_readline(apr_pool_t * p, request_rec * r, int sock, char *data);
int receive_data(apr_pool_t * p, request_rec * r, struct connection_state *cs, char *data);
int send_handshake(apr_pool_t * p, request_rec * r, int sock);
int send_auth_request(apr_pool_t * p, request_rec * r, int sock, const char *user, const char *pass, char *remotehost);

static void *create_authn_dovecot_dir_config(apr_pool_t * p, char *d)
{
	authn_dovecot_config_rec *conf = apr_pcalloc(p, sizeof(*conf));

	conf->dovecotauthsocket = "/var/run/dovecot/auth-client";	/* just to illustrate the default really */
	conf->dovecotauthtimeout = 5;
	conf->authoritative = 1;	// by default we are authoritative
	return conf;
}

static const command_rec authn_dovecot_cmds[] = {
	AP_INIT_TAKE1("AuthDovecotAuthSocket", ap_set_string_slot,
		      (void *)APR_OFFSETOF(authn_dovecot_config_rec,
					   dovecotauthsocket),
		      OR_AUTHCFG, "Dovecot auth deamon listening socket"),
	AP_INIT_FLAG("AuthDovecotAuthoritative", ap_set_flag_slot,
		     (void *)APR_OFFSETOF(authn_dovecot_config_rec,
					  authoritative),
		     OR_AUTHCFG,
		     "Set to 'Off' to allow access control to be passed along to "
		     "lower modules if the UserID is not known to this module. " "(default is On)."),
	AP_INIT_TAKE1("AuthDovecotTimeout", ap_set_int_slot,
		     (void *)APR_OFFSETOF(authn_dovecot_config_rec,
					  dovecotauthtimeout),
		     OR_AUTHCFG, "Timeout waiting for authorization in seconds"),
	{NULL}
};

module AP_MODULE_DECLARE_DATA authn_dovecot_module;


// main check password function which do real job of authentication against dovecot
static authn_status check_password(request_rec * r, const char *user, const char *password)
{
	authn_dovecot_config_rec *conf = ap_get_module_config(r->per_dir_config,
							      &authn_dovecot_module);
	apr_pool_t *p;		// sub pool of r->pool

	int i, auths, readsocks, result, opts, fdmax, cnt, auth_in_progress, retval;
	struct sockaddr_un address;
	struct timeval tv;
	struct connection_state cs;

	apr_pool_create(&p, r->pool);	// create subpool for local functions, variables...

	// setting default values for connection state 
	cs.version_ok = 0;
	cs.mech_available = 0;
	cs.hshake_done = 0;
	cs.authenticated = 0;	// by default user is NOT authenticated :)
	cs.handshake_sent = 0;

	fd_set socks_r;
	fd_set socks_w;
	fd_set error_fd;
	
	char *line = apr_pcalloc(p, sizeof(char) * (BUFFMAX + 1));
	auths = socket(AF_UNIX, SOCK_STREAM, 0);
	opts = fcntl(auths, F_GETFL);
	opts = (opts | O_NONBLOCK);
	if (fcntl(auths, F_SETFL, opts) < 0) {
		perror("fcntl(F_SETFL)");
	}
	address.sun_family = AF_UNIX;
	strncpy(address.sun_path,conf->dovecotauthsocket, strlen(conf->dovecotauthsocket));
	result = connect(auths, (struct sockaddr *)&address, sizeof address);
	if (result) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Dovecot Authentication: could not connect to dovecot socket");
		if (conf->authoritative == 0) {
			return DECLINED;
		} else {
			return AUTH_USER_NOT_FOUND;
		}
	}
	cnt = 0;

	auth_in_progress = 0;
	// loop trough sockets for writability and for data on socket to read,
	// wait untill authenticated or if timeoout occurs error out with AUTH_USER_NOT_FOUND and log it
	while (cnt < conf->dovecotauthtimeout) {
		fdmax = auths;	// simply this is only one really used socket so ...
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		FD_ZERO(&socks_r);
		FD_SET(auths, &socks_r);
		FD_ZERO(&error_fd);
		FD_SET(auths, &error_fd);
		if (cs.handshake_sent == 0) {
			FD_ZERO(&socks_w);
			FD_SET(auths, &socks_w);
		} else {
			FD_ZERO(&socks_w);
		}

		readsocks = select(fdmax + 1, &socks_r, &socks_w, NULL, &tv);
		if (readsocks < 0) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Dovecot Authentication: socket select");
			return DECLINED;
		}

		if (readsocks == 0) {
			cnt++;	// wait for timeout and count to conf->dovecotauthtimeout
			// only add to counter in case of timeout!
			//fprintf(stderr, "%i ", cnt);
			fflush(stdout);
		} else {
			for (i = 0; i <= fdmax; i++) {
				if (FD_ISSET(i, &socks_w)) {
					if (cs.handshake_sent == 0) {
						cs.handshake_sent = send_handshake(p, r, i);
						ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Dovecot Authentication: handshake is sent");
					}
				}
				if (FD_ISSET(i, &socks_r)) {
					while ((retval = sock_readline(p, r, i, line)) > 0) {
						if (!receive_data(p, r, &cs, line)) {
							ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Dovecot Authentication: problems while receiving data from socket");
							if (conf->authoritative == 0) {
								return DECLINED;
							} else {
								return AUTH_USER_NOT_FOUND;
							}
						} else {
							if (cs.hshake_done == 1) {
								if (!cs.version_ok && !cs.mech_available) {
									ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
										      "Dovecot Authentication: No authentication possible protocol version wrong or plaintext method not available...");
									close(auths);
									return AUTH_USER_NOT_FOUND;
								} else {
									if (auth_in_progress != 1) {
										ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Dovecot Authentication: Sending authentication request");
										send_auth_request(p, r, i, user, password, r->connection->remote_ip);
										auth_in_progress = 1;
									}
								}
							}
							if (cs.authenticated == 1) {
								ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Dovecot Authentication: Authenticated user=\"%s\"", user);
								close(auths);
								return AUTH_GRANTED;
							}
							if (cs.authenticated == -1) {
								ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Dovecot Authentication: Denied authentication for user=\"%s\"", user);
								close(auths);
								if (conf->authoritative == 0) {
									return DECLINED;
								} else {
									return AUTH_USER_NOT_FOUND;
								}
							}
							break;
						}
					}
					if (retval == -1) {
						ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Dovecot Authentication: socket reading failed bailing out");
						close(auths);
						if (conf->authoritative == 0) {
							return DECLINED;
						} else {
							return AUTH_USER_NOT_FOUND;
						}
					}
				}
			}
		}
	}
	close(auths);
	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Dovecot Authentication Timeout");
	if (conf->authoritative == 0) {
		return DECLINED;
	} else {
		return AUTH_USER_NOT_FOUND;
	}
}

// helper function for reading from socket and converting single chars to line and return it
// return -1 if recv is not possible so main function can error out in case of failure (for instance if dovecot-auth dies
// in the middle of transaction)
int sock_readline(apr_pool_t * p, request_rec * r, int sock, char *data)
{
	int i = 0;
	char c;
	if (recv(sock, &c, 1, MSG_PEEK) == 0) {
		return -1;
	}
	memset(data, 0x0, BUFFMAX);
	while (i < BUFFMAX && recv(sock, &c, 1, 0) != 0) {
		data[i] = c;
		i++;
		if (c == '\n') {
			break;
		}
	}
	data[i] = '\0';
	return i;
}


// helper function for sending dovecot authentication protocol handshake request
int send_handshake(apr_pool_t * p, request_rec * r, int sock)
{
	char *handshake_data = apr_pcalloc(p, 100);
	handshake_data = apr_psprintf(p, "VERSION\t%u\t%u\n" "CPID\t%u\n", AUTH_PROTOCOL_MAJOR_VERSION, AUTH_PROTOCOL_MINOR_VERSION, (unsigned int)getpid());
	if (send(sock, handshake_data, strlen(handshake_data), 0) > 0) {
		return 1;
	} else {
		return 0;
	}
}
// helper function for receiving data and actual checking of response from auth sockets
// returns state of connection trough connection_state struct
int receive_data(apr_pool_t * p, request_rec * r, struct connection_state *cs, char *data)
{
	int ver_major;
	int ver_minor;
	char *auth_method;
	char *auth_protocol;
	char *last;
	if (strncmp("MECH", data, 4) == 0) {
		apr_strtok(data, "\t", &last);
		auth_method = apr_strtok(NULL, "\t", &last);
		auth_protocol = apr_strtok(NULL, "\t", &last);
		if (strncmp("PLAINTEXT", auth_protocol,9) == 0) {
			if (strncmp(AUTH_MECHANISM, auth_method,strlen(AUTH_MECHANISM)) == 0) {
				cs->mech_available = 1;
			}
		}
	}

	if (strncmp("VERSION", data, 7) == 0) {
		if (sscanf(&data[8], "%u\t%u\n", &ver_major, &ver_minor) != 2) {
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Dovecot Authentication: sscanf failed on reading version");
		}
		if (ver_major == AUTH_PROTOCOL_MAJOR_VERSION)
			cs->version_ok = 1;
	}
	if (strncmp("DONE", data, 4) == 0) {
		cs->hshake_done = 1;
	}

	if (strncmp("FAIL", data, 4) == 0) {
		cs->authenticated = -1;
		return 1;
	}

	if (strncmp("OK", data, 2) == 0) {
		cs->authenticated = 1;
		return 1;
	}
	return 1;
}

// helper function used for sending prepared data to socket for authorization against dovecot auth
int send_auth_request(apr_pool_t * p, request_rec * r, int sock, const char *user, const char *pass, char *remotehost)
{
	char *data=apr_pcalloc(p,BUFFMAX);
	int up_size;
	struct iovec concat[4];

	up_size = strlen(user) + strlen(pass) + 2;
	if (up_size > BUFFMAX - 1024) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Dovecot Authentication: User and pass length is over (or close) BUFFMAX=%i which is NOT allowed size=%i\n", BUFFMAX, up_size);
		return 0;
	}
	char *user_pass = apr_pcalloc(p, up_size);
	char * encoded_user_pass = (char *)apr_pcalloc(p, apr_base64_encode_len(sizeof(user_pass)));
	// this beautifull code snippet from bellow (concat blah blah) is needed for use of apr_pstrcatv
	// as without using apr_pstrcatv apr_pstrcat  will remove \0 which we need for creating base64 encoded user_pass combination...
	concat[0].iov_base = (void *)"\0";
	concat[0].iov_len = 1;
	concat[1].iov_base = (void *)user;
	concat[1].iov_len = strlen(user);
	concat[2].iov_base = (void *)"\0";
	concat[2].iov_len = 1;
	concat[3].iov_base = (void *)pass;
	concat[3].iov_len = strlen(pass);
	user_pass = apr_pstrcatv(p, concat, 4, NULL);
	apr_base64_encode(encoded_user_pass, user_pass, up_size);
	data = apr_psprintf(p, "AUTH\t1\tPLAIN\tservice=apache\tnologin"	// local ip (lip) is hardcoded as we are using local unix socket anyway...
		"\tlip=127.0.0.1\trip=%s\tsecured\tresp=%s\n", remotehost, encoded_user_pass);
	if (send(sock, data, strlen(data), 0) > 0) {
		return 1;
	} else {
		return 0;
	}
}

static const authn_provider authn_dovecot_provider = {
	&check_password
};

static void register_hooks(apr_pool_t * p)
{
	ap_register_provider(p, AUTHN_PROVIDER_GROUP, "dovecot", "0", &authn_dovecot_provider);
}

module AP_MODULE_DECLARE_DATA authn_dovecot_module = {
	STANDARD20_MODULE_STUFF,
	create_authn_dovecot_dir_config,	/* dir config creater */
	NULL,			/* dir merger --- default is to override */
	NULL,			/* server config */
	NULL,			/* merge server config */
	authn_dovecot_cmds,	/* command apr_table_t */
	register_hooks		/* register hooks */
};
