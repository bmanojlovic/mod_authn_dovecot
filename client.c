#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <err.h>
#include <stdlib.h>
#include <errno.h>

// if used with lighttpd simplest solution is to use gbase64 implementation...
#include <glib.h>

#define AUTH_TIMEOUT 5
#define BUFFMAX 8192
#define AUTH_PROTOCOL_MAJOR_VERSION 1
#define AUTH_PROTOCOL_MINOR_VERSION 1
#define AUTH_MECHANISM "PLAIN"

// Communication...
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

struct connection_state {
	int version_ok;
	int mech_available;
	int hshake_done;
	int authenticated;
};

/* proto */
int sock_readline(int sock, char *data);
int receive_data( struct connection_state *cs, char *data);
int send_handshake(int sock);
int send_data(int sock, char *user, char *pass);

int main()
{
	int i, auths, readsocks, result, opts, fdmax, cnt,auth_in_progress;
	struct sockaddr_un address;
	struct timeval tv;
	static int handshake_sent;
	struct connection_state cs;

	cs.version_ok = 0;
	cs.mech_available = 0;
	cs.hshake_done = 0;
	cs.authenticated = 0;	// by default user is NOT authenticated :)
	fd_set socks_r;
	fd_set socks_w;
	fd_set error_fd;
	char *line = malloc(sizeof(char) * (BUFFMAX + 1));
	auths = socket(AF_UNIX, SOCK_STREAM, 0);
	opts = fcntl(auths, F_GETFL);
	opts = (opts | O_NONBLOCK);
	if (fcntl(auths, F_SETFL, opts) < 0) {
		perror("fcntl(F_SETFL)");
	}
	address.sun_family = AF_UNIX;
	strncpy(address.sun_path, "/var/run/dovecot/auth-client", strlen("/var/run/dovecot/auth-client"));
	result = connect(auths, (struct sockaddr *)&address, sizeof address);
	if (result) {
		perror("Connect failed");
		exit(-1);
	}
	cnt = 0;
	handshake_sent = 0;
	while (cnt < AUTH_TIMEOUT) {
		fdmax = auths;	// simply this is only one really used socket so ...
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		FD_ZERO(&socks_r);
		FD_SET(auths, &socks_r);
		FD_ZERO(&error_fd);
		FD_SET(auths, &error_fd);
		if (handshake_sent == 0) {
			FD_ZERO(&socks_w);
			FD_SET(auths, &socks_w);
		} else {
			FD_ZERO(&socks_w);
		}

		readsocks = select(fdmax + 1, &socks_r, &socks_w, NULL, &tv);
		if (readsocks < 0) {
			perror("select");
			exit(-1);
		}

		if (readsocks == 0) {
			cnt++;	// wait for timeout and count to AUTH_TIMEOUT
			// only add to counter in case of timeout!
			printf("%i ", cnt);
			fflush(stdout);
		} else {
			for (i = 0; i <= fdmax; i++) {
				if (FD_ISSET(i, &socks_w)) {
					if (handshake_sent == 0) {
						handshake_sent = send_handshake(i);
//						printf("handshake_sent=%i\n", handshake_sent);
					}
				}
				if (FD_ISSET(i, &socks_r)) {
					while (sock_readline(i, line) > 0) {
						if (!receive_data( &cs, line)) {
							printf("Recive data problems\n");
							break;
						} else {
							if (cs.hshake_done == 1) {
								if (!cs.version_ok && !cs.mech_available) {
									perror
									    ("No authentication possible protocol version wrong or plaintext method not available...");
									return 0;
								} else {
									if(auth_in_progress != 1) {
										send_data(i, "virus", "proba");
										auth_in_progress=1;
									}
								}
							}
							if (cs.authenticated == 1) {
								printf("I am authenticated!!!\n");
								return 0;
							} 
							if (cs.authenticated == -1) {
								printf ( "NO ACCESS!!!\n");
								return 1;
							}
							break;
						}
					}
				}
			}
		}
	}
	close(auths);
	printf("\n");
	exit(0);
}

int sock_readline(int sock, char *data)
{
	int i = 0;
	char c;
	if (recv(sock,&c, 1,MSG_PEEK) == 0) {
		return 0;
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

int send_handshake(int sock)
{
	char handshake_data[100];
	memset(handshake_data, 0x0, sizeof(char) * (100));
	snprintf(handshake_data,
		 sizeof(handshake_data),
		 "VERSION\t%u\t%u\n"
		 "CPID\t%u\n", AUTH_PROTOCOL_MAJOR_VERSION, AUTH_PROTOCOL_MINOR_VERSION, (unsigned int)getpid());
	if (send(sock, handshake_data, strlen(handshake_data), 0) > 0) {
		return 1;
	} else {
		return 0;
	}
}

int receive_data(struct connection_state *cs, char *data)
{
	int ver_major;
	int ver_minor;
	char *auth_method;
	char *auth_protocol;
	//cs->hshake_done = 1;
	if (strncmp("MECH", data, 4) == 0) {
		strtok(data, "\t");
		auth_method = strtok(NULL, "\t");
		auth_protocol = strtok(NULL, "\t");
//		printf("auth_method=\%s\n", auth_method);
//		printf("auth_protocol=\%s\n", auth_protocol);
		if (strncasecmp("PLAINTEXT", auth_protocol, 9) == 0) {
			if (strncasecmp(AUTH_MECHANISM, auth_method, strlen(AUTH_MECHANISM)) == 0) {
				cs->mech_available = 1;
			}
		}
//              printf("is auth mechanism available...:");
//              printf("%i\n",cs->mech_available);
	}

	if (strncmp("VERSION", data, 7) == 0) {
//              printf("Version check...:");
		if (sscanf(&data[8], "%u\t%u\n", &ver_major, &ver_minor) != 2) {
			perror("sscanf failed version impossible to read");
		}
		if (ver_major == AUTH_PROTOCOL_MAJOR_VERSION)
			cs->version_ok = 1;
//              printf("%i\n",cs->version_ok);
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
		//exit(-1);
		return 1;
	}
	return 1;
}

int send_data(int sock, char *user, char *pass)
{
	char data[BUFFMAX];
	char *user_pass;
	int up_size;
	
	up_size = strlen(user) + strlen(pass);
	if (up_size > BUFFMAX - 100 ) {
		perror ("username password too long for this implementation");	
	}
//	printf("user=%s pass=%s up_size=%i\n", user, pass, up_size);
	user_pass = malloc(up_size + 2);
	memset(user_pass,0x0,up_size + 2); // +2 is for \0
  	strcat(&user_pass[1],user);
  	strcat(&user_pass[1+strlen(user)+1],pass);
	snprintf(data,BUFFMAX, 
				"AUTH\t1\tPLAIN\tservice=apache\tnologin"
				"\tlip=127.0.0.1\trip=10.10.10.1\tsecured\tresp=%s\n",
			 	g_base64_encode((const guchar *)user_pass, up_size + 2));
	if (send(sock, data, strlen(data), 0) > 0) {
		return 1;
	} else {
		return 0;
	}
}
