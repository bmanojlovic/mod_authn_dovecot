#include <stdio.h>
#include <string.h>
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

#include "apr_base64.h" // base64 encode

int main(int argc, const char * const argv[]) {
  apr_pool_t *p;
  struct iovec concat[4];
  
  apr_app_initialize(&argc, &argv, NULL);
  apr_pool_create(&p, NULL);
  char *blah = apr_pcalloc(p, strlen("virus") + strlen("password") + 2);
  char *encoded_blah = apr_pcalloc(p, apr_base64_encode_len(sizeof(blah)));
  concat[0].iov_base = (void *)"\0";
  concat[0].iov_len = 1;
  concat[1].iov_base = (void *)"virus";
  concat[1].iov_len = sizeof("virus") - 1;
  concat[2].iov_base = (void *)"\0";
  concat[2].iov_len = 1;
  concat[3].iov_base = (void *)"password";
  concat[3].iov_len = sizeof("password") - 1;
  blah = apr_pstrcatv(p, concat, 4, NULL);
  apr_base64_encode(encoded_blah, blah, strlen("virus") + strlen("password") + 2);
  printf("%s\n", encoded_blah);
  return 0;
}