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
#include <glib.h>

int main() {
  char *blah;
  
  blah = malloc(1 + strlen("virus") + 1 + strlen("proba"));
  memset(blah,0x0, 1 + strlen("virus") + 1 + strlen("proba"));
  strcat(&blah[1],"virus");
  strcat(&blah[1+strlen("virus")+1],"proba");
  printf("%s\n", g_base64_encode((const guchar *)blah,  1 + strlen("virus") + 1 + strlen("proba")));
  return 0;
}