#include "mydebug.h"
#include <execinfo.h>
#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

void
mybacktrace(void)
{
  void *btbuffer[500];
  char **symbols;
  int n_bt, i;
  n_bt = backtrace(btbuffer, sizeof btbuffer);
  //printf("%d: backtrace:", getpid());
  symbols = backtrace_symbols(btbuffer, n_bt);
  for (i = n_bt-1; i >= 0; i--) {
    printf("%s\n", symbols[i]);

    char syscom[256], addr[18];
    int j, k = 0;
    bool flag = false;

    for (j = 0; symbols[i] != '\0'; j++) {
      if (symbols[i][j] == ']') {
        addr[k] = '\0';
        break;
      }
      if (flag) {
        addr[k++] = symbols[i][j];  
      }
      if (symbols[i][j] == '[') {
        flag = true;
      }
    }
    sprintf(syscom,"addr2line %s -e ./qemu-system-x86_64", addr);
    system(syscom);

  }
  printf("=======\n");
  free(symbols);
}

bool start_logging = false;
