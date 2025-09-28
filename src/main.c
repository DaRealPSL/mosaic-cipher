#include "cli.h"
#include <stdio.h>

int main(void){
  print_banner();
  printf("Welcome to Mosaic Cipher CLI!\n");
  cli_loop();
  printf("Goodbye!\n");
  return 0;
}
