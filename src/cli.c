#include "cli.h"
#include "util.h"
#include "mosaic.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define INPUT_SIZE 4096

//ascii banner
//https://manytools.org/hacker-tools/ascii-banner/
void print_banner(void){
  printf(" ██████   ██████                             ███                █████████   ███            █████                        \n");
  printf("░░██████ ██████                             ░░░                ███░░░░░███ ░░░            ░░███                         \n");
  printf(" ░███░█████░███   ██████   █████   ██████   ████   ██████     ███     ░░░  ████  ████████  ░███████    ██████  ████████ \n");
  printf(" ░███░░███ ░███  ███░░███ ███░░   ░░░░░███ ░░███  ███░░███   ░███         ░░███ ░░███░░███ ░███░░███  ███░░███░░███░░███\n");
  printf(" ░███ ░░░  ░███ ░███ ░███░░█████   ███████  ░███ ░███ ░░░    ░███          ░███  ░███ ░███ ░███ ░███ ░███████  ░███ ░░░ \n");
  printf(" ░███      ░███ ░███ ░███ ░░░░███ ███░░███  ░███ ░███  ███   ░░███     ███ ░███  ░███ ░███ ░███ ░███ ░███░░░   ░███     \n");
  printf(" █████     █████░░██████  ██████ ░░████████ █████░░██████     ░░█████████  █████ ░███████  ████ █████░░██████  █████    \n");
  printf("░░░░░     ░░░░░  ░░░░░░  ░░░░░░   ░░░░░░░░ ░░░░░  ░░░░░░       ░░░░░░░░░  ░░░░░  ░███░░░  ░░░░ ░░░░░  ░░░░░░  ░░░░░     \n");
  printf("                                                                                 ░███                                   \n");
  printf("                                                                                 █████                                  \n");
  printf("                                                                                ░░░░░                                   \n");
}

/* small helper: skip leading whitespace */
static char *skip_spaces(char *s){
  while(*s && isspace((unsigned char)*s)) s++;
  return s;
}

/* extract argument portion (handles "quoted strings" and unquoted rest)
 * - in: pointer to start of arguments (may be NULL or empty)
 * - returns: malloc'ed string (caller must free) or NULL if none
 */
static char *extract_arg(const char *in){
  if(!in) return NULL;

  /* make a writable copy */
  char *tmp = strdup(in);
  if(!tmp) return NULL;

  char *p = skip_spaces(tmp);
  if(!*p){ free(tmp); return NULL; }

  if(*p == '"' || *p == '\''){
    char quote = *p;
    p++;
    char *end = strchr(p, quote);
    if(end) *end = '\0';
    /* trim trailing spaces inside quotes (rare) */
    char *t = p + strlen(p) - 1;
    while(t >= p && isspace((unsigned char)*t)){ *t = '\0'; t--; }
    char *res = strdup(p);
    free(tmp);
    return res;
  } else {
    /* return rest of string trimmed of leading/trailing spaces */
    char *start = p;
    /* trim trailing spaces */
    char *end = start + strlen(start) - 1;
    while(end >= start && isspace((unsigned char)*end)){ *end = '\0'; end--; }
    char *res = strdup(start);
    free(tmp);
    return res;
  }
}

/* print help */
static void print_help(void){
  printf("Available commands:\n");
  printf("  encrypt <text>    - encrypt plain text (alias: encode)\n");
  printf("  decrypt <text>    - decrypt cipher text (alias: decode)\n");
  printf("  help              - show this help menu\n");
  printf("  exit | quit       - quit the program\n");
}

/* main REPL loop */
void cli_loop(void){
  char input[INPUT_SIZE];

  while(1){
    printf("mosaic> ");
    fflush(stdout);

    if(!safe_read_line(input, sizeof(input))){
      /* EOF or error -> exit gracefully */
      printf("\n");
      break;
    }

    /* skip empty lines */
    char *line = skip_spaces(input);
    if(!*line) continue;

    /* copy line so we can tokenize without destroying original argument string */
    char *work = strdup(line);
    if(!work) continue;

    /* extract first token (command) */
    char *cmd = work;
    char *p = cmd;
    while(*p && !isspace((unsigned char)*p)) p++;
    if(*p){ *p = '\0'; p++; }
    char *rest = p; /* remaining text (may be NULL or empty) */

    /* normalize command */
    str_to_lower(cmd);

    if(strcmp(cmd, "exit") == 0 || strcmp(cmd, "quit") == 0){
      free(work);
      break;
    }

    else if(strcmp(cmd, "help") == 0){
      print_help();
    }

    else if(strcmp(cmd, "encrypt") == 0 || strcmp(cmd, "encode") == 0){
      char *arg = extract_arg(rest);
      if(!arg){
        printf("Usage: encrypt <text>\n");
      } else {
        char *out = mosaic_encrypt(arg);
        if(!out){
          printf("Encryption failed.\n");
        } else {
          printf("Encrypted: %s\n", out);
          free(out);
        }
        free(arg);
      }
    }

    else if(strcmp(cmd, "decrypt") == 0 || strcmp(cmd, "decode") == 0){
      char *arg = extract_arg(rest);
      if(!arg){
        printf("Usage: decrypt <ciphertext>\n");
      } else {
        char *plain = mosaic_decrypt(arg);
        if(!plain){
          printf("Decryption failed (malformed input or checksum error).\n");
        } else {
          /* print as text; decrypted data might be binary */
          printf("Decrypted: %s\n", plain);
          free(plain);
        }
        free(arg);
      }
    }

    else {
      printf("Unknown command: %s\n", cmd);
      printf("Type 'help' for available commands.\n");
    }

    free(work);
  }
}
