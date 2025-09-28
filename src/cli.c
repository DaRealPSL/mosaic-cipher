#include "cli.h"
#include "util.h"
#include "mosaic.h"
#include "xor_key.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include <time.h>
#include <errno.h>

#define INPUT_SIZE 4096

typedef enum {
  CIPHER_MOSAIC,
  CIPHER_XOR
} CipherType;

/* globals (session state) */
static CipherType current_cipher = CIPHER_MOSAIC;
static char *current_key = NULL; /* session key (may be NULL) */
static bool should_exit = false;

/* ---------- helpers for safer allocation / zeroing ---------- */

static void oom_abort(const char *context){
  fprintf(stderr, "Fatal: out of memory (%s). Exiting.\n", context ? context : "");
  fflush(stderr);
  abort();
}

static char *xstrdup(const char *s){
  if(!s) return NULL;
  char *r = strdup(s);
  if(!r) oom_abort("strdup");
  return r;
}

static void *xmalloc(size_t n){
  void *p = malloc(n);
  if(!p) oom_abort("malloc");
  return p;
}

/* secure overwrite then free (attempt not to be optimized away) */
static void secure_memzero(void *v, size_t n){
  if(!v || n == 0) return;
  volatile unsigned char *p = (volatile unsigned char *)v;
  while(n--) *p++ = 0;
}

/* free both args (safe for NULL) and set pointers to NULL */
static void free_pair(char **a1, char **a2){
  if(a1 && *a1){
    free(*a1);
    *a1 = NULL;
  }
  if(a2 && *a2){
    free(*a2);
    *a2 = NULL;
  }
}

/* -------------------- banner -------------------- */

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

/* -------------------- small helpers -------------------- */

/* skip leading whitespace */
static char *skip_spaces(char *s){
  while(*s && isspace((unsigned char)*s)) s++;
  return s;
}

/* replace current session key (duplicates incoming key).
 * Overwrites previous key contents before freeing for modest secrecy.
 */
static void set_cli_key(const char *k){
  if(current_key){
    secure_memzero(current_key, strlen(current_key));
    free(current_key);
    current_key = NULL;
  }
  current_key = k ? xstrdup(k) : NULL;
}

/* Helper to extract one token (supports single/double quotes)
 * Advances *in to the next char after token (similar to original lambda intent)
 * Returns 1 if token produced and stores heap-allocated token in *out, else 0.
 */
static int extract_token(const char **in, char **out){
  const char *s = *in;
  while(*s && isspace((unsigned char)*s)) s++;
  if(!*s){
    *out = NULL;
    *in = s;
    return 0;
  }

  char quote = 0;
  if(*s == '"' || *s == '\''){
    quote = *s++;
  }
  const char *start = s;

  if(quote){
    while(*s && *s != quote) s++;
  } else {
    while(*s && !isspace((unsigned char)*s)) s++;
  }

  size_t len = (size_t)(s - start);
  *out = (char*)xmalloc(len + 1);
  memcpy(*out, start, len);
  (*out)[len] = '\0';

  if(quote && *s == quote) s++; /* skip closing quote if present */

  *in = s;
  return 1;
}

/* parse up to two arguments from a line (supports quoted strings).
 * Caller must free *arg1 and *arg2 if non-NULL.
 * Returns number of args parsed (0..2).
 */
static int parse_two_args(const char *line, char **arg1, char **arg2){
  *arg1 = NULL;
  *arg2 = NULL;
  if(!line) return 0;

  const char *p = line;
  while(*p && isspace((unsigned char)*p)) p++;
  if(!*p) return 0;

  const char *cur = p;
  int got1 = extract_token(&cur, arg1);
  while(*cur && isspace((unsigned char)*cur)) cur++;
  int got2 = 0;
  if(*cur) got2 = extract_token(&cur, arg2);

  return got1 + got2;
}

/* print one-line command usage/help */
static void print_command_help(const char *name, const char *hint){
  printf("  %-12s - %s\n", name, hint ? hint : "");
}

/* -------------------- commands -------------------- */

/* forward declarations */
static void cmd_help(const char *rest);
static void cmd_exit(const char *rest);
static void cmd_showkey(const char *rest);
static void cmd_setkey(const char *rest);
static void cmd_set_cipher(const char *rest);
static void cmd_encrypt(const char *rest);
static void cmd_decrypt(const char *rest);

typedef void (*cmd_fn)(const char *);
typedef struct {
  const char *name;
  cmd_fn handler;
  const char *help;
} command_def;

static const command_def commands[] = {
  { "help",      cmd_help,       "show this help menu" },
  { "h",         cmd_help,       "alias for help" },
  { "exit",      cmd_exit,       "exit the program" },
  { "quit",      cmd_exit,       "alias for exit" },
  { "showkey",   cmd_showkey,    "show the currently set session key" },
  { "setkey",    cmd_setkey,     "set session key: setkey <key>" },
  { "set_cipher",cmd_set_cipher, "choose algorithm: set_cipher <mosaic|xor>" },
  { "encrypt",   cmd_encrypt,    "encrypt text: encrypt <text> [key]" },
  { "encode",    cmd_encrypt,    "alias for encrypt" },
  { "decrypt",   cmd_decrypt,    "decrypt text: decrypt <ciphertext> [key]" },
  { "decode",    cmd_decrypt,    "alias for decrypt" },
};

static const size_t commands_len = sizeof(commands) / sizeof(commands[0]);

/* single-line dispatcher: caller provides a modifiable buffer 'work'
 * Returns: 0 = handled, 1 = unknown command, -1 = error
 */
static int execute_line(char *work){
  if(!work) return -1;

  char *cmd = work;
  char *p = cmd;
  while(*p && !isspace((unsigned char)*p)) p++;
  char *rest = NULL;
  if(*p){
    *p = '\0';
    rest = p + 1;
  } else {
    rest = p;
  }

  for(char *q = cmd; *q; ++q) *q = (char)tolower((unsigned char)*q);

  for(size_t i = 0; i < commands_len; ++i){
    if(strcmp(cmd, commands[i].name) == 0){
      commands[i].handler(rest);
      return 0;
    }
  }

  return 1;
}

/* -------------------- handlers -------------------- */

static void cmd_help(const char *rest){
  (void)rest;
  printf("Available commands:\n");
  for(size_t i = 0; i < commands_len; i++){
    print_command_help(commands[i].name, commands[i].help);
  }
  printf("\nNotes:\n");
  printf("  • Mosaic: key is optional; if omitted, uses the session key if set.\n");
  printf("  • XOR: key is required; if not given, session key is used; if still NULL, a weak default is used.\n");
}

static void cmd_exit(const char *rest){
  (void)rest;
  should_exit = true;
}

static void cmd_showkey(const char *rest){
  (void)rest;
  if(!current_key || !*current_key){
    printf("No key set.\n");
  } else {
    printf("Current key: %s\n", current_key);
  }
}

static void cmd_setkey(const char *rest){
  char *a1 = NULL, *a2 = NULL;
  int n = parse_two_args(rest ? rest : "", &a1, &a2);
  (void)a2;
  if(n < 1 || !a1){
    printf("Usage: setkey <key>\n");
  } else {
    set_cli_key(a1);
    printf("Key set%s.\n", current_key ? "" : " (NULL)");
  }
  free_pair(&a1, &a2);
}

static void cmd_set_cipher(const char *rest){
  char *a1 = NULL, *a2 = NULL;
  int n = parse_two_args(rest ? rest : "", &a1, &a2);
  (void)a2;
  if(n < 1 || !a1){
    printf("Usage: set_cipher <mosaic|xor>\n");
    free_pair(&a1, &a2);
    return;
  }

  for(char *q = a1; *q; ++q) *q = (char)tolower((unsigned char)*q);
  if(strcmp(a1, "mosaic") == 0){
    current_cipher = CIPHER_MOSAIC;
    printf("Cipher set to mosaic\n");
  } else if(strcmp(a1, "xor") == 0){
    current_cipher = CIPHER_XOR;
    printf("Cipher set to xor\n");
  } else {
    printf("Unknown cipher: %s\n", a1);
  }
  free_pair(&a1, &a2);
}

static void cmd_encrypt(const char *rest){
  char *arg1 = NULL, *arg2 = NULL;
  int n = parse_two_args(rest ? rest : "", &arg1, &arg2);
  if(n < 1 || !arg1){
    printf("Usage: encrypt <text> [key]\n");
    free_pair(&arg1, &arg2);
    return;
  }

  const char *resolved_key = arg2 ? arg2 : current_key;
  if(!resolved_key || !*resolved_key){
    resolved_key = "default-key";
    printf("(No key set, using default key)\n");
  }

  char *out = NULL;
  if(current_cipher == CIPHER_MOSAIC){
    out = mosaic_encrypt(arg1, resolved_key);
  } else {
    out = xor_encrypt(arg1, resolved_key);
  }

  if(!out){
    printf("Encryption failed.\n");
  } else {
    printf("Encrypted: %s\n", out);
    free(out);
  }

  free_pair(&arg1, &arg2);
}

static void cmd_decrypt(const char *rest){
  char *arg1 = NULL, *arg2 = NULL;
  int n = parse_two_args(rest ? rest : "", &arg1, &arg2);
  if(n < 1 || !arg1){
    printf("Usage: decrypt <ciphertext> [key]\n");
    free_pair(&arg1, &arg2);
    return;
  }

  const char *resolved_key = arg2 ? arg2 : current_key;
  if(!resolved_key || !*resolved_key){
    resolved_key = "default-key";
    printf("(No key set, using default key)\n");
  }

  char *plain = NULL;
  if(current_cipher == CIPHER_MOSAIC){
    plain = mosaic_decrypt(arg1, resolved_key);
  } else {
    plain = xor_decrypt(arg1, resolved_key);
  }

  if(!plain){
    printf("Decryption failed (malformed input, wrong key, or checksum error).\n");
  } else {
    printf("Decrypted: %s\n", plain);
    free(plain);
  }

  free_pair(&arg1, &arg2);
}

/* -------------------- main REPL loop -------------------- */

void cli_loop(void){
  char input[INPUT_SIZE];

  while(!should_exit){
    printf("mosaic> ");
    fflush(stdout);

    if(!safe_read_line(input, sizeof(input))){
      /* EOF or error -> exit */
      printf("\n");
      break;
    }

    /* skip empty lines */
    char *line = skip_spaces(input);
    if(!*line) continue;

    /* working copy for tokenization/dispatch (execute_line expects writable buffer) */
    char *work = strdup(line);
    if(!work) {
      fprintf(stderr, "warning: out of memory, skipping line\n");
      continue;
    }

    int rc = execute_line(work);
    if(rc == 1){
      printf("Unknown command: %s\n", work);
      printf("Type 'help' for available commands.\n");
    } else if(rc < 0){
      fprintf(stderr, "Error: failed to execute command.\n");
    }

    free(work);
  }

  /* cleanup sensitive data */
  if(current_key){
    secure_memzero(current_key, strlen(current_key));
    free(current_key);
    current_key = NULL;
  }
  should_exit = false;
}
