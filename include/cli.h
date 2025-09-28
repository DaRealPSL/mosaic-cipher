#ifndef CLI_H
#define CLI_H

#ifdef __cplusplus
extern "C" {
#endif

void cli_loop(void);
void print_banner(void);
void cli_init(void);
void cli_cleanup(void);
void cli_set_key(const char *key);
const char *cli_get_key(void);
void cli_set_cipher(const char *name);
const char *cli_get_cipher(void);
int cli_execute(const char *line);

#ifdef __cplusplus
}
#endif

#endif
