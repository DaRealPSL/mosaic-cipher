#ifndef XOR_KEY_H
#define XOR_KEY_H

#include <stddef.h>

/* simple XOR helper that is used by both encrypt AND decrypt */
void xor_with_key(unsigned char *data, size_t len, const char *key);

/* hex-encode(XOR(plaintext, key)) */
char *xor_encrypt(const char *plaintext, const char *key);

/* XOR(hex-decode(ciphertext), key) */
char *xor_decrypt(const char *ciphertext, const char *key);

#endif