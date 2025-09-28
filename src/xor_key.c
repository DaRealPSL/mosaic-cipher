#include "xor_key.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* apply XOR with repeating key */
void xor_with_key(unsigned char *data, size_t len, const char *key){
  if(!data || !key) return;
  size_t klen = strlen(key);
  if(klen == 0) return; /* theres nothing to do if key is empty */
  for(size_t i = 0; i < len; i++){
    data[i] = (unsigned char)(data[i] ^ (unsigned char)key[i % klen]);
  }
}

/* convert a single hex nibble to value, or -1 on error */
/* I'll be honest, no idea what the hell a hex nibble was until now. */
static int hexval(char c){
  if(c >= '0' && c <= '9') return c - '0';
  if(c >= 'a' && c <= 'f') return 10 + (c - 'a');
  if(c >= 'A' && c <= 'F') return 10 + (c - 'A');
  return -1;
}

char *xor_encrypt(const char *plaintext, const char *key){
  if(!plaintext) return NULL;
  if(!key || !*key) key = "default-key"; /* fallback */

  size_t n = strlen(plaintext);
  /* work on a mutable copy */
  unsigned char *buf = (unsigned char*)malloc(n ? n : 1);
  if(!buf) return NULL;
  if(n) memcpy(buf, plaintext, n);

  xor_with_key(buf, n, key);

  /* hex-encode */
  char *out = (char*)malloc(n * 2 + 1);
  if(!out){
    free(buf);
    return NULL;
  }
  for(size_t i = 0; i < n; i++){
    /* write two hex chars per byte */
    sprintf(out + (i * 2), "%02X", buf[i]);
  }
  out[n * 2] = '\0';
  free(buf);
  return out;
}

char *xor_decrypt(const char *ciphertext, const char *key){
  if(!ciphertext) return NULL;
  if(!key || !*key) key = "default-key"; /* fallback */

  size_t L = strlen(ciphertext);
  if(L % 2 != 0) return NULL; /* must be even length hex */

  size_t n = L / 2;
  unsigned char *buf = (unsigned char*)malloc(n + 1);
  if(!buf) return NULL;

  /* hex-decode with validation */
  for(size_t i = 0; i < n; i++){
    int hi = hexval(ciphertext[2 * i]);
    int lo = hexval(ciphertext[2 * i + 1]);
    if(hi < 0 || lo < 0){
      free(buf);
      return NULL;
    }
    buf[i] = (unsigned char)((hi << 4) | lo);
  }

  xor_with_key(buf, n, key);
  buf[n] = '\0'; /* make it a c-string for printing */
  return (char*)buf;
}
