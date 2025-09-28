#include "mosaic.h"
#include "xor_key.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

/* ---------------- Core parameters ---------------- */
static const char MOSAIC_ALPHABET[] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*_-?";

static const char NOISE_SET[] =
  "abcdefghijklmnopqrstuvwxyz";

static const mosaic_params MOSAIC_PARAMS = {
  MOSAIC_ALPHABET,
  '~',
  47,
  5,
  8,
  4
};

const mosaic_params* mosaic_get_params(void){
  return &MOSAIC_PARAMS;
}

/* ---------------- Helper functions ---------------- */

/* rotate base alphabet left by `rot` */
static void rotate_alphabet(char *dst, const char *base, int len, int rot){
  rot %= len;
  if(rot < 0) rot += len;
  for(int i = 0; i < len; i++) dst[i] = base[(i + rot) % len];
  dst[len] = '\0';
}

static void build_rev(int rev[256], const char *alpha, int len){
  for(int i = 0; i < 256; i++) rev[i] = -1;
  for(int i = 0; i < len; i++) rev[(unsigned char)alpha[i]] = i;
}

/* ---------------- Encode/Decode helpers ---------------- */

static void u40_to_base47(uint8_t in5[5], int base, int out_digits[8]){
  uint8_t buf[5];
  memcpy(buf, in5, 5);
  for(int d = 7; d >= 0; d--){
    unsigned int rem = 0u;
    for(int i = 0; i < 5; i++){
      unsigned int cur = (rem << 8) | buf[i];
      unsigned int q = cur / (unsigned)base;
      rem = cur % (unsigned)base;
      buf[i] = (uint8_t)q;
    }
    out_digits[d] = (int)rem;
  }
}

static void base47_to_u40(const int digits[8], int base, uint8_t out5[5]){
  uint8_t acc[5] = {0,0,0,0,0};
  for(int d = 0; d < 8; d++){
    unsigned int carry = (unsigned int)digits[d];
    for(int i = 4; i >= 0; i--){
      unsigned int v = (unsigned int)acc[i] * (unsigned)base + carry;
      acc[i] = (uint8_t)(v & 0xFFu);
      carry = v >> 8;
    }
  }
  memcpy(out5, acc, 5);
}

/* compute rotation for block index (deterministic only on block_index)
 * Important: rotation must be deterministic from block_index so decoder can
 * reconstruct the rotation before mapping characters. */
static int rotation_for_block(size_t block_index){
  return (int)(((block_index * 13u) + 11u) % 47u);
}

/* compute checksum value (0..46) from `blocks` worth of 5-byte blocks */
static int checksum47(const uint8_t *block5xN, size_t blocks){
  unsigned int x = 0u;
  for(size_t b = 0; b < blocks; b++){
    for(int i = 0; i < 5; i++) x ^= block5xN[b * 5 + i];
  }
  return (int)(x % 47u);
}

/* helper: insert a "noise" character (ignored by decoder) */
static char noise_char(void){
  return NOISE_SET[rand() % (sizeof(NOISE_SET) - 1)];
}

/* ---------------- Capacity helper ---------------- */
static size_t encode_capacity(size_t in_len){
  const mosaic_params *P = mosaic_get_params();
  size_t n_blocks = (in_len + P->block_bytes - 1) / P->block_bytes;
  size_t per_blocks = n_blocks * (size_t)(P->block_symbols + 1); /* symbols + terminator */
  size_t checksums = n_blocks / (size_t)P->checksum_period;
  /* trailer: "~~" + 1 digit */
  return per_blocks + checksums + 3;
}

/* ---------------- Encode ---------------- */
size_t mosaic_encode(const uint8_t *in, size_t in_len, char *out, size_t out_cap){
  const mosaic_params *P = mosaic_get_params();
  const int BASE = P->base;
  const int B = P->block_bytes;
  const int S = P->block_symbols;

  if(!in) return (size_t)-1;

  size_t need = encode_capacity(in_len);
  if(!out) return need;
  if(out_cap < need) return (size_t)-1;

  size_t o = 0;
  size_t blocks = (in_len + (B - 1)) / B;
  size_t full_blocks = in_len / B;
  size_t rem = in_len % B;
  uint8_t buf5[5];
  char rotated[48];
  uint8_t cs_buf[4 * 5];
  size_t cs_count = 0;

  /* seed randomness for noise insertion; ok to call here */
  srand((unsigned)time(NULL) ^ (unsigned)(uintptr_t)in);

  for(size_t b = 0; b < blocks; b++){
    memset(buf5, 0, 5);
    if(b < full_blocks){
      memcpy(buf5, in + b * B, B);
    } else if(rem){
      memcpy(buf5, in + b * B, rem);
    }

    int digits[8];
    u40_to_base47(buf5, BASE, digits);

    int rot = rotation_for_block(b);
    rotate_alphabet(rotated, P->alphabet, BASE, rot);

    for(int i = 0; i < S; i++){
      out[o++] = rotated[digits[i]];
    }

    /* insert noise char 50% chance */
    if(rand() & 1){
      out[o++] = noise_char();
    }

    /* block terminator */
    out[o++] = P->term_char;

    /* accumulate block for checksum window */
    memcpy(cs_buf + cs_count * 5, buf5, 5);
    cs_count++;
    if(cs_count == (size_t)P->checksum_period){
      int c = checksum47(cs_buf, cs_count);
      out[o++] = P->alphabet[c];
      cs_count = 0;
    }
  }

  /* trailer: "~~" + pad_count digit */
  size_t pad_count = (B - (in_len % B)) % B;
  out[o++] = P->term_char;
  out[o++] = P->term_char;
  out[o++] = P->alphabet[pad_count];

  return o;
}

/* ---------------- Decode ---------------- */
size_t mosaic_decode(const char *in, size_t in_len, uint8_t *out, size_t out_cap){
  const mosaic_params *P = mosaic_get_params();
  const int BASE = P->base;
  const int B = P->block_bytes;
  const int S = P->block_symbols;

  if(!in) return (size_t)-1;

  size_t o = 0;
  size_t block_index = 0;
  size_t i = 0;
  int rev_rot[256];
  int rev_base[256];
  build_rev(rev_base, P->alphabet, BASE);
  uint8_t cs_buf[4 * 5];
  size_t cs_count = 0;

  while(i < in_len){
    /* skip whitespace */
    while(i < in_len && isspace((unsigned char)in[i])) i++;
    if(i >= in_len) break;

    /* trailer detection */
    if(in_len - i >= 3 && in[i] == P->term_char && in[i + 1] == P->term_char){
      int pad_digit = rev_base[(unsigned char)in[i + 2]];
      if(pad_digit < 0 || pad_digit >= BASE) return (size_t)-1;
      size_t pad_count = (size_t)pad_digit;
      if(out){
        if(o < pad_count) return (size_t)-1;
        o -= pad_count;
      }
      i += 3;
      if(i != in_len) return (size_t)-1;
      return o;
    }

    /* prepare rotated alphabet for this block */
    char rotated[48];
    int rot = rotation_for_block(block_index);
    rotate_alphabet(rotated, P->alphabet, BASE, rot);
    build_rev(rev_rot, rotated, BASE);

    /* read S symbols, skipping noise characters */
    int digits[8];
    for(int k = 0; k < S; k++){
      while(i < in_len && strchr(NOISE_SET, in[i])) i++;
      if(i >= in_len) return (size_t)-1;
      unsigned char c = (unsigned char)in[i++];
      if(c == (unsigned char)P->term_char) return (size_t)-1;
      int v = rev_rot[c];
      if(v < 0) return (size_t)-1;
      digits[k] = v;
    }

    /* skip noise then expect terminator */
    while(i < in_len && strchr(NOISE_SET, in[i])) i++;
    if(i >= in_len || in[i] != P->term_char) return (size_t)-1;
    i++; /* consume terminator */

    uint8_t block5[5];
    base47_to_u40(digits, BASE, block5);

    if(!out){
      o += 5;
    } else {
      if(out_cap - o < 5) return (size_t)-1;
      memcpy(out + o, block5, 5);
      o += 5;
    }

    memcpy(cs_buf + cs_count * 5, block5, 5);
    cs_count++;
    block_index++;

    if(cs_count == (size_t)P->checksum_period){
      while(i < in_len && strchr(NOISE_SET, in[i])) i++;
      if(i >= in_len) return (size_t)-1;
      unsigned char chk = (unsigned char)in[i++];
      int got = rev_base[chk];
      if(got < 0) return (size_t)-1;
      int expect = checksum47(cs_buf, cs_count);
      if(got != expect) return (size_t)-1;
      cs_count = 0;
    }
  }

  return (size_t)-1;
}

/* ---------------- CLI-friendly wrappers ---------------- */

char* mosaic_encrypt(const char *plaintext, const char *key){
  if(!plaintext || !key) return NULL;

  size_t in_len = strlen(plaintext);

  // copy input into buffer we can mutate
  uint8_t *buf = malloc(in_len + 1);
  if(!buf) return NULL;
  memcpy(buf, plaintext, in_len);
  buf[in_len] = '\0';

  // XOR with key
  xor_with_key(buf, in_len, key);

  // encode XORed buffer
  size_t cap = mosaic_encode(buf, in_len, NULL, 0);
  if(cap == (size_t)-1){ free(buf); return NULL; }

  char *out = malloc(cap + 1);
  if(!out){ free(buf); return NULL; }

  size_t wrote = mosaic_encode(buf, in_len, out, cap);
  free(buf);
  if(wrote == (size_t)-1){ free(out); return NULL; }

  out[wrote] = '\0';
  return out;
}

char* mosaic_decrypt(const char *ciphertext, const char *key){
  if(!ciphertext || !key) return NULL;

  size_t in_len = strlen(ciphertext);
  
  // decode ciphertext first.
  size_t cap = mosaic_decode(ciphertext, in_len, NULL, 0);
  if (cap == (size_t)-1) return NULL;

  uint8_t *buf = malloc(cap + 1);
  if(!buf) return NULL;

  size_t wrote = mosaic_decode(ciphertext, in_len, buf, cap);
  if(wrote == (size_t)-1){ free(buf); return NULL; };
  buf[wrote] = '\0';

  // XOR with key to get back the plaintext
  xor_with_key(buf, wrote, key);

  return (char*)buf; // already null terminated
}
