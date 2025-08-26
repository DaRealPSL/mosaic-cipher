#ifndef MOSAIC_H
#define MOSAIC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Parameters struct
typedef struct {
    const char *alphabet;   // 47 unique printable chars, excludes '~'
    char term_char;         // block terminator
    int base;               // radix
    int block_bytes;        // input bytes per block
    int block_symbols;      // symbols per block
    int checksum_period;    // blocks per checksum
} mosaic_params;

// Core API
size_t mosaic_encode(const uint8_t *in, size_t in_len, char *out, size_t out_cap);
size_t mosaic_decode(const char *in, size_t in_len, uint8_t *out, size_t out_cap);
const mosaic_params* mosaic_get_params(void);

// CLI-friendly wrappers
char* mosaic_encrypt(const char *plaintext); // returns malloced string
char* mosaic_decrypt(const char *ciphertext); // returns malloced string

#ifdef __cplusplus
}
#endif

#endif // MOSAIC_H
