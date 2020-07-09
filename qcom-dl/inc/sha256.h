#pragma once

#include <stdint.h>

#define SHA256_BLOCK_LENGTH 64
#define SHA256_DIGEST_LENGTH 32
#define SHA256_DIGEST_STRING_LENGTH (32 * 2)

typedef uint8_t sha256_digest[SHA256_DIGEST_LENGTH];

typedef struct _sha256_ctx {
    uint32_t state[8];
    uint64_t bitcount;
    uint8_t  buffer[SHA256_BLOCK_LENGTH];
} sha256_ctx;

void sha256_init(sha256_ctx *ctx);
void sha256_update(sha256_ctx* ctx, const uint8_t *data, size_t len);
void sha256_final(sha256_digest digest, sha256_ctx*);
void sha256(sha256_digest digest, const uint8_t *data, size_t len);
