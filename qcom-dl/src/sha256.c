/* 
 * A minimal/cleaned-up version of sha256 based on the one by
 * Aaron Gifford - http://www.aarongifford.com/computers/sha.html
 *
 * Note: This version is probably not FIPS compliant
 */

#include <string.h>
#include <stdint.h>
#include "sha256.h"

#define SHA256_SHORT_BLOCK_LENGTH   (SHA256_BLOCK_LENGTH - 8)

#ifndef BYTE_ORDER
#define BYTE_ORDER __BYTE_ORDER__
#define LITTLE_ENDIAN __ORDER_LITTLE_ENDIAN__
#endif

#if BYTE_ORDER == LITTLE_ENDIAN
#define REVERSE32(w,x)  { \
    uint32_t tmp = (w); \
    tmp = (tmp >> 16) | (tmp << 16); \
    (x) = ((tmp & (uint32_t)0xff00ff00UL) >> 8) | ((tmp & (uint32_t)0x00ff00ffUL) << 8); \
}
#define REVERSE64(w,x)  { \
    uint64_t tmp = (w); \
    tmp = (tmp >> 32) | (tmp << 32); \
    tmp = ((tmp & (uint64_t)0xff00ff00ff00ff00ULL) >> 8) | \
          ((tmp & (uint64_t)0x00ff00ff00ff00ffULL) << 8); \
    (x) = ((tmp & (uint64_t)0xffff0000ffff0000ULL) >> 16) | \
          ((tmp & (uint64_t)0x0000ffff0000ffffULL) << 16); \
}
#endif

#define R(b,x)      ((x) >> (b))
#define S32(b,x)    (((x) >> (b)) | ((x) << (32 - (b))))

#define Ch(x,y,z)   (((x) & (y)) ^ ((~(x)) & (z)))
#define Maj(x,y,z)  (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#define Sigma0_256(x)   (S32(2,  (x)) ^ S32(13, (x)) ^ S32(22, (x)))
#define Sigma1_256(x)   (S32(6,  (x)) ^ S32(11, (x)) ^ S32(25, (x)))
#define sigma0_256(x)   (S32(7,  (x)) ^ S32(18, (x)) ^ R(3 ,   (x)))
#define sigma1_256(x)   (S32(17, (x)) ^ S32(19, (x)) ^ R(10,   (x)))

const static uint32_t K256[64] = {
    0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL,
    0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL,
    0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL,
    0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL,
    0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
    0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
    0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL,
    0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL,
    0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL,
    0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
    0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL,
    0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
    0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL,
    0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL,
    0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
    0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
};

const static uint32_t sha256_initial_hash_value[8] = {
    0x6a09e667UL,
    0xbb67ae85UL,
    0x3c6ef372UL,
    0xa54ff53aUL,
    0x510e527fUL,
    0x9b05688cUL,
    0x1f83d9abUL,
    0x5be0cd19UL
};

#if BYTE_ORDER == LITTLE_ENDIAN

#define ROUND256_0_TO_15(a,b,c,d,e,f,g,h)   \
    REVERSE32(*data++, W256[j]); \
    T1 = (h) + Sigma1_256(e) + Ch((e), (f), (g)) + \
        K256[j] + W256[j]; \
    (d) += T1; \
    (h) = T1 + Sigma0_256(a) + Maj((a), (b), (c)); \
    j++

#else

#define ROUND256_0_TO_15(a,b,c,d,e,f,g,h)   \
    T1 = (h) + Sigma1_256(e) + Ch((e), (f), (g)) + \
        K256[j] + (W256[j] = *data++); \
    (d) += T1; \
    (h) = T1 + Sigma0_256(a) + Maj((a), (b), (c)); \
    j++

#endif

#define ROUND256(a,b,c,d,e,f,g,h)   \
    s0 = W256[(j+1)&0x0f]; \
    s0 = sigma0_256(s0); \
    s1 = W256[(j+14)&0x0f]; \
    s1 = sigma1_256(s1); \
    T1 = (h) + Sigma1_256(e) + Ch((e), (f), (g)) + K256[j] + \
        (W256[j&0x0f] += s1 + W256[(j+9)&0x0f] + s0); \
    (d) += T1; \
    (h) = T1 + Sigma0_256(a) + Maj((a), (b), (c)); \
    j++

static void sha256_transform(sha256_ctx* ctx, const uint32_t* data)
{
    uint32_t s0 = 0;
    uint32_t s1 = 0;
    uint32_t T1 = 0;
    uint32_t *W256 = (uint32_t*)(void*)ctx->buffer;

    uint32_t a = ctx->state[0];
    uint32_t b = ctx->state[1];
    uint32_t c = ctx->state[2];
    uint32_t d = ctx->state[3];
    uint32_t e = ctx->state[4];
    uint32_t f = ctx->state[5];
    uint32_t g = ctx->state[6];
    uint32_t h = ctx->state[7];

    int j = 0;
    do {
        ROUND256_0_TO_15(a,b,c,d,e,f,g,h);
        ROUND256_0_TO_15(h,a,b,c,d,e,f,g);
        ROUND256_0_TO_15(g,h,a,b,c,d,e,f);
        ROUND256_0_TO_15(f,g,h,a,b,c,d,e);
        ROUND256_0_TO_15(e,f,g,h,a,b,c,d);
        ROUND256_0_TO_15(d,e,f,g,h,a,b,c);
        ROUND256_0_TO_15(c,d,e,f,g,h,a,b);
        ROUND256_0_TO_15(b,c,d,e,f,g,h,a);
    } while (j < 16);

    do {
        ROUND256(a,b,c,d,e,f,g,h);
        ROUND256(h,a,b,c,d,e,f,g);
        ROUND256(g,h,a,b,c,d,e,f);
        ROUND256(f,g,h,a,b,c,d,e);
        ROUND256(e,f,g,h,a,b,c,d);
        ROUND256(d,e,f,g,h,a,b,c);
        ROUND256(c,d,e,f,g,h,a,b);
        ROUND256(b,c,d,e,f,g,h,a);
    } while (j < 64);

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

#pragma mark Public Functions

void sha256_init(sha256_ctx* ctx)
{
    if (ctx == NULL) {
        return;
    }
    memcpy(ctx->state, sha256_initial_hash_value, SHA256_DIGEST_LENGTH);
    memset(ctx->buffer, 0, SHA256_BLOCK_LENGTH);
    ctx->bitcount = 0;
}

void sha256_update(sha256_ctx* ctx, const uint8_t *data, size_t len)
{
    if ((len == 0) || (ctx == NULL) || (data == NULL)) {
        return;
    }

    size_t usedspace = (ctx->bitcount >> 3) % SHA256_BLOCK_LENGTH;
    if (usedspace > 0) {
        /* Calculate how much free space is available in the buffer */
        size_t freespace = SHA256_BLOCK_LENGTH - usedspace;

        if (len >= freespace) {
            /* Fill the buffer completely and process it */
            memcpy(&ctx->buffer[usedspace], data, freespace);
            ctx->bitcount += freespace << 3;
            len -= freespace;
            data += freespace;
            sha256_transform(ctx, (uint32_t*)(void*)ctx->buffer);
        } else {
            /* The buffer is not yet full */
            memcpy(&ctx->buffer[usedspace], data, len);
            ctx->bitcount += len << 3;
            return;
        }
    }
    while (len >= SHA256_BLOCK_LENGTH) {
        /* Process as many complete blocks as we can */
        sha256_transform(ctx, (const uint32_t*)(const void*)data);
        ctx->bitcount += SHA256_BLOCK_LENGTH << 3;
        len -= SHA256_BLOCK_LENGTH;
        data += SHA256_BLOCK_LENGTH;
    }
    if (len > 0) {
        /* There's left-overs, so save 'em */
        memcpy(ctx->buffer, data, len);
        ctx->bitcount += len << 3;
    }
}

void sha256_final(sha256_digest digest, sha256_ctx* ctx)
{

    if (ctx == NULL) {
        return;
    }

    uint32_t *d = (uint32_t*)(void*)digest;

    size_t usedspace = (ctx->bitcount >> 3) % SHA256_BLOCK_LENGTH;
#if BYTE_ORDER == LITTLE_ENDIAN
    REVERSE64(ctx->bitcount,ctx->bitcount);
#endif
    if (usedspace > 0) {
        /* Begin padding with a 1 bit: */
        ctx->buffer[usedspace++] = 0x80;

        if (usedspace <= SHA256_SHORT_BLOCK_LENGTH) {
            /* Set-up for the last transform: */
            memset(&ctx->buffer[usedspace], 0, SHA256_SHORT_BLOCK_LENGTH - usedspace);
        } else {
            if (usedspace < SHA256_BLOCK_LENGTH) {
                memset(&ctx->buffer[usedspace], 0, SHA256_BLOCK_LENGTH - usedspace);
            }
            /* Do second-to-last transform: */
            sha256_transform(ctx, (uint32_t*)(void*)ctx->buffer);

            /* And set-up for the last transform: */
            memset(ctx->buffer, 0, SHA256_SHORT_BLOCK_LENGTH);
        }
    } else {
        /* Set-up for the last transform: */
        memset(ctx->buffer, 0, SHA256_SHORT_BLOCK_LENGTH);

        /* Begin padding with a 1 bit: */
        *ctx->buffer = 0x80;
    }
    /* Set the bit count: */
    *(uint64_t*)(void*)&ctx->buffer[SHA256_SHORT_BLOCK_LENGTH] = ctx->bitcount;

    /* Final transform: */
    sha256_transform(ctx, (uint32_t*)(void*)ctx->buffer);

#if BYTE_ORDER == LITTLE_ENDIAN
    for (int j = 0; j < 8; j++) {
        REVERSE32(ctx->state[j],ctx->state[j]);
        *d++ = ctx->state[j];
    }
#else
    memcpy(d, ctx->state, SHA256_DIGEST_LENGTH);
#endif
}

void sha256(sha256_digest digest, const uint8_t *data, size_t len)
{
    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(digest, &ctx);
}
