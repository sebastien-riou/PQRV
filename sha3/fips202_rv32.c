/* Based on the public domain implementation in crypto_hash/keccakc512/simple/
 * from http://bench.cr.yp.to/supercop.html by Ronny Van Keer and the public
 * domain "TweetFips202" implementation from https://twitter.com/tweetfips202 by
 * Gilles Van Assche, Daniel J. Bernstein, and Peter Schwabe */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "fips202.h"
/*************************************************
 * Name:        KeccakF1600_StatePermute
 *
 * Description: The Keccak F1600 Permutation
 *
 * Arguments:   - uint64_t *state: pointer to input/output Keccak state
 **************************************************/
extern void KeccakF1600_StatePermute_RV32ASM(uint64_t state[25]);
void KeccakF1600_StatePermute(uint64_t state[25])
{
    KeccakF1600_StatePermute_RV32ASM(state);
}

#ifdef BIT_INTERLEAVING

/**
 * https://github.com/XKCP/XKCP/blob/master/lib/low/KeccakP-1600/plain-32bits-inplace/KeccakP-1600-inplace32BI.c
 * Credit to Henry S. Warren, Hacker's Delight, Addison-Wesley, 2002
 */
#    define prepareToBitInterleaving(low, high, temp, temp0, temp1) \
        temp0 = (low);                                              \
        temp = (temp0 ^ (temp0 >> 1)) & 0x22222222UL;               \
        temp0 = temp0 ^ temp ^ (temp << 1);                         \
        temp = (temp0 ^ (temp0 >> 2)) & 0x0C0C0C0CUL;               \
        temp0 = temp0 ^ temp ^ (temp << 2);                         \
        temp = (temp0 ^ (temp0 >> 4)) & 0x00F000F0UL;               \
        temp0 = temp0 ^ temp ^ (temp << 4);                         \
        temp = (temp0 ^ (temp0 >> 8)) & 0x0000FF00UL;               \
        temp0 = temp0 ^ temp ^ (temp << 8);                         \
        temp1 = (high);                                             \
        temp = (temp1 ^ (temp1 >> 1)) & 0x22222222UL;               \
        temp1 = temp1 ^ temp ^ (temp << 1);                         \
        temp = (temp1 ^ (temp1 >> 2)) & 0x0C0C0C0CUL;               \
        temp1 = temp1 ^ temp ^ (temp << 2);                         \
        temp = (temp1 ^ (temp1 >> 4)) & 0x00F000F0UL;               \
        temp1 = temp1 ^ temp ^ (temp << 4);                         \
        temp = (temp1 ^ (temp1 >> 8)) & 0x0000FF00UL;               \
        temp1 = temp1 ^ temp ^ (temp << 8)

#    define toBitInterleavingAndXOR(low, high, even, odd, temp, temp0, temp1) \
        prepareToBitInterleaving(low, high, temp, temp0, temp1);              \
        even ^= (temp0 & 0x0000FFFF) | (temp1 << 16);                         \
        odd ^= (temp0 >> 16) | (temp1 & 0xFFFF0000)

#    define toBitInterleavingAndXOR64b(in, out, temp, temp0, temp1)         \
        prepareToBitInterleaving((uint32_t)(in & 0xFFFFFFFF),               \
                                 (uint32_t)(in >> 32), temp, temp0, temp1); \
        out ^= ((uint64_t)((temp0 >> 16) | (temp1 & 0xFFFF0000)) << 32) |   \
               ((temp0 & 0x0000FFFF) | (temp1 << 16))

#    define toBitInterleaving64b(in, out, temp, temp0, temp1)               \
        prepareToBitInterleaving((uint32_t)(in & 0xFFFFFFFF),               \
                                 (uint32_t)(in >> 32), temp, temp0, temp1); \
        out = ((uint64_t)((temp0 >> 16) | (temp1 & 0xFFFF0000)) << 32) |    \
              ((temp0 & 0x0000FFFF) | (temp1 << 16))

#    define prepareFromBitInterleaving(even, odd, temp, temp0, temp1) \
        temp0 = (even);                                               \
        temp1 = (odd);                                                \
        temp = (temp0 & 0x0000FFFF) | (temp1 << 16);                  \
        temp1 = (temp0 >> 16) | (temp1 & 0xFFFF0000);                 \
        temp0 = temp;                                                 \
        temp = (temp0 ^ (temp0 >> 8)) & 0x0000FF00UL;                 \
        temp0 = temp0 ^ temp ^ (temp << 8);                           \
        temp = (temp0 ^ (temp0 >> 4)) & 0x00F000F0UL;                 \
        temp0 = temp0 ^ temp ^ (temp << 4);                           \
        temp = (temp0 ^ (temp0 >> 2)) & 0x0C0C0C0CUL;                 \
        temp0 = temp0 ^ temp ^ (temp << 2);                           \
        temp = (temp0 ^ (temp0 >> 1)) & 0x22222222UL;                 \
        temp0 = temp0 ^ temp ^ (temp << 1);                           \
        temp = (temp1 ^ (temp1 >> 8)) & 0x0000FF00UL;                 \
        temp1 = temp1 ^ temp ^ (temp << 8);                           \
        temp = (temp1 ^ (temp1 >> 4)) & 0x00F000F0UL;                 \
        temp1 = temp1 ^ temp ^ (temp << 4);                           \
        temp = (temp1 ^ (temp1 >> 2)) & 0x0C0C0C0CUL;                 \
        temp1 = temp1 ^ temp ^ (temp << 2);                           \
        temp = (temp1 ^ (temp1 >> 1)) & 0x22222222UL;                 \
        temp1 = temp1 ^ temp ^ (temp << 1)

#    define fromBitInterleaving(even, odd, low, high, temp, temp0, temp1) \
        prepareFromBitInterleaving(even, odd, temp, temp0, temp1);        \
        low = temp0;                                                      \
        high = temp1

#    define fromBitInterleaving64b(in, out, temp, temp0, temp1)               \
        prepareFromBitInterleaving((uint32_t)(in & 0xFFFFFFFF),               \
                                   (uint32_t)(in >> 32), temp, temp0, temp1); \
        out = (((uint64_t)temp1 << 32) | temp0)
#endif

/*************************************************
 * Name:        load64_le
 *
 * Description: Load 8 bytes into a 64-bit integer in little-endian order.
 *              Word accesses are used only when x is 4-byte aligned, so that
 *              cores without misaligned access support (e.g. RV32IMC MCUs)
 *              do not trap on unaligned input buffers.
 *
 * Arguments:   - const uint8_t *x: pointer to input byte array
 *
 * Returns the loaded 64-bit unsigned integer
 **************************************************/
static inline uint64_t load64_le(const uint8_t *x)
{
    unsigned int i;
    uint32_t lo, hi;
    uint64_t r = 0;

    if (((uintptr_t)x & 3) == 0) {
        /* Two word accesses, the compiler keeps them in registers */
        memcpy(&lo, __builtin_assume_aligned(x, 4), 4);
        memcpy(&hi, __builtin_assume_aligned(x + 4, 4), 4);
        return ((uint64_t)hi << 32) | lo;
    }
    for (i = 0; i < 8; i++)
        r |= (uint64_t)x[i] << 8 * i;
    return r;
}

/*************************************************
 * Name:        store64_le
 *
 * Description: Store a 64-bit integer to an array of 8 bytes in little-endian
 *              order. Word accesses are used only when x is 4-byte aligned.
 *
 * Arguments:   - uint8_t *x: pointer to the output byte array
 *              - uint64_t u: input 64-bit unsigned integer
 **************************************************/
static inline void store64_le(uint8_t *x, uint64_t u)
{
    unsigned int i;
    uint32_t lo = (uint32_t)u, hi = (uint32_t)(u >> 32);

    if (((uintptr_t)x & 3) == 0) {
        memcpy(__builtin_assume_aligned(x, 4), &lo, 4);
        memcpy(__builtin_assume_aligned(x + 4, 4), &hi, 4);
        return;
    }
    for (i = 0; i < 8; i++)
        x[i] = u >> 8 * i;
}

/*************************************************
 * Name:        keccak_init
 *
 * Description: Initializes the Keccak state.
 *
 * Arguments:   - uint64_t *s: pointer to Keccak state
 **************************************************/
static void keccak_init(uint64_t s[25])
{
    unsigned int i;
    for (i = 0; i < 25; i++)
        s[i] = 0;
}

/*************************************************
 * Name:        keccak_absorb
 *
 * Description: Absorb step of Keccak; incremental.
 *
 * Arguments:   - uint64_t *s: pointer to Keccak state
 *              - unsigned int pos: position in current block to be absorbed
 *              - unsigned int r: rate in bytes (e.g., 168 for SHAKE128)
 *              - const uint8_t *in: pointer to input to be absorbed into s
 *              - size_t inlen: length of input in bytes
 *
 * Returns new position pos in current block
 **************************************************/
static unsigned int keccak_absorb(uint64_t s[25], unsigned int pos,
                                  unsigned int r, const uint8_t *in,
                                  size_t inlen)
{
    unsigned int i, n;
    uint64_t lane;
#ifdef BIT_INTERLEAVING
    uint32_t t, t0, t1;
#endif

    /* r is a multiple of 8: absorb one (possibly partial) lane at a time */
    while (inlen > 0) {
        n = 8 - pos % 8;
        if (n > inlen)
            n = inlen;
        if (n == 8) {
            lane = load64_le(in);
        } else {
            lane = 0;
            for (i = 0; i < n; i++)
                lane |= (uint64_t)in[i] << 8 * ((pos + i) % 8);
        }
#ifndef BIT_INTERLEAVING
        s[pos / 8] ^= lane;
#else
        toBitInterleavingAndXOR64b(lane, s[pos / 8], t, t0, t1);
#endif
        in += n;
        pos += n;
        inlen -= n;
        if (pos == r) {
            KeccakF1600_StatePermute(s);
            pos = 0;
        }
    }
    return pos;
}

/*************************************************
 * Name:        keccak_finalize
 *
 * Description: Finalize absorb step.
 *
 * Arguments:   - uint64_t *s: pointer to Keccak state
 *              - unsigned int pos: position in current block to be absorbed
 *              - unsigned int r: rate in bytes (e.g., 168 for SHAKE128)
 *              - uint8_t p: domain separation byte
 **************************************************/
static void keccak_finalize(uint64_t s[25], unsigned int pos, unsigned int r,
                            uint8_t p)
{
#ifdef BIT_INTERLEAVING
    uint32_t t, t0, t1;
    uint64_t lane = (uint64_t)p << 8 * (pos % 8);

    toBitInterleavingAndXOR64b(lane, s[pos / 8], t, t0, t1);
    toBitInterleavingAndXOR64b((1ULL << 63), s[r / 8 - 1], t, t0, t1);
#else
    s[pos / 8] ^= (uint64_t)p << 8 * (pos % 8);
    s[r / 8 - 1] ^= 1ULL << 63;
#endif
}

/*************************************************
 * Name:        keccak_absorb_once
 *
 * Description: Absorb step of Keccak;
 *              non-incremental, starts by zeroeing the state.
 *
 * Arguments:   - uint64_t *s: pointer to (uninitialized) output Keccak state
 *              - unsigned int r: rate in bytes (e.g., 168 for SHAKE128)
 *              - const uint8_t *in: pointer to input to be absorbed into s
 *              - size_t inlen: length of input in bytes
 *              - uint8_t p: domain-separation byte for different Keccak-derived
 *functions
 **************************************************/
static void keccak_absorb_once(uint64_t s[25], unsigned int r,
                               const uint8_t *in, size_t inlen, uint8_t p)
{
    unsigned int i, j;
    uint64_t lane;
#ifdef BIT_INTERLEAVING
    uint32_t t, t0, t1;
#endif

    for (i = 0; i < 25; i++)
        s[i] = 0;

    while (inlen >= r) {
        for (i = 0; i < r / 8; i++) {
            lane = load64_le(in + 8 * i);
#ifndef BIT_INTERLEAVING
            s[i] ^= lane;
#else
            toBitInterleavingAndXOR64b(lane, s[i], t, t0, t1);
#endif
        }
        in += r;
        inlen -= r;
        KeccakF1600_StatePermute(s);
    }

    for (i = 0; inlen >= 8; i += 1, in += 8, inlen -= 8) {
        lane = load64_le(in);
#ifndef BIT_INTERLEAVING
        s[i] ^= lane;
#else
        toBitInterleavingAndXOR64b(lane, s[i], t, t0, t1);
#endif
    }

    lane = (uint64_t)p << 8 * inlen;
    for (j = 0; j < inlen; j++)
        lane |= (uint64_t)in[j] << 8 * j;
#ifndef BIT_INTERLEAVING
    s[i] ^= lane;
    s[(r - 1) / 8] ^= (1ULL << 63);
#else
    toBitInterleavingAndXOR64b(lane, s[i], t, t0, t1);
    toBitInterleavingAndXOR64b((1ULL << 63), s[(r - 1) / 8], t, t0, t1);
#endif
}

/*************************************************
 * Name:        keccak_squeeze
 *
 * Description: Squeeze step of Keccak. Squeezes arbitratrily many bytes.
 *              Modifies the state. Can be called multiple times to keep
 *              squeezing, i.e., is incremental.
 *
 * Arguments:   - uint8_t *out: pointer to output
 *              - size_t outlen: number of bytes to be squeezed (written to out)
 *              - uint64_t *s: pointer to input/output Keccak state
 *              - unsigned int pos: number of bytes in current block already
 *squeezed
 *              - unsigned int r: rate in bytes (e.g., 168 for SHAKE128)
 *
 * Returns new position pos in current block
 **************************************************/
static unsigned int keccak_squeeze(uint8_t *out, size_t outlen, uint64_t s[25],
                                   unsigned int pos, unsigned int r)
{
    unsigned int i;
#ifdef BIT_INTERLEAVING
    uint32_t t, t0, t1;
    uint64_t lane = 0;
    unsigned int computed_index = -1;
#endif

    while (outlen) {
        if (pos == r) {
            KeccakF1600_StatePermute(s);
            pos = 0;
        }
        for (i = pos; i < r && i < pos + outlen; i++) {
#ifdef BIT_INTERLEAVING
            if (computed_index != i / 8) {
                fromBitInterleaving64b(s[(i / 8)], lane, t, t0, t1);
                computed_index = i / 8;
            }
            *out++ = lane >> 8 * (i % 8);
#else
            *out++ = s[i / 8] >> 8 * (i % 8);
#endif
        }
        outlen -= i - pos;
        pos = i;
    }

    return pos;
}

/*************************************************
 * Name:        keccak_squeezeblocks
 *
 * Description: Squeeze step of Keccak. Squeezes full blocks of r bytes each.
 *              Modifies the state. Can be called multiple times to keep
 *              squeezing, i.e., is incremental. Assumes zero bytes of current
 *              block have already been squeezed.
 *
 * Arguments:   - uint8_t *out: pointer to output blocks
 *              - size_t nblocks: number of blocks to be squeezed (written to
 *out)
 *              - uint64_t *s: pointer to input/output Keccak state
 *              - unsigned int r: rate in bytes (e.g., 168 for SHAKE128)
 **************************************************/
static void keccak_squeezeblocks(uint8_t *out, size_t nblocks, uint64_t s[25],
                                 unsigned int r)
{
    unsigned int i;
#ifdef BIT_INTERLEAVING
    uint32_t t, t0, t1;
    uint64_t lane;
#endif

    while (nblocks) {
        KeccakF1600_StatePermute(s);
        for (i = 0; i < r / 8; i++) {
#ifndef BIT_INTERLEAVING
            store64_le(out + 8 * i, s[i]);
#else
            fromBitInterleaving64b(s[i], lane, t, t0, t1);
            store64_le(out + 8 * i, lane);
#endif
        }
        out += r;
        nblocks -= 1;
    }
}

/*************************************************
 * Name:        shake128_init
 *
 * Description: Initilizes Keccak state for use as SHAKE128 XOF
 *
 * Arguments:   - keccak_state *state: pointer to (uninitialized) Keccak state
 **************************************************/
void shake128_init(keccak_state *state)
{
    keccak_init(state->s);
    state->pos = 0;
}

/*************************************************
 * Name:        shake128_absorb
 *
 * Description: Absorb step of the SHAKE128 XOF; incremental.
 *
 * Arguments:   - keccak_state *state: pointer to (initialized) output Keccak
 *state
 *              - const uint8_t *in: pointer to input to be absorbed into s
 *              - size_t inlen: length of input in bytes
 **************************************************/
void shake128_absorb(keccak_state *state, const uint8_t *in, size_t inlen)
{
    state->pos = keccak_absorb(state->s, state->pos, SHAKE128_RATE, in, inlen);
}

/*************************************************
 * Name:        shake128_finalize
 *
 * Description: Finalize absorb step of the SHAKE128 XOF.
 *
 * Arguments:   - keccak_state *state: pointer to Keccak state
 **************************************************/
void shake128_finalize(keccak_state *state)
{
    keccak_finalize(state->s, state->pos, SHAKE128_RATE, 0x1F);
    state->pos = SHAKE128_RATE;
}

/*************************************************
 * Name:        shake128_squeeze
 *
 * Description: Squeeze step of SHAKE128 XOF. Squeezes arbitraily many
 *              bytes. Can be called multiple times to keep squeezing.
 *
 * Arguments:   - uint8_t *out: pointer to output blocks
 *              - size_t outlen : number of bytes to be squeezed (written to
 *output)
 *              - keccak_state *s: pointer to input/output Keccak state
 **************************************************/
void shake128_squeeze(uint8_t *out, size_t outlen, keccak_state *state)
{
    state->pos =
        keccak_squeeze(out, outlen, state->s, state->pos, SHAKE128_RATE);
}

/*************************************************
 * Name:        shake128_absorb_once
 *
 * Description: Initialize, absorb into and finalize SHAKE128 XOF;
 *non-incremental.
 *
 * Arguments:   - keccak_state *state: pointer to (uninitialized) output Keccak
 *state
 *              - const uint8_t *in: pointer to input to be absorbed into s
 *              - size_t inlen: length of input in bytes
 **************************************************/
void shake128_absorb_once(keccak_state *state, const uint8_t *in, size_t inlen)
{
    keccak_absorb_once(state->s, SHAKE128_RATE, in, inlen, 0x1F);
    state->pos = SHAKE128_RATE;
}

/*************************************************
 * Name:        shake128_squeezeblocks
 *
 * Description: Squeeze step of SHAKE128 XOF. Squeezes full blocks of
 *              SHAKE128_RATE bytes each. Can be called multiple times
 *              to keep squeezing. Assumes new block has not yet been
 *              started (state->pos = SHAKE128_RATE).
 *
 * Arguments:   - uint8_t *out: pointer to output blocks
 *              - size_t nblocks: number of blocks to be squeezed (written to
 *output)
 *              - keccak_state *s: pointer to input/output Keccak state
 **************************************************/
void shake128_squeezeblocks(uint8_t *out, size_t nblocks, keccak_state *state)
{
    keccak_squeezeblocks(out, nblocks, state->s, SHAKE128_RATE);
}

/*************************************************
 * Name:        shake256_init
 *
 * Description: Initilizes Keccak state for use as SHAKE256 XOF
 *
 * Arguments:   - keccak_state *state: pointer to (uninitialized) Keccak state
 **************************************************/
void shake256_init(keccak_state *state)
{
    keccak_init(state->s);
    state->pos = 0;
}

/*************************************************
 * Name:        shake256_absorb
 *
 * Description: Absorb step of the SHAKE256 XOF; incremental.
 *
 * Arguments:   - keccak_state *state: pointer to (initialized) output Keccak
 *state
 *              - const uint8_t *in: pointer to input to be absorbed into s
 *              - size_t inlen: length of input in bytes
 **************************************************/
void shake256_absorb(keccak_state *state, const uint8_t *in, size_t inlen)
{
    state->pos = keccak_absorb(state->s, state->pos, SHAKE256_RATE, in, inlen);
}

/*************************************************
 * Name:        shake256_finalize
 *
 * Description: Finalize absorb step of the SHAKE256 XOF.
 *
 * Arguments:   - keccak_state *state: pointer to Keccak state
 **************************************************/
void shake256_finalize(keccak_state *state)
{
    keccak_finalize(state->s, state->pos, SHAKE256_RATE, 0x1F);
    state->pos = SHAKE256_RATE;
}

/*************************************************
 * Name:        shake256_squeeze
 *
 * Description: Squeeze step of SHAKE256 XOF. Squeezes arbitraily many
 *              bytes. Can be called multiple times to keep squeezing.
 *
 * Arguments:   - uint8_t *out: pointer to output blocks
 *              - size_t outlen : number of bytes to be squeezed (written to
 *output)
 *              - keccak_state *s: pointer to input/output Keccak state
 **************************************************/
void shake256_squeeze(uint8_t *out, size_t outlen, keccak_state *state)
{
    state->pos =
        keccak_squeeze(out, outlen, state->s, state->pos, SHAKE256_RATE);
}

/*************************************************
 * Name:        shake256_absorb_once
 *
 * Description: Initialize, absorb into and finalize SHAKE256 XOF;
 *non-incremental.
 *
 * Arguments:   - keccak_state *state: pointer to (uninitialized) output Keccak
 *state
 *              - const uint8_t *in: pointer to input to be absorbed into s
 *              - size_t inlen: length of input in bytes
 **************************************************/
void shake256_absorb_once(keccak_state *state, const uint8_t *in, size_t inlen)
{
    keccak_absorb_once(state->s, SHAKE256_RATE, in, inlen, 0x1F);
    state->pos = SHAKE256_RATE;
}

/*************************************************
 * Name:        shake256_squeezeblocks
 *
 * Description: Squeeze step of SHAKE256 XOF. Squeezes full blocks of
 *              SHAKE256_RATE bytes each. Can be called multiple times
 *              to keep squeezing. Assumes next block has not yet been
 *              started (state->pos = SHAKE256_RATE).
 *
 * Arguments:   - uint8_t *out: pointer to output blocks
 *              - size_t nblocks: number of blocks to be squeezed (written to
 *output)
 *              - keccak_state *s: pointer to input/output Keccak state
 **************************************************/
void shake256_squeezeblocks(uint8_t *out, size_t nblocks, keccak_state *state)
{
    keccak_squeezeblocks(out, nblocks, state->s, SHAKE256_RATE);
}

/*************************************************
 * Name:        shake128
 *
 * Description: SHAKE128 XOF with non-incremental API
 *
 * Arguments:   - uint8_t *out: pointer to output
 *              - size_t outlen: requested output length in bytes
 *              - const uint8_t *in: pointer to input
 *              - size_t inlen: length of input in bytes
 **************************************************/
void shake128(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen)
{
    size_t nblocks;
    keccak_state state;

    shake128_absorb_once(&state, in, inlen);
    nblocks = outlen / SHAKE128_RATE;
    shake128_squeezeblocks(out, nblocks, &state);
    outlen -= nblocks * SHAKE128_RATE;
    out += nblocks * SHAKE128_RATE;
    shake128_squeeze(out, outlen, &state);
}

/*************************************************
 * Name:        shake256
 *
 * Description: SHAKE256 XOF with non-incremental API
 *
 * Arguments:   - uint8_t *out: pointer to output
 *              - size_t outlen: requested output length in bytes
 *              - const uint8_t *in: pointer to input
 *              - size_t inlen: length of input in bytes
 **************************************************/
void shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen)
{
    size_t nblocks;
    keccak_state state;

    shake256_absorb_once(&state, in, inlen);
    nblocks = outlen / SHAKE256_RATE;
    shake256_squeezeblocks(out, nblocks, &state);
    outlen -= nblocks * SHAKE256_RATE;
    out += nblocks * SHAKE256_RATE;
    shake256_squeeze(out, outlen, &state);
}

/*************************************************
 * Name:        sha3_256
 *
 * Description: SHA3-256 with non-incremental API
 *
 * Arguments:   - uint8_t *h: pointer to output (32 bytes)
 *              - const uint8_t *in: pointer to input
 *              - size_t inlen: length of input in bytes
 **************************************************/
void sha3_256(uint8_t h[32], const uint8_t *in, size_t inlen)
{
    unsigned int i;
    uint64_t s[25];
#ifdef BIT_INTERLEAVING
    uint32_t t, t0, t1;
    uint64_t lane;
#endif

    keccak_absorb_once(s, SHA3_256_RATE, in, inlen, 0x06);
    KeccakF1600_StatePermute(s);
    for (i = 0; i < 4; i++) {
#ifndef BIT_INTERLEAVING
        store64_le(h + 8 * i, s[i]);
#else
        fromBitInterleaving64b(s[i], lane, t, t0, t1);
        store64_le(h + 8 * i, lane);
#endif
    }
}

/*************************************************
 * Name:        sha3_512
 *
 * Description: SHA3-512 with non-incremental API
 *
 * Arguments:   - uint8_t *h: pointer to output (64 bytes)
 *              - const uint8_t *in: pointer to input
 *              - size_t inlen: length of input in bytes
 **************************************************/
void sha3_512(uint8_t h[64], const uint8_t *in, size_t inlen)
{
    unsigned int i;
    uint64_t s[25];
#ifdef BIT_INTERLEAVING
    uint32_t t, t0, t1;
    uint64_t lane;
#endif

    keccak_absorb_once(s, SHA3_512_RATE, in, inlen, 0x06);
    KeccakF1600_StatePermute(s);
    for (i = 0; i < 8; i++) {
#ifndef BIT_INTERLEAVING
        store64_le(h + 8 * i, s[i]);
#else
        fromBitInterleaving64b(s[i], lane, t, t0, t1);
        store64_le(h + 8 * i, lane);
#endif
    }
}
