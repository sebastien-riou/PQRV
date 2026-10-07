/*
 * Known-answer test of ML-DSA (FIPS 204) against the test vectors of
 * crypto-benchmark (libmldsa-lbmk/include, generated with BTVG-MLDSA):
 *   - KeyGen from the seed xi gives the expected pk and sk,
 *   - deterministic signing with an empty context gives the expected
 *     signatures (checked through the SHA-256 digest of their concatenation)
 *     after the expected number of iterations of the rejection loop,
 *   - verification accepts them and rejects tampered signatures.
 * It also checks the context string and internal APIs, and the incremental
 * SHAKE256 absorb at any split of the input.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fips202.h"
#include "params.h"
#include "randombytes.h"
#include "sha-256.h"
#include "sign.h"

#if defined(DILITHIUM_RANDOMIZED_SIGNING)
#    error "the known-answer test needs deterministic signing"
#endif

#if DILITHIUM_MODE == 2
#    include "mldsa44-m69-hBFB024F2.c"
#    include "mldsa44-m10K-h6AA1568B.c"
#    define TV_SHORT mldsa44_m69_test_vectors
#    define TV_LONG mldsa44_m10K_test_vectors
#elif DILITHIUM_MODE == 3
#    include "mldsa65-m69-hE1970117.c"
#    include "mldsa65-m10K-h5DD83C7E.c"
#    define TV_SHORT mldsa65_m69_test_vectors
#    define TV_LONG mldsa65_m10K_test_vectors
#elif DILITHIUM_MODE == 5
#    include "mldsa87-m69-hF0AA0CAA.c"
#    include "mldsa87-m10K-hECF6652D.c"
#    define TV_SHORT mldsa87_m69_test_vectors
#    define TV_LONG mldsa87_m10K_test_vectors
#endif

_Static_assert(sizeof(TV_SHORT.mldsa_seed) == SEEDBYTES, "seed size");
_Static_assert(sizeof(TV_SHORT.pk) == CRYPTO_PUBLICKEYBYTES, "pk size");
_Static_assert(sizeof(TV_SHORT.sk) == CRYPTO_SECRETKEYBYTES, "sk size");
_Static_assert(sizeof(TV_LONG.mldsa_seed) == SEEDBYTES, "seed size");
_Static_assert(sizeof(TV_LONG.pk) == CRYPTO_PUBLICKEYBYTES, "pk size");
_Static_assert(sizeof(TV_LONG.sk) == CRYPTO_SECRETKEYBYTES, "sk size");

/* Each message is 8 bytes from the vectors followed by zeros */
#define MSG_PREFIX_SIZE 8
#define MSG_MAX_SIZE 10240
#define SHORT_MSG_SIZE 69

/* Vector set, independent of the number of messages */
typedef struct {
    const char *name;
    const uint8_t *seed;
    const uint8_t *pk;
    const uint8_t *sk;
    unsigned int nmessages;
    const unsigned int *repetitions;
    unsigned int message_size;
    const uint8_t (*messages)[MSG_PREFIX_SIZE];
    const uint8_t *digest;
} kat_t;

#define KAT_INIT(tv)                                                     \
    {tv.name, tv.mldsa_seed, tv.pk, tv.sk, tv.nmessages, tv.repetitions, \
     tv.message_size, tv.sign_messages, tv.sigs_sha256_digest}

/* One spare byte to also run the tests on misaligned buffers */
static uint8_t msg_buf[MSG_MAX_SIZE + 1] __attribute__((aligned(8)));
static uint8_t sig_buf[CRYPTO_BYTES + 1] __attribute__((aligned(8)));
static uint8_t sig2_buf[CRYPTO_BYTES + 1] __attribute__((aligned(8)));
static uint8_t pk_buf[CRYPTO_PUBLICKEYBYTES + 1] __attribute__((aligned(8)));
static uint8_t sk_buf[CRYPTO_SECRETKEYBYTES + 1] __attribute__((aligned(8)));
static uint8_t sm_buf[CRYPTO_BYTES + SHORT_MSG_SIZE];

/* The test is deterministic: the RNG must not be used */
void randombytes(uint8_t *out, size_t outlen)
{
    (void)out;
    (void)outlen;
    printf("ERROR: randombytes() called by the deterministic test\n");
    exit(1);
}

static void make_message(uint8_t *m, const kat_t *tv, unsigned int index)
{
    memset(m, 0, tv->message_size);
    memcpy(m, tv->messages[index], MSG_PREFIX_SIZE);
}

/*************************************************
 * Name:        test_absorb
 *
 * Description: Check that absorbing an input in two parts, split at any
 *              offset, or byte by byte, gives the same SHAKE256 output as
 *              absorbing it at once.
 *
 * Returns the number of errors
 **************************************************/
static int test_absorb(void)
{
    uint8_t in[300 + 1], ref[64], out[64];
    keccak_state state;
    unsigned int i, split, offset;
    int errors = 0;

    for (i = 0; i < sizeof(in); i++)
        in[i] = 7 * i + 1;

    for (offset = 0; offset < 2; offset++) {
        const uint8_t *p = in + offset;
        const unsigned int len = sizeof(in) - 1;

        shake256(ref, sizeof(ref), p, len);
        for (split = 0; split <= len; split++) {
            shake256_init(&state);
            shake256_absorb(&state, p, split);
            shake256_absorb(&state, p + split, len - split);
            shake256_finalize(&state);
            shake256_squeeze(out, sizeof(out), &state);
            if (memcmp(out, ref, sizeof(ref))) {
                printf("ERROR: SHAKE256 absorb split at %u (offset %u)\n",
                       split, offset);
                errors++;
            }
        }

        shake256_init(&state);
        for (i = 0; i < len; i++)
            shake256_absorb(&state, p + i, 1);
        shake256_finalize(&state);
        shake256_squeeze(out, sizeof(out), &state);
        if (memcmp(out, ref, sizeof(ref))) {
            printf("ERROR: SHAKE256 absorb byte by byte (offset %u)\n",
                   offset);
            errors++;
        }
    }

    printf("SHAKE256 incremental absorb: %s\n", errors ? "FAIL" : "OK");
    return errors;
}

/*************************************************
 * Name:        test_kat
 *
 * Description: Run a vector set: KeyGen, then sign and verify each message.
 *
 * Arguments:   - const kat_t *tv: vector set
 *              - unsigned int offset: offset of the buffers from 8-byte
 *                                     alignment
 *
 * Returns the number of errors
 **************************************************/
static int test_kat(const kat_t *tv, unsigned int offset)
{
    uint8_t *m = msg_buf + offset;
    uint8_t *sig = sig_buf + offset;
    uint8_t *pk = pk_buf + offset;
    uint8_t *sk = sk_buf + offset;
    uint8_t digest[SIZE_OF_SHA_256_HASH];
    struct Sha_256 sha_256;
    size_t siglen;
    unsigned int i;
    int ret, errors = 0;

    if (tv->message_size > MSG_MAX_SIZE) {
        printf("ERROR: %s: message too long\n", tv->name);
        return 1;
    }

    crypto_sign_keypair_internal(pk, sk, tv->seed);
    if (memcmp(pk, tv->pk, CRYPTO_PUBLICKEYBYTES)) {
        printf("ERROR: %s: public key mismatch\n", tv->name);
        errors++;
    }
    if (memcmp(sk, tv->sk, CRYPTO_SECRETKEYBYTES)) {
        printf("ERROR: %s: secret key mismatch\n", tv->name);
        errors++;
    }

    sha_256_init(&sha_256, digest);
    for (i = 0; i < tv->nmessages; i++) {
        make_message(m, tv, i);
        ret = crypto_sign_signature(sig, &siglen, m, tv->message_size, NULL, 0,
                                    sk);
        if (ret < 0 || siglen != CRYPTO_BYTES) {
            printf("ERROR: %s: message %u: signing failed\n", tv->name, i);
            errors++;
        }
#if defined(DILITHIUM_COUNT_REJ_NUM)
        /* ret is the number of rejections */
        if ((unsigned int)ret + 1 != tv->repetitions[i]) {
            printf("ERROR: %s: message %u: %u iterations, expected %u\n",
                   tv->name, i, (unsigned int)ret + 1, tv->repetitions[i]);
            errors++;
        }
#endif
        sha_256_write(&sha_256, sig, CRYPTO_BYTES);

        if (crypto_sign_verify(sig, siglen, m, tv->message_size, NULL, 0,
                               pk)) {
            printf("ERROR: %s: message %u: verification failed\n", tv->name,
                   i);
            errors++;
        }
        sig[(37 * i) % CRYPTO_BYTES] ^= 1 << (i % 8);
        if (!crypto_sign_verify(sig, siglen, m, tv->message_size, NULL, 0,
                                pk)) {
            printf("ERROR: %s: message %u: tampered signature accepted\n",
                   tv->name, i);
            errors++;
        }
    }
    sha_256_close(&sha_256);
    if (memcmp(digest, tv->digest, SIZE_OF_SHA_256_HASH)) {
        printf("ERROR: %s: signatures digest mismatch\n", tv->name);
        errors++;
    }

    printf("%s (%u messages, %s buffers): %s\n", tv->name, tv->nmessages,
           offset ? "unaligned" : "aligned", errors ? "FAIL" : "OK");
    return errors;
}

/*************************************************
 * Name:        test_api
 *
 * Description: Check the internal and context string APIs with the first
 *              message of a vector set, whose keys are in pk_buf and sk_buf.
 *
 * Returns the number of errors
 **************************************************/
static int test_api(const kat_t *tv)
{
    static const uint8_t ctx[] = {'P', 'Q', 'R', 'V'};
    static const uint8_t pre[2] = {0, 0};
    static const uint8_t rnd[RNDBYTES] = {0};
    uint8_t *m = msg_buf;
    uint8_t *sig = sig_buf;
    uint8_t *sig2 = sig2_buf;
    const uint8_t *pk = pk_buf;
    const uint8_t *sk = sk_buf;
    size_t siglen, smlen, mlen;
    int errors = 0;

    make_message(m, tv, 0);

    /* Sign(m, ctx = "") = Sign_internal(0 || 0 || m) */
    crypto_sign_signature(sig, &siglen, m, tv->message_size, NULL, 0, sk);
    crypto_sign_signature_internal(sig2, &siglen, m, tv->message_size, pre,
                                   sizeof(pre), rnd, sk);
    if (memcmp(sig, sig2, CRYPTO_BYTES)) {
        printf("ERROR: internal signing API mismatch\n");
        errors++;
    }
    if (crypto_sign_verify_internal(sig, siglen, m, tv->message_size, pre,
                                    sizeof(pre), pk)) {
        printf("ERROR: internal verification API failed\n");
        errors++;
    }

    /* Non-empty context string */
    if (crypto_sign_signature(sig, &siglen, m, tv->message_size, ctx,
                              sizeof(ctx), sk) < 0 ||
        crypto_sign_verify(sig, siglen, m, tv->message_size, ctx, sizeof(ctx),
                           pk)) {
        printf("ERROR: signature with context string failed\n");
        errors++;
    }
    if (!crypto_sign_verify(sig, siglen, m, tv->message_size, NULL, 0, pk)) {
        printf("ERROR: signature verified with the wrong context string\n");
        errors++;
    }

    /* Context strings are at most 255 bytes long */
    if (crypto_sign_signature(sig, &siglen, m, tv->message_size, msg_buf, 256,
                              sk) != -1 ||
        crypto_sign_verify(sig, siglen, m, tv->message_size, msg_buf, 256,
                           pk) != -1) {
        printf("ERROR: context string longer than 255 bytes accepted\n");
        errors++;
    }

    /* Signed message API */
    if (crypto_sign(sm_buf, &smlen, m, SHORT_MSG_SIZE, ctx, sizeof(ctx), sk) ||
        smlen != CRYPTO_BYTES + SHORT_MSG_SIZE ||
        crypto_sign_open(sm_buf, &mlen, sm_buf, smlen, ctx, sizeof(ctx), pk) ||
        mlen != SHORT_MSG_SIZE || memcmp(sm_buf, m, SHORT_MSG_SIZE)) {
        printf("ERROR: signed message API failed\n");
        errors++;
    }

    printf("Internal, context string and signed message APIs: %s\n",
           errors ? "FAIL" : "OK");
    return errors;
}

int main(void)
{
    const kat_t tv_short = KAT_INIT(TV_SHORT);
    const kat_t tv_long = KAT_INIT(TV_LONG);
    int errors = 0;

    printf("%s known-answer test\n", CRYPTO_ALGNAME);
    errors += test_absorb();
    errors += test_kat(&tv_short, 0);
    errors += test_kat(&tv_long, 1);
    errors += test_kat(&tv_long, 0);
    errors += test_api(&tv_long);
    printf("%s: %s\n", CRYPTO_ALGNAME, errors ? "FAIL" : "PASS");

    return errors ? 1 : 0;
}
