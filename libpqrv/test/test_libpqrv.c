/*
 * Known-answer test of libpqrv against the test vectors of crypto-benchmark
 * (libmlkem-lbmk/include and libmldsa-lbmk/include). All the parameter sets of
 * ML-KEM and ML-DSA are linked in this program, through pqrv.h only.
 *
 * ML-KEM: KeyGen_internal (digests of pk and sk), input checking,
 * Encaps_internal (digest of ct, shared secret), Decaps_internal (shared
 * secret, implicit rejection).
 * ML-DSA: KeyGen_internal (pk and sk), deterministic signing with an empty
 * context (digest of the signatures), verification, rejection of tampered
 * signatures, internal and context string APIs.
 *
 * randombytes is not defined: the randomized functions must be removed by
 * --gc-sections.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "pqrv.h"
#include "sha-256.h"

/* Types of the ML-KEM vectors, as in crypto-benchmark
 * libmlkem-lbmk/source/core.c */
#define MLKEM_KEYGEN_SEEDBYTES 64
#define MLKEM_ENCAPS_SEEDBYTES 32
#define MLKEM_SHAREDSECRETBYTES 32

typedef struct {
    uint8_t keygen_seed[MLKEM_KEYGEN_SEEDBYTES];
    uint8_t encaps_seed[MLKEM_ENCAPS_SEEDBYTES];
    uint8_t pk_sha256[32];
    uint8_t sk_sha256[32];
    uint8_t ct_sha256[32];
    uint8_t ss[MLKEM_SHAREDSECRETBYTES];
    uint8_t ss_reject[MLKEM_SHAREDSECRETBYTES];
} mlkem_test_case_t;

typedef struct {
    const char *name;
    unsigned int mlkem_pset;
    unsigned int ncases;
    const mlkem_test_case_t *cases;
} mlkem_test_vectors_t;

#include "mlkem512-n16-hA9D61CDB.c"
#include "mlkem768-n16-h99342E63.c"
#include "mlkem1024-n16-hCDD815CA.c"

#include "mldsa44-m69-hBFB024F2.c"
#include "mldsa44-m10K-h6AA1568B.c"
#include "mldsa65-m69-hE1970117.c"
#include "mldsa65-m10K-h5DD83C7E.c"
#include "mldsa87-m69-hF0AA0CAA.c"
#include "mldsa87-m10K-hECF6652D.c"

#define MAX(a, b) ((a) > (b) ? (a) : (b))

#define MLKEM_MAX_PUBLICKEYBYTES PQRV_MLKEM1024_PUBLICKEYBYTES
#define MLKEM_MAX_SECRETKEYBYTES PQRV_MLKEM1024_SECRETKEYBYTES
#define MLKEM_MAX_CIPHERTEXTBYTES PQRV_MLKEM1024_CIPHERTEXTBYTES
#define MLDSA_MAX_PUBLICKEYBYTES PQRV_MLDSA87_PUBLICKEYBYTES
#define MLDSA_MAX_SECRETKEYBYTES PQRV_MLDSA87_SECRETKEYBYTES
#define MLDSA_MAX_BYTES PQRV_MLDSA87_BYTES

/* ML-DSA messages are 8 bytes from the vectors followed by zeros */
#define MSG_PREFIX_SIZE 8
#define MSG_MAX_SIZE 10240
#define SHORT_MSG_SIZE 69

/* One spare byte to also run the tests on misaligned buffers */
#define BUF(name, size) static uint8_t name[(size) + 1] __attribute__((aligned(8)))
BUF(pk_buf, MAX(MLKEM_MAX_PUBLICKEYBYTES, MLDSA_MAX_PUBLICKEYBYTES));
BUF(pk2_buf, MLKEM_MAX_PUBLICKEYBYTES);
BUF(sk_buf, MAX(MLKEM_MAX_SECRETKEYBYTES, MLDSA_MAX_SECRETKEYBYTES));
BUF(sk2_buf, MLKEM_MAX_SECRETKEYBYTES);
BUF(ct_buf, MLKEM_MAX_CIPHERTEXTBYTES);
BUF(msg_buf, MSG_MAX_SIZE);
BUF(sig_buf, MLDSA_MAX_BYTES);
BUF(sig2_buf, MLDSA_MAX_BYTES);
static uint8_t sm_buf[MLDSA_MAX_BYTES + SHORT_MSG_SIZE];

/* ML-KEM parameter set */
typedef struct {
    unsigned int pset;
    size_t pk_bytes, sk_bytes, ct_bytes;
    int (*keypair_derand)(uint8_t *pk, uint8_t *sk, const uint8_t *coins);
    int (*enc_derand)(uint8_t *ct, uint8_t *ss, const uint8_t *pk,
                      const uint8_t *coins);
    int (*dec)(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
    int (*check_pk)(const uint8_t *pk);
    int (*check_sk)(const uint8_t *sk);
    const mlkem_test_vectors_t *tv;
} mlkem_impl_t;

#define MLKEM_IMPL(NNN)                                                   \
    {NNN,                                                                 \
     PQRV_MLKEM##NNN##_PUBLICKEYBYTES,                                    \
     PQRV_MLKEM##NNN##_SECRETKEYBYTES,                                    \
     PQRV_MLKEM##NNN##_CIPHERTEXTBYTES,                                   \
     pqrv_mlkem##NNN##_keypair_derand,                                    \
     pqrv_mlkem##NNN##_enc_derand,                                        \
     pqrv_mlkem##NNN##_dec,                                               \
     pqrv_mlkem##NNN##_check_pk,                                          \
     pqrv_mlkem##NNN##_check_sk,                                          \
     &mlkem##NNN##_n16_test_vectors}

static const mlkem_impl_t mlkem_impls[] = {MLKEM_IMPL(512), MLKEM_IMPL(768),
                                           MLKEM_IMPL(1024)};

/* ML-DSA parameter set */
typedef struct {
    unsigned int pset;
    size_t pk_bytes, sk_bytes, sig_bytes;
    int (*keypair_internal)(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
    int (*signature)(uint8_t *sig, size_t *siglen, const uint8_t *m,
                     size_t mlen, const uint8_t *ctx, size_t ctxlen,
                     const uint8_t *sk);
    int (*signature_internal)(uint8_t *sig, size_t *siglen, const uint8_t *m,
                              size_t mlen, const uint8_t *pre, size_t prelen,
                              const uint8_t *rnd, const uint8_t *sk);
    int (*sign)(uint8_t *sm, size_t *smlen, const uint8_t *m, size_t mlen,
                const uint8_t *ctx, size_t ctxlen, const uint8_t *sk);
    int (*verify)(const uint8_t *sig, size_t siglen, const uint8_t *m,
                  size_t mlen, const uint8_t *ctx, size_t ctxlen,
                  const uint8_t *pk);
    int (*verify_internal)(const uint8_t *sig, size_t siglen,
                           const uint8_t *m, size_t mlen, const uint8_t *pre,
                           size_t prelen, const uint8_t *pk);
    int (*open)(uint8_t *m, size_t *mlen, const uint8_t *sm, size_t smlen,
                const uint8_t *ctx, size_t ctxlen, const uint8_t *pk);
} mldsa_impl_t;

#define MLDSA_IMPL(NN)                                                    \
    {NN,                                                                  \
     PQRV_MLDSA##NN##_PUBLICKEYBYTES,                                     \
     PQRV_MLDSA##NN##_SECRETKEYBYTES,                                     \
     PQRV_MLDSA##NN##_BYTES,                                              \
     pqrv_mldsa##NN##_keypair_internal,                                   \
     pqrv_mldsa##NN##_signature,                                          \
     pqrv_mldsa##NN##_signature_internal,                                 \
     pqrv_mldsa##NN##_sign,                                               \
     pqrv_mldsa##NN##_verify,                                             \
     pqrv_mldsa##NN##_verify_internal,                                    \
     pqrv_mldsa##NN##_open}

/* ML-DSA vector set, independent of the number of messages */
typedef struct {
    const char *name;
    const uint8_t *seed;
    const uint8_t *pk;
    const uint8_t *sk;
    size_t pk_bytes, sk_bytes;
    unsigned int nmessages;
    unsigned int message_size;
    const uint8_t (*messages)[MSG_PREFIX_SIZE];
    const uint8_t *digest;
} mldsa_kat_t;

#define MLDSA_KAT(tv)                                                  \
    {tv.name, tv.mldsa_seed, tv.pk, tv.sk, sizeof(tv.pk), sizeof(tv.sk), \
     tv.nmessages, tv.message_size, tv.sign_messages,                  \
     tv.sigs_sha256_digest}

static int check(int ok, const char *what, unsigned int pset,
                 unsigned int index)
{
    if (!ok)
        printf("ERROR: %u: %s (case %u)\n", pset, what, index);
    return !ok;
}

/*************************************************
 * Name:        test_mlkem
 *
 * Description: Run the 16 vector cases of an ML-KEM parameter set, with
 *              aligned (even cases) and unaligned (odd cases) buffers.
 *
 * Returns the number of errors
 **************************************************/
static int test_mlkem(const mlkem_impl_t *impl)
{
    const mlkem_test_vectors_t *tv = impl->tv;
    uint8_t digest[SIZE_OF_SHA_256_HASH];
    uint8_t ss[PQRV_MLKEM_SSBYTES];
    const uint8_t *last_pk = pk_buf, *last_sk = sk_buf;
    unsigned int i, off;
    const unsigned int pset = impl->pset;
    int errors = 0;

    errors += check(tv->mlkem_pset == pset, "vector set mismatch", pset, 0);
    for (i = 0; i < tv->ncases; i++) {
        const mlkem_test_case_t *c = &tv->cases[i];
        uint8_t *pk = pk_buf + (i & 1);
        uint8_t *sk = sk_buf + (i & 1);
        uint8_t *ct = ct_buf + (i & 1);

        errors += check(!impl->keypair_derand(pk, sk, c->keygen_seed),
                        "keypair_derand failed", pset, i);
        calc_sha_256(digest, pk, impl->pk_bytes);
        errors += check(!memcmp(digest, c->pk_sha256, sizeof(digest)),
                        "public key mismatch", pset, i);
        calc_sha_256(digest, sk, impl->sk_bytes);
        errors += check(!memcmp(digest, c->sk_sha256, sizeof(digest)),
                        "secret key mismatch", pset, i);
        errors += check(!impl->check_pk(pk), "check_pk failed", pset, i);
        errors += check(!impl->check_sk(sk), "check_sk failed", pset, i);

        errors += check(!impl->enc_derand(ct, ss, pk, c->encaps_seed),
                        "enc_derand failed", pset, i);
        calc_sha_256(digest, ct, impl->ct_bytes);
        errors += check(!memcmp(digest, c->ct_sha256, sizeof(digest)),
                        "ciphertext mismatch", pset, i);
        errors += check(!memcmp(ss, c->ss, sizeof(ss)),
                        "encapsulated shared secret mismatch", pset, i);

        memset(ss, 0, sizeof(ss));
        errors += check(!impl->dec(ss, ct, sk), "dec failed", pset, i);
        errors += check(!memcmp(ss, c->ss, sizeof(ss)),
                        "decapsulated shared secret mismatch", pset, i);

        ct[0] ^= 1;
        errors += check(!impl->dec(ss, ct, sk), "dec failed", pset, i);
        errors += check(!memcmp(ss, c->ss_reject, sizeof(ss)),
                        "implicit rejection mismatch", pset, i);
        last_pk = pk;
        last_sk = sk;
    }

    /* Input checking: coefficients of pk are 12-bit values which must be
     * less than q = 3329, the hash of pk is stored in sk. Start from the
     * last key pair, which is valid. */
    off = impl->sk_bytes - impl->pk_bytes - 2 * 32;
    for (i = 0; i < 4; i++) {
        static const uint16_t coeffs[4] = {3328, 3329, 4095, 0};
        const int expected = coeffs[i] < 3329 ? 0 : -1;
        uint8_t *pk2 = pk2_buf + (i & 1);

        memcpy(pk2, last_pk, impl->pk_bytes);
        if (i & 1) { /* second coefficient of the last 3 bytes */
            uint8_t *p = pk2 + impl->pk_bytes - 32 - 3;
            p[1] = (p[1] & 0x0F) | (uint8_t)(coeffs[i] << 4);
            p[2] = coeffs[i] >> 4;
        } else { /* first coefficient */
            pk2[0] = coeffs[i];
            pk2[1] = (pk2[1] & 0xF0) | (coeffs[i] >> 8);
        }
        errors += check(impl->check_pk(pk2) == expected,
                        "check_pk result on modified key", pset, i);
    }
    for (i = 0; i < 2; i++) {
        uint8_t *sk2 = sk2_buf + i;

        memcpy(sk2, last_sk, impl->sk_bytes);
        sk2[i ? off + impl->pk_bytes : off] ^= 0x80; /* pk, then H(pk) */
        errors += check(impl->check_sk(sk2) == -1,
                        "check_sk accepted a modified key", pset, i);
    }

    printf("ML-KEM-%u: %u cases, input checking: %s\n", pset, tv->ncases,
           errors ? "FAIL" : "OK");
    return errors;
}

/*************************************************
 * Name:        test_mldsa_kat
 *
 * Description: Run an ML-DSA vector set: KeyGen, then sign and verify each
 *              message.
 *
 * Arguments:   - const mldsa_impl_t *impl: parameter set
 *              - const mldsa_kat_t *tv: vector set
 *              - unsigned int offset: offset of the buffers from 8-byte
 *                                     alignment
 *
 * Returns the number of errors
 **************************************************/
static int test_mldsa_kat(const mldsa_impl_t *impl, const mldsa_kat_t *tv,
                          unsigned int offset)
{
    uint8_t *m = msg_buf + offset;
    uint8_t *sig = sig_buf + offset;
    uint8_t *pk = pk_buf + offset;
    uint8_t *sk = sk_buf + offset;
    uint8_t digest[SIZE_OF_SHA_256_HASH];
    struct Sha_256 sha_256;
    size_t siglen;
    unsigned int i;
    const unsigned int pset = impl->pset;
    int errors = 0;

    if (tv->message_size > MSG_MAX_SIZE || tv->pk_bytes != impl->pk_bytes ||
        tv->sk_bytes != impl->sk_bytes) {
        printf("ERROR: %s: unexpected vector set\n", tv->name);
        return 1;
    }

    impl->keypair_internal(pk, sk, tv->seed);
    errors += check(!memcmp(pk, tv->pk, impl->pk_bytes),
                    "public key mismatch", pset, 0);
    errors += check(!memcmp(sk, tv->sk, impl->sk_bytes),
                    "secret key mismatch", pset, 0);

    sha_256_init(&sha_256, digest);
    for (i = 0; i < tv->nmessages; i++) {
        memset(m, 0, tv->message_size);
        memcpy(m, tv->messages[i], MSG_PREFIX_SIZE);
        errors += check(!impl->signature(sig, &siglen, m, tv->message_size,
                                         NULL, 0, sk) &&
                            siglen == impl->sig_bytes,
                        "signing failed", pset, i);
        sha_256_write(&sha_256, sig, impl->sig_bytes);
        errors += check(!impl->verify(sig, siglen, m, tv->message_size, NULL,
                                      0, pk),
                        "verification failed", pset, i);
        sig[(37 * i) % impl->sig_bytes] ^= 1 << (i % 8);
        errors += check(impl->verify(sig, siglen, m, tv->message_size, NULL,
                                     0, pk) == -1,
                        "tampered signature accepted", pset, i);
    }
    sha_256_close(&sha_256);
    errors += check(!memcmp(digest, tv->digest, SIZE_OF_SHA_256_HASH),
                    "signatures digest mismatch", pset, 0);

    printf("ML-DSA-%u: %s (%u messages, %s buffers): %s\n", pset, tv->name,
           tv->nmessages, offset ? "unaligned" : "aligned",
           errors ? "FAIL" : "OK");
    return errors;
}

/*************************************************
 * Name:        test_mldsa_api
 *
 * Description: Check the internal, context string and signed message APIs
 *              with the first message of a vector set, whose keys are in
 *              pk_buf and sk_buf.
 *
 * Returns the number of errors
 **************************************************/
static int test_mldsa_api(const mldsa_impl_t *impl, const mldsa_kat_t *tv)
{
    static const uint8_t ctx[] = {'P', 'Q', 'R', 'V'};
    static const uint8_t pre[2] = {0, 0};
    static const uint8_t rnd[PQRV_MLDSA_RNDBYTES] = {0};
    uint8_t *m = msg_buf;
    size_t siglen, smlen, mlen;
    const unsigned int pset = impl->pset;
    int errors = 0;

    memset(m, 0, tv->message_size);
    memcpy(m, tv->messages[0], MSG_PREFIX_SIZE);

    /* Sign(m, ctx = "") = Sign_internal(0 || 0 || m, rnd = 0) */
    impl->signature(sig_buf, &siglen, m, tv->message_size, NULL, 0, sk_buf);
    impl->signature_internal(sig2_buf, &siglen, m, tv->message_size, pre,
                             sizeof(pre), rnd, sk_buf);
    errors += check(!memcmp(sig_buf, sig2_buf, impl->sig_bytes),
                    "internal signing API mismatch", pset, 0);
    errors += check(!impl->verify_internal(sig_buf, siglen, m,
                                           tv->message_size, pre, sizeof(pre),
                                           pk_buf),
                    "internal verification API failed", pset, 0);

    /* Non-empty context string */
    errors += check(!impl->signature(sig_buf, &siglen, m, tv->message_size,
                                     ctx, sizeof(ctx), sk_buf) &&
                        !impl->verify(sig_buf, siglen, m, tv->message_size,
                                      ctx, sizeof(ctx), pk_buf),
                    "signature with context string failed", pset, 0);
    errors += check(impl->verify(sig_buf, siglen, m, tv->message_size, NULL,
                                 0, pk_buf) == -1,
                    "signature verified with the wrong context string", pset,
                    0);

    /* Context strings are at most 255 bytes long */
    errors += check(impl->signature(sig_buf, &siglen, m, tv->message_size,
                                    msg_buf, 256, sk_buf) == -1 &&
                        impl->verify(sig_buf, siglen, m, tv->message_size,
                                     msg_buf, 256, pk_buf) == -1,
                    "context string longer than 255 bytes accepted", pset, 0);

    /* Signed message API */
    errors += check(!impl->sign(sm_buf, &smlen, m, SHORT_MSG_SIZE, ctx,
                                sizeof(ctx), sk_buf) &&
                        smlen == impl->sig_bytes + SHORT_MSG_SIZE &&
                        !impl->open(sm_buf, &mlen, sm_buf, smlen, ctx,
                                    sizeof(ctx), pk_buf) &&
                        mlen == SHORT_MSG_SIZE &&
                        !memcmp(sm_buf, m, SHORT_MSG_SIZE),
                    "signed message API failed", pset, 0);

    printf("ML-DSA-%u: internal, context string and signed message APIs: "
           "%s\n",
           pset, errors ? "FAIL" : "OK");
    return errors;
}

static int test_mldsa(const mldsa_impl_t *impl, const mldsa_kat_t *tv_short,
                      const mldsa_kat_t *tv_long)
{
    int errors = 0;

    errors += test_mldsa_kat(impl, tv_short, 0);
    errors += test_mldsa_kat(impl, tv_long, 1);
    /* Last, leaves the keys at offset 0 for test_mldsa_api */
    errors += test_mldsa_kat(impl, tv_long, 0);
    errors += test_mldsa_api(impl, tv_long);
    return errors;
}

int main(void)
{
    static const mldsa_impl_t mldsa44 = MLDSA_IMPL(44);
    static const mldsa_impl_t mldsa65 = MLDSA_IMPL(65);
    static const mldsa_impl_t mldsa87 = MLDSA_IMPL(87);
    const mldsa_kat_t mldsa44_short = MLDSA_KAT(mldsa44_m69_test_vectors);
    const mldsa_kat_t mldsa44_long = MLDSA_KAT(mldsa44_m10K_test_vectors);
    const mldsa_kat_t mldsa65_short = MLDSA_KAT(mldsa65_m69_test_vectors);
    const mldsa_kat_t mldsa65_long = MLDSA_KAT(mldsa65_m10K_test_vectors);
    const mldsa_kat_t mldsa87_short = MLDSA_KAT(mldsa87_m69_test_vectors);
    const mldsa_kat_t mldsa87_long = MLDSA_KAT(mldsa87_m10K_test_vectors);
    unsigned int i;
    int errors = 0;

    printf("libpqrv known-answer test\n");
    for (i = 0; i < sizeof(mlkem_impls) / sizeof(mlkem_impls[0]); i++)
        errors += test_mlkem(&mlkem_impls[i]);
    errors += test_mldsa(&mldsa44, &mldsa44_short, &mldsa44_long);
    errors += test_mldsa(&mldsa65, &mldsa65_short, &mldsa65_long);
    errors += test_mldsa(&mldsa87, &mldsa87_short, &mldsa87_long);
    printf("libpqrv: %s\n", errors ? "FAIL" : "PASS");

    return errors ? 1 : 0;
}
