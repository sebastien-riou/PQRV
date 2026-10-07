#ifndef PQRV_H
#define PQRV_H

/*
 * libpqrv: ML-KEM (FIPS 203) and ML-DSA (FIPS 204) optimized for RV32 (see
 * the PQRV README for how to build the library).
 *
 * All parameter sets are available and can be used together:
 *   - pqrv_mlkem512_*, pqrv_mlkem768_*, pqrv_mlkem1024_*
 *   - pqrv_mldsa44_*, pqrv_mldsa65_*, pqrv_mldsa87_*
 * Keys, ciphertexts and signatures are byte strings encoded as specified by
 * FIPS 203 and FIPS 204. Buffers can have any alignment.
 *
 * Randomness: the functions which do not take their randomness as an argument
 * (pqrv_mlkemNNN_keypair, pqrv_mlkemNNN_enc and pqrv_mldsaNN_keypair) call
 *   void randombytes(uint8_t *out, size_t outlen);
 * which the application must provide. It is not needed if these functions
 * are not used and the application is linked with --gc-sections.
 *
 * Stack usage (measured with crypto-benchmark on RV32IMC): up to 10 KB,
 * 16 KB and 22 KB for ML-KEM-512/768/1024. ML-DSA keeps the expanded matrix
 * on the stack: signing needs up to 53 KB, 81 KB and 124 KB for
 * ML-DSA-44/65/87.
 *
 * The assembly routines use the gp and tp registers as scratch registers
 * (saved and restored): interrupt handlers running during a call must not rely
 * on gp (link with --no-relax-gp) nor tp.
 */

#include <stddef.h>
#include <stdint.h>

/* ML-KEM (FIPS 203) */
#define PQRV_MLKEM_SSBYTES 32
#define PQRV_MLKEM_KEYPAIRCOINBYTES 64 /* d || z */
#define PQRV_MLKEM_ENCCOINBYTES 32     /* m */

#define PQRV_MLKEM512_PUBLICKEYBYTES 800
#define PQRV_MLKEM512_SECRETKEYBYTES 1632
#define PQRV_MLKEM512_CIPHERTEXTBYTES 768

#define PQRV_MLKEM768_PUBLICKEYBYTES 1184
#define PQRV_MLKEM768_SECRETKEYBYTES 2400
#define PQRV_MLKEM768_CIPHERTEXTBYTES 1088

#define PQRV_MLKEM1024_PUBLICKEYBYTES 1568
#define PQRV_MLKEM1024_SECRETKEYBYTES 3168
#define PQRV_MLKEM1024_CIPHERTEXTBYTES 1568

/*
 * For each parameter set NNN:
 *
 * int pqrv_mlkemNNN_keypair_derand(uint8_t *pk, uint8_t *sk,
 *                                  const uint8_t *coins);
 *   ML-KEM.KeyGen_internal: key pair from coins = d || z
 *   (PQRV_MLKEM_KEYPAIRCOINBYTES bytes). Returns 0.
 * int pqrv_mlkemNNN_keypair(uint8_t *pk, uint8_t *sk);
 *   ML-KEM.KeyGen: same with coins from randombytes. Returns 0.
 * int pqrv_mlkemNNN_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk,
 *                              const uint8_t *coins);
 *   ML-KEM.Encaps_internal: encapsulation with coins = m
 *   (PQRV_MLKEM_ENCCOINBYTES bytes). Returns 0.
 * int pqrv_mlkemNNN_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
 *   Same with m from randombytes. Returns 0.
 * int pqrv_mlkemNNN_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
 *   ML-KEM.Decaps_internal, with implicit rejection. Returns 0.
 * int pqrv_mlkemNNN_check_pk(const uint8_t *pk);
 * int pqrv_mlkemNNN_check_sk(const uint8_t *sk);
 *   Input checking of FIPS 203 (modulus check of the encapsulation key,
 *   hash check of the decapsulation key). Return 0 if the check passes and
 *   -1 otherwise. ML-KEM.Encaps and ML-KEM.Decaps require these checks
 *   (once per key is enough), the functions above do not perform them.
 */
#define PQRV_MLKEM_API(NNN)                                              \
    int pqrv_mlkem##NNN##_keypair_derand(uint8_t *pk, uint8_t *sk,       \
                                         const uint8_t *coins);          \
    int pqrv_mlkem##NNN##_keypair(uint8_t *pk, uint8_t *sk);             \
    int pqrv_mlkem##NNN##_enc_derand(uint8_t *ct, uint8_t *ss,           \
                                     const uint8_t *pk,                  \
                                     const uint8_t *coins);              \
    int pqrv_mlkem##NNN##_enc(uint8_t *ct, uint8_t *ss,                  \
                              const uint8_t *pk);                        \
    int pqrv_mlkem##NNN##_dec(uint8_t *ss, const uint8_t *ct,            \
                              const uint8_t *sk);                        \
    int pqrv_mlkem##NNN##_check_pk(const uint8_t *pk);                   \
    int pqrv_mlkem##NNN##_check_sk(const uint8_t *sk);

PQRV_MLKEM_API(512)
PQRV_MLKEM_API(768)
PQRV_MLKEM_API(1024)

/* ML-DSA (FIPS 204) */
#define PQRV_MLDSA_SEEDBYTES 32 /* xi */
#define PQRV_MLDSA_RNDBYTES 32

#define PQRV_MLDSA44_PUBLICKEYBYTES 1312
#define PQRV_MLDSA44_SECRETKEYBYTES 2560
#define PQRV_MLDSA44_BYTES 2420

#define PQRV_MLDSA65_PUBLICKEYBYTES 1952
#define PQRV_MLDSA65_SECRETKEYBYTES 4032
#define PQRV_MLDSA65_BYTES 3309

#define PQRV_MLDSA87_PUBLICKEYBYTES 2592
#define PQRV_MLDSA87_SECRETKEYBYTES 4896
#define PQRV_MLDSA87_BYTES 4627

/*
 * For each parameter set NN:
 *
 * int pqrv_mldsaNN_keypair_internal(uint8_t *pk, uint8_t *sk,
 *                                   const uint8_t *seed);
 *   ML-DSA.KeyGen_internal: key pair from seed = xi
 *   (PQRV_MLDSA_SEEDBYTES bytes). Returns 0.
 * int pqrv_mldsaNN_keypair(uint8_t *pk, uint8_t *sk);
 *   ML-DSA.KeyGen: same with xi from randombytes. Returns 0.
 * int pqrv_mldsaNN_signature(uint8_t *sig, size_t *siglen,
 *                            const uint8_t *m, size_t mlen,
 *                            const uint8_t *ctx, size_t ctxlen,
 *                            const uint8_t *sk);
 *   ML-DSA.Sign, deterministic variant (rnd = 0), with a context string of
 *   at most 255 bytes. Returns 0, or -1 if the context string is too long.
 *   For the hedged variant, use pqrv_mldsaNN_signature_internal with
 *   pre = 0 || ctxlen || ctx and a random rnd.
 * int pqrv_mldsaNN_signature_internal(uint8_t *sig, size_t *siglen,
 *                                     const uint8_t *m, size_t mlen,
 *                                     const uint8_t *pre, size_t prelen,
 *                                     const uint8_t *rnd,
 *                                     const uint8_t *sk);
 *   ML-DSA.Sign_internal of the message pre || m with randomness rnd
 *   (PQRV_MLDSA_RNDBYTES bytes). Returns 0.
 * int pqrv_mldsaNN_sign(uint8_t *sm, size_t *smlen,
 *                       const uint8_t *m, size_t mlen,
 *                       const uint8_t *ctx, size_t ctxlen,
 *                       const uint8_t *sk);
 *   Signed message sm = sig || m, as pqrv_mldsaNN_signature.
 * int pqrv_mldsaNN_verify(const uint8_t *sig, size_t siglen,
 *                         const uint8_t *m, size_t mlen,
 *                         const uint8_t *ctx, size_t ctxlen,
 *                         const uint8_t *pk);
 *   ML-DSA.Verify. Returns 0 if the signature is valid and -1 otherwise.
 * int pqrv_mldsaNN_verify_internal(const uint8_t *sig, size_t siglen,
 *                                  const uint8_t *m, size_t mlen,
 *                                  const uint8_t *pre, size_t prelen,
 *                                  const uint8_t *pk);
 *   ML-DSA.Verify_internal of the message pre || m.
 * int pqrv_mldsaNN_open(uint8_t *m, size_t *mlen,
 *                       const uint8_t *sm, size_t smlen,
 *                       const uint8_t *ctx, size_t ctxlen,
 *                       const uint8_t *pk);
 *   Verify a signed message and extract the message.
 */
#define PQRV_MLDSA_API(NN)                                                  \
    int pqrv_mldsa##NN##_keypair_internal(uint8_t *pk, uint8_t *sk,         \
                                          const uint8_t *seed);             \
    int pqrv_mldsa##NN##_keypair(uint8_t *pk, uint8_t *sk);                 \
    int pqrv_mldsa##NN##_signature(uint8_t *sig, size_t *siglen,            \
                                   const uint8_t *m, size_t mlen,           \
                                   const uint8_t *ctx, size_t ctxlen,       \
                                   const uint8_t *sk);                      \
    int pqrv_mldsa##NN##_signature_internal(                                \
        uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,        \
        const uint8_t *pre, size_t prelen, const uint8_t *rnd,              \
        const uint8_t *sk);                                                 \
    int pqrv_mldsa##NN##_sign(uint8_t *sm, size_t *smlen, const uint8_t *m, \
                              size_t mlen, const uint8_t *ctx,              \
                              size_t ctxlen, const uint8_t *sk);            \
    int pqrv_mldsa##NN##_verify(const uint8_t *sig, size_t siglen,          \
                                const uint8_t *m, size_t mlen,              \
                                const uint8_t *ctx, size_t ctxlen,          \
                                const uint8_t *pk);                         \
    int pqrv_mldsa##NN##_verify_internal(                                   \
        const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,   \
        const uint8_t *pre, size_t prelen, const uint8_t *pk);              \
    int pqrv_mldsa##NN##_open(uint8_t *m, size_t *mlen, const uint8_t *sm,  \
                              size_t smlen, const uint8_t *ctx,             \
                              size_t ctxlen, const uint8_t *pk);

PQRV_MLDSA_API(44)
PQRV_MLDSA_API(65)
PQRV_MLDSA_API(87)

#endif
