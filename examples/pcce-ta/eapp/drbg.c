/* drbg.c — sealing key由来のenclave内DRBG。drbg.h参照 */
#include "drbg.h"

#include <string.h>
#include <sys/random.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>

#include "app/sealing.h"
#include "app/syscall.h"

#define DRBG_KEY_IDENT "riv:drbg:v1"
#define DRBG_SEED_INFO "riv-drbg-seed-v1"
#define DRBG_OUT_INFO  "riv-drbg-out-v1"

static uint8_t drbg_seed[32];
static uint64_t drbg_counter;
static int drbg_ready;

int riv_drbg_init(void)
{
    struct sealing_key skey;
    uint8_t fresh[32];
    EVP_PKEY_CTX *ctx = NULL;
    size_t len = sizeof(drbg_seed);
    int rc = -1;

    memset(&skey, 0, sizeof(skey));
    if (get_sealing_key(&skey, sizeof(skey), (void *)DRBG_KEY_IDENT,
                        strlen(DRBG_KEY_IDENT)) != 0)
        return -1;
    /* eyrie→SM(sbi_random)。Linux非経由。失敗時は0埋め(秘密性は
     * sealing keyが担い、新鮮さだけが落ちる)を許容せず初期化失敗にする */
    if (getrandom(fresh, sizeof(fresh), 0) != (ssize_t)sizeof(fresh))
        goto out;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!ctx || EVP_PKEY_derive_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(ctx, fresh, (int)sizeof(fresh)) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(ctx, skey.key, SEALING_KEY_SIZE) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(ctx, (const unsigned char *)DRBG_SEED_INFO,
                                    (int)strlen(DRBG_SEED_INFO)) <= 0 ||
        EVP_PKEY_derive(ctx, drbg_seed, &len) <= 0 || len != sizeof(drbg_seed))
        goto out;
    drbg_counter = 0;
    drbg_ready = 1;
    rc = 0;
out:
    EVP_PKEY_CTX_free(ctx);
    memset(&skey, 0, sizeof(skey));
    memset(fresh, 0, sizeof(fresh));
    return rc;
}

int riv_drbg_random(uint8_t *out, size_t n)
{
    uint8_t block[32];
    uint8_t msg[8 + sizeof(DRBG_OUT_INFO) - 1];
    unsigned int blen;
    size_t i;

    if (!drbg_ready)
        return -1;
    memcpy(msg + 8, DRBG_OUT_INFO, sizeof(DRBG_OUT_INFO) - 1);
    while (n > 0) {
        size_t take = n < sizeof(block) ? n : sizeof(block);

        for (i = 0; i < 8; i++)
            msg[i] = (uint8_t)(drbg_counter >> (56 - 8 * i));
        drbg_counter++;
        blen = sizeof(block);
        if (!HMAC(EVP_sha256(), drbg_seed, sizeof(drbg_seed), msg,
                  sizeof(msg), block, &blen) || blen != sizeof(block))
            return -1;
        memcpy(out, block, take);
        out += take;
        n -= take;
    }
    memset(block, 0, sizeof(block));
    return 0;
}
