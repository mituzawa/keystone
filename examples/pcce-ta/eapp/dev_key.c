/* dev_key.c — sealing keyからのsk_dev/pk_dev決定論的導出(段階2暫定) */
#include "dev_key.h"

#include <string.h>

#include <openssl/evp.h>

#include "app/sealing.h"
#include "app/syscall.h"

#define DEV_KEY_IDENT "riv:ta-x25519-seed:v1"

int riv_derive_dev_key(uint8_t sk_dev[32], uint8_t pk_dev[32])
{
    struct sealing_key skey;
    EVP_PKEY *pkey;
    size_t plen = 32;
    int rc = -1;

    memset(&skey, 0, sizeof(skey));
    if (get_sealing_key(&skey, sizeof(skey), (void *)DEV_KEY_IDENT,
                        strlen(DEV_KEY_IDENT)) != 0)
        return -1;

    memcpy(sk_dev, skey.key, 32);
    memset(&skey, 0, sizeof(skey)); /* 128B鍵の残りと署名は使わない */

    /* X25519 clamp(導出の決定論性を明示するため自前でも行う) */
    sk_dev[0] &= 248;
    sk_dev[31] &= 127;
    sk_dev[31] |= 64;

    pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, sk_dev, 32);
    if (pkey && EVP_PKEY_get_raw_public_key(pkey, pk_dev, &plen) > 0 &&
        plen == 32)
        rc = 0;
    EVP_PKEY_free(pkey);
    return rc;
}
