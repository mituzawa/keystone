/* sealed_state.c — 封印状態の読み書き。sealed_state.h参照 */
#include "sealed_state.h"

#include <stdio.h>
#include <string.h>

#include "app/sealing.h"
#include "app/syscall.h"
#include "edge/edge_common.h"

#include "eapp/ocall_ids.h"
#include <riv/riv_crypto.h>

#include "drbg.h"

#define KEK_IDENT      "riv:ta-kek:v1"
#define ROLLBACK_IDENT "riv:rollback:v1"

int riv_sealing_key32(const char *key_ident, uint8_t out[32])
{
    struct sealing_key skey;
    int rc;

    memset(&skey, 0, sizeof(skey));
    rc = get_sealing_key(&skey, sizeof(skey), (void *)key_ident,
                         strlen(key_ident));
    if (rc == 0)
        memcpy(out, skey.key, 32);
    memset(&skey, 0, sizeof(skey)); /* 残りと署名は使わない */
    return rc == 0 ? 0 : -1;
}

int riv_host_state_load(uint16_t kind, uint8_t *buf, size_t cap, size_t *len)
{
    struct riv_state_req req = { kind, 0 };
    struct edge_data retdata;

    retdata.offset = 0;
    retdata.size = 0;
    if (ocall(OCALL_STATE_LOAD, &req, sizeof(req), &retdata,
              sizeof(retdata)) != 0)
        return -1;
    if (retdata.size > cap)
        return -1;
    if (retdata.size)
        copy_from_shared(buf, retdata.offset, retdata.size);
    *len = retdata.size;
    return 0;
}

int riv_host_state_store(uint16_t kind, const uint8_t *blob, size_t len)
{
    uint8_t msg[sizeof(struct riv_state_req) + 256];
    struct riv_state_req req = { kind, 0 };
    unsigned long ok = 0;

    if (len > sizeof(msg) - sizeof(req))
        return -1;
    memcpy(msg, &req, sizeof(req));
    memcpy(msg + sizeof(req), blob, len);
    if (ocall(OCALL_STATE_STORE, msg, sizeof(req) + len, &ok,
              sizeof(ok)) != 0 || ok != 1)
        return -1;
    return 0;
}

int riv_dev_key_setup(uint8_t sk_dev[32], uint8_t pk_dev[32])
{
    uint8_t kek[32], iv[RIV_SEAL_IV_LEN];
    uint8_t blob[32 + RIV_SEAL_OVERHEAD + 64];
    size_t blob_len = 0, pt_len = 0;
    int rc = -1;

    if (riv_sealing_key32(KEK_IDENT, kek) != 0)
        return -1;
    if (riv_host_state_load(RIV_SEAL_KIND_DEV_KEY, blob, sizeof(blob),
                            &blob_len) != 0)
        goto out;

    if (blob_len > 0) {
        if (riv_unseal(kek, RIV_SEAL_KIND_DEV_KEY, blob, blob_len, sk_dev, 32,
                       &pt_len) != 0 || pt_len != 32) {
            rc = -2;
            goto out;
        }
        rc = 0;
    } else {
        /* 初回プロビジョニング: enclave内生成 → 封印 → hostへ保存 */
        if (riv_drbg_random(sk_dev, 32) != 0 ||
            riv_drbg_random(iv, sizeof(iv)) != 0)
            goto out;
        sk_dev[0] &= 248; /* X25519 clamp */
        sk_dev[31] &= 127;
        sk_dev[31] |= 64;
        if (riv_seal(kek, RIV_SEAL_KIND_DEV_KEY, iv, sk_dev, 32, blob,
                     sizeof(blob), &blob_len) != 0)
            goto out;
        if (riv_host_state_store(RIV_SEAL_KIND_DEV_KEY, blob, blob_len) != 0) {
            rc = -3;
            goto out;
        }
        rc = 1;
    }
    if (riv_x25519_pubkey(sk_dev, pk_dev) != 0)
        rc = -1;
out:
    memset(kek, 0, sizeof(kek));
    memset(blob, 0, sizeof(blob));
    if (rc < 0)
        memset(sk_dev, 0, 32);
    return rc;
}

int riv_rollback_load(uint32_t *max_fw)
{
    uint8_t key[32], blob[4 + RIV_SEAL_OVERHEAD + 64], pt[4];
    size_t blob_len = 0, pt_len = 0;
    int rc = -1;

    *max_fw = 0;
    if (riv_sealing_key32(ROLLBACK_IDENT, key) != 0)
        return -1;
    if (riv_host_state_load(RIV_SEAL_KIND_ROLLBACK, blob, sizeof(blob),
                            &blob_len) != 0)
        goto out;
    if (blob_len == 0) {
        rc = 0; /* 状態なし(初回、またはhostが削除した=best effortの限界) */
        goto out;
    }
    if (riv_unseal(key, RIV_SEAL_KIND_ROLLBACK, blob, blob_len, pt,
                   sizeof(pt), &pt_len) != 0 || pt_len != 4) {
        rc = -2;
        goto out;
    }
    *max_fw = ((uint32_t)pt[0] << 24) | ((uint32_t)pt[1] << 16) |
              ((uint32_t)pt[2] << 8) | pt[3];
    rc = 0;
out:
    memset(key, 0, sizeof(key));
    return rc;
}

int riv_rollback_store(uint32_t max_fw)
{
    uint8_t key[32], iv[RIV_SEAL_IV_LEN], pt[4];
    uint8_t blob[4 + RIV_SEAL_OVERHEAD];
    size_t blob_len = 0;
    int rc = -1;

    if (riv_sealing_key32(ROLLBACK_IDENT, key) != 0)
        return -1;
    pt[0] = (uint8_t)(max_fw >> 24);
    pt[1] = (uint8_t)(max_fw >> 16);
    pt[2] = (uint8_t)(max_fw >> 8);
    pt[3] = (uint8_t)max_fw;
    if (riv_drbg_random(iv, sizeof(iv)) == 0 &&
        riv_seal(key, RIV_SEAL_KIND_ROLLBACK, iv, pt, sizeof(pt), blob,
                 sizeof(blob), &blob_len) == 0 &&
        riv_host_state_store(RIV_SEAL_KIND_ROLLBACK, blob, blob_len) == 0)
        rc = 0;
    memset(key, 0, sizeof(key));
    return rc;
}
