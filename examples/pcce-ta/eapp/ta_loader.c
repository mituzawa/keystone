/*
 * ta_loader.c — 暗号化TA(ta.enc)のhost経由チャンクロード。
 *
 * 設計: rivリポジトリ doc/design/wasm-ta.md「シーケンス(A) TAロード」。
 * hostは信頼しない給仕役。必ず copy_from_shared() でenclave内バッファへ
 * コピーしてから検証・復号する(共有バッファ上のデータをhostが後から
 * 書き換えるTOCTOUの排除)。検証チェーン本体は riv/riv_ta.h の
 * riv_ta_verify_decrypt()(rivのcommon/src/riv_ta_verify.c、
 * staging libcrypto.aとともにリンク)。
 */
#include "ta_loader.h"

#include <stdio.h>
#include <string.h>

#include "app/syscall.h"
#include "edge/edge_common.h"

#include "eapp/ocall_ids.h"
#include <riv/riv_ta.h>

/* ta.enc全体を受けるenclave内バッファ(暗号文なので秘匿不要だが、
 * 検証対象はこのコピーに固定する) */
static uint8_t ta_enc[RIV_TA_ENC_MAX];

int riv_ta_load_from_host(const uint8_t pk_ta[64], const uint8_t sk_dev[32],
                          uint32_t fw_version_min,
                          uint8_t *plain, size_t plain_cap,
                          size_t *plain_len, uint8_t ta_hash[32],
                          uint32_t *fw_version)
{
    uint64_t total = 0;
    uint64_t off;
    int rc;

    if (ocall(OCALL_TA_INFO, 0, 0, &total, sizeof(total)) != 0)
        return -RIV_TA_ERR_INTERNAL;
    if (total == 0)
        return 1; /* プロビジョニングモード */
    if (total > sizeof(ta_enc)) {
        printf("ta: ta.encが大きすぎる (%lu > %lu)\n",
               (unsigned long)total, (unsigned long)sizeof(ta_enc));
        return -RIV_TA_ERR_SYNTAX;
    }

    for (off = 0; off < total;) {
        struct riv_ta_chunk_req req;
        struct edge_data retdata;

        req.offset = off;
        req.len = total - off;
        if (req.len > RIV_TA_CHUNK_LEN)
            req.len = RIV_TA_CHUNK_LEN;
        retdata.offset = 0;
        retdata.size = 0;
        if (ocall(OCALL_TA_CHUNK, &req, sizeof(req), &retdata,
                  sizeof(retdata)) != 0 ||
            retdata.size == 0 || retdata.size > req.len) {
            printf("ta: チャンク取得に失敗 (offset=%lu)\n",
                   (unsigned long)off);
            return -RIV_TA_ERR_INTERNAL;
        }
        copy_from_shared(ta_enc + off, retdata.offset, retdata.size);
        off += retdata.size;
    }

    rc = riv_ta_verify_decrypt(ta_enc, (size_t)total, pk_ta, sk_dev,
                               fw_version_min, plain, plain_cap, plain_len,
                               ta_hash, fw_version);
    if (rc != RIV_TA_OK)
        return -rc;
    return 0;
}
