/*
 * ta_main.c — PCCE TA本体(C言語)。wasi-sdkで wasm32-wasip1 にコンパイル
 * され、pcce-ta runner(enclave内WAMR)で実行される。
 *
 * TAはKeystoneのAPI(ocall / attest_enclave等)を直接importしない。
 * runnerが"env"モジュールとして提供する意味論の高いimportだけを使う
 * (rivリポジトリ doc/design/wasm-ta.md「Wasm importブリッジ」)。
 *
 * 段階3: TA=Relying Partyとして、Verifierの署名付きAttestation Result(AR)を
 * 取得し自分で検証する(rivリポジトリ doc/design/pcce-mapping.md
 * 「実装上の含意」)。
 *   nonce_ta = get_random(32)              … runnerのsealing key由来DRBG
 *   AR_REQ{nonce_ta} → query_attestation → AR_RESP(Verifier署名付き)
 *   nonce_ta一致(再生排除) + ecdsa_p256_verify(pk_ar焼き込み, TBS, sig)
 * rivのプロトコル実装(riv_proto.c)をWasmに直接コンパイルインして
 * フレーム/TLVを扱う(依存最小Cの効能)。署名検証の数学だけはrunnerの
 * importを借りる(鍵はこのイメージ内の pk_ar_embedded)。
 */
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <riv/riv_proto.h>

#include "pk_ar_test.h"

__attribute__((import_module("env"), import_name("query_attestation")))
int32_t query_attestation(const uint8_t *req, uint32_t req_len,
                          uint8_t *resp, uint32_t resp_cap);

__attribute__((import_module("env"), import_name("riv_log")))
void riv_log(const char *msg);

__attribute__((import_module("env"), import_name("get_random")))
int32_t get_random(uint8_t *buf, uint32_t len);

__attribute__((import_module("env"), import_name("ecdsa_p256_verify")))
int32_t ecdsa_p256_verify(const uint8_t *pk, uint32_t pk_len,
                          const uint8_t *msg, uint32_t msg_len,
                          const uint8_t *sig, uint32_t sig_len);

static void print_hex(const uint8_t *p, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++)
        printf("%02x", p[i]);
}

int main(void)
{
    uint8_t nonce_ta[RIV_NONCE_LEN];
    uint8_t frame[64], resp[512], tbs[RIV_AR_TBS_LEN];
    riv_ar_req req;
    riv_ar_resp ar;
    uint8_t msg_type = 0;
    uint32_t plen = 0;
    int32_t n, len;

    riv_log("pcce-ta: TA (wasm) started");

    if (get_random(nonce_ta, sizeof(nonce_ta)) != 0) {
        printf("pcce-ta: get_random failed\n");
        return 0;
    }
    req.nonce = nonce_ta;
    len = riv_build_ar_req(frame, sizeof(frame), &req);
    if (len < 0) {
        printf("pcce-ta: AR_REQ build failed\n");
        return 0;
    }

    n = query_attestation(frame, (uint32_t)len, resp, sizeof(resp));
    if (n < 0) {
        printf("pcce-ta: query_attestation unavailable (%d)\n", (int)n);
        riv_log("pcce-ta: TA (wasm) done");
        return 0;
    }
    if (n < RIV_HDR_LEN || riv_hdr_parse(resp, &msg_type, &plen) < 0 ||
        (uint32_t)n != RIV_HDR_LEN + plen) {
        printf("pcce-ta: AR応答のフレームが不正\n");
        return 0;
    }
    if (msg_type == RIV_MSG_ERROR) {
        uint16_t code = 0;
        const char *m = NULL;
        size_t mlen = 0;

        riv_parse_error(resp + RIV_HDR_LEN, plen, &code, &m, &mlen);
        printf("pcce-ta: Verifierがエラー応答 code=%u %.*s\n", code, (int)mlen,
               m ? m : "");
        return 0;
    }
    if (msg_type != RIV_MSG_AR_RESP ||
        riv_parse_ar_resp(resp + RIV_HDR_LEN, plen, &ar) < 0) {
        printf("pcce-ta: AR_RESPが不正\n");
        return 0;
    }

    /* 再生排除: 自分が出したnonce_taと一致すること */
    if (memcmp(ar.nonce, nonce_ta, RIV_NONCE_LEN) != 0) {
        printf("pcce-ta: AR拒否 (nonce不一致)\n");
        return 0;
    }
    /* 真正性: 焼き込みpk_arでVerifier署名を検証(TBSは正規化配置) */
    riv_ar_tbs(ar.verdict, ar.nonce, ar.ta_hash, ar.timestamp, tbs);
    if (ecdsa_p256_verify(pk_ar_embedded, sizeof(pk_ar_embedded), tbs,
                          sizeof(tbs), ar.sig, (uint32_t)ar.sig_len) != 1) {
        printf("pcce-ta: AR拒否 (署名不正)\n");
        return 0;
    }
    printf("pcce-ta: AR検証OK verdict=%s ta_hash=",
           ar.verdict == RIV_AR_PASS ? "PASS" : "FAIL");
    print_hex(ar.ta_hash, 32);
    printf(" timestamp=%" PRIu64 "\n", ar.timestamp);

    riv_log("pcce-ta: TA (wasm) done");
    return 0;
}
