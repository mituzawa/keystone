/*
 * ta_main.c — PCCE TA本体(C言語)。wasi-sdkで wasm32-wasip1 にコンパイル
 * され、pcce-ta runner(enclave内WAMR)で実行される。
 *
 * TAはKeystoneのAPI(ocall / attest_enclave等)を直接importしない。
 * runnerが"env"モジュールとして提供する意味論の高いimportだけを使う
 * (rivリポジトリ doc/design/wasm-ta.md「Wasm importブリッジ」)。
 *
 * 段階1: query_attestationはrunner側スタブ。段階3でVerifier署名付き
 * Attestation Resultの検証(焼き込み公開鍵+nonce束縛)が入る。
 */
#include <stdint.h>
#include <stdio.h>

__attribute__((import_module("env"), import_name("query_attestation")))
int32_t query_attestation(const uint8_t *req, uint32_t req_len,
                          uint8_t *resp, uint32_t resp_cap);

__attribute__((import_module("env"), import_name("riv_log")))
void riv_log(const char *msg);

int main(void)
{
    uint8_t resp[256];
    static const uint8_t req[] = "attest?";
    int32_t n;

    riv_log("pcce-ta: TA (wasm) started");

    n = query_attestation(req, sizeof(req) - 1, resp, sizeof(resp));
    if (n > 0 && (uint32_t)n <= sizeof(resp))
        printf("pcce-ta: query_attestation -> %.*s\n", (int)n, resp);
    else
        printf("pcce-ta: query_attestation failed (%d)\n", (int)n);

    riv_log("pcce-ta: TA (wasm) done");
    return 0;
}
