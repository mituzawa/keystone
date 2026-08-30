/*
 * runner_main.c — PCCE TA runner eapp(段階1b: 平文埋め込みWasm)。
 *
 * examples/wasm_runner/embedded_wasm_main.c を出発点に、
 *  (1) "env"モジュールのnative import(query_attestation / riv_log)を登録し、
 *  (2) TA実行後に riv attester(rivリポジトリ attesters/keystone/eapp/
 *      attester.c を同一enclaveにリンク)のフレーム処理ループを回す。
 *
 * enclave測定値はrunner+埋め込みWasm+eyrieを一体で覆う(段階1)。
 * 段階2で埋め込みを廃し、暗号化TAのhost経由ロード+Hash束縛に移行する
 * (rivリポジトリ doc/design/wasm-ta.md)。
 *
 * TAにはKeystone API(ocall等)を直接importさせない。これにより
 * wasi-sdkリンク時に --allow-undefined が不要になり、import漏れを
 * リンク時に検出できる。
 */
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "wasm_export.h"

#include "app/syscall.h"
#include "edge/edge_common.h"

#include "eapp/attester.h"
#include "eapp/ocall_ids.h"

extern const unsigned char embedded_wasm[];
extern const unsigned int embedded_wasm_len;

#define WASM_STACK_SIZE (64 * 1024)
#define WASM_HEAP_SIZE  (64 * 1024)
#define WAMR_GLOBAL_HEAP_SIZE (4 * 1024 * 1024)

static uint8_t wamr_global_heap[WAMR_GLOBAL_HEAP_SIZE]
    __attribute__((aligned(8)));

/* ---- "env" native imports ----
 * シグネチャの '*~' はWAMRがWasm線形メモリのアドレス検証と
 * ネイティブポインタ変換を行う(バッファ+長さの組)。 */

/* i32 query_attestation(u8* req, u32 req_len, u8* resp, u32 resp_cap)
 * 段階1スタブ: 固定の応答を返す。段階3でOCALL_AR_EXCHANGE経由の
 * Verifier署名付きAttestation Result取得に置き換える。 */
static int32_t
native_query_attestation(wasm_exec_env_t exec_env,
                         uint8_t *req, uint32_t req_len,
                         uint8_t *resp, uint32_t resp_cap)
{
    static const char stub[] = "stub:verdict=unknown(stage1)";
    uint32_t n = (uint32_t)sizeof(stub) - 1;

    (void)exec_env;
    (void)req;
    (void)req_len;
    if (resp_cap < n)
        return -1;
    memcpy(resp, stub, n);
    return (int32_t)n;
}

/* void riv_log(const char* msg) — デバッグ出力(hostのコンソールへ) */
static void
native_riv_log(wasm_exec_env_t exec_env, const char *msg)
{
    (void)exec_env;
    printf("[TA] %s\n", msg ? msg : "(null)");
}

static NativeSymbol native_symbols[] = {
    { "query_attestation", native_query_attestation, "(*~*~)i", NULL },
    { "riv_log", native_riv_log, "($)", NULL },
};

/* ---- riv attesterフレーム処理ループ(hostのRECV/SEND_FRAME対向) ---- */

static uint8_t rxbuf[RIV_KEYSTONE_MAX_FRAME];
static uint8_t txbuf[RIV_KEYSTONE_MAX_FRAME];

static void serve_attestation(void)
{
    printf("pcce-ta runner: attester serving\n");
    for (;;) {
        struct edge_data retdata;
        unsigned long ret;
        int len;

        retdata.offset = 0;
        retdata.size = 0;
        ocall(OCALL_RECV_FRAME, 0, 0, &retdata, sizeof(retdata));
        if (retdata.size == 0)
            break;
        if (retdata.size > sizeof(rxbuf) || retdata.size < 1)
            continue;
        copy_from_shared(rxbuf, retdata.offset, retdata.size);

        /* 段階1: TAは埋め込み(測定値に含まれる)のためnonceのみ束縛。
         * 段階2でta_hash/P_devを渡す96Bレイアウトへ移行する。 */
        len = riv_keystone_handle_frame(rxbuf[0], rxbuf + 1,
                                        retdata.size - 1,
                                        txbuf, sizeof(txbuf), 0, 0);
        if (len > 0)
            ocall(OCALL_SEND_FRAME, txbuf, (size_t)len, &ret,
                  sizeof(ret));
    }
}

int main(int argc, char **argv)
{
    RuntimeInitArgs init_args;
    wasm_module_t module = NULL;
    wasm_module_inst_t module_inst = NULL;
    char error_buf[128];
    int ret = 1;

    printf("pcce-ta runner: embedded wasm %u bytes\n", embedded_wasm_len);

    memset(&init_args, 0, sizeof(init_args));
    /* enclave内ではOSのアロケータに依存しない固定プールを使う */
    init_args.mem_alloc_type = Alloc_With_Pool;
    init_args.mem_alloc_option.pool.heap_buf = wamr_global_heap;
    init_args.mem_alloc_option.pool.heap_size = sizeof(wamr_global_heap);

    if (!wasm_runtime_full_init(&init_args)) {
        fprintf(stderr, "wasm_runtime_full_init failed\n");
        return 1;
    }

    if (!wasm_runtime_register_natives("env", native_symbols,
                                       sizeof(native_symbols) /
                                           sizeof(native_symbols[0]))) {
        fprintf(stderr, "wasm_runtime_register_natives failed\n");
        goto cleanup_runtime;
    }

    module = wasm_runtime_load((uint8_t *)embedded_wasm,
                               (uint32_t)embedded_wasm_len,
                               error_buf, sizeof(error_buf));
    if (!module) {
        fprintf(stderr, "wasm_runtime_load failed: %s\n", error_buf);
        goto cleanup_runtime;
    }

    wasm_runtime_set_wasi_args(module, NULL, 0, NULL, 0, NULL, 0,
                               argv, argc);

    module_inst = wasm_runtime_instantiate(module, WASM_STACK_SIZE,
                                           WASM_HEAP_SIZE, error_buf,
                                           sizeof(error_buf));
    if (!module_inst) {
        fprintf(stderr, "wasm_runtime_instantiate failed: %s\n", error_buf);
        goto cleanup_module;
    }

    if (!wasm_application_execute_main(module_inst, argc, argv)) {
        const char *exception = wasm_runtime_get_exception(module_inst);

        fprintf(stderr, "wasm execution failed: %s\n",
                exception ? exception : "(no exception)");
        goto cleanup_instance;
    }
    ret = 0;

    /* TA実行後、同一enclaveのriv attesterとしてVerifierに応答する */
    serve_attestation();

cleanup_instance:
    wasm_runtime_deinstantiate(module_inst);
cleanup_module:
    wasm_runtime_unload(module);
cleanup_runtime:
    wasm_runtime_destroy();
    return ret;
}
