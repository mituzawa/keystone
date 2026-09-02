/*
 * runner_main.c — PCCE TA runner eapp(段階3: プロビジョニング+AR本実装)。
 *
 * examples/wasm_runner/embedded_wasm_main.c を出発点に、
 *  (1) sealing key由来DRBG(drbg.c)を初期化し、デバイスTA復号鍵ペア
 *      sk_dev/pk_devを sealed blob から復号(無ければenclave内で生成して
 *      封印しhostへ保存=初回プロビジョニング。sealed_state.c)、
 *  (2) 暗号化TA(ta.enc)をhostからチャンクロードしてenclave内で
 *      検証・復号し(ta_loader.c、検証チェーンはrivのriv_ta_verify.c。
 *      アンチロールバック段は封印した既見最大fw_versionと比較)、
 *  (3) "env"モジュールのnative import(query_attestation / riv_log /
 *      get_random / ecdsa_p256_verify)を登録してTAを実行し、
 *  (4) TA実行後に riv attester(rivリポジトリ attesters/keystone/eapp/
 *      attester.c を同一enclaveにリンク)のフレーム処理ループを回す。
 *
 * enclave測定値はrunner+eyrieのみを覆い、TAには依存しない。TAは
 * report data(nonce ∥ ta_hash ∥ pk_dev の96B)へのHash束縛で
 * Evidenceに入る(rivリポジトリ doc/design/wasm-ta.md)。
 * ta.encが無い場合はプロビジョニングモード(ta_hash=全ゼロ)で
 * attestationのみ応答し、Verifierはpk_devを採取できる。
 *
 * query_attestation(TA→Verifier のAttestation Result要求)は
 * OCALL_AR_EXCHANGEでhostにVerifierのARサービスへ接続させ、Verifierが
 * 同一接続上で送ってくるATTEST_REQにはこの関数の中で応答する
 * (TA実行中はattesterループが回っていないため)。AR_RESPの署名検証は
 * TA側(焼き込みpk_ar)が行い、runnerはECDSA-P256の数学だけを
 * ecdsa_p256_verify importで貸す(TAにECCライブラリを持ち込まない)。
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
#include <riv/riv_crypto.h>
#include <riv/riv_proto.h>
#include <riv/riv_ta.h>

#include "drbg.h"
#include "pk_ta_test.h"
#include "sealed_state.h"
#include "ta_loader.h"

#define WASM_STACK_SIZE (64 * 1024)
#define WASM_HEAP_SIZE  (64 * 1024)
#define WAMR_GLOBAL_HEAP_SIZE (4 * 1024 * 1024)

static uint8_t wamr_global_heap[WAMR_GLOBAL_HEAP_SIZE]
    __attribute__((aligned(8)));

/* 復号済みTA。WAMRインタプリタは実行中もこのバッファを参照するため
 * 実行終了まで保持し、終了時にゼロ化する(平文はenclave外に出ない) */
static uint8_t ta_plain[RIV_TA_PLAIN_MAX] __attribute__((aligned(8)));

/* attestation応答に載せる値(TAロード後に確定。AR中継中も使う) */
static uint8_t g_ta_hash[32];
static uint8_t g_pk_dev[32];

static uint8_t rxbuf[RIV_KEYSTONE_MAX_FRAME];
static uint8_t txbuf[RIV_KEYSTONE_MAX_FRAME];

/* ---- "env" native imports ----
 * シグネチャの '*~' はWAMRがWasm線形メモリのアドレス検証と
 * ネイティブポインタ変換を行う(バッファ+長さの組)。 */

/* i32 query_attestation(u8* req, u32 req_len, u8* resp, u32 resp_cap)
 * req = AR_REQ完全フレーム。resp にはVerifierからのAR_RESP(またはERROR)
 * 完全フレームを書き戻し、その長さを返す。負=中継失敗。 */
static int32_t
native_query_attestation(wasm_exec_env_t exec_env,
                         uint8_t *req, uint32_t req_len,
                         uint8_t *resp, uint32_t resp_cap)
{
    unsigned long ok = 0;
    int32_t rc = -1;

    (void)exec_env;
    if (req_len < RIV_HDR_LEN || req[5] != RIV_MSG_AR_REQ)
        return -1;
    ocall(OCALL_AR_EXCHANGE, req, req_len, &ok, sizeof(ok));
    if (ok != 1) {
        printf("pcce-ta runner: AR中継を開始できない(hostにVerifier未設定?)\n");
        return -1;
    }
    for (;;) {
        struct edge_data retdata;
        unsigned long sent;
        uint8_t msg_type;
        size_t plen;
        int len;

        retdata.offset = 0;
        retdata.size = 0;
        ocall(OCALL_RECV_FRAME, 0, 0, &retdata, sizeof(retdata));
        if (retdata.size == 0) {
            printf("pcce-ta runner: AR接続が切断された\n");
            rc = -2;
            break;
        }
        if (retdata.size > sizeof(rxbuf) || retdata.size < 1)
            continue;
        copy_from_shared(rxbuf, retdata.offset, retdata.size);
        msg_type = rxbuf[0];
        plen = retdata.size - 1;

        if (msg_type == RIV_MSG_AR_RESP || msg_type == RIV_MSG_ERROR) {
            /* TAへは完全フレームで返す(TAは riv_hdr_parse で解析) */
            if (RIV_HDR_LEN + plen > resp_cap) {
                rc = -3;
                break;
            }
            riv_hdr_write(resp, msg_type, (uint32_t)plen);
            memcpy(resp + RIV_HDR_LEN, rxbuf + 1, plen);
            rc = (int32_t)(RIV_HDR_LEN + plen);
            break;
        }
        /* Verifierが同一接続上で送ってくるATTEST_REQ等に応答する */
        len = riv_keystone_handle_frame(msg_type, rxbuf + 1, plen, txbuf,
                                        sizeof(txbuf), g_ta_hash, g_pk_dev);
        if (len > 0)
            ocall(OCALL_SEND_FRAME, txbuf, (size_t)len, &sent, sizeof(sent));
    }
    ocall(OCALL_AR_EXCHANGE, NULL, 0, &ok, sizeof(ok)); /* 接続を閉じる */
    return rc;
}

/* void riv_log(const char* msg) — デバッグ出力(hostのコンソールへ) */
static void
native_riv_log(wasm_exec_env_t exec_env, const char *msg)
{
    (void)exec_env;
    printf("[TA] %s\n", msg ? msg : "(null)");
}

/* i32 get_random(u8* buf, u32 len) — sealing key由来DRBG(Linux非経由)。
 * 0=成功 */
static int32_t
native_get_random(wasm_exec_env_t exec_env, uint8_t *buf, uint32_t len)
{
    (void)exec_env;
    return riv_drbg_random(buf, len) == 0 ? 0 : -1;
}

/* i32 ecdsa_p256_verify(pk, pk_len, msg, msg_len, sig, sig_len)
 * 1=正当 0=不正。鍵はTA側(焼き込みpk_ar)が渡す。runnerは数学のみ */
static int32_t
native_ecdsa_p256_verify(wasm_exec_env_t exec_env,
                         const uint8_t *pk, uint32_t pk_len,
                         const uint8_t *msg, uint32_t msg_len,
                         const uint8_t *sig, uint32_t sig_len)
{
    (void)exec_env;
    if (pk_len != 64 || sig_len != 64)
        return 0;
    return riv_ecdsa_p256_verify(msg, msg_len, sig, pk);
}

static NativeSymbol native_symbols[] = {
    { "query_attestation", native_query_attestation, "(*~*~)i", NULL },
    { "riv_log", native_riv_log, "($)", NULL },
    { "get_random", native_get_random, "(*~)i", NULL },
    { "ecdsa_p256_verify", native_ecdsa_p256_verify, "(*~*~*~)i", NULL },
};

/* ---- riv attesterフレーム処理ループ(hostのRECV/SEND_FRAME対向) ----
 * report dataは常に96B(nonce ∥ ta_hash ∥ pk_dev)。TA未ロード時は
 * ta_hash=全ゼロ(プロビジョニングモード)。 */

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

        len = riv_keystone_handle_frame(rxbuf[0], rxbuf + 1,
                                        retdata.size - 1,
                                        txbuf, sizeof(txbuf), g_ta_hash,
                                        g_pk_dev);
        if (len > 0)
            ocall(OCALL_SEND_FRAME, txbuf, (size_t)len, &ret,
                  sizeof(ret));
    }
}

static int run_ta(size_t ta_len, int argc, char **argv)
{
    RuntimeInitArgs init_args;
    wasm_module_t module = NULL;
    wasm_module_inst_t module_inst = NULL;
    char error_buf[128];
    int ret = 1;

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

    module = wasm_runtime_load(ta_plain, (uint32_t)ta_len, error_buf,
                               sizeof(error_buf));
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

cleanup_instance:
    wasm_runtime_deinstantiate(module_inst);
cleanup_module:
    wasm_runtime_unload(module);
cleanup_runtime:
    wasm_runtime_destroy();
    return ret;
}

int main(int argc, char **argv)
{
    uint8_t sk_dev[32];
    uint32_t max_fw = 0, fw_version = 0;
    size_t ta_len = 0;
    int rc;

    /* enclave内glibcのstdoutはリダイレクト時に全バッファリングされ、
     * 状態表示がhost側ログに出ない。E2Eがログを判定に使うため無バッファ化 */
    setvbuf(stdout, NULL, _IONBF, 0);

    if (riv_drbg_init() != 0) {
        fprintf(stderr, "pcce-ta runner: DRBG初期化に失敗\n");
        return 1;
    }

    /* (1) sk_dev/pk_dev: sealed blobから復号、無ければ生成して封印 */
    rc = riv_dev_key_setup(sk_dev, g_pk_dev);
    if (rc == -2) {
        fprintf(stderr,
                "pcce-ta runner: sealed blobの復号に失敗"
                "(別enclave/別デバイスで封印されたか改ざん)\n");
        return 1;
    }
    if (rc == -3) {
        fprintf(stderr, "pcce-ta runner: sealed blobの保存に失敗\n");
        return 1;
    }
    if (rc < 0) {
        fprintf(stderr, "pcce-ta runner: sk_devの準備に失敗\n");
        return 1;
    }
    printf("pcce-ta runner: sk_dev %s\n",
           rc == 1 ? "生成・封印(初回プロビジョニング。pk_devの登録が必要)"
                   : "sealed blobから復号");

    /* (2) アンチロールバック状態 → TAロード */
    rc = riv_rollback_load(&max_fw);
    if (rc == -2) {
        fprintf(stderr, "pcce-ta runner: ロールバック状態の復号に失敗(改ざん)\n");
        memset(sk_dev, 0, sizeof(sk_dev));
        return 1;
    }
    if (rc < 0) {
        fprintf(stderr, "pcce-ta runner: ロールバック状態の取得に失敗\n");
        memset(sk_dev, 0, sizeof(sk_dev));
        return 1;
    }
    printf("pcce-ta runner: 既見の最大fw_version=%lu\n", (unsigned long)max_fw);

    rc = riv_ta_load_from_host(pk_ta_embedded, sk_dev, max_fw, ta_plain,
                               sizeof(ta_plain), &ta_len, g_ta_hash,
                               &fw_version);
    memset(sk_dev, 0, sizeof(sk_dev)); /* アンラップ後は不要 */

    if (rc < 0) {
        /* 検証チェーンのどの段で失敗したかを理由コードで示して終了 */
        fprintf(stderr, "pcce-ta runner: TAロード拒否: %s (code=%d)\n",
                riv_ta_strerror(-rc), -rc);
        return 1;
    }

    if (rc == 1) {
        memset(g_ta_hash, 0, sizeof(g_ta_hash));
        printf("pcce-ta runner: TAなし(プロビジョニングモード)\n");
        serve_attestation();
        return 0;
    }

    printf("pcce-ta runner: TAロード成功 (%lu bytes, fw_version=%lu)\n",
           (unsigned long)ta_len, (unsigned long)fw_version);
    if (fw_version > max_fw) {
        if (riv_rollback_store(fw_version) == 0)
            printf("pcce-ta runner: ロールバック状態を更新 (%lu)\n",
                   (unsigned long)fw_version);
        else
            printf("pcce-ta runner: ロールバック状態の保存に失敗(継続)\n");
    }

    if (run_ta(ta_len, argc, argv) != 0) {
        memset(ta_plain, 0, sizeof(ta_plain));
        return 1;
    }

    /* TA実行後、同一enclaveのriv attesterとしてVerifierに応答する */
    serve_attestation();

    memset(ta_plain, 0, sizeof(ta_plain));
    return 0;
}
