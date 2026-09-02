/* sealed_state.h — sealing key派生鍵による封印状態(host FSに保管) */
#ifndef PCCE_SEALED_STATE_H
#define PCCE_SEALED_STATE_H

#include <stddef.h>
#include <stdint.h>

/*
 * 設計: rivリポジトリ doc/design/wasm-ta.md「鍵管理: sealing key派生」
 * (段階3)。封印はrivのriv_seal/riv_unseal(riv_crypto.h。AES-256-GCM、
 * kind付きヘッダをAAD)、鍵は get_sealing_key(key_ident) の128B keyの
 * 先頭32B。hostはOCALL_STATE_LOAD/STOREで中身を解釈せず保管する。
 * sealing keyはデバイス鍵+enclave測定値に束縛されるため、別enclave・
 * 別デバイスで作られたblobは復号できない。
 */

/* get_sealing_key(key_ident)の先頭32Bを返す。0=成功 */
int riv_sealing_key32(const char *key_ident, uint8_t out[32]);

/* host FS上の封印ブロブの読み書き。load: 0=成功(len 0=無し) 負=ocall失敗 */
int riv_host_state_load(uint16_t kind, uint8_t *buf, size_t cap, size_t *len);
int riv_host_state_store(uint16_t kind, const uint8_t *blob, size_t len);

/* デバイスTA復号鍵ペア(sk_dev/pk_dev)。
 * sealed blobがあればK_seal_kek("riv:ta-kek:v1")で復号、無ければDRBGで
 * 生成して封印・保存する(初回プロビジョニング)。
 * 戻り値: 0=既存を復号, 1=新規生成(要pk_dev登録),
 *   -1=内部エラー, -2=unseal失敗(別enclave/別デバイス/改ざん),
 *   -3=封印の保存失敗 */
int riv_dev_key_setup(uint8_t sk_dev[32], uint8_t pk_dev[32]);

/* アンチロールバック状態(既見の最大fw_version)。K_seal_rollback
 * ("riv:rollback:v1")で封印。best effort(hostがファイルを消せば0に戻る)。
 * load: 0=成功(無ければ*max_fw=0)、-2=unseal失敗(改ざん) */
int riv_rollback_load(uint32_t *max_fw);
int riv_rollback_store(uint32_t max_fw);

#endif /* PCCE_SEALED_STATE_H */
