/* ta_loader.h — 暗号化TA(ta.enc)のhost経由ロード+enclave内検証・復号 */
#ifndef PCCE_TA_LOADER_H
#define PCCE_TA_LOADER_H

#include <stddef.h>
#include <stdint.h>

/*
 * OCALL_TA_INFO/TA_CHUNKでhostからta.encを取り寄せ、enclave内バッファへ
 * コピーした上で検証チェーン(riv_ta_verify_decrypt)を通す。
 *
 * 戻り値:
 *   0   ロード成功(plain/plain_len/ta_hashが有効)
 *   1   TAなし=プロビジョニングモード(hostがサイズ0を返した)
 *   <0  -riv_ta_result(検証チェーンの失敗段。呼び出し側でstrerror表示)
 */
int riv_ta_load_from_host(const uint8_t pk_ta[64], const uint8_t sk_dev[32],
                          uint8_t *plain, size_t plain_cap,
                          size_t *plain_len, uint8_t ta_hash[32]);

#endif /* PCCE_TA_LOADER_H */
