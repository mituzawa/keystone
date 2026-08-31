/* dev_key.h — デバイスTA復号鍵(sk_dev/pk_dev)の導出 */
#ifndef PCCE_DEV_KEY_H
#define PCCE_DEV_KEY_H

#include <stdint.h>

/*
 * 段階2の暫定方式(決定論的導出。rivリポジトリ doc/design/wasm-ta.md):
 *   sk_dev = clamp(get_sealing_key(key_ident="riv:ta-x25519-seed:v1")
 *                  の先頭32B)
 * sealing keyがデバイス+enclave測定値に束縛されているため、同じrunnerは
 * 常に同じ鍵を導出し、別enclave・別デバイスは導出できない。ストレージ・
 * 封印コードが不要な代わりに、runnerを変えずに鍵だけのローテーションは
 * できない。段階3で主方式(enclave内生成+sealed blob封印)へ切り替える。
 *
 * 戻り値: 0=成功。失敗時は負値。
 */
int riv_derive_dev_key(uint8_t sk_dev[32], uint8_t pk_dev[32]);

#endif /* PCCE_DEV_KEY_H */
