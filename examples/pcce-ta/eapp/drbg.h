/* drbg.h — sealing key由来のenclave内DRBG(秘密乱数) */
#ifndef PCCE_DRBG_H
#define PCCE_DRBG_H

#include <stddef.h>
#include <stdint.h>

/*
 * 設計: rivリポジトリ doc/design/tee-channel.md「採用: sealing key由来の
 * DRBG」、wasm-ta.md「鍵管理」段階3。
 *
 *   seed = HKDF-SHA-256(salt=fresh, ikm=K_seal_drbg, info="riv-drbg-seed-v1")
 *   out_i = HMAC-SHA-256(seed, counter_i ∥ "riv-drbg-out-v1")
 *
 * K_seal_drbg = get_sealing_key("riv:drbg:v1")(デバイス鍵+enclave測定値に
 * 束縛。untrusted Linuxは構造的に知り得ない=秘密性)。
 * fresh = eyrieのgetrandom(SMのsbi_random。QEMU/genericでは rdcycle 由来の
 * TEST ONLY実装だがLinuxを経由しない)=起動ごとの新鮮さ(best effort)。
 * Linux経由の乱数(hostからの入力)は使わない。
 *
 * 用途: sk_devの生成、sealed blobのIV、TAの nonce_ta(get_random import)。
 */
int riv_drbg_init(void);                       /* 0=成功 */
int riv_drbg_random(uint8_t *out, size_t n);   /* 0=成功(init済みが前提) */

#endif /* PCCE_DRBG_H */
