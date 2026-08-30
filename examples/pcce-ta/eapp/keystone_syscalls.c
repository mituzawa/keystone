/*
 * keystone_syscalls.c — eyrieシステムコールの薄いラッパ。
 *
 * SDKの sdk/src/app/syscall.c と同一実装。libkeystone-eapp.a を
 * リンクするとglibc静的リンクのrunnerに tiny-malloc.o が引き込まれ、
 * eappリンカスクリプト由来のシンボル(__malloc_start)が未解決になる
 * ため、必要なラッパのみを自前で定義する。
 */
#include "app/syscall.h"

int
ocall(unsigned long call_id, void *data, size_t data_len,
      void *return_buffer, size_t return_len)
{
    return SYSCALL_5(RUNTIME_SYSCALL_OCALL, call_id, data, data_len,
                     return_buffer, return_len);
}

int
copy_from_shared(void *dst, uintptr_t offset, size_t data_len)
{
    return SYSCALL_3(RUNTIME_SYSCALL_SHAREDCOPY, dst, offset, data_len);
}

int
attest_enclave(void *report, void *data, size_t size)
{
    return SYSCALL_3(RUNTIME_SYSCALL_ATTEST_ENCLAVE, report, data, size);
}

int
get_sealing_key(struct sealing_key *sealing_key_struct,
                size_t sealing_key_struct_size, void *key_ident,
                size_t key_ident_size)
{
    return SYSCALL_4(RUNTIME_SYSCALL_GET_SEALING_KEY, sealing_key_struct,
                     sealing_key_struct_size, key_ident, key_ident_size);
}
