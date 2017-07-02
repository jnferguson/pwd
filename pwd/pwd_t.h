#ifndef PWD_T_H__
#define PWD_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


int initialize_enclave(void* sealed_data, uint32_t sealed_length);
int destroy_enclave(void* sealed_data, uint32_t sealed_length, uint32_t* out_length);
int initialize_mmap(void* base, uint64_t length, uint32_t align, uint64_t seed);
int add_user(const char* user, const char* pwd);
int update_user(const char* user, const char* old_pwd, const char* new_pwd);
int check_password(const char* user, const char* pwd);
int find_user(const char* user, char* pwd, uint64_t pwd_len);
int encrypt_records();
int get_public_key(void* key, uint64_t key_len);
int is_public_key(void* key, uint64_t key_len, char* match);
int challenge_response(const char* user, void* txn, uint64_t txn_len);

sgx_status_t SGX_CDECL ocall_print(const char* str);
sgx_status_t SGX_CDECL log_msg(unsigned int priority, const char* file, unsigned int line, const char* msg);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
