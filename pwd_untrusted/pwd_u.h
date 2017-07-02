#ifndef PWD_U_H__
#define PWD_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */


#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print, (const char* str));
void SGX_UBRIDGE(SGX_NOCONVENTION, log_msg, (unsigned int priority, const char* file, unsigned int line, const char* msg));

sgx_status_t initialize_enclave(sgx_enclave_id_t eid, int* retval, void* sealed_data, uint32_t sealed_length);
sgx_status_t destroy_enclave(sgx_enclave_id_t eid, int* retval, void* sealed_data, uint32_t sealed_length, uint32_t* out_length);
sgx_status_t initialize_mmap(sgx_enclave_id_t eid, int* retval, void* base, uint64_t length, uint32_t align, uint64_t seed);
sgx_status_t add_user(sgx_enclave_id_t eid, int* retval, const char* user, const char* pwd);
sgx_status_t update_user(sgx_enclave_id_t eid, int* retval, const char* user, const char* old_pwd, const char* new_pwd);
sgx_status_t check_password(sgx_enclave_id_t eid, int* retval, const char* user, const char* pwd);
sgx_status_t find_user(sgx_enclave_id_t eid, int* retval, const char* user, char* pwd, uint64_t pwd_len);
sgx_status_t encrypt_records(sgx_enclave_id_t eid, int* retval);
sgx_status_t get_public_key(sgx_enclave_id_t eid, int* retval, void* key, uint64_t key_len);
sgx_status_t is_public_key(sgx_enclave_id_t eid, int* retval, void* key, uint64_t key_len, char* match);
sgx_status_t challenge_response(sgx_enclave_id_t eid, int* retval, const char* user, void* txn, uint64_t txn_len);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
