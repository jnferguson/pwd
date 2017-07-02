#include "pwd_u.h"
#include <errno.h>

typedef struct ms_initialize_enclave_t {
	int ms_retval;
	void* ms_sealed_data;
	uint32_t ms_sealed_length;
} ms_initialize_enclave_t;

typedef struct ms_destroy_enclave_t {
	int ms_retval;
	void* ms_sealed_data;
	uint32_t ms_sealed_length;
	uint32_t* ms_out_length;
} ms_destroy_enclave_t;

typedef struct ms_initialize_mmap_t {
	int ms_retval;
	void* ms_base;
	uint64_t ms_length;
	uint32_t ms_align;
	uint64_t ms_seed;
} ms_initialize_mmap_t;

typedef struct ms_add_user_t {
	int ms_retval;
	char* ms_user;
	char* ms_pwd;
} ms_add_user_t;

typedef struct ms_update_user_t {
	int ms_retval;
	char* ms_user;
	char* ms_old_pwd;
	char* ms_new_pwd;
} ms_update_user_t;

typedef struct ms_check_password_t {
	int ms_retval;
	char* ms_user;
	char* ms_pwd;
} ms_check_password_t;

typedef struct ms_find_user_t {
	int ms_retval;
	char* ms_user;
	char* ms_pwd;
	uint64_t ms_pwd_len;
} ms_find_user_t;

typedef struct ms_encrypt_records_t {
	int ms_retval;
} ms_encrypt_records_t;

typedef struct ms_get_public_key_t {
	int ms_retval;
	void* ms_key;
	uint64_t ms_key_len;
} ms_get_public_key_t;

typedef struct ms_is_public_key_t {
	int ms_retval;
	void* ms_key;
	uint64_t ms_key_len;
	char* ms_match;
} ms_is_public_key_t;

typedef struct ms_challenge_response_t {
	int ms_retval;
	char* ms_user;
	void* ms_txn;
	uint64_t ms_txn_len;
} ms_challenge_response_t;

typedef struct ms_ocall_print_t {
	char* ms_str;
} ms_ocall_print_t;

typedef struct ms_log_msg_t {
	unsigned int ms_priority;
	char* ms_file;
	unsigned int ms_line;
	char* ms_msg;
} ms_log_msg_t;

static sgx_status_t SGX_CDECL pwd_ocall_print(void* pms)
{
	ms_ocall_print_t* ms = SGX_CAST(ms_ocall_print_t*, pms);
	ocall_print((const char*)ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL pwd_log_msg(void* pms)
{
	ms_log_msg_t* ms = SGX_CAST(ms_log_msg_t*, pms);
	log_msg(ms->ms_priority, (const char*)ms->ms_file, ms->ms_line, (const char*)ms->ms_msg);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * func_addr[2];
} ocall_table_pwd = {
	2,
	{
		(void*)(uintptr_t)pwd_ocall_print,
		(void*)(uintptr_t)pwd_log_msg,
	}
};

sgx_status_t initialize_enclave(sgx_enclave_id_t eid, int* retval, void* sealed_data, uint32_t sealed_length)
{
	sgx_status_t status;
	ms_initialize_enclave_t ms;
	ms.ms_sealed_data = sealed_data;
	ms.ms_sealed_length = sealed_length;
	status = sgx_ecall(eid, 0, &ocall_table_pwd, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t destroy_enclave(sgx_enclave_id_t eid, int* retval, void* sealed_data, uint32_t sealed_length, uint32_t* out_length)
{
	sgx_status_t status;
	ms_destroy_enclave_t ms;
	ms.ms_sealed_data = sealed_data;
	ms.ms_sealed_length = sealed_length;
	ms.ms_out_length = out_length;
	status = sgx_ecall(eid, 1, &ocall_table_pwd, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t initialize_mmap(sgx_enclave_id_t eid, int* retval, void* base, uint64_t length, uint32_t align, uint64_t seed)
{
	sgx_status_t status;
	ms_initialize_mmap_t ms;
	ms.ms_base = base;
	ms.ms_length = length;
	ms.ms_align = align;
	ms.ms_seed = seed;
	status = sgx_ecall(eid, 2, &ocall_table_pwd, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t add_user(sgx_enclave_id_t eid, int* retval, const char* user, const char* pwd)
{
	sgx_status_t status;
	ms_add_user_t ms;
	ms.ms_user = (char*)user;
	ms.ms_pwd = (char*)pwd;
	status = sgx_ecall(eid, 3, &ocall_table_pwd, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t update_user(sgx_enclave_id_t eid, int* retval, const char* user, const char* old_pwd, const char* new_pwd)
{
	sgx_status_t status;
	ms_update_user_t ms;
	ms.ms_user = (char*)user;
	ms.ms_old_pwd = (char*)old_pwd;
	ms.ms_new_pwd = (char*)new_pwd;
	status = sgx_ecall(eid, 4, &ocall_table_pwd, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t check_password(sgx_enclave_id_t eid, int* retval, const char* user, const char* pwd)
{
	sgx_status_t status;
	ms_check_password_t ms;
	ms.ms_user = (char*)user;
	ms.ms_pwd = (char*)pwd;
	status = sgx_ecall(eid, 5, &ocall_table_pwd, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t find_user(sgx_enclave_id_t eid, int* retval, const char* user, char* pwd, uint64_t pwd_len)
{
	sgx_status_t status;
	ms_find_user_t ms;
	ms.ms_user = (char*)user;
	ms.ms_pwd = pwd;
	ms.ms_pwd_len = pwd_len;
	status = sgx_ecall(eid, 6, &ocall_table_pwd, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t encrypt_records(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_encrypt_records_t ms;
	status = sgx_ecall(eid, 7, &ocall_table_pwd, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t get_public_key(sgx_enclave_id_t eid, int* retval, void* key, uint64_t key_len)
{
	sgx_status_t status;
	ms_get_public_key_t ms;
	ms.ms_key = key;
	ms.ms_key_len = key_len;
	status = sgx_ecall(eid, 8, &ocall_table_pwd, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t is_public_key(sgx_enclave_id_t eid, int* retval, void* key, uint64_t key_len, char* match)
{
	sgx_status_t status;
	ms_is_public_key_t ms;
	ms.ms_key = key;
	ms.ms_key_len = key_len;
	ms.ms_match = match;
	status = sgx_ecall(eid, 9, &ocall_table_pwd, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t challenge_response(sgx_enclave_id_t eid, int* retval, const char* user, void* txn, uint64_t txn_len)
{
	sgx_status_t status;
	ms_challenge_response_t ms;
	ms.ms_user = (char*)user;
	ms.ms_txn = txn;
	ms.ms_txn_len = txn_len;
	status = sgx_ecall(eid, 10, &ocall_table_pwd, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

