#include "pwd_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */

#include <errno.h>
#include <string.h> /* for memcpy etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


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

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4127)
#pragma warning(disable: 4200)
#endif

static sgx_status_t SGX_CDECL sgx_initialize_enclave(void* pms)
{
	ms_initialize_enclave_t* ms = SGX_CAST(ms_initialize_enclave_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_sealed_data = ms->ms_sealed_data;
	uint32_t _tmp_sealed_length = ms->ms_sealed_length;
	size_t _len_sealed_data = _tmp_sealed_length;
	void* _in_sealed_data = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_initialize_enclave_t));
	CHECK_UNIQUE_POINTER(_tmp_sealed_data, _len_sealed_data);

	if (_tmp_sealed_data != NULL) {
		_in_sealed_data = (void*)malloc(_len_sealed_data);
		if (_in_sealed_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_sealed_data, _tmp_sealed_data, _len_sealed_data);
	}
	ms->ms_retval = initialize_enclave(_in_sealed_data, _tmp_sealed_length);
err:
	if (_in_sealed_data) free(_in_sealed_data);

	return status;
}

static sgx_status_t SGX_CDECL sgx_destroy_enclave(void* pms)
{
	ms_destroy_enclave_t* ms = SGX_CAST(ms_destroy_enclave_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_sealed_data = ms->ms_sealed_data;
	uint32_t _tmp_sealed_length = ms->ms_sealed_length;
	size_t _len_sealed_data = _tmp_sealed_length;
	void* _in_sealed_data = NULL;
	uint32_t* _tmp_out_length = ms->ms_out_length;
	size_t _len_out_length = sizeof(*_tmp_out_length);
	uint32_t* _in_out_length = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_destroy_enclave_t));
	CHECK_UNIQUE_POINTER(_tmp_sealed_data, _len_sealed_data);
	CHECK_UNIQUE_POINTER(_tmp_out_length, _len_out_length);

	if (_tmp_sealed_data != NULL) {
		if ((_in_sealed_data = (void*)malloc(_len_sealed_data)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sealed_data, 0, _len_sealed_data);
	}
	if (_tmp_out_length != NULL) {
		if ((_in_out_length = (uint32_t*)malloc(_len_out_length)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_out_length, 0, _len_out_length);
	}
	ms->ms_retval = destroy_enclave(_in_sealed_data, _tmp_sealed_length, _in_out_length);
err:
	if (_in_sealed_data) {
		memcpy(_tmp_sealed_data, _in_sealed_data, _len_sealed_data);
		free(_in_sealed_data);
	}
	if (_in_out_length) {
		memcpy(_tmp_out_length, _in_out_length, _len_out_length);
		free(_in_out_length);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_initialize_mmap(void* pms)
{
	ms_initialize_mmap_t* ms = SGX_CAST(ms_initialize_mmap_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_base = ms->ms_base;

	CHECK_REF_POINTER(pms, sizeof(ms_initialize_mmap_t));

	ms->ms_retval = initialize_mmap(_tmp_base, ms->ms_length, ms->ms_align, ms->ms_seed);


	return status;
}

static sgx_status_t SGX_CDECL sgx_add_user(void* pms)
{
	ms_add_user_t* ms = SGX_CAST(ms_add_user_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_user = ms->ms_user;
	size_t _len_user = _tmp_user ? strlen(_tmp_user) + 1 : 0;
	char* _in_user = NULL;
	char* _tmp_pwd = ms->ms_pwd;
	size_t _len_pwd = _tmp_pwd ? strlen(_tmp_pwd) + 1 : 0;
	char* _in_pwd = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_add_user_t));
	CHECK_UNIQUE_POINTER(_tmp_user, _len_user);
	CHECK_UNIQUE_POINTER(_tmp_pwd, _len_pwd);

	if (_tmp_user != NULL) {
		_in_user = (char*)malloc(_len_user);
		if (_in_user == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_user, _tmp_user, _len_user);
		_in_user[_len_user - 1] = '\0';
	}
	if (_tmp_pwd != NULL) {
		_in_pwd = (char*)malloc(_len_pwd);
		if (_in_pwd == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_pwd, _tmp_pwd, _len_pwd);
		_in_pwd[_len_pwd - 1] = '\0';
	}
	ms->ms_retval = add_user((const char*)_in_user, (const char*)_in_pwd);
err:
	if (_in_user) free((void*)_in_user);
	if (_in_pwd) free((void*)_in_pwd);

	return status;
}

static sgx_status_t SGX_CDECL sgx_update_user(void* pms)
{
	ms_update_user_t* ms = SGX_CAST(ms_update_user_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_user = ms->ms_user;
	size_t _len_user = _tmp_user ? strlen(_tmp_user) + 1 : 0;
	char* _in_user = NULL;
	char* _tmp_old_pwd = ms->ms_old_pwd;
	size_t _len_old_pwd = _tmp_old_pwd ? strlen(_tmp_old_pwd) + 1 : 0;
	char* _in_old_pwd = NULL;
	char* _tmp_new_pwd = ms->ms_new_pwd;
	size_t _len_new_pwd = _tmp_new_pwd ? strlen(_tmp_new_pwd) + 1 : 0;
	char* _in_new_pwd = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_update_user_t));
	CHECK_UNIQUE_POINTER(_tmp_user, _len_user);
	CHECK_UNIQUE_POINTER(_tmp_old_pwd, _len_old_pwd);
	CHECK_UNIQUE_POINTER(_tmp_new_pwd, _len_new_pwd);

	if (_tmp_user != NULL) {
		_in_user = (char*)malloc(_len_user);
		if (_in_user == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_user, _tmp_user, _len_user);
		_in_user[_len_user - 1] = '\0';
	}
	if (_tmp_old_pwd != NULL) {
		_in_old_pwd = (char*)malloc(_len_old_pwd);
		if (_in_old_pwd == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_old_pwd, _tmp_old_pwd, _len_old_pwd);
		_in_old_pwd[_len_old_pwd - 1] = '\0';
	}
	if (_tmp_new_pwd != NULL) {
		_in_new_pwd = (char*)malloc(_len_new_pwd);
		if (_in_new_pwd == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_new_pwd, _tmp_new_pwd, _len_new_pwd);
		_in_new_pwd[_len_new_pwd - 1] = '\0';
	}
	ms->ms_retval = update_user((const char*)_in_user, (const char*)_in_old_pwd, (const char*)_in_new_pwd);
err:
	if (_in_user) free((void*)_in_user);
	if (_in_old_pwd) free((void*)_in_old_pwd);
	if (_in_new_pwd) free((void*)_in_new_pwd);

	return status;
}

static sgx_status_t SGX_CDECL sgx_check_password(void* pms)
{
	ms_check_password_t* ms = SGX_CAST(ms_check_password_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_user = ms->ms_user;
	size_t _len_user = _tmp_user ? strlen(_tmp_user) + 1 : 0;
	char* _in_user = NULL;
	char* _tmp_pwd = ms->ms_pwd;
	size_t _len_pwd = _tmp_pwd ? strlen(_tmp_pwd) + 1 : 0;
	char* _in_pwd = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_check_password_t));
	CHECK_UNIQUE_POINTER(_tmp_user, _len_user);
	CHECK_UNIQUE_POINTER(_tmp_pwd, _len_pwd);

	if (_tmp_user != NULL) {
		_in_user = (char*)malloc(_len_user);
		if (_in_user == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_user, _tmp_user, _len_user);
		_in_user[_len_user - 1] = '\0';
	}
	if (_tmp_pwd != NULL) {
		_in_pwd = (char*)malloc(_len_pwd);
		if (_in_pwd == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_pwd, _tmp_pwd, _len_pwd);
		_in_pwd[_len_pwd - 1] = '\0';
	}
	ms->ms_retval = check_password((const char*)_in_user, (const char*)_in_pwd);
err:
	if (_in_user) free((void*)_in_user);
	if (_in_pwd) free((void*)_in_pwd);

	return status;
}

static sgx_status_t SGX_CDECL sgx_find_user(void* pms)
{
	ms_find_user_t* ms = SGX_CAST(ms_find_user_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_user = ms->ms_user;
	size_t _len_user = _tmp_user ? strlen(_tmp_user) + 1 : 0;
	char* _in_user = NULL;
	char* _tmp_pwd = ms->ms_pwd;
	uint64_t _tmp_pwd_len = ms->ms_pwd_len;
	size_t _len_pwd = _tmp_pwd_len;
	char* _in_pwd = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_find_user_t));
	CHECK_UNIQUE_POINTER(_tmp_user, _len_user);
	CHECK_UNIQUE_POINTER(_tmp_pwd, _len_pwd);

	if (_tmp_user != NULL) {
		_in_user = (char*)malloc(_len_user);
		if (_in_user == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_user, _tmp_user, _len_user);
		_in_user[_len_user - 1] = '\0';
	}
	if (_tmp_pwd != NULL) {
		if ((_in_pwd = (char*)malloc(_len_pwd)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_pwd, 0, _len_pwd);
	}
	ms->ms_retval = find_user((const char*)_in_user, _in_pwd, _tmp_pwd_len);
err:
	if (_in_user) free((void*)_in_user);
	if (_in_pwd) {
		memcpy(_tmp_pwd, _in_pwd, _len_pwd);
		free(_in_pwd);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_encrypt_records(void* pms)
{
	ms_encrypt_records_t* ms = SGX_CAST(ms_encrypt_records_t*, pms);
	sgx_status_t status = SGX_SUCCESS;

	CHECK_REF_POINTER(pms, sizeof(ms_encrypt_records_t));

	ms->ms_retval = encrypt_records();


	return status;
}

static sgx_status_t SGX_CDECL sgx_get_public_key(void* pms)
{
	ms_get_public_key_t* ms = SGX_CAST(ms_get_public_key_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_key = ms->ms_key;
	uint64_t _tmp_key_len = ms->ms_key_len;
	size_t _len_key = _tmp_key_len;
	void* _in_key = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_get_public_key_t));
	CHECK_UNIQUE_POINTER(_tmp_key, _len_key);

	if (_tmp_key != NULL) {
		if ((_in_key = (void*)malloc(_len_key)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_key, 0, _len_key);
	}
	ms->ms_retval = get_public_key(_in_key, _tmp_key_len);
err:
	if (_in_key) {
		memcpy(_tmp_key, _in_key, _len_key);
		free(_in_key);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_is_public_key(void* pms)
{
	ms_is_public_key_t* ms = SGX_CAST(ms_is_public_key_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_key = ms->ms_key;
	char* _tmp_match = ms->ms_match;
	size_t _len_match = sizeof(*_tmp_match);
	char* _in_match = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_is_public_key_t));
	CHECK_UNIQUE_POINTER(_tmp_match, _len_match);

	if (_tmp_match != NULL) {
		if ((_in_match = (char*)malloc(_len_match)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_match, 0, _len_match);
	}
	ms->ms_retval = is_public_key(_tmp_key, ms->ms_key_len, _in_match);
err:
	if (_in_match) {
		memcpy(_tmp_match, _in_match, _len_match);
		free(_in_match);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_challenge_response(void* pms)
{
	ms_challenge_response_t* ms = SGX_CAST(ms_challenge_response_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_user = ms->ms_user;
	size_t _len_user = _tmp_user ? strlen(_tmp_user) + 1 : 0;
	char* _in_user = NULL;
	void* _tmp_txn = ms->ms_txn;
	uint64_t _tmp_txn_len = ms->ms_txn_len;
	size_t _len_txn = _tmp_txn_len;
	void* _in_txn = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_challenge_response_t));
	CHECK_UNIQUE_POINTER(_tmp_user, _len_user);
	CHECK_UNIQUE_POINTER(_tmp_txn, _len_txn);

	if (_tmp_user != NULL) {
		_in_user = (char*)malloc(_len_user);
		if (_in_user == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_user, _tmp_user, _len_user);
		_in_user[_len_user - 1] = '\0';
	}
	if (_tmp_txn != NULL) {
		_in_txn = (void*)malloc(_len_txn);
		if (_in_txn == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_txn, _tmp_txn, _len_txn);
	}
	ms->ms_retval = challenge_response((const char*)_in_user, _in_txn, _tmp_txn_len);
err:
	if (_in_user) free((void*)_in_user);
	if (_in_txn) {
		memcpy(_tmp_txn, _in_txn, _len_txn);
		free(_in_txn);
	}

	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* call_addr; uint8_t is_priv;} ecall_table[11];
} g_ecall_table = {
	11,
	{
		{(void*)(uintptr_t)sgx_initialize_enclave, 0},
		{(void*)(uintptr_t)sgx_destroy_enclave, 0},
		{(void*)(uintptr_t)sgx_initialize_mmap, 0},
		{(void*)(uintptr_t)sgx_add_user, 0},
		{(void*)(uintptr_t)sgx_update_user, 0},
		{(void*)(uintptr_t)sgx_check_password, 0},
		{(void*)(uintptr_t)sgx_find_user, 0},
		{(void*)(uintptr_t)sgx_encrypt_records, 0},
		{(void*)(uintptr_t)sgx_get_public_key, 0},
		{(void*)(uintptr_t)sgx_is_public_key, 0},
		{(void*)(uintptr_t)sgx_challenge_response, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[2][11];
} g_dyn_entry_table = {
	2,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_print(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_t);
	void *__tmp = NULL;

	ocalloc_size += (str != NULL && sgx_is_within_enclave(str, _len_str)) ? _len_str : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_t));

	if (str != NULL && sgx_is_within_enclave(str, _len_str)) {
		ms->ms_str = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_str);
		memcpy((void*)ms->ms_str, str, _len_str);
	} else if (str == NULL) {
		ms->ms_str = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(0, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL log_msg(unsigned int priority, const char* file, unsigned int line, const char* msg)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_file = file ? strlen(file) + 1 : 0;
	size_t _len_msg = msg ? strlen(msg) + 1 : 0;

	ms_log_msg_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_log_msg_t);
	void *__tmp = NULL;

	ocalloc_size += (file != NULL && sgx_is_within_enclave(file, _len_file)) ? _len_file : 0;
	ocalloc_size += (msg != NULL && sgx_is_within_enclave(msg, _len_msg)) ? _len_msg : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_log_msg_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_log_msg_t));

	ms->ms_priority = priority;
	if (file != NULL && sgx_is_within_enclave(file, _len_file)) {
		ms->ms_file = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_file);
		memcpy((void*)ms->ms_file, file, _len_file);
	} else if (file == NULL) {
		ms->ms_file = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_line = line;
	if (msg != NULL && sgx_is_within_enclave(msg, _len_msg)) {
		ms->ms_msg = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_msg);
		memcpy((void*)ms->ms_msg, msg, _len_msg);
	} else if (msg == NULL) {
		ms->ms_msg = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(1, ms);


	sgx_ocfree();
	return status;
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif
