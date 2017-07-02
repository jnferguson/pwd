#include "pwd_t.h"

#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include "sgx_tae_service.h"
#include "sgx_tseal.h"

#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "records.hpp"
#include "common.hpp"
#include "util.hpp"
#include "challenge_reponse.hpp"

/* At present the trusted crypto library from Intel is a little half baked; all of the integrated crypto functionality
   is using 128-bit keys, however the only asymmetric algorithm is ECC-256 which can be used to generate a symmetric shared
   DH session key, which is also 256-bits in length, however then there is no interface to actually do anything with either key
   and the AES et al algorithms are all 128-bit. The trusted library ships with an integrated copy of IPP which includes RSA and
   other functionality, but its not advertised and so I should probably avoid using it. Ultimately, I will need to integrate an 
   AES-256 and possibly RSA implementation, but crypto is far from a strong point of mine and I want to get other more relevant
   aspects of this program written first, so I will just use part of the session key, which is probably horribly wrong but is okay
   for initial testing purposes.
*/

#define REPLAY_RESISTANT_DATA_LENGTH 32

typedef struct {
	sgx_ec256_private_t		priv_key;
	sgx_ec256_public_t		pub_key;
	aes_gcm_data_t			gcm_data;
	uint8_t					rdata[REPLAY_RESISTANT_DATA_LENGTH];
} enclave_ctxt_t;

enclave_ctxt_t* g_ecc_ctxt = NULL;
records_t* g_records = NULL;
dh_challenge_response_t* g_charesp = NULL;

signed int
destroy_enclave(void* sealed_data, uint32_t sealed_length, uint32_t* out_length)
{
	const uint32_t	length = sgx_calc_sealed_data_size(0, sizeof(enclave_ctxt_t));
	signed int		retval(0);

	if (NULL != out_length)
		*out_length = length;

	if (length != sealed_length) 
		return -1;

	if (NULL != g_ecc_ctxt) {
		if (SGX_SUCCESS != ::sgx_read_rand(&g_ecc_ctxt->rdata[0], sizeof(g_ecc_ctxt->rdata)))
			retval = -1;
		else
			// XXX JF FIXME - first parameters are MAC related which I should be using
			if (SGX_SUCCESS != sgx_seal_data(0, NULL, sizeof(enclave_ctxt_t), (uint8_t*)g_ecc_ctxt, sealed_length, (sgx_sealed_data_t*)sealed_data)) 
				retval = -1;

		::memset_s(g_ecc_ctxt, sizeof(enclave_ctxt_t), 0, sizeof(enclave_ctxt_t));
		delete g_ecc_ctxt;
		g_ecc_ctxt = NULL;
	}

	if (NULL != g_records) {
		delete g_records;
		g_records = NULL;
	}

	if (NULL != g_charesp) {
		delete g_charesp;
		g_charesp = NULL;
	}

	return retval;
}

signed int
initialize_enclave(void* sealed_data, uint32_t sealed_length)
{
	sgx_sealed_data_t*	sdata = (sgx_sealed_data_t*)sealed_data;
	enclave_ctxt_t		udata = { 0 };
	uint32_t			ulen = sizeof(enclave_ctxt_t);

	if (NULL != g_ecc_ctxt) 
		delete g_ecc_ctxt;

	g_ecc_ctxt = new enclave_ctxt_t;

	if (NULL == sdata) {
		sgx_ecc_state_handle_t hnd(NULL);

		if (SGX_SUCCESS != sgx_ecc256_open_context(&hnd))
			return -1;

		if (SGX_SUCCESS != sgx_ecc256_create_key_pair(&g_ecc_ctxt->priv_key, &g_ecc_ctxt->pub_key, hnd))
			return -1;

		if (SGX_SUCCESS != sgx_ecc256_close_context(hnd)) {
			// XXX JF i dont think this is necessary
			memset_s(&g_ecc_ctxt, sizeof(g_ecc_ctxt), 0, sizeof(g_ecc_ctxt));
			return -1;
		}

		if (SGX_SUCCESS != sgx_read_rand(&g_ecc_ctxt->gcm_data.key[0], sizeof(g_ecc_ctxt->gcm_data.key))) {
			::memset_s(g_ecc_ctxt, sizeof(enclave_ctxt_t), 0, sizeof(enclave_ctxt_t));
			return -1;
		}

		if (SGX_SUCCESS != sgx_read_rand(&g_ecc_ctxt->gcm_data.iv[0], sizeof(g_ecc_ctxt->gcm_data.iv))) {
			::memset_s(g_ecc_ctxt, sizeof(enclave_ctxt_t), 0, sizeof(enclave_ctxt_t));
			return -1;
		}

		if (NULL != g_charesp) 
			delete g_charesp;

		g_charesp = new dh_challenge_response_t(g_ecc_ctxt->pub_key, g_ecc_ctxt->priv_key);
		return 0;
	}

	if (sizeof(enclave_ctxt_t) != sgx_get_encrypt_txt_len(sdata))
		return -1;

	if (SGX_SUCCESS != sgx_unseal_data(sdata, NULL, 0, (uint8_t*)&udata, &ulen))
		return -1;

	memcpy(g_ecc_ctxt, &udata, sizeof(enclave_ctxt_t));
	// XXX JF TDL: do I need to add code to prevent tampering and verify the keys?

	if (NULL != g_charesp)
		delete g_charesp;

	g_charesp = new dh_challenge_response_t(g_ecc_ctxt->pub_key, g_ecc_ctxt->priv_key);

	return 0;
}

signed int
initialize_mmap(void* base, uint64_t length, uint32_t align, uint64_t seed)
{
	records_t* tmp = NULL;

	if (NULL == base || NULL == g_ecc_ctxt) 
		return -1;

	try {
		tmp = new records_t(&g_ecc_ctxt->gcm_data, base, length, align, seed);
	} catch (std::bad_alloc&) {
		return -1;
	}

	if (NULL != g_records) 
		delete g_records;
	
	g_records = tmp;
	return 0;
}

signed int 
add_user(const char* user, const char* pwd)
{
	if (NULL == user || NULL == pwd || 0 == ::strlen(user) || 0 == ::strlen(pwd) || NULL == g_records)
		return -1;

	if (false == g_records->add_user(user, pwd)) {
		ocall_print(std::string("add_user(): Failed to add user'" + std::string(user)).c_str());
		return -1;
	}

	//ocall_print(std::string("Added user: '" + std::string(user) + "'\n").c_str());
	return 0;
}

signed int 
update_user(const char* user, const char* old_pwd, const char* new_pwd)
{
	user_record_t		user_entry = { 0 };
	std::size_t			pwd_len(0);

	/* This can and should be streamlined to omit the find_user() call
	 * and thus only perform the search of the sector once instead of how
	 * this code presently handles it, which is reading the same chunk of 
	 * memory thrice. I'm doing this as essentially a check and double check
	 * that the code is functioning as anticipated.
	 */
	if (NULL == user || NULL == old_pwd || NULL == new_pwd ||
		0 == ::strlen(user) || 0 == ::strlen(old_pwd) || 0 == ::strlen(new_pwd) ||
		NULL == g_records)
		return -1;

	pwd_len = ::strlen(old_pwd);

	if (false == g_records->find_user(user, user_entry)) 
		return -1;

	if (pwd_len == ::strlen(reinterpret_cast< char* >(&user_entry.pwd[0])) && ! ::memcmp(old_pwd, &user_entry.pwd[0], pwd_len)) //{
		if (false == g_records->update_user(user, new_pwd)) 
			return -1;
	/*	else
			if (false == g_records->check_password(user, new_pwd)) {
				ocall_print("Error occurred somewhere after password was updated such that it no longer authenticates");
				return -1;
			}
	}*/

	return 0;
}

signed int 
check_password(const char* user, const char* pwd)
{
	if (NULL == user || NULL == pwd || 0 == ::strlen(user) || 0 == ::strlen(pwd) || NULL == g_records)
		return -1;

	if (false == g_records->check_password(user, pwd))
		return -1;

	return 0;
}

signed int 
find_user(const char* user, char* pwd, const uint64_t pwd_len)
{
	user_record_t o;

	if (NULL == user || NULL == pwd || 0 == ::strlen(user) || 0 == pwd_len || NULL == g_records)
		return -1;

	if (false == g_records->find_user(user, o))
		return -1;

	::memcpy(pwd, o.pwd, pwd_len < ::strlen(reinterpret_cast< const char* >(o.pwd)) ? pwd_len : ::strlen(reinterpret_cast< const char* >(o.pwd)));
	return 0;
}

signed int
encrypt_records(void)
{
	if (NULL == g_records)
		return -1;

	if (false == g_records->encrypt_records())
		return -1;

	return 0;
}

/* 
public int get_public_key([out,size=key_len] void* key, uint64_t key_len);
public int is_public_key([in,size=key_len] void* key, uint64_t key_len, [out] char match);
public int challenge_response([in,string] const char* user, [in,out,size=txn_len] charesp_transaction_t* txn, uint64_t txn_len);
*/

signed int
get_public_key(void* key, uint64_t key_len)
{
	if (NULL == g_ecc_ctxt || key_len != sizeof(g_ecc_ctxt->pub_key)) 
		return -1;

	std::memcpy(key, &g_ecc_ctxt->pub_key, sizeof(g_ecc_ctxt->pub_key));
	return 0;
}

signed int
is_public_key(void* key, uint64_t key_len, char* match)
{
	if (NULL == g_ecc_ctxt || key_len != sizeof(g_ecc_ctxt->pub_key) || NULL == match)
		return -1;

	*match = 0;

	if ( ! std::memcmp(key, &g_ecc_ctxt->pub_key, key_len))
		*match = 1;

	return 0;
}

/*
 * Because timing is at play here we ought to ensure that each transaction takes a constant period of time
 * so that no side channel information can leak out; todo v2.
 */
signed int
challenge_response(const char* user, void* txn, uint64_t txn_len)
{
	user_record_t			rec			= { 0 };
	charesp_transaction_t*	transaction = static_cast< charesp_transaction_t* >(txn);

	if (txn_len != sizeof(charesp_transaction_t) || NULL == txn || NULL == g_records || NULL == g_charesp) {
		ocall_print("enclave: one or more parameters were invalid");
		return -1;
	}

	/*
	 * I decided for the time being that the performance hit of a find_user()/derive_key() for each interaction
	 * was maybe better than the troubles associated with storing the session key once negotiated. this may not prove
	 * to be the right answer, in which case justin this is about where you want to touch and modify things to store the
	 * session key instead of recalculating it each iteraction.
	 */

//	ocall_print(std::string("enclave: challenge_response(): attempting to locate user '" + std::string(user) + "'").c_str());

	if (false == g_records->find_user(user, rec)) {
		ocall_print("enclave: challenge_response(): no such user identified, authentication failure");
		return -1;
	}

//	ocall_print("enclave: challenge_response(): valid user encountered, initiating challenge response authentication");

	if (false == g_charesp->challenge_response(rec.pwd, *transaction)) {
		ocall_print("enclave: challenge_response(): failure in challenge_response function");
		return -1;
	}

	//ocall_print("enclave: challenge_response(): function completed successfully");
	return 0;
}

/*#include "sgx_key.h"
#include "sgx_report.h"
#include "sgx_utils.h"
#include "sgx_attributes.h"


#define MISC_NON_SECURITY_BITS      0x0FFFFFFF  //* bit[27:0]: have no security implications 
#define TSEAL_DEFAULT_MISCMASK      (~MISC_NON_SECURITY_BITS)

#define FLAGS_NON_SECURITY_BITS     (0xFFFFFFFFFFFFC0ULL | 0x0000000000000004ULL | 0x0000000000000010ULL| 0x0000000000000020ULL)
#define TSEAL_DEFAULT_FLAGSMASK     (~FLAGS_NON_SECURITY_BITS)

signed int 
print_key(void)
{
	sgx_key_request_t	kr;
	sgx_key_id_t		kid;
	sgx_report_t		report;
	sgx_status_t		ret = SGX_SUCCESS;
	sgx_attributes_t	attribute_mask;
	sgx_key_128bit_t	seal_key;
	

	memset(&attribute_mask, 0, sizeof(sgx_attributes_t));
	memset(&kr, 0, sizeof(sgx_key_request_t));
	memset(&report, 0, sizeof(sgx_report_t));
	memset(&kid, 0, sizeof(sgx_key_id_t));
	memset(&seal_key, 0, sizeof(sgx_key_128bit_t));

	attribute_mask.flags = TSEAL_DEFAULT_FLAGSMASK;
	attribute_mask.xfrm = 0x0;

	ret = sgx_create_report(NULL, NULL, &report);

	if (SGX_SUCCESS != ret) {
		ocall_print("Error in sgx_create_report()\n");
		return -1;
	}

	ret = sgx_read_rand(reinterpret_cast<uint8_t *>(&kid), sizeof(sgx_key_id_t));

	if (SGX_SUCCESS != ret) {
		ocall_print("Error in sgx_read_rand()\n");
		return -1;
	}

	memcpy(&(kr.cpu_svn), &(report.body.cpu_svn), sizeof(sgx_cpu_svn_t));
	memcpy(&(kr.isv_svn), &(report.body.isv_svn), sizeof(sgx_isv_svn_t));
	kr.key_name = SGX_KEYSELECT_SEAL;
	kr.key_policy = SGX_KEYPOLICY_MRSIGNER;
	kr.attribute_mask.flags = attribute_mask.flags;
	kr.attribute_mask.xfrm = attribute_mask.xfrm;
	memcpy(&(kr.key_id), &kid, sizeof(sgx_key_id_t));
	kr.misc_mask = TSEAL_DEFAULT_MISCMASK;

	ret = sgx_get_key(&kr, &seal_key);

	if (SGX_SUCCESS != ret) {
		ocall_print("Error in sgx_get_key()\n");
		return -1;
	}

	std::string kstr("MRSIGNER KEY: ");
	for (std::size_t idx = 0; idx < sizeof(sgx_key_128bit_t); idx++) {
		kstr += xitoa("%.02x", (unsigned char)seal_key[idx]);
		kstr += ":";
	}

	kstr = kstr.substr(0, kstr.length() - 1);
	ocall_print(kstr.c_str());

	kr.key_policy = SGX_KEYPOLICY_MRENCLAVE;
	ret = sgx_get_key(&kr, &seal_key);

	if (SGX_SUCCESS != ret) {
		ocall_print("Error in sgx_get_key()\n");
		return -1;
	}

	kstr = "MRENCLAVE KEY: ";
	for (std::size_t idx = 0; idx < sizeof(sgx_key_128bit_t); idx++) {
		kstr += xitoa("%.02x", (unsigned char)seal_key[idx]);
		kstr += ":";
	}

	kstr = kstr.substr(0, kstr.length() - 1);
	ocall_print(kstr.c_str());

	return 0;
}*/