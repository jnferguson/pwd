#pragma once
#include <cstdint>
#include <string>
#include <cstdlib>
#include <cstring>
#include <string.h>

#include <ippcp.h>
#include "sgx_error.h"
#include "sgx_tcrypto.h"

#ifndef ERROR_BREAK
#define ERROR_BREAK(x)  if(x != ippStsNoErr){break;}
#endif
#ifndef NULL_BREAK
#define NULL_BREAK(x)   if(!x){break;}
#endif
#ifndef SAFE_FREE
#define SAFE_FREE(ptr) {if (NULL != (ptr)) {free(ptr); (ptr)=NULL;}}
#endif 

#define UNUSED(val) (void)(val)
#define	ROUND_TO(x, align)  (((x) + ((align)-1)) & ~((align)-1))

typedef void* ecc_state_handle_t;

const uint32_t _nistp256_r[] = {
	0xFC632551, 0xF3B9CAC2, 0xA7179E84, 0xBCE6FAAD, 0xFFFFFFFF, 0xFFFFFFFF,
	0x00000000, 0xFFFFFFFF };

/* This is an overload class that is a copy/paste of portions of the SGX library wrappers around IPP
 * because for whatever reason the crypto interfaces from SGX are only accessible in the trusted libraries for the enclave code
 * because I'm only writing the C++ portions of the client for debugging and testing purposes, this thoroughly suffices.
 */
class sgx_replace_t
{
	private:
	protected:
		static IppStatus _ipp_newBN(const Ipp32u *, int, IppsBigNumState **);
		static void _ipp_secure_free_BN(IppsBigNumState*, int);
		static IppStatus __STDCALL _ipp_DRNGen(Ipp32u*, int, void*);
		static inline IppStatus check_copy_size(size_t, size_t);
		static void _secure_free_cmac128_state(IppsAES_CMACState*);


	public:
		sgx_replace_t();
		~sgx_replace_t();

		static sgx_status_t SGXAPI read_rand(uint8_t*, size_t);
		static sgx_status_t ecc256_open_context(ecc_state_handle_t*);	
		static sgx_status_t ecc256_create_key_pair(sgx_ec256_private_t*, sgx_ec256_public_t*, sgx_ecc_state_handle_t);
		static sgx_status_t ecc256_close_context(ecc_state_handle_t);
		static sgx_status_t ecc256_check_point(const sgx_ec256_public_t*, const ecc_state_handle_t, int *);
		static sgx_status_t ecc256_compute_shared_dhkey(sgx_ec256_private_t*, sgx_ec256_public_t*, sgx_ec256_dh_shared_t*, ecc_state_handle_t);
		static sgx_status_t cmac128_init(const sgx_cmac_128bit_key_t*, sgx_cmac_state_handle_t*);
		static sgx_status_t cmac128_update(const uint8_t*, uint32_t, sgx_cmac_state_handle_t);
		static sgx_status_t cmac128_final(sgx_cmac_state_handle_t, sgx_cmac_128bit_tag_t*);
		static sgx_status_t cmac128_close(sgx_cmac_state_handle_t);
		static sgx_status_t ecdsa_verify(const uint8_t*, uint32_t, const sgx_ec256_public_t*, sgx_ec256_signature_t*, uint8_t*, ecc_state_handle_t);
		static sgx_status_t ecdsa_sign(const uint8_t*, uint32_t, sgx_ec256_private_t*, sgx_ec256_signature_t*, ecc_state_handle_t);
		static sgx_status_t aes_ctr_encrypt(const sgx_aes_ctr_128bit_key_t*, const uint8_t*, const uint32_t, uint8_t*, const uint32_t, uint8_t*);
		static sgx_status_t aes_ctr_decrypt(const sgx_aes_ctr_128bit_key_t*, const uint8_t*, const uint32_t, uint8_t*, const uint32_t, uint8_t*);
		static sgx_status_t sha256_init(sgx_sha_state_handle_t*);
		static sgx_status_t sha256_update(const uint8_t*, uint32_t, sgx_sha_state_handle_t);
		static sgx_status_t sha256_close(sgx_sha_state_handle_t);
		static sgx_status_t sha256_get_hash(sgx_sha_state_handle_t, sgx_sha256_hash_t*);

};

