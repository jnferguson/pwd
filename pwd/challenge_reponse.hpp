#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <stdexcept>
#include <exception>
#include <string>

#include "sgx_tcrypto.h"
#include "sgx_trts.h"

#include "common.hpp"
#include "pwd_t.h"
#include "util.hpp"

#define CR_AES_BLOCK_SIZE 16

class dh_challenge_response_t {

	private:
		sgx_sha_state_handle_t	m_sha256_handle;
		sgx_ecc_state_handle_t	m_ecc256_handle;
		ec256_public_key_t		m_public;
		ec256_private_key_t		m_private;
		const uint32_t			m_inc_bits;
		uint8_t					m_ipad[SHA256_SIZE]; 
		uint8_t					m_opad[SHA256_SIZE];

		bool initialize_server_hello(const aes_ctr_128bit_key_t&, charesp_server_hello_t&);
		bool initialize_server_response(const aes_ctr_128bit_key_t&, charesp_server_response_t&, const sha256_hash_t&);
		bool get_server_hello_plain(charesp_server_hello_t&, charesp_server_hello_t&, const aes_ctr_128bit_key_t&);
		bool get_client_response_plain(charesp_client_response_t&, charesp_client_response_t&, const aes_ctr_128bit_key_t&);
		bool verify_server_hello(const charesp_server_hello_t&);
		bool verify_client_response(const ec256_public_key_t&, charesp_client_response_t&);

	protected:
		bool derive_key(const uint8_t*, ec256_public_key_t&, aes_ctr_128bit_key_t&);
		bool sha256(const uint8_t*, size_t, sha256_hash_t&);
		bool sha256_hmac(const uint8_t*, size_t, const uint8_t*, size_t, sha256_hash_t&);
		
		bool verify_ecdsa(const uint8_t*, size_t, ec256_signature_t&, const ec256_public_key_t&);
		bool sign_ecdsa(const uint8_t*, size_t, ec256_signature_t&);


		bool aes_ctr_encrypt(const uint8_t* src, const size_t src_siz, uint8_t* dst, const size_t dst_siz, const uint8_t* nonce, const aes_ctr_128bit_key_t& key);
		bool aes_ctr_decrypt(const uint8_t* src, const size_t src_siz, uint8_t* dst, const size_t dst_siz, const uint8_t* nonce, const aes_ctr_128bit_key_t& key);

	public:
		dh_challenge_response_t(void);
		dh_challenge_response_t(ec256_public_key_t&, ec256_private_key_t&, uint32_t ctr_inc_bits = 0x20);
		~dh_challenge_response_t(void);

		void private_key(uint8_t*, std::size_t&, bool get_or_set = true);
		void public_key(uint8_t*, std::size_t&, bool get_or_set = true);

		bool process_authentication(const uint8_t*, const aes_ctr_128bit_key_t&, charesp_transaction_t&);
		bool challenge_response(const uint8_t*, charesp_transaction_t&);
};
