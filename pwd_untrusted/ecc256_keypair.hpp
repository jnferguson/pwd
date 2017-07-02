#pragma once
#include <cstdint>
#include <string>
#include <vector>

#include "enclave.hpp"		// XXX JF FIXME - replace SGX crypto (trusted usage only blah)
#include "base64.hpp"
#include "sgx_replace.hpp"

#define CR_AES_BLOCK_SIZE 16

typedef struct {
	void*		key;
	std::size_t				size;
	std::vector< uint8_t >	buffer;

	std::string to_string(void) const
	{
		std::string ret("");
		base64_t	b64;

		for (std::size_t idx = sizeof(void*); idx < buffer.size(); idx++)
			ret += buffer[idx];

		return b64.encode(ret);
	}
} ecc_key_t;

class ecc256_keypair_t {
	private:
	protected:
		sgx_ec256_public_t			m_public;
		sgx_ec256_private_t			m_private;
		sgx_ecc_state_handle_t		m_handle;
		sgx_ec256_dh_shared_t		m_shared;

		bool generate_ecdh_keys(void);

	public:
		ecc256_keypair_t(void);
		~ecc256_keypair_t(void);

		const sgx_ec256_public_t& public_key(void) const;
		const sgx_ec256_private_t& private_key(void) const;

		//const sgx_ec256_private_t& private_key(void) const;
		const sgx_ec256_dh_shared_t& shared_key(void) const;

		std::string to_public_string(void);
		std::string to_private_string(void);

		bool from_public_string(const std::string&);
		bool from_private_string(const std::string&);

		bool check_point(const sgx_ec256_public_t&);

		bool derive_key(const uint8_t*, ec256_public_key_t&, aes_ctr_128bit_key_t&);

		bool verify(const std::string&, const sgx_ec256_public_t&, sgx_ec256_signature_t&);
		bool verify(const uint8_t*, std::size_t, const sgx_ec256_public_t&, sgx_ec256_signature_t&);

		bool sign(const uint8_t*, size_t, ec256_signature_t&);

		bool aes_ctr_encrypt(const uint8_t*, const size_t, uint8_t*, const size_t, const uint8_t*, const aes_ctr_128bit_key_t&, const uint32_t);
		bool aes_ctr_decrypt(const uint8_t*, const size_t, uint8_t*, const size_t, const uint8_t*, const aes_ctr_128bit_key_t&, const uint32_t);
};

