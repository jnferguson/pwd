#pragma once

#include <cstdint>
#include <string>
#include <array>
#include <vector>

#define SHA256LEN 32
#define SHA256_SIZE SHA256LEN
//typedef std::array< uint8_t, SHA256LEN > sha256_hash_t;
#include "sgx_replace.hpp"

typedef sgx_sha256_hash_t sha256_hash_t;

class sha256_t {
	private:
	protected:
		uint8_t					m_ipad[SHA256LEN];
		uint8_t					m_opad[SHA256LEN];
		sgx_sha_state_handle_t	m_sha256_handle;

	public:
		sha256_t(void);
		~sha256_t(void);

		bool hash(const uint8_t*, const size_t, sha256_hash_t&);
		bool hash(const char*, const std::size_t, sha256_hash_t&);
		bool hash(const std::string&, sha256_hash_t&);
		bool hash(const std::vector< uint8_t >&, sha256_hash_t&);
		bool hash(const std::vector< char >&, sha256_hash_t&);

		bool hmac(const uint8_t*, std::size_t, const uint8_t*, std::size_t, sha256_hash_t&);
		bool hmac(const char*, std::size_t, const uint8_t*, std::size_t, sha256_hash_t&);
		bool hmac(const std::string&, const std::string&, sha256_hash_t&);
		bool hmac(const std::vector< uint8_t >&, const std::vector< uint8_t >&, sha256_hash_t&);
		bool hmac(const std::vector< char >&, const std::vector< char >&, sha256_hash_t&);

		std::string hash_to_string(const sha256_hash_t&, bool prepend = true) const;

};

