#include "stdafx.h"
#include "sha256.hpp"


// I'm not terribly certain why I am having to cast nullptr, but HCRYPTPROV and HCRYPTHASH are typedef'd to UONG_PTR
// and so I'm guessing its some intellisense garbage from the stack of typedef's or similar
sha256_t::sha256_t(void) : m_sha256_handle(nullptr)
{
	
	if (SGX_SUCCESS != sgx_replace_t::sha256_init(&m_sha256_handle))
		throw std::runtime_error("...");

	::memset(&m_ipad[0], 0x5C, sizeof(m_ipad));
	::memset(&m_opad[0], 0x36, sizeof(m_opad));

	return;
}

sha256_t::~sha256_t(void)
{
	sgx_replace_t::sha256_close(m_sha256_handle);
	return;
}

bool 
sha256_t::hash(const char* in, const std::size_t siz, sha256_hash_t& hash)
{
	return this->hash(reinterpret_cast< const uint8_t* >(in), siz, hash);
}

bool 
sha256_t::hash(const std::string& in, sha256_hash_t& hash)
{
	return this->hash(reinterpret_cast< const uint8_t* >(in.data()), in.length(), hash);
}

bool 
sha256_t::hash(const std::vector< uint8_t >& in, sha256_hash_t& hash)
{
	return this->hash(reinterpret_cast< const uint8_t* >(in.data()), in.size(), hash);
}

bool 
sha256_t::hash(const std::vector< char >& in, sha256_hash_t& hash)
{
	return this->hash(in.data(), in.size(), hash);
}

bool
sha256_t::hash(const uint8_t* in, size_t siz, sha256_hash_t& hash)
{
	sgx_sha_state_handle_t	hnd = NULL;

	if (siz > UINT32_MAX)
		return false;

	printf("sha256_t::hash(): IN (%u):\n", siz);
	const uint8_t* ptr = in;
	for ( std::size_t idx = 0; idx < siz; idx++ )
		printf("%x", (uint8_t)ptr[ idx ]);
	printf("\n");

	if (SGX_SUCCESS != sgx_replace_t::sha256_update(in, static_cast< uint32_t >(siz), m_sha256_handle))
		return false;

	if (SGX_SUCCESS != sgx_replace_t::sha256_get_hash(m_sha256_handle, &hash))
		return false;

	printf("sha256_t::hash(): HASH:\n");
	ptr = (const uint8_t*)&hash;
	for ( std::size_t idx = 0; idx < sizeof(sha256_hash_t); idx++ )
		printf("%x", (uint8_t)ptr[ idx ]);
	printf("\n");

	return true;
}

bool 
sha256_t::hmac(const char* msg, std::size_t msg_siz, const uint8_t* key, std::size_t key_siz, sha256_hash_t& hash)
{
	return this->hmac(reinterpret_cast< const uint8_t* >(msg), msg_siz, reinterpret_cast< const uint8_t* >(key), key_siz, hash);
}

bool 
sha256_t::hmac(const std::string& msg, const std::string& key, sha256_hash_t& hash)
{
	return this->hmac(	reinterpret_cast< const uint8_t * >(msg.data()), msg.length(), 
						reinterpret_cast< const uint8_t* >(key.data()), key.length(), hash);
}

bool 
sha256_t::hmac(const std::vector< uint8_t >& msg, const std::vector< uint8_t >& key, sha256_hash_t& hash)
{
	return this->hmac(msg.data(), msg.size(), key.data(), key.size(), hash);
}

bool 
sha256_t::hmac(const std::vector< char >& msg, const std::vector< char >& key, sha256_hash_t& hash)
{
	return this->hmac(	reinterpret_cast< const uint8_t* >(msg.data()), msg.size(), 
						reinterpret_cast< const uint8_t* >(key.data()), key.size(), hash);
}

bool
sha256_t::hmac(const uint8_t* msg, size_t msg_siz, const uint8_t* key, size_t key_siz, sha256_hash_t& hash)
{
	uint8_t			mod_key[SHA256_SIZE] = { 0 };
	uint8_t			ipad[SHA256_SIZE] = { 0 };
	uint8_t			opad[SHA256_SIZE] = { 0 };
	sha256_hash_t	inner = { 0 };
	const size_t	scratch_len = sizeof(opad) + sizeof(sha256_hash_t);
	uint8_t			scratch[scratch_len] = { 0 };

	memset(&mod_key[0], 0, sizeof(mod_key));

	if (SHA256_SIZE < key_siz) {
		sha256_hash_t	key_hash = { 0 };

		if (false == this->hash(key, key_siz, key_hash))
			return false;

		if (sizeof(key_hash) != sizeof(mod_key))
			throw std::runtime_error("...");

		::memcpy(&mod_key[0], &key_hash, sizeof(mod_key));

	}
	else if (SHA256_SIZE > key_siz)
		::memcpy(&mod_key[0], key, key_siz);

	for (std::size_t idx = 0; idx < sizeof(m_ipad); idx++)
		ipad[idx] = m_ipad[idx] ^ mod_key[idx];
	for (std::size_t idx = 0; idx < sizeof(opad); idx++)
		opad[idx] = m_opad[idx] ^ mod_key[idx];

	if (false == this->hash(msg, msg_siz, inner))
		return false;

	::memcpy(&scratch[0], &opad[0], sizeof(opad));
	::memcpy(&scratch[ sizeof(opad) ], &inner, sizeof(sha256_hash_t)); 

	if (false == this->hash(&scratch[0], sizeof(scratch), hash))
		return false;

	return true;
}

std::string 
sha256_t::hash_to_string(const sha256_hash_t& hash, bool prepend) const
{
	const std::string	hex_chars("0123456789abcdef");
	std::string			ret(true == prepend ? "0x" : "");

	for (auto& itr : hash) {
		ret += hex_chars[itr >> 4];
		ret += hex_chars[itr & 0x0F];
	}

	return ret;
}