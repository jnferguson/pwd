#include "stdafx.h"
#include "ecc256_keypair.hpp"

ecc256_keypair_t::ecc256_keypair_t(void) : m_handle(nullptr)
{
	std::memset(&m_public, 0, sizeof(m_public));
	std::memset(&m_private, 0, sizeof(m_private));
	std::memset(&m_shared, 0, sizeof(m_shared));

	if (SGX_SUCCESS != sgx_replace_t::ecc256_open_context(&m_handle))
		throw std::runtime_error("...");

	if (SGX_SUCCESS != sgx_replace_t::ecc256_create_key_pair(&m_private, &m_public, m_handle))
		throw std::runtime_error("...");

	return;
}

ecc256_keypair_t::~ecc256_keypair_t(void)
{
	sgx_replace_t::ecc256_close_context(m_handle);
	m_handle = nullptr;

	std::memset(&m_private, 0, sizeof(m_private));
	std::memset(&m_public, 0, sizeof(m_public));
	return;
}

bool
ecc256_keypair_t::generate_ecdh_keys(void)
{
	return true;
}


const sgx_ec256_public_t&
ecc256_keypair_t::public_key(void) const 
{ 
	return m_public; 
}

const sgx_ec256_private_t&
ecc256_keypair_t::private_key(void) const 
{ 
	return m_private; 
}

const sgx_ec256_dh_shared_t& 
ecc256_keypair_t::shared_key(void) const 
{ 
	return m_shared; 
}

std::string
ecc256_keypair_t::to_public_string(void)
{
	base64_t		b64;
	std::string		ret("");

	ret.resize(sizeof(m_public));
	std::memset(&ret[ 0 ], 0x00, ret.size());
	std::memcpy(&ret[0], &m_public, ret.size());

	return b64.encode(ret);
}

std::string
ecc256_keypair_t::to_private_string(void)
{
	base64_t		b64;
	std::string		ret("");

	ret.resize(sizeof(m_private));
	std::memcpy(&ret[0], &m_private, ret.size());
	return b64.encode(ret);
}

bool
ecc256_keypair_t::from_public_string(const std::string& pub)
{
	base64_t	b64;
	std::string key(b64.decode(pub));

	if (sizeof(m_public) != key.size())
		return false;

	std::memcpy(&m_public, &key[0], key.size());
	return check_point(m_public);
}

bool
ecc256_keypair_t::from_private_string(const std::string& priv)
{
	base64_t	b64;
	std::string	key(b64.encode(priv));

	if (sizeof(m_private) != key.size())
		return false;

	std::memcpy(&m_private, &key[0], key.size());
	return true;
}

bool
ecc256_keypair_t::check_point(const sgx_ec256_public_t& pub)
{
	signed int valid(0);

	if (SGX_SUCCESS != sgx_replace_t::ecc256_check_point(&pub, m_handle, &valid))
		return false;

	if (1 != valid)
		return false;

	return true;
}

bool
ecc256_keypair_t::derive_key(const uint8_t* pwd, sgx_ec256_public_t& pub_key, aes_ctr_128bit_key_t& session_key)
{
	sgx_ec256_dh_shared_t		dhshared = { 0 };
	sgx_cmac_128bit_key_t		cmac_key = { 0 };
	sgx_cmac_state_handle_t		cmac_hnd = NULL;
	sgx_cmac_128bit_tag_t		cmac_tag = { 0 };

	if (SGX_SUCCESS != sgx_replace_t::ecc256_compute_shared_dhkey(&m_private, &pub_key, &dhshared, m_handle))
		return false;

	std::memset(&cmac_key, 0, sizeof(cmac_key));

	if (SGX_SUCCESS != sgx_replace_t::cmac128_init(&cmac_key, &cmac_hnd))
		return false;

	if (SGX_SUCCESS != sgx_replace_t::cmac128_update(reinterpret_cast< const uint8_t* >(&dhshared),
		sizeof(sgx_ec256_dh_shared_t),
		cmac_hnd))

		return false;

	if (SGX_SUCCESS != sgx_replace_t::cmac128_update(&pwd[0], ::strlen(reinterpret_cast<const char*>(&pwd[0])), cmac_hnd))
		return false;

	if (SGX_SUCCESS != sgx_replace_t::cmac128_final(cmac_hnd, &cmac_tag))
		return false;

	if (SGX_SUCCESS != sgx_replace_t::cmac128_close(cmac_hnd))
		return false;

	std::memcpy(&session_key, &cmac_tag, sizeof(session_key));
	return true;
}

bool
ecc256_keypair_t::verify(const std::string& data, const sgx_ec256_public_t& pub, sgx_ec256_signature_t& sig)
{
	unsigned char ret(0x00);

	if ( SGX_SUCCESS != sgx_replace_t::ecdsa_verify(reinterpret_cast<const unsigned char*>( data.data() ), data.length(), &pub, &sig, &ret, m_handle) )
		return false;

	return true;
}

bool
ecc256_keypair_t::verify(const uint8_t* data, std::size_t length, const sgx_ec256_public_t& pub, sgx_ec256_signature_t& sig)
{
	unsigned char ret(0x00);

	if ( nullptr == data )
		return false;

	if ( SGX_SUCCESS != sgx_replace_t::ecdsa_verify(data, length, &pub, &sig, &ret, m_handle) )
		return false;

	return true;
}

bool
ecc256_keypair_t::sign(const uint8_t* msg, size_t siz, ec256_signature_t& sig)
{
	if (NULL == msg || 0 == siz || UINT32_MAX < siz)
		return false;

	if (SGX_SUCCESS != sgx_replace_t::ecdsa_sign(msg, siz, &m_private, &sig, m_handle))
		return false;

	return true;
}

bool
ecc256_keypair_t::aes_ctr_encrypt(	const uint8_t* ct, const size_t ct_siz, uint8_t* pt, const size_t pt_siz,
									const uint8_t* nonce, const aes_ctr_128bit_key_t& key, const uint32_t inc_bits)
{
	uint8_t tmp_nonce[CR_AES_BLOCK_SIZE] = { 0 };

	/* It's not stated anywhere, but the counter/nonce is 128 bits in length; this might be a strict requirement
	* that the variable be the block size, I'm not positive. Internally however anything longer than this is ignored
	* and anything shorter causes an out-of-bounds read access.
	*
	* The Intel crypto code is horrible to deal with an has tons of assumptions baked into it.
	*/

	if ( NULL == ct || 0 == ct_siz || NULL == pt || 0 == pt_siz || ct_siz > pt_siz || NULL == nonce ) 
		return false;

	/*
	* Intel APIs have a bizarre affinity with 32-bit integers and it would probably be easier if we
	* continued that affinity, however because I've elected to take a size_t as a parameter, I need to
	* explicitly verify that we won't accidentally truncate a message or produce some sort of garbled
	* partial cipher-text partial plain-text (although I think we would just end up with a truncated message)
	* in practice, this is a non-issue because the messages are sufficiently short as to be well within the 4GB
	* bounds.
	*/
	if ( UINT32_MAX < ct_siz || UINT32_MAX < pt_siz ) 
		return false;

	/*
	* We make this copy of the nonce because the variable is marked non-const in the API and I'm not
	* going to go through it to such an extent to verify that the nonce is never actually modified; it doesn't
	* appear to be-- the first 16-bytes and only the first 16-bytes are copied into a counter variable, but still.
	*/

	::memcpy(&tmp_nonce[0], nonce, sizeof(tmp_nonce));

	if ( SGX_SUCCESS != sgx_replace_t::aes_ctr_encrypt(&key, ct, static_cast<uint32_t>( ct_siz ), &tmp_nonce[ 0 ], inc_bits, pt) ) 
		return false;

	return true;
}

bool
ecc256_keypair_t::aes_ctr_decrypt(	const uint8_t* ct, const size_t ct_siz, uint8_t* pt, const size_t pt_siz,
									const uint8_t* nonce, const aes_ctr_128bit_key_t& key, const uint32_t inc_bits)
{
	uint8_t tmp_nonce[CR_AES_BLOCK_SIZE] = { 0 };

	/*
	* It's not stated anywhere, but the counter/nonce is 128 bits in length; this might be a strict requirement
	* that the variable be the block size, I'm not positive. Internally however anything longer than this is ignored
	* and anything shorter causes an out-of-bounds read access.
	*
	* The Intel crypto code is horrible to deal with an has tons of assumptions baked into it.
	*/
	if ( NULL == ct || 0 == ct_siz || NULL == pt || 0 == pt_siz || ct_siz > pt_siz || NULL == nonce ) 
		return false;

	/*
	* Intel APIs have a bizarre affinity with 32-bit integers and it would probably be easier if we
	* continued that affinity, however because I've elected to take a size_t as a parameter, I need to
	* explicitly verify that we won't accidentally truncate a message or produce some sort of garbled
	* partial cipher-text partial plain-text (although I think we would just end up with a truncated message)
	* in practice, this is a non-issue because the messages are sufficiently short as to be well within the 4GB
	* bounds.
	*/
	if ( UINT32_MAX < ct_siz || UINT32_MAX < pt_siz ) 
		return false;

	/*
	* We make this copy of the nonce because the variable is marked non-const in the API and I'm not
	* going to go through it to such an extent to verify that the nonce is never actually modified; it doesn't
	* appear to be-- the first 16-bytes and only the first 16-bytes are copied into a counter variable, but still.
	*/

	::memcpy(&tmp_nonce[0], nonce, sizeof(tmp_nonce));

	if ( SGX_SUCCESS != sgx_replace_t::aes_ctr_decrypt(&key, ct, static_cast<uint32_t>( ct_siz ), &tmp_nonce[ 0 ], inc_bits, pt) )
		return false;

	return true;
}
