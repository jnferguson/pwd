#include "challenge_reponse.hpp"

dh_challenge_response_t::dh_challenge_response_t(ec256_public_key_t& pub_key, ec256_private_key_t& priv_key, uint32_t ctr_inc_bits)
	: m_sha256_handle(NULL), m_ecc256_handle(NULL), m_public(pub_key), m_private(priv_key), m_inc_bits(ctr_inc_bits)
{
	static const char* str("...");

	if (SGX_SUCCESS != ::sgx_sha256_init(&m_sha256_handle))
		throw std::runtime_error("...");

	if (SGX_SUCCESS != ::sgx_ecc256_open_context(&m_ecc256_handle))
		throw std::runtime_error("...");

	::memset(&m_ipad[0], 0x5C, sizeof(m_ipad));
	::memset(&m_opad[0], 0x36, sizeof(m_opad));

	return;
}

dh_challenge_response_t::dh_challenge_response_t(void)
	: m_sha256_handle(NULL), m_ecc256_handle(NULL), m_inc_bits(0x20)
{
	static const char* str("...");

	if (SGX_SUCCESS != ::sgx_sha256_init(&m_sha256_handle))
		throw std::runtime_error("...");

	if (SGX_SUCCESS != ::sgx_ecc256_open_context(&m_ecc256_handle))
		throw std::runtime_error("...");

	::memset(&m_ipad[0], 0x5C, sizeof(m_ipad));
	::memset(&m_opad[0], 0x36, sizeof(m_opad));
	::memset(&m_public, 0, sizeof(m_public));
	::memset(&m_private, 0, sizeof(m_private));
	return;
}

dh_challenge_response_t::~dh_challenge_response_t(void)
{
	::sgx_sha256_close(m_sha256_handle); // potential leak
	::sgx_ecc256_close_context(m_ecc256_handle); // potential leak

	return;
}

bool 
dh_challenge_response_t::sha256(const uint8_t* in, size_t siz, sha256_hash_t& hash)
{
	sgx_sha_state_handle_t	hnd = NULL;

	if (siz > UINT32_MAX)
		return false;

	std::string str = "dh_challenge_response_t::sha256(): IN ";
	const uint8_t* ptr = in;
	str += itoa_64("(%u):\n", siz);
	for ( std::size_t idx = 0; idx < siz; idx++ )
		str += itoa_8("%x", ptr[ idx ]);
	str += "\n";

	if (SGX_SUCCESS != ::sgx_sha256_update(in, static_cast< uint32_t >(siz), m_sha256_handle))
		return false;

	if (SGX_SUCCESS != ::sgx_sha256_get_hash(m_sha256_handle, &hash))
		return false;

	str += "dh_challenge_response_t::sha256(): HASH:\n";
	ptr = (const uint8_t*)&hash;
	for ( std::size_t idx = 0; idx < sizeof(sha256_hash_t); idx++ )
		str += itoa_8("%x", ptr[ idx ]);
	str += "\n";
	ocall_print(str.c_str());

	return true;
}

bool
dh_challenge_response_t::sha256_hmac(const uint8_t* msg, size_t msg_siz, const uint8_t* key, size_t key_siz, sha256_hash_t& hash)
{
	uint8_t			mod_key[SHA256_SIZE]	= { 0 };
	uint8_t			ipad[SHA256_SIZE]		= { 0 };
	uint8_t			opad[SHA256_SIZE]		= { 0 };
	sha256_hash_t	inner					= { 0 };
	const size_t	scratch_len				= sizeof(opad) + sizeof(sha256_hash_t);
	uint8_t			scratch[scratch_len]	= { 0 };

	::memset_s(&mod_key[0], sizeof(mod_key), 0, sizeof(mod_key));

	if (SHA256_SIZE < key_siz) {
		sha256_hash_t	key_hash = { 0 };

		if (false == sha256(key, key_siz, key_hash))
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

	/*std::string tstr("dh_challenge_response_t::sha256_hmac(): MSG:\n");
	const uint8_t* tptr = (uint8_t*)msg;
	for ( std::size_t idx = 0; idx < msg_siz; idx++ )
		tstr += itoa_8("%x", tptr[ idx ]);
	tstr += itoa_64(" (%x)\n", msg_siz);
	ocall_print(tstr.c_str());*/

	if (false == sha256(msg, msg_siz, inner))
		return false;

	/*std::string str("dh_challenge_response_t::sha256_hmac(): INNER:\n");
	const uint8_t* ptr = (uint8_t*)&inner;
	for ( std::size_t idx = 0; idx < sizeof(sha256_hash_t); idx++ )
		str += itoa_8("%x", ptr[ idx ]);
	str += "\n";
	ocall_print(str.c_str());*/

	::memcpy(&scratch[0], &opad[0], sizeof(opad));
	::memcpy(&scratch[sizeof(opad)], &inner, sizeof(sha256_hash_t));

	if (false == sha256(&scratch[0], sizeof(scratch), hash))
		return false;

	return true;
}

bool
dh_challenge_response_t::verify_ecdsa(const uint8_t* msg, size_t siz, ec256_signature_t& sig, const ec256_public_key_t& key)
{
	uint8_t res = SGX_EC_INVALID_SIGNATURE;

	if (NULL == msg || 0 == siz || UINT32_MAX < siz) 
		return false;

	if (SGX_SUCCESS != ::sgx_ecdsa_verify(msg, siz, &key, &sig, &res, m_ecc256_handle)) 
		return false;

	if (SGX_EC_VALID != res) 
		return false;

	return true;
}

bool
dh_challenge_response_t::sign_ecdsa(const uint8_t* msg, size_t siz, ec256_signature_t& sig)
{
	if (NULL == msg || 0 == siz || UINT32_MAX < siz)
		return false;

	if (SGX_SUCCESS != ::sgx_ecdsa_sign(msg, siz, &m_private, &sig, m_ecc256_handle))
		return false;

	return true;
}

bool
dh_challenge_response_t::aes_ctr_encrypt(const uint8_t* src, const size_t src_siz, uint8_t* dst, const size_t dst_siz,
										const uint8_t* nonce, const aes_ctr_128bit_key_t& key)
{
	uint8_t tmp_nonce[CR_NONCE_SIZE] = { 0 };

	/* It's not stated anywhere, but the counter/nonce is 128 bits in length; this might be a strict requirement
	* that the variable be the block size, I'm not positive. Internally however anything longer than this is ignored
	* and anything shorter causes an out-of-bounds read access.
	*
	* The Intel crypto code is horrible to deal with an has tons of assumptions baked into it.
	*/
	if (NULL == src || 0 == src_siz || NULL == dst || 0 == dst_siz || src_siz > dst_siz || NULL == nonce) {
		ocall_print("dh_challenge_response_t::aes_ctr_encrypt(): one or more parameters were invalid");
		return false;
	}

	/*
	* Intel APIs have a bizarre affinity with 32-bit integers and it would probably be easier if we
	* continued that affinity, however because I've elected to take a size_t as a parameter, I need to
	* explicitly verify that we won't accidentally truncate a message or produce some sort of garbled
	* partial cipher-text partial plain-text (although I think we would just end up with a truncated message)
	* in practice, this is a non-issue because the messages are sufficiently short as to be well within the 4GB
	* bounds.
	*/
	if (UINT32_MAX <= src_siz || UINT32_MAX <= dst_siz) {
		ocall_print("dh_challenge_response_t::aes_ctr_encrypt(): cipher and/or plain-text size exceeds permissible upper bounds");
		return false;
	}
	/*
	* We make this copy of the nonce because the variable is marked non-const in the API and I'm not
	* going to go through it to such an extent to verify that the nonce is never actually modified; it doesn't
	* appear to be-- the first 16-bytes and only the first 16-bytes are copied into a counter variable, but still.
	*/

	::memcpy(&tmp_nonce[0], nonce, sizeof(tmp_nonce));


	if (SGX_SUCCESS != ::sgx_aes_ctr_encrypt(&key, src, static_cast<uint32_t>(src_siz), &tmp_nonce[0], m_inc_bits, dst)) {
		ocall_print("dh_challenge_response_t::aes_ctr_encrypt(): failure in sgx_aes_ctr_encrypt()");
		return false;
	}

	return true;
}

bool
dh_challenge_response_t::aes_ctr_decrypt(const uint8_t* src, const size_t src_siz, uint8_t* dst, const size_t dst_siz,
										const uint8_t* nonce, const aes_ctr_128bit_key_t& key)
{
	uint8_t tmp_nonce[CR_AES_BLOCK_SIZE] = { 0 };

	/*
	* It's not stated anywhere, but the counter/nonce is 128 bits in length; this might be a strict requirement
	* that the variable be the block size, I'm not positive. Internally however anything longer than this is ignored
	* and anything shorter causes an out-of-bounds read access.
	*
	* The Intel crypto code is horrible to deal with an has tons of assumptions baked into it.
	*/
	if (NULL == src || 0 == src_siz || NULL == dst || 0 == dst_siz || src_siz > dst_siz || NULL == nonce)
		return false;

	/*
	* Intel APIs have a bizarre affinity with 32-bit integers and it would probably be easier if we
	* continued that affinity, however because I've elected to take a size_t as a parameter, I need to
	* explicitly verify that we won't accidentally truncate a message or produce some sort of garbled
	* partial cipher-text partial plain-text (although I think we would just end up with a truncated message)
	* in practice, this is a non-issue because the messages are sufficiently short as to be well within the 4GB
	* bounds.
	*/
	if (UINT32_MAX <= src_siz || UINT32_MAX <= dst_siz)
		return false;

	/*
	* We make this copy of the nonce because the variable is marked non-const in the API and I'm not
	* going to go through it to such an extent to verify that the nonce is never actually modified; it doesn't
	* appear to be-- the first 16-bytes and only the first 16-bytes are copied into a counter variable, but still.
	*/

	::memcpy(&tmp_nonce[0], nonce, sizeof(tmp_nonce));

	if (SGX_SUCCESS != ::sgx_aes_ctr_decrypt(&key, src, static_cast< uint32_t >(src_siz), &tmp_nonce[0], m_inc_bits, dst))
		return false;

	return true;
}

bool
dh_challenge_response_t::verify_server_hello(const charesp_server_hello_t& hello)
{
	ec256_signature_t		sig = { 0 };
	charesp_server_hello_t	tmp = { 0 };

	::memcpy(&tmp, &hello, sizeof(charesp_server_hello_t));
	::memcpy(&sig, &tmp.signature, sizeof(ec256_signature_t));
	::memset_s(&tmp.signature, sizeof(ec256_signature_t), 0, sizeof(ec256_signature_t));

	if (false == verify_ecdsa(reinterpret_cast< const uint8_t* >(&tmp), sizeof(tmp), sig, m_public))
		return false;

	return true;
}

bool
dh_challenge_response_t::verify_client_response(const ec256_public_key_t& pub_key, charesp_client_response_t& resp)
{
	ec256_signature_t			sig = { 0 };
	charesp_client_response_t	tmp = { 0 };

	::memcpy(&tmp, &resp, sizeof(charesp_client_response_t));
	::memcpy(&sig, &tmp.signature, sizeof(ec256_signature_t));
	::memset_s(&tmp.signature, sizeof(ec256_signature_t), 0, sizeof(ec256_signature_t));

	if (false == verify_ecdsa(reinterpret_cast< const uint8_t* >(&tmp), sizeof(tmp), sig, pub_key))
		return false;

	return true;
}

bool
dh_challenge_response_t::initialize_server_hello(const aes_ctr_128bit_key_t& session_key, charesp_server_hello_t& hello)
{
	charesp_server_hello_t		tmp = { 0 };
	charesp_server_hello_ct_t*	ct(reinterpret_cast< charesp_server_hello_ct_t* >(&tmp));
	charesp_server_hello_ct_t*	hct(reinterpret_cast< charesp_server_hello_ct_t* >(&hello));
	ec256_signature_t			sig = { 0 };
	const uint32_t				scratch_len = sizeof(tmp.challenge) + sizeof(tmp.increment) + sizeof(tmp.nonce);
	uint8_t						scratch[scratch_len] = { 0 };

	::memset_s(&hello, sizeof(hello), 0, sizeof(hello));

	if (SGX_SUCCESS != ::sgx_read_rand(&scratch[0], scratch_len)) 
		return false;

	::memcpy(&tmp.challenge, &scratch[0], sizeof(tmp.challenge));
	::memcpy(&tmp.increment, &scratch[sizeof(tmp.challenge)], sizeof(tmp.increment));
	::memcpy(&tmp.nonce[0], &scratch[sizeof(tmp.challenge) + sizeof(tmp.increment)], sizeof(tmp.nonce));

	if (false == aes_ctr_encrypt(&ct->cipher_text[0], sizeof(ct->cipher_text),
									&hct->cipher_text[0], sizeof(hct->cipher_text),
									&ct->nonce[0], session_key)) {
		return false;
	}

	hello.time = 0;
	::memcpy(&hello.nonce[0], &ct->nonce[0], sizeof(hello.nonce));

	::memset_s(&sig, sizeof(sig), 0, sizeof(sig));

	if (false == sign_ecdsa(reinterpret_cast<const uint8_t*>(&hello), sizeof(hello), sig)) 
		return false;

	memcpy(&hct->signature, &sig, sizeof(hct->signature));
	return true;
}

bool
dh_challenge_response_t::initialize_server_response(const aes_ctr_128bit_key_t& session_key, charesp_server_response_t& resp,
												const sha256_hash_t& hash)
{
	charesp_server_response_t			tmp = { 0 };
	charesp_server_response_ct_t* const	src(reinterpret_cast< charesp_server_response_ct_t* >(&tmp));
	charesp_server_response_ct_t* const	dst(reinterpret_cast< charesp_server_response_ct_t* >(&resp));
	ec256_signature_t					sig = { 0 };

	::memset_s(&resp, sizeof(charesp_server_response_t), 0, sizeof(charesp_server_response_t));

	if ( SGX_SUCCESS != ::sgx_read_rand(&tmp.nonce[ 0 ], sizeof(tmp.nonce)) ) {
		ocall_print("dh_challenge_response_t::initialize_server_response():  failure in sgx_read_rand()");
		return false;
	}

	resp.time = 0;
	::memcpy(&resp.nonce[ 0 ], &tmp.nonce[ 0 ], sizeof(resp.nonce));
	::memcpy(&tmp.hash, &hash, sizeof(tmp.hash));

	//aes_ctr_encrypt(src, siz, dst, siz)
	if ( false == aes_ctr_encrypt(&src->cipher_text[ 0 ], sizeof(src->cipher_text),
								  &dst->cipher_text[ 0 ], sizeof(dst->cipher_text),
								  &src->nonce[ 0 ], session_key) ) {
		ocall_print("dh_challenge_response_t::initialize_server_response():  failure in aes_ctr_encrypt()");
		return false;
	}

	//::memcpy(&resp.hash[0], &hash, sizeof(resp.hash));

	if ( false == sign_ecdsa(reinterpret_cast<const uint8_t*>( &resp ), sizeof(resp), sig) ) {
		ocall_print("dh_challenge_response_t::initialize_server_response(): failure in sign_ecdsa()");
		return false;
	}

	::memcpy(&resp.signature, &sig, sizeof(resp.signature));
	return true;
}

bool
dh_challenge_response_t::get_server_hello_plain(charesp_server_hello_t& in, charesp_server_hello_t& out,
											const aes_ctr_128bit_key_t& session_key)
{
	charesp_server_hello_ct_t* const ct = reinterpret_cast< charesp_server_hello_ct_t* const >(&in);
	charesp_server_hello_ct_t* const pt = reinterpret_cast< charesp_server_hello_ct_t* const >(&out);

	::memcpy(&out, &in, sizeof(out));

	if (false == aes_ctr_decrypt(&ct->cipher_text[0], sizeof(ct->cipher_text),
								reinterpret_cast< uint8_t* >(&pt->cipher_text[0]), sizeof(pt->cipher_text),
								&ct->nonce[0], session_key))
		return false;

	return true;
}

bool
dh_challenge_response_t::get_client_response_plain(charesp_client_response_t& in, charesp_client_response_t& out,
												const aes_ctr_128bit_key_t& session_key)
{
	charesp_client_response_ct_t* const ct = reinterpret_cast< charesp_client_response_ct_t* const >(&in);
	charesp_client_response_ct_t* const pt = reinterpret_cast< charesp_client_response_ct_t* const >(&out);

	::memcpy(&out, &in, sizeof(out));

	if (false == aes_ctr_decrypt(	&ct->cipher_text[0], sizeof(ct->cipher_text),
									reinterpret_cast< uint8_t* >(&pt->cipher_text[0]), sizeof(pt->cipher_text),
									&ct->nonce[0], session_key))
		return false;

	return true;
}

void 
dh_challenge_response_t::private_key(uint8_t* key, std::size_t& key_len, bool get_or_set)
{
	if (NULL == key || 0 == key_len && false == get_or_set)
		return;
	else if ((key_len < sizeof(m_private)) || (key_len > sizeof(m_private) && false == get_or_set)) {
		key_len = sizeof(m_private);
		key = NULL;
		return;
	}

	if (true == get_or_set) {
		::memcpy(key, &m_private, key_len > sizeof(m_private) ? sizeof(m_private) : key_len);
		return;
	} 
	
	::memset_s(&m_private, sizeof(m_private), 0, sizeof(m_private));
	::memcpy(&m_private, key, key_len);
	return;
}

void 
dh_challenge_response_t::public_key(uint8_t* key, std::size_t& key_len, bool get_or_set)
{
	if (NULL == key || 0 == key_len && false == get_or_set)
		return;
	else if ((key_len < sizeof(m_public)) || (key_len > sizeof(m_public) && false == get_or_set)) {
		key_len = sizeof(m_public);
		key = NULL;
		return;
	}

	if (true == get_or_set) {
		::memcpy(key, &m_public, key_len > sizeof(m_public) ? sizeof(m_public) : key_len);
		return;
	}

	::memset_s(&m_public, sizeof(m_public), 0, sizeof(m_public));
	::memcpy(&m_public, key, key_len);
	return;
}

bool
dh_challenge_response_t::process_authentication(const uint8_t* pwd, const aes_ctr_128bit_key_t& session_key, charesp_transaction_t& txn)
{
	charesp_server_hello_t			sh_plain = { 0 };
	charesp_client_response_t		cr_plain = { 0 };
	uint64_t						schallenge = 0;
	uint64_t						cchallenge = 0;
	sha256_hash_t					hash = { 0 };
	charesp_hmac_msg_t				msg = { 0 };

	//ocall_print("dh_challenge_response_t::process_authentication(): entry");
	// First verify our prior hello message because it was stored outside of the enclave
	if ( false == verify_server_hello(txn.server_hello) ) {
		ocall_print(std::string("dh_challenge_response_t::process_authentication(): verify_server_hello failure").c_str());
		return false;
	}

	if ( false == verify_client_response(txn.client_hello.public_key, txn.client_response) ) {
		ocall_print(std::string("dh_challenge_response_t::process_authentication(): verify_client_response() failure").c_str());
		return false;
	}

	// now decrypt both the server hello and the client response with the session key
	if ( false == get_server_hello_plain(txn.server_hello, sh_plain, session_key) ) {
		ocall_print(std::string("dh_challenge_response_t::process_authentication(): get_server_hello_plain() failure").c_str());
		return false;
	}
	
	if ( false == get_client_response_plain(txn.client_response, cr_plain, session_key) ) {
		ocall_print(std::string("dh_challenge_response_t::process_authentication(): get_client_response_plain() failure").c_str());
		return false;
	}

	// construct the clients msg that generated its HMAC
	msg.client_hello = txn.client_hello;
	msg.server_hello = sh_plain; //txn.server_hello;
	msg.client_challenge = cr_plain.challenge;
	msg.server_challenge = sh_plain.challenge;
	msg.client_challenge += cr_plain.increment;
	msg.server_challenge += sh_plain.increment;

	if ( false == sha256_hmac(reinterpret_cast<const uint8_t*>( &msg ), sizeof(msg), pwd,
							  ::strlen(reinterpret_cast<const char*>( pwd )), hash) ) {
		ocall_print(std::string("dh_challenge_response_t::process_authentication(): sha256_hmac() failure").c_str());
		return false;
	}

	if ( 0 != ::memcmp(&cr_plain.hash, &hash, sizeof(sha256_hash_t)) ) {
		ocall_print(std::string("dh_challenge_response_t::process_authentication(): memcmp() failure").c_str());
		return false;
	}

	::memset_s(&hash, sizeof(hash), 0, sizeof(hash));

	// Now generate our HMAC, which is run over the same data but with the challenges incremented a second time
	msg.server_challenge += sh_plain.increment;
	msg.client_challenge += cr_plain.increment;

	/*std::string xstr("dh_challenge_response_t::process_authentication(): MSG:\n");
	char* xptr = (char*)&msg;
	for ( std::size_t idx = 0; idx < sizeof(msg); idx++ )
		xstr += itoa_8("%x", xptr[ idx ]);
	xstr += "\n";
	ocall_print(xstr.c_str());

	std::string pwd_str("dh_challenge_response_t::process_authentication(): password: ");
	for ( std::size_t idx = 0; idx < ::strlen((const char*)pwd); idx++ )
		pwd_str += pwd[ idx ];
	pwd_str += itoa_64("(%u)\n", ::strlen((const char*)pwd));
	ocall_print(pwd_str.c_str());*/
	ocall_print("\n\n\nhere\n\n\n");
	if ( false == sha256_hmac(reinterpret_cast<const uint8_t*>( &msg ), sizeof(msg),
							  pwd, ::strlen(reinterpret_cast<const char*>( pwd )), hash) ) {
		ocall_print(std::string("dh_challenge_response_t::process_authentication(): sha256_hmac() failure").c_str());
		return false;
	}

	/*std::string str("dh_challenge_response_t::process_authentication(): HASH:\n");
	char* ptr = (char*)&hash;
	for ( std::size_t idx = 0; idx < sizeof(hash); idx++ )
		str += itoa_8("%x", ptr[ idx ]);
	str += "\n";*/

	if ( false == initialize_server_response(session_key, /*tmp_resp*/txn.server_response, hash) ) {
		ocall_print(std::string("dh_challenge_response_t::process_authentication(): initialize_server_response() failure").c_str());
		return false;
	}

	/*ptr = (char*)&txn.server_response.hash;
	str += "dh_challenge_response_t::process_authentication(): e(HASH):\n";
	for ( std::size_t idx = 0; idx < sizeof(txn.server_response.hash); idx++ )
		str += itoa_8("%x", ptr[ idx ]);
	str += "\n";
	ocall_print(str.c_str());*/
	return true;
}

bool
dh_challenge_response_t::derive_key(const uint8_t* pwd, ec256_public_key_t& pub_key, aes_ctr_128bit_key_t& session_key)
{
	sgx_ec256_dh_shared_t		dhshared	= { 0 };
	sgx_cmac_128bit_key_t		cmac_key	= { 0 };
	sgx_cmac_state_handle_t		cmac_hnd	= NULL;
	sgx_cmac_128bit_tag_t		cmac_tag	= { 0 };
	signed int					valid		= 0;

	if ( SGX_SUCCESS != ::sgx_ecc256_check_point(&pub_key, m_ecc256_handle, &valid) ) {
		ocall_print("dh_challenge_response_t::derive_key(): failure in sgx_ecc256_check_point()");
		return false;
	}

	if ( 0 == valid ) {
		ocall_print("dh_challenge_response_t::derive_key(): point on ECC curve invalid");
		return false;
	}

	if ( SGX_SUCCESS != ::sgx_ecc256_compute_shared_dhkey(&m_private, &pub_key, &dhshared, m_ecc256_handle) ) {
		ocall_print(std::string("dh_challenge_response_t::derive_key(): failure in sgx_ecc256_compute_shared_dhkey()").c_str()); // : " + itoa_64("%x", ret)).c_str());
		return false;
	}

	::memset_s(&cmac_key, sizeof(cmac_key), 0, sizeof(cmac_key));

	if ( SGX_SUCCESS != ::sgx_cmac128_init(&cmac_key, &cmac_hnd) ) {
		ocall_print("dh_challenge_response_t::derive_key(): failure in sgx_cmac128_init()");
		return false;
	}

	if ( SGX_SUCCESS != ::sgx_cmac128_update(reinterpret_cast<const uint8_t*>( &dhshared ), sizeof(sgx_ec256_dh_shared_t), cmac_hnd) ) {
		ocall_print("dh_challenge_response_t::derive_key(): failure in sgx_cmac128_update()");
		return false;
	}

	if ( SGX_SUCCESS != ::sgx_cmac128_update(&pwd[ 0 ], ::strlen(reinterpret_cast<const char*>( &pwd[ 0 ] )), cmac_hnd) ) {
		ocall_print("dh_challenge_response_t::derive_key(): sgx_cmac128_update()");
		return false;
	}

	if ( SGX_SUCCESS != ::sgx_cmac128_final(cmac_hnd, &cmac_tag) ) {
		ocall_print("dh_challenge_response_t::derive_key(): failure in sgx_cmac128_final()");
		return false;
	}

	if ( SGX_SUCCESS != ::sgx_cmac128_close(cmac_hnd) ) {
		ocall_print("dh_challenge_response_t::derive_key(): failure in sgx_cmac128_close()");
		return false;
	}

	::memcpy(&session_key, &cmac_tag, sizeof(session_key));
	return true;
}

bool
dh_challenge_response_t::challenge_response(const uint8_t* pwd, charesp_transaction_t& txn)
{
	aes_ctr_128bit_key_t session_key = { 0 };

	if (false == derive_key(pwd, txn.client_hello.public_key, session_key)) {
		ocall_print("dh_challenge_response_t::challenge_response(): failure during deriving session key");
		return false;
	}

	if (charesp_state_t::CHARESP_STATE_CLIENT_HELLO == txn.state) {
		//ocall_print("dh_challenge_response_t::challenge_response(): state client hello");

		if (false == initialize_server_hello(session_key, txn.server_hello)) {
			ocall_print("dh_challenge_response_t::challenge_response(): error while initializing server hello");
			return false;
		}

		txn.state = charesp_state_t::CHARESP_STATE_SERVER_HELLO;
	
	} else if (charesp_state_t::CHARESP_STATE_SERVER_HELLO == txn.state) {
		//ocall_print("dh_challenge_response_t::challenge_response(): state server hello");

		if (false == process_authentication(pwd, session_key, txn)) {
			ocall_print("dh_challenge_response_t::challenge_response(): process_authentication failure");
			return false;
		}

		txn.state = charesp_state_t::CHARESP_STATE_CLIENT_AUTHENTICATED;
	
	} else {
		ocall_print("dh_challenge_response_t::challenge_response(): unknown transaction state");
		throw std::runtime_error("...");
		return false;
	}

	//ocall_print("dh_challenge_response_t::challenge_response(): returning successfully");
	return true;
}
