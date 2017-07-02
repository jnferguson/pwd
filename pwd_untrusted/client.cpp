#pragma once
#include "stdafx.h"
#include "client.hpp"

std::string
client_t::ptr_to_str(void* ptr, std::size_t len)
{
	std::string ret("");

	if ( nullptr == ptr ) {
		ERROR("client_t::ptr_to_str(): Invalid parameter(s) specified");
		throw std::runtime_error("client_t::ptr_to_str(): Invalid parameter(s) specified");
	}

	ret.resize(len);
	std::memcpy(&ret[ 0 ], ptr, len);
	return ret;
}

ec256_public_key_t
client_t::get_svc_key(void)
{
	std::string			svc_key_str = get_public_key();
	ec256_public_key_t	svc_key = { 0 };

	if ( sizeof(svc_key) != svc_key_str.length() ) {
		ERROR("client_t::get_svc_key(): The size of the retrieved service public key is not the expected length");
		throw std::runtime_error("client_t::get_svc_key(): The size of the retrieved service public key is not the expected length");
	}

	std::memcpy(&svc_key, svc_key_str.data(), sizeof(svc_key));
	return svc_key;
}

std::string
client_t::trim_whitespace(const std::string& str)
{
	const std::string	whitespace(" \t\n\r\f\v");
	std::size_t			begin(0), end(0);

	begin = str.find_first_not_of(whitespace);

	if ( std::string::npos == begin ) {
		DEBUG("client_t::trim_whitespace(): Empty string encountered");
		return std::string(""); // no content
	}

	end = str.find_last_not_of(whitespace);
	return str.substr(begin, end - begin + 1);
}

/*bool
client_t::parse_server_hello(json11::Json& json, response_context_t& ctx, challenge_response_base_t& crb)
{
	server_hello_t* sh = dynamic_cast<server_hello_t*>( &crb );
	base64_t		b64;
	bool			n(false), t(false), s(false), c(false), i(false);

	if ( nullptr == sh ) 
		return false;

	if ( false == json.is_object() ) 
		return false;

	// so this json parser truly sucks and is hairbrained bullshit pumped out by web 2.0 coders
	// and the quality reflects that. However, this entire class is only for testing purposes and
	// so it need not be totally bullet proof and the int_value() calls can reasonably fail as a result
	// which is good because its not entirely clear how i am supposed to check for that and if I call
	// it on the wrong json type it will just return zero, which could be catostrophic for the actual
	// challenge response mechanisms.	
	for ( auto& itr = json.object_items().begin(); itr != json.object_items().end(); itr++ ) {
		if ( !itr->first.compare("nonce") ) {
			std::string								nonce = itr->second.string_value();
			std::array< uint8_t, CR_NONCE_SIZE >	nonce_array;

			if ( 0 == nonce.length() ) 
				return false;

			nonce = b64.decode(nonce);

			if ( nonce.length() != nonce_array.size() ) {
				ERROR("client_t::parse_server_hello(): ");
				return false;
			}

			std::memcpy(&nonce_array[ 0 ], nonce.data(), nonce_array.size());
			sh->nonce(nonce_array);
			n = true;
		} else if ( !itr->first.compare("timestamp") ) {
			sh->time(itr->second.int_value());
			t = true;
		} else if ( !itr->first.compare("signature") ) {
			std::string			signature_str = itr->second.string_value();
			ec256_signature_t	signature;

			signature_str = b64.decode(signature_str);

			if ( signature_str.length() != sizeof(signature) ) 
				return false;

			std::memcpy(&signature, signature_str.data(), sizeof(signature));
			sh->signature(signature);
			s = true;
		} else if ( !itr->first.compare("challenge") ) {
			sh->challenge(itr->second.int_value());
			c = true;
		} else if ( !itr->first.compare("increment") ) {
			sh->increment(itr->second.int_value());
			i = true;
		} else 
			return false;
	}

	if ( true != n || true != t || true != s || true != c || true != i ) 
		return false;

	return true;
}
*/

bool
client_t::parse_ciphertext(json11::Json& json, response_context_t& ctx, challenge_response_base_t& crb)
{
	challenge_response_ciphertext_t*	cr(dynamic_cast< challenge_response_ciphertext_t* >( &crb ));
	bool								c(false), n(false), s(false);
	base64_t							b64;

	if ( nullptr == cr )
		return false;

	if ( false == json.is_object() )
		return false;

	// as client_t is just a test class, i am not doing proper error checking here.
	for ( auto& itr = json.object_items().begin(); itr != json.object_items().end(); itr++ ) {
		if ( !itr->first.compare("cipher_text") )
			cr->ciphertext(b64.decode(itr->second.string_value()));
		else if ( !itr->first.compare("nonce") )
			cr->nonce(b64.decode(itr->second.string_value()));
		else if ( !itr->first.compare("signature") )
			cr->signature(b64.decode(itr->second.string_value()));
		else if ( !itr->first.compare("msg") )
			cr->message(b64.decode(itr->second.string_value()));
		else if ( !itr->first.compare("timestamp") )
			cr->timestamp(itr->second.int_value());
		else
			return false;
	}

	return true;
}

bool
client_t::decrypt_server_response(challenge_response_ciphertext_t& cr, charesp_server_response_t& ret,
						ec256_public_key_t& svc_key, aes_ctr_128bit_key_t& session_key)
{
	charesp_server_response_ct_t			ct = { 0 };
	ec256_signature_t						signature = { 0 };
	charesp_server_response_ct_t* const		pt = reinterpret_cast<charesp_server_response_ct_t* const>( &ret );

	std::memset(&ct, 0, sizeof(charesp_server_response_ct_t));

	if ( cr.ciphertext().length() != sizeof(ct.cipher_text) )
		return false;

	std::memcpy(&ct.cipher_text, cr.ciphertext().data(), sizeof(ct.cipher_text));

	if ( cr.nonce().length() != sizeof(ct.nonce) )
		return false;

	std::memcpy(&ct.nonce, cr.nonce().data(), sizeof(ct.nonce));

	if ( cr.signature().length() != sizeof(signature) )
		return false;

	std::memcpy(&signature, cr.signature().data(), sizeof(ct.signature));

	ct.time = cr.timestamp();

	if ( false == m_keypair.verify(reinterpret_cast<const uint8_t*>( &ct ), sizeof(ct), svc_key, signature) )
		return false;

	//charesp_server_response_t* csr_ptr = (charesp_server_response_t*)&ct;
	/*char* ptr = (char*)&csr_ptr->hash;
	printf("client_t::decrypt_server_response(): e(HASH):\n");
	for ( std::size_t idx = 0; idx < sizeof(csr_ptr->hash); idx++ )
		printf("%x", (uint8_t)ptr[ idx ]);
	printf("\n");*/

	if ( false == m_keypair.aes_ctr_decrypt(&ct.cipher_text[ 0 ], sizeof(ct.cipher_text),
											reinterpret_cast<uint8_t*>( &pt->cipher_text[ 0 ] ),
											sizeof(pt->cipher_text), &ct.nonce[ 0 ], session_key, 0x20) )
		return false;

	std::memcpy(&ret.nonce, &ct.nonce, sizeof(ret.nonce));
	std::memcpy(&ret.signature, &signature, sizeof(ret.signature));
	ret.time = ct.time;

	return true;
}

bool
client_t::decrypt_server_hello(challenge_response_ciphertext_t& cr, charesp_server_hello_t& ret,
					 ec256_public_key_t& svc_key, aes_ctr_128bit_key_t& session_key)
{
	charesp_server_hello_ct_t			ct = { 0 };
	ec256_signature_t					signature = { 0 };
	charesp_server_hello_ct_t* const	pt = reinterpret_cast< charesp_server_hello_ct_t* const >( &ret );

	std::memset(&ct, 0, sizeof(charesp_server_hello_ct_t));

	if ( cr.ciphertext().length() != sizeof(ct.cipher_text) )
		return false;

	std::memcpy(&ct.cipher_text, cr.ciphertext().data(), sizeof(ct.cipher_text));

	if ( cr.nonce().length() != sizeof(ct.nonce) )
		return false;

	std::memcpy(&ct.nonce, cr.nonce().data(), sizeof(ct.nonce));

	if ( cr.signature().length() != sizeof(signature) )
		return false;

	std::memcpy(&signature, cr.signature().data(), sizeof(ct.signature));

	ct.time = cr.timestamp();

	if ( false == m_keypair.verify(reinterpret_cast<const uint8_t*>( &ct ), sizeof(ct), svc_key, signature) )
		return false;

	if ( false == m_keypair.aes_ctr_decrypt(&ct.cipher_text[ 0 ], sizeof(ct.cipher_text),
											reinterpret_cast<uint8_t*>( &pt->cipher_text[ 0 ] ),
											sizeof(pt->cipher_text), &ct.nonce[ 0 ], session_key, 0x20) )
		return false;

	std::memcpy(&ret.nonce, &ct.nonce, sizeof(ret.nonce));
	std::memcpy(&ret.signature, &signature, sizeof(ret.signature));
	ret.time = ct.time;

	return true;
}

bool 
client_t::get_server_hello(charesp_transaction_t& ctxn, ec256_public_key_t& svc_key, aes_ctr_128bit_key_t& session_key)
{
	response_context_t					ctx;
	parameter_map_t						parameters;
	challenge_response_ciphertext_t		ctext;
	std::string							ret = "";
	parser_callback_t					callback = &client_t::parse_ciphertext;
	time_t								timestamp = 0;

	std::memset(&ctxn, 0, sizeof(charesp_transaction_t));

	timestamp = ::time(nullptr);
	parameters[ "public_key" ] = m_keypair.to_public_string();
	parameters[ "timestamp" ] = std::to_string(timestamp);
	parameters[ "username" ] = m_user;

	std::memcpy(&ctxn.client_hello.public_key, &m_keypair.public_key(), sizeof(ctxn.client_hello)); //ctxn.client_hello.public_key
	ctxn.client_hello.time = timestamp;

	m_txn.clear();

	if ( false == m_server.do_request(SERVICE_AUTHENTICATE, m_txn, parameters, ret) )
		return false;

	if ( false == parse_response(ret, ctx, ctext, callback) )
		return false;

	if ( false == decrypt_server_hello(ctext, ctxn.server_hello, svc_key, session_key) )
		return false;

	return true;
}

bool
client_t::get_client_response(charesp_transaction_t& ctxn, ec256_public_key_t& svc_key, aes_ctr_128bit_key_t& session_key)
{
	const std::size_t					cresp_length(sizeof(ctxn.client_response.challenge) +
													 sizeof(ctxn.client_response.increment) +
													 sizeof(ctxn.client_response.nonce));
	std::size_t							offset(0);
	std::array< uint8_t, cresp_length > buf;
	charesp_hmac_msg_t					msg = { 0 };
	sha256_t							sha256;
	charesp_client_response_t			tmp = { 0 };
	ec256_signature_t					sig = { 0 };
	charesp_client_response_ct_t* const ct = reinterpret_cast<charesp_client_response_ct_t* const>( &tmp );
	charesp_client_response_ct_t* const pt = reinterpret_cast<charesp_client_response_ct_t* const>( &ctxn.client_response );

	if ( SGX_SUCCESS != sgx_replace_t::read_rand(&buf[ 0 ], buf.size()) )
		return false;

	ctxn.client_response.time = ::time(nullptr);

	std::memcpy(&ctxn.client_response.challenge, &buf[ offset ], sizeof(ctxn.client_response.challenge));
	offset += sizeof(ctxn.client_response.challenge);

	std::memcpy(&ctxn.client_response.increment, &buf[ offset ], sizeof(ctxn.client_response.increment));
	offset += sizeof(ctxn.client_response.increment);

	std::memcpy(&ctxn.client_response.nonce, &buf[ offset ], sizeof(ctxn.client_response.nonce));


	// XXX JF do I want to do the client response challenge+increment here for the HMAC?
	msg.client_hello = ctxn.client_hello;
	msg.server_hello = ctxn.server_hello;
	msg.server_challenge = ctxn.server_hello.challenge;
	msg.client_challenge = ctxn.client_response.challenge;
	msg.server_challenge += ctxn.server_hello.increment;
	msg.client_challenge += ctxn.client_response.increment;

	if ( false == sha256.hmac(reinterpret_cast<const uint8_t*>( &msg ), sizeof(msg),
							  reinterpret_cast<const uint8_t*>( m_password.c_str() ),
							  m_password.length(),
							  ctxn.client_response.hash) )
		return false;

	// XXX JF do not move this relative to the following call to encrypt the data
	// one of the pointer parameters points to it.
	std::memcpy(&tmp, &ctxn.client_response, sizeof(charesp_client_response_t));

	if ( false == m_keypair.aes_ctr_encrypt(&pt->cipher_text[ 0 ], sizeof(pt->cipher_text),
											reinterpret_cast<uint8_t*>( &ct->cipher_text[ 0 ] ),
											sizeof(ct->cipher_text),
											ctxn.client_response.nonce, session_key, 0x20) )
		return false;

	std::memcpy(&sig, &tmp.signature, sizeof(ec256_signature_t));
	std::memset(&tmp.signature, 0, sizeof(ec256_signature_t));

	if ( false == m_keypair.sign(reinterpret_cast <const uint8_t*>( &tmp ), sizeof(tmp), sig) )
		return false;

	std::memcpy(&tmp.signature, &sig, sizeof(ec256_signature_t));
	std::memcpy(&ctxn.client_response, &tmp, sizeof(ctxn.client_response));
	return true;
}

bool
client_t::put_client_response(charesp_transaction_t& ctxn, ec256_public_key_t& svc_key, aes_ctr_128bit_key_t& session_key)
{
	response_context_t					ctx;
	challenge_response_ciphertext_t		ctext;
	parameter_map_t						parameters;
	charesp_client_response_ct_t*		ct(nullptr);
	charesp_server_response_t			csr = { 0 };
	std::string							ret("");
	base64_t							b64;
	parser_callback_t					callback(&client_t::parse_ciphertext);

	if ( false == get_client_response(ctxn, svc_key, session_key) )
		return false;

	ct = reinterpret_cast< charesp_client_response_ct_t* >( &ctxn.client_response );
	parameters[ "cipher_text" ] = b64.encode(ptr_to_str(&ct->cipher_text[ 0 ], sizeof(ct->cipher_text)));
	parameters[ "nonce" ] = b64.encode(ptr_to_str(&ct->nonce[ 0 ], sizeof(ct->nonce)));
	parameters[ "signature" ] = b64.encode(ptr_to_str(&ct->signature, sizeof(ct->signature)));
	parameters[ "timestamp" ] = std::to_string(ct->time);

	m_txn.clear();

	if ( false == m_server.do_request(SERVICE_AUTHENTICATE, m_txn, parameters, ret) )
		return false;

	if ( false == parse_response(ret, ctx, ctext, callback) )
		return false;

	if ( false == decrypt_server_response(ctext, csr, svc_key, session_key) )
		return false;

	std::memcpy(&ctxn.server_response, &csr, sizeof(ctxn.server_response));
	return true;
}

bool
client_t::parse_response(const std::string& resp, response_context_t& ctx, challenge_response_base_t& crb, parser_callback_t& cb) const
{
	const std::string			lfnl("\r\n");
	const std::size_t			lfnl_len(lfnl.length());
	const std::size_t			max_code_length(::strlen("000"));
	std::string					resp_str(resp), error("");
	json11::Json				json;
	std::size_t					pos(0);

	if ( max_code_length > resp.length() )
		return false;

	ctx.code = std::strtoul(resp_str.substr(0, max_code_length).c_str(), nullptr, 10);

	if ( 0 == ctx.code || 99 > ctx.code || 9999 < ctx.code ) // invalid code
		return false;

	resp_str = resp_str.substr(max_code_length, std::string::npos);
	pos = resp_str.find_first_of(lfnl, 0);

	if ( std::string::npos == pos ) // invalid format
		return false;

	ctx.code_str = resp_str.substr(0, pos);

	// the += lfnl.length() is guaranteed to always exist by
	// virtue of the find_first_of() not returning npos
	pos += lfnl_len;
	resp_str = resp_str.substr(pos, std::string::npos);

	while ( resp_str.compare(0, lfnl_len, lfnl) ) {
		std::string line(""), key(""), value("");
		std::size_t split_pos(0);

		pos = resp_str.find_first_of(lfnl, 0);

		if ( std::string::npos == pos ) // invalid format
			return false;

		line = resp_str.substr(0, pos);
		split_pos = line.find_first_of(':');

		if ( std::string::npos == split_pos || line.length() <= split_pos ) // unpossible ? / malformed line
			return false;

		key = trim_whitespace(line.substr(0, split_pos));
		value = trim_whitespace(line.substr(split_pos + 1));

		if ( 0 == key.length() || 0 == value.length() ) // invalid/malformed
			return false;

		ctx.headers[ key ] = value;

		// the += lfnl.length() is guaranteed to always exist by
		// virtue of the find_first_of() not returning npos
		pos += lfnl_len;
		resp_str = resp_str.substr(pos, std::string::npos);
	}

	if ( resp_str.compare(0, lfnl_len, lfnl) )	// we ran out of space, there was no body 
		return false;							// or somehow we didnt have the trailing \r\n, which is invalid.

	error.clear();
	json = json11::Json::parse(resp_str.substr(lfnl_len, std::string::npos), error);

	// The json parser here is a little funky and an error is returned as Json(nullptr) 
	// which should evaluate to Json(nullptr).is_null == true, however that means there
	// is no clear manner to discern between error and a null object; however the returned
	// string should be empty on non-error so we can just test that instead
	if ( 0 != error.length() || false == json.is_object() )
		return false;

	return cb(json, ctx, crb);
}

client_t::client_t(server_t& s) : m_server(s), m_txn(), m_parameters(), m_keypair(), m_user(""), m_password("")
{
	return;
}

client_t::client_t(const std::string& u, const std::string& p, server_t& s)
	: m_server(s), m_txn(), m_parameters(), m_keypair(), m_user(u), m_password(p)
{
	return;
}

client_t::~client_t(void) 
{ 
	return;
}

const std::string& 
client_t::username(void) const 
{ 
	return m_user; 
}

void 
client_t::username(const std::string& u) 
{ 
	m_user = u; 
	return;
}

const std::string& 
client_t::password(void) const 
{ 
	return m_password; 
}

void 
client_t::password(const std::string& p) 
{ 
	m_password = p; 
	return; 
}

bool 
client_t::do_request(const server_opcodes_t operation) 
{ 
	return m_server.do_request(operation, m_txn, m_parameters, std::string()); 
}

txn_t& 
client_t::txn(void)
{ 
	return m_txn; 
}

parameter_map_t& 
client_t::parameters(void) 
{ 
	return m_parameters; 
}

void
client_t::insert_parameters(const std::string& key, const std::string& value)
{
	m_parameters.insert(std::make_pair(key, value));
	return;
}

std::string
client_t::get_public_key(bool decode_b64)
{
	std::string ret("");
	base64_t	b64;

	if ( false == m_server.do_request(SERVICE_GET_PUBLIC_KEY, m_txn, m_parameters, ret) ) {
		ERROR("client_t::get_public_key(): Error in server_t::do_request(SERVICE_GET_PUBLIC_KEY)");
		throw std::runtime_error("client_t::get_public_key(): Error in server_t::do_request(SERVICE_GET_PUBLIC_KEY)");
	}


	for ( auto& itr = m_txn.body().body().begin(); itr != m_txn.body().body().end(); itr++ )
		if ( !( *itr )->name().compare("PWDSVC_ECC256_PUBLIC_KEY") ) {
			json_string_t* ptr = dynamic_cast< json_string_t* >( *itr );

			if ( nullptr == ptr ) {
				ERROR("client_t::get_public_key(): Error dynamic_cast to json_string_t failure");
				throw std::runtime_error("client_t::get_public_key(): Error dynamic_cast to json_string_t failure");
			}

			ret = ptr->value();
		}

	if ( true == decode_b64 )
		ret = b64.decode(ret);

	return ret; //m_txn.body().to_base64(); //.to_string();
}

std::string
client_t::authenticate(void)
{
	charesp_transaction_t				ctxn;
	aes_ctr_128bit_key_t				session_key = { 0 };
	ec256_public_key_t					svc_key		= get_svc_key();

	std::memset(&ctxn, 0, sizeof(charesp_transaction_t));

	if ( false == m_keypair.derive_key(reinterpret_cast<const uint8_t*>( m_password.c_str() ), svc_key, session_key) ) {
		ERROR("client_t::authenticate(): Error in ec256_keypair_t::derive_key()");
		throw std::runtime_error("client_t::authenticate(): Error in ec256_keypair_t::derive_key()");
	}

	if ( false == get_server_hello(ctxn, svc_key, session_key) ) {
		ERROR("client_t::authenticate(): Error in client_t::get_server_hello()");
		throw std::runtime_error("client_t::authenticate(): Error in client_t::get_server_hello()");
	}

	if ( false == put_client_response(ctxn, svc_key, session_key) ) {
		ERROR("client_t::authenticate(): Error in client_t::put_client_response()");
		throw std::runtime_error("client_t::authenticate(): Error in client_t::put_client_response()");
	}

	charesp_client_response_t crplain		= { 0 };
	charesp_client_response_ct_t* crptr		= reinterpret_cast<charesp_client_response_ct_t*>( &ctxn.client_response );
	charesp_client_response_ct_t* crpptr	= reinterpret_cast<charesp_client_response_ct_t*>( &crplain );

	if ( false == m_keypair.aes_ctr_decrypt(&crptr->cipher_text[ 0 ],
											sizeof(crptr->cipher_text),
											&crpptr->cipher_text[ 0 ],
											sizeof(crpptr->cipher_text),
											&crptr->nonce[ 0 ], session_key,
											0x20) ) 
	{
		ERROR("client_t::authenticate(): Error in ec256_keypair_t::aes_ctr_decrypt()");
		throw std::runtime_error("client_t::authenticate(): Error in ec256_keypair_t::aes_ctr_decrypt()");
	}


	charesp_hmac_msg_t	msg		= { 0 };
	sha256_t			sha256;
	sha256_hash_t		hash	= { 0 };

	msg.client_hello		= ctxn.client_hello;
	msg.server_hello		= ctxn.server_hello;
	msg.client_challenge	= crplain.challenge; //ctxn.client_response.challenge;
	msg.server_challenge	= ctxn.server_hello.challenge;
	msg.client_challenge	+= crplain.increment;
	msg.client_challenge	+= crplain.increment;
	msg.server_challenge	+= ctxn.server_hello.increment;
	msg.server_challenge	+= ctxn.server_hello.increment;

	std::memset(&hash, 0, sizeof(hash));

	if ( false == sha256.hmac(reinterpret_cast<const uint8_t*>( &msg ), sizeof(msg),
							  reinterpret_cast<const uint8_t*>( m_password.c_str() ),
							  m_password.length(), hash) ) 
	{
		ERROR("client_t::authenticate(): Error in sha256_t::hmac()");
		throw std::runtime_error("client_t::authenticate(): Error in sha256_t::hmac()");
	}

	/*char* ptr = (char*)&ctxn.server_response.hash;
	char* ptr_two = (char*)&hash;

	printf("client_t::authenticate(): ctxn.server_response.hash: 0x");
	for ( std::size_t idx = 0; idx < sizeof(ctxn.server_response.hash); idx++ )
		printf("%x", (uint8_t)ptr[ idx ]);
	printf("\n");
	printf("client_t::authenticate(): hash: 0x");
	for ( std::size_t idx = 0; idx < sizeof(hash); idx++ )
		printf("%x", (uint8_t)ptr_two[ idx ]);
	printf("\n");*/

	return m_txn.body().to_string();
}

std::string
client_t::add_user(void)
{
	std::string ret("");

	m_parameters[ "username" ] = m_user;
	m_parameters[ "password" ] = m_password;

	if ( false == m_server.do_request(SERVICE_ADD_USER, m_txn, m_parameters, ret) ) {
		ERROR("Error in server_t::do_request(SERVICE_ADD_USER)");
		throw std::runtime_error("client_t::add_user(): Error in server_t::do_request(SERVICE_ADD_USER)");
	}

	return ret;
}

std::string
client_t::update_user(void)
{
	if ( false == m_server.do_request(SERVICE_UPDATE_USER, m_txn, m_parameters, std::string()) ) {
		ERROR("Error in server_t::do_request(SERVICE_UPDATE_USER)");
		throw std::runtime_error("client_t::update_user(): Error in server_t::do_request(SERVICE_UPDATE_USER)");
	}

	return m_txn.body().to_string();
}

