#include "stdafx.h"
#include "server.hpp"

static inline std::string
http_code_to_status(const uint32_t code)
{
	std::string ret("");

	switch (code) {
		case 100: // continue
			ret += "100 Continue";
			break;
		case 101: // switching protocols
			ret += "101 Switching Protocols";
			break;
		case 102: // processing
			ret += "102 Processing";
			break;
		case 200: // okay
			ret += "200 Okay";
			break;
		case 201: // created
			ret += "201 Created";
			break;
		case 202: // accepted
			ret += "202 Accepted";
			break;
		case 203: // Non-authoritative information
			ret += "203 Non-authoritative Information";
			break;
		case 204: // no content
			ret += "204 No Content";
			break;
		case 205: // reset content
			ret += "205 Reset Content";
			break;
		case 206: // partial content
			ret += "206 Partial Content";
			break;
		case 207: // multi-status (WebDAV)
			ret += "207 Multi-Status";
			break;
		case 208: // already reported (WebDAV)
			ret += "208 Already Reported";
			break;
		case 226: // IM used
			ret += "226 IM Used";
			break;
		case 300: // multiple choices
			ret += "300 Multiple Choices";
			break;
		case 301: // moved permanently
			ret += "301 Moved Permanently";
			break;
		case 302: // found
			ret += "302 Found";
			break;
		case 303: // see other
			ret += "303 See Other";
			break;
		case 304: // not modified
			ret += "304 Not Modified";
			break;
		case 305: // use proxy
			ret += "305 Use Proxy";
			break;
		case 306: // switch proxy
			ret += "306 Switch Proxy";
			break;
		case 307: // temporary redirect
			ret += "307 Temporary Redirect";
			break;
		case 308: // permanent redirect
			ret += "308 Permanent Redirect";
			break;
		case 400: // bad request
			ret += "400 Bad Request";
			break;
		case 401: // unauthorized
			ret += "401 Unauthorized";
			break;
		case 402: // payment required
			ret += "402 Payment Required";
			break;
		case 403: // forbidden
			ret += "403 Forbidden";
			break;
		case 404: // not found
			ret += "404 Not Found";
			break;
		case 405: // method not allowed
			ret += "405 Method Not Allowed";
			break;
		case 406: // not acceptable
			ret += "406 Not Acceptable";
			break;
		case 408: // request timeout
			ret += "408 Request Timeout";
			break;
		case 409: // conflict
			ret += "409 Conflict";
			break;
		case 410: // gone
			ret += "410 Gone";
			break;
		case 411: // length required
			ret += "411 Length Required";
			break;
		case 412: // precondition failed
			ret += "412 Precondition Failed";
			break;
		case 413: // payload too large
			ret += "413 Payload Too Large";
			break;
		case 414: // uri too long
			ret += "414 URI Too Long";
			break;
		case 415: // unsupported media type
			ret += "415 Unsupported Media Type";
			break;
		case 416: // range not satisfiable
			ret += "416 Range Not Satisfiable";
			break;
		case 417: // expectation failed
			ret += "417 Expectation Failed";
			break;
		case 418: // im a teapot
			ret += "418 I'm a teapot";
			break;
		case 421: // misdirected request
			ret += "421 Misdirected Request";
			break;	
		case 422: // unprocesable entity (WebDAV)
			ret += "422 Unprocessable Entity";
			break;
		case 423: // locked (WebDAV)
			ret += "423 Locked";
			break;
		case 424: // failed dependency (WebDAV)
			ret += "424 Failed Dependency";
			break;
		case 426: // upgrade required
			ret += "426 Upgrade Required";
			break;
		case 428: // precondition required
			ret += "428 Precondition Required";
			break;
		case 429: // too many requests
			ret += "429 Too Many Requests";
			break;
		case 431: // request header fields too large
			ret += "431 Request Header Fields Too Large";
			break;
		case 451: // unavailable for legal reasons
			ret += "451 Unavailable For Legal Reasons";
			break;
		case 500: // internal server error
			ret += "500 Internal Server Error";
			break;
		case 501: // not implemented
			ret += "501 Not Implemented";
			break;
		case 502: // bad gateway
			ret += "502 Bad Gateway";
			break;
		case 503: // service unavilable
			ret += "503 Service Unavailable";
			break;
		case 504: // gateway timeout
			ret += "504 Gateway Timeout";
			break;
		case 505: // http version not supported
			ret += "505 HTTP Version Not Supported";
			break;
		case 506: // variant also negotiates
			ret += "506 Variant Also Negotiates";
			break;
		case 507: // insufficient storage (WebDAV)
			ret += "507 Insufficient Storage";
			break;
		case 508: // loop detected (WebDAV)
			ret += "508 Loop Detected";
			break;
		case 510: // not extended
			ret += "510 Not Extended";
			break;
		case 511: // network authentication required
			ret += "511 Network Authentication Required";
			break;
		default:
			throw std::invalid_argument("...");
			break;
		}

	ret += "\r\n";
	return ret;
}

static inline std::string 
timepoint_to_string(const std::chrono::time_point< std::chrono::system_clock >& tp)
{
	char				buf[4096]	= { 0 };
	const std::time_t	timestamp	= std::chrono::system_clock::to_time_t(tp);
	std::tm				tm			= { 0 };
	std::size_t			ret			= 0x00;
	
	if (::localtime_s(&tm, &timestamp))
		throw std::runtime_error("timepoint_to_string(): Error in ::localtime_s()");

	ret = std::strftime(&buf[0], sizeof(buf), "%c %Z", &tm);

	if (0 == ret || ret > sizeof(buf))
		throw std::invalid_argument("timepoint_to_string(): Error in std::strftime()");

	return std::string(&buf[0], ret);
}

json_body_t::json_body_t(void) : m_body("") 
{
	return;
}

json_body_t::json_body_t(const char* body) : m_body(body) 
{
	return;
}

json_body_t::~json_body_t(void) 
{
	return;
}

json_object_t& 
json_body_t::body(void) 
{ 
	return m_body; 
}

const std::string 
json_body_t::name(void) 
{ 
	return m_body.name(); 
}

/*void 
json_body_t::add(const json_element_t& e) 
{ 
	m_body.add(e); 
	return; 
}*/

void 
json_body_t::append_element(const json_array_t* val)
{
	if (nullptr == val)
		throw std::invalid_argument("...");

	m_body.append_element(val);
}

void 
json_body_t::append_element(const json_object_t* val)
{
	if (nullptr == val)
		throw std::invalid_argument("...");

	m_body.append_element(val);
}

void 
json_body_t::append_element(const json_boolean_t* val)
{
	if (nullptr == val)
		throw std::invalid_argument("...");

	m_body.append_element(val);
}

void 
json_body_t::append_element(const json_decimal_t* val)
{
	if (nullptr == val)
		throw std::invalid_argument("...");

	m_body.append_element(val);
}

void 
json_body_t::append_element(const json_string_t* val)
{
	if (nullptr == val)
		throw std::invalid_argument("...");

	m_body.append_element(val);
}

const char* 
json_body_t::operator()(void) 
{ 
	return m_body.to_string().c_str(); 
}

std::string 
json_body_t::to_base64(void) const
{
	base64_t	b64;

	return b64.encode(m_body.to_string());
}

std::string 
json_body_t::to_string(void) const 
{ 
	return m_body.to_string(); 
}

void 
json_body_t::clear_elements(void) 
{ 
	m_body.clear_elements(); 
	return; 
}

response_context_t::response_context_t(void) 
	: code(0x500) 
{ 
	headers.clear(); 
	body.clear_elements();
	return; 
}

response_context_t::~response_context_t(void) 
{ 
	clear(); 
	return; 
}

void 
response_context_t::clear(void) 
{ 
	code = 500; 
	headers.clear(); 
	body.clear_elements();
	return; 
}


/*txn_t::txn_t(timestamp_t& timestamp, response_context_t& response, uint128_t id)
	: m_id(id), m_timestamp(timestamp), m_response(response)
{
	return;
}*/

txn_t::~txn_t(void)
{
	m_id.low = 0;
	m_id.high = 0;
	m_response.clear();
	return;
}

const uint128_t 
txn_t::id(void) const 
{ 
	return m_id; 
}

void 
txn_t::id(const uint128_t id) 
{ 
	m_id = id; 
	return; 
}

timestamp_t& 
txn_t::timestamp(void) 
{ 
	return m_timestamp; 
}

void 
txn_t::timestamp(const timestamp_t& ts) 
{ 
	m_timestamp = ts; 
	return; 
}

void
txn_t::error(const std::string& msg, const uint32_t code)
{
	const json_string_t message("error_msg", msg.c_str());

	m_response.code = code;
	m_response.body.append_element(&message);
	return;
}

void
txn_t::status(const std::string& msg, const uint32_t code)
{
	const json_string_t message("msg", msg.c_str());

	m_response.code = code;
	m_response.body.append_element(&message);
	return;
}

json_body_t& 
txn_t::body(void) 
{ 
	return m_response.body; 
}

header_map_t& 
txn_t::headers(void) 
{ 
	return m_response.headers; 
}

uint32_t& 
txn_t::code(void) 
{ 
	return m_response.code; 
}

std::string
txn_t::to_string(void) const
{
	const timestamp_t			time_now(std::chrono::system_clock::now());
	const std::string			timestamp(timepoint_to_string(time_now));
	const unsigned int			status_code(m_response.code);
	const std::string			lfnl("\r\n");
	const std::string			body(m_response.body.to_string());
	std::string					ret("");

	
	ret = http_code_to_status(status_code);

	if (0 != body.length()) {
		ret += "Character-Encoding: " HTTP_CHARACTER_ENCODING + lfnl;
		ret += "Content-Length: " + std::to_string(body.length()) + lfnl;
	}

	ret += "Date: " + timestamp + lfnl;
	ret += "Server: " HTTP_SERVER_NAME + lfnl;
	ret += HTTP_SESSION_ID_NAME ": " + uint128_to_string(id()) + lfnl;

	for (auto& hdr : m_response.headers)
		ret += hdr.first + ": " + hdr.second + lfnl;

	ret += lfnl;

	if (0 != body.length())
		ret += body + lfnl;

	return ret;
}


txn_map_t::txn_map_t(void)
{
	return;
}

txn_map_t::txn_map_t(const txn_map_t& rhs) : m_map(rhs.m_map)
{
	return;
}

txn_map_t::~txn_map_t(void)
{ 
	m_map.clear(); 
	return; 
}

void
txn_map_t::add(const uint128_t& id, const txn_t& txn)
{
	std::lock_guard< std::mutex > lock(m_mutex);

	m_map.insert(std::make_pair(id, txn));
	return;
}

void
txn_map_t::add(const txn_t& txn)
{
	std::lock_guard< std::mutex > lock(m_mutex);

	// XXX JF FIXME 128 -> 64
	m_map.insert(std::make_pair(txn.id(), const_cast< const txn_t& >(txn)));
	return;
}

bool 
txn_map_t::has(const uint128_t& id) 
{
	std::lock_guard< std::mutex > lock(m_mutex);

	//printf("txn_map_t::has(): 0x%x%x (%x)\n", id.low, id.high, m_map.size());
	if (m_map.end() == m_map.find(id))
		return false;

	return true;
}

txn_t& 
txn_map_t::operator[](const uint128_t& id)
{
	std::lock_guard< std::mutex > lock(m_mutex);

	return m_map[id]; //.at(id);
}


bool
txn_map_t::get(const uint128_t& id, txn_t& txn)
{
	std::lock_guard< std::mutex > lock(m_mutex);

	if (m_map.end() == m_map.find(id))
		return false;

	txn = m_map.at(id);
	return true;
}

bool
txn_map_t::erase(const uint128_t& id)
{
	if (true == has(id)) {
		m_map.erase(id);
		return true;
	}

	return false;
}

void
txn_map_t::clear(void)
{
	m_map.clear();
	return;
}

std::size_t 
txn_map_t::size(void) const
{ 
	return m_map.size(); 
}


server_t::server_t(enclave_t& e) : m_enclave(e)
{
	m_reg128 = { 0,0 };

	//set_transaction(g_svr_volatile_invalid_txn.id(), g_svr_volatile_invalid_txn);
	return;
}

server_t::server_t(const server_t& rhs) 
	: m_enclave(rhs.m_enclave), m_public(rhs.m_public), m_transactions(rhs.m_transactions), m_reg128(rhs.m_reg128)
{
	return;
}


server_t::~server_t(void)
{
	m_reg128 = { 0,0 };

	return;
}

// XXX JF FIXME infinite loop
inline uint128_t
server_t::generate_id(void)
{
	uint128_t						id = { 0x0,0x0 };

	//printf("server_t::generate_id(): entry\n");
	do { id = generate_rand128(); } while (m_transactions.has(id));
	//printf("server_t::generate_id(): finished\n");
	return id;
}

uint64_t
server_t::now(void)
{
	/*time_t		tstamp = std::time(nullptr);
	struct tm*	tinfo	= std::localtime(&tstamp);

	if (nullptr == tinfo)
		throw std::runtime_error("...");

	return std::string(std::asctime(tinfo));*/
	return std::time(nullptr);
}

transaction_entry_t&
server_t::get_transaction(const uint128_t& id)
{

	if ( m_charesp_txn_map.end() == m_charesp_txn_map.find(id) ) {
		transaction_entry_t txn;
		//charesp_transaction_t txn;

		txn.first.state			= CHARESP_STATE_CLIENT_HELLO;
		txn.second				= "";
		m_charesp_txn_map[ id ] = txn;

		return m_charesp_txn_map[ id ];
	}

	return m_charesp_txn_map[ id ];
}

bool
server_t::initialize_transaction(txn_t& txn, const std::chrono::seconds timeout)
{
	const uint128_t		invalid_id = { 0x00, 0x00 };
	const timestamp_t	time_now(std::chrono::system_clock::now());

	if ( invalid_id == txn.id() ) {
		txn.id(generate_id());
		txn.timestamp(time_now);
		m_transactions.add(txn.id(), txn);

	} else if ( true == m_transactions.has(txn.id()) ) {
		txn_t& old_txn = m_transactions[ txn.id() ];

		if ( timeout < time_now - old_txn.timestamp() ) {
			m_transactions.erase(txn.id());
			txn.id(generate_id());
			txn.timestamp(time_now);
			m_transactions.add(txn.id(), txn);
			txn.status("session timed out", 401);
			return false;
		}

		old_txn.timestamp(time_now);
	}

	return true;

}

bool
server_t::getpublickey(txn_t& txn)
{
	std::string		key("");
	json_string_t	resp;
	base64_t		b64;

	if ( false == m_enclave.public_key(key) )
		return false;

	resp.name("PWDSVC_ECC256_PUBLIC_KEY");
	resp.value(b64.encode(key));
	
	txn.body().append_element(&resp);

	return true;
}

bool 
server_t::handle_service_authenticate(txn_t& txn, parameter_map_t& parameters)
{
	std::string				user	= ( parameters.end() == parameters.find("username") ?
										std::string("") : parameters[ "username" ] );
	transaction_entry_t&	tex		= get_transaction(txn.id());
	charesp_transaction_t&	ctxn	= tex.first;
	//charesp_transaction_t&	ctxn = get_transaction(txn.id());

	if ( ! tex.second.empty() )
		user = tex.second;
	else
		tex.second = user;

	if ( 0 == user.length() ) {
		txn.status("Authentication failed - invalid username", 401);
		return false;
	}

	switch ( ctxn.state ) {
		case CHARESP_STATE_CLIENT_HELLO:

			if ( false == handle_client_hello(user, ctxn, txn, parameters) ) 
				return false;

			ctxn.state = CHARESP_STATE_SERVER_HELLO;
			break;

		case CHARESP_STATE_SERVER_HELLO:
			//printf("case CHARESP_STATE_SERVER_HELLO\n");
			if ( false == handle_client_response(user, ctxn, txn, parameters) )
				return false;

			ctxn.state = CHARESP_STATE_CLIENT_AUTHENTICATED;
			break;
		case CHARESP_STATE_CLIENT_AUTHENTICATED:
			break;
		case CHARESP_STATE_SERVER_AUTHENTICATED:
			break;
		default:
			break;
	}

	return true;
}

bool 
server_t::handle_client_hello(const std::string& user, charesp_transaction_t& ctxn, txn_t& txn, parameter_map_t& parameters)
{
	const std::string	pk_str("public_key"), ts_str("timestamp");
	const std::string	invalid_parameters("Authentication Failed - Invalid parameter(s)");
	std::string			public_key(""), timestamp("");
	uint64_t			ts(0);
	base64_t			b64;

	txn.body().clear_elements();

	if ( parameters.end() != parameters.find(pk_str) )
		public_key = parameters[ pk_str ];
	if ( parameters.end() != parameters.find(ts_str) )
		timestamp = parameters[ ts_str ];

	public_key = b64.decode(public_key);

	if ( 0 == public_key.length() || sizeof(ctxn.client_hello.public_key) != public_key.length()
		|| 0 == timestamp.length() || !timestamp.compare("0") ) 
	{
		txn.status(invalid_parameters, 401);
		return false;
	}

	ts = std::strtoull(timestamp.c_str(), nullptr, 10);

	if ( 0 == ts ) {
		txn.status(invalid_parameters, 401);
		return false;
	}

	std::memcpy(&ctxn.client_hello.public_key, public_key.c_str(), sizeof(ctxn.client_hello.public_key));
	ctxn.client_hello.time = ts;

	if ( false == m_enclave.do_challenge_response(user, &ctxn) ) {
		txn.status("Authentication Failed: enclave", 401);
		return false;
	}

	{
		charesp_server_hello_ct_t*	ct = reinterpret_cast<charesp_server_hello_ct_t*>( &ctxn.server_hello );
		json_string_t	nonce;
		json_decimal_t	time;
		json_string_t	signature;
		json_string_t	cipher_text;

		nonce.name("nonce");
		nonce.value(b64.encode(std::string(reinterpret_cast<char*>( &ct->nonce ), sizeof(ct->nonce))));
		txn.body().append_element(&nonce);

		time.name("timestamp");
		time.integral(ct->time);
		txn.body().append_element(&time);

		signature.name("signature");
		signature.value(b64.encode(std::string(reinterpret_cast<char*>( &ct->signature ), sizeof(ct->signature))));
		txn.body().append_element(&signature);

		cipher_text.name("cipher_text");
		cipher_text.value(b64.encode(std::string(reinterpret_cast<char*>( &ct->cipher_text ), sizeof(ct->cipher_text))));
		txn.body().append_element(&cipher_text);

	}

	//printf("server_t::handle_client_hello(): challenge: %x challenge: %x increment: %x [e]\n", ctxn.server_hello.challenge + ctxn.server_hello.increment, ctxn.server_hello.challenge, ctxn.server_hello.increment);
	return true;
}

bool 
server_t::handle_client_response(const std::string& user, charesp_transaction_t& ctxn, txn_t& txn, parameter_map_t& parameters)
{
	const std::string				ct_str("cipher_text"), nonce_str("nonce");
	const std::string				sig_str("signature"), time_str("timestamp");
	const std::string				invalid_parameters("Authentication Failed - Invalid parameter(s)");
	charesp_client_response_ct_t*	csr = reinterpret_cast< charesp_client_response_ct_t* >( &ctxn.client_response );
	charesp_server_response_ct_t*	ssr = reinterpret_cast< charesp_server_response_ct_t* >( &ctxn.server_response );
	std::string						tmp("");
	base64_t						b64;

	if ( false == has_parameter(ct_str, parameters) || false == has_parameter(nonce_str, parameters) ||
		false == has_parameter(sig_str, parameters) || false == has_parameter(time_str, parameters) ) {

		txn.status(invalid_parameters, 401);
		return false;
	}

	tmp = b64.decode(parameters[ ct_str ]);

	if ( sizeof(csr->cipher_text) != tmp.length() ) {
		txn.status(invalid_parameters, 401);
		return false;
	}

	std::memcpy(&csr->cipher_text, tmp.data(), sizeof(csr->cipher_text));

	tmp = b64.decode(parameters[ nonce_str ]);

	if ( sizeof(csr->nonce) != tmp.length() ) {
		txn.status(invalid_parameters, 401);
		return false;
	}

	std::memcpy(&csr->nonce, tmp.data(), sizeof(csr->nonce));

	tmp = b64.decode(parameters[sig_str]);

	if ( sizeof(csr->signature) != tmp.length() ) {
		txn.status(invalid_parameters, 401);
		return false;
	}

	std::memcpy(&csr->signature, tmp.data(), sizeof(csr->signature));

	csr->time = std::strtoul(parameters[ time_str ].c_str(), nullptr, 10);

	if ( 0 == time ) {
		txn.status(invalid_parameters, 401);
		return false;
	}

	if ( false == m_enclave.do_challenge_response(user, &ctxn) ) {
		printf("server_t::handle_client_response():  do_challenge_response()\n");
		txn.status("Authentication Failed: enclave", 401);
		return false;
	}

	{
		json_string_t	nonce;
		json_decimal_t	time;
		json_string_t	signature;
		json_string_t	cipher_text;

		nonce.name("nonce");
		nonce.value(b64.encode(std::string(reinterpret_cast<char*>( &ssr->nonce ), sizeof(ssr->nonce))));
		txn.body().append_element(&nonce);

		time.name("timestamp");
		time.integral(ssr->time);
		txn.body().append_element(&time);

		signature.name("signature");
		signature.value(b64.encode(std::string(reinterpret_cast<char*>( &ssr->signature ), sizeof(ssr->signature))));
		txn.body().append_element(&signature);

		cipher_text.name("cipher_text");
		cipher_text.value(b64.encode(std::string(reinterpret_cast<char*>( &ssr->cipher_text ), sizeof(ssr->cipher_text))));
		txn.body().append_element(&cipher_text);
	}

	return true;
}

bool 
server_t::handle_service_adduser(txn_t& txn, parameter_map_t& parameters)
{
	const std::string	user_str("username"), pass_str("password");
	std::string			username(""), password("");

	if ( parameters.end() != parameters.find(user_str) )
		username = parameters[ user_str ];
	if ( parameters.end() != parameters.find(pass_str) )
		password = parameters[ pass_str ];

	if ( 0 == username.length() || 0 == password.length() ) {
		printf("adduser 0 == ...\n");
		txn.status("Add User Failed: Invalid Parameter(s)", 400);
		return false;
	}

	if ( false == m_enclave.user_add(username, password) ) {
		printf("user_add() ...\n");
		txn.status("Add User Failed: enclave", 400);
		return false;
	}

	printf("handle_service_adduser() finished\n");
	return true;
}

bool 
server_t::handle_service_updateuser(txn_t& txn, parameter_map_t& parameters)
{
	return true;
}

bool
server_t::do_request(const server_opcodes_t operation, txn_t& txn,
					 parameter_map_t& parameters, std::string& ret,
					 const std::chrono::seconds timeout)
{

	if ( false == initialize_transaction(txn, timeout) ) 
		return false;

	switch ( operation ) {
		case SERVICE_GET_PUBLIC_KEY:
		{
			//if (0 == m_public.length()) {
			//	m_enclave.public_key(m_public);
			//} // else {
			// m_enclave.is_public_key_same(m_public) ? 
			// ...

			if ( false == getpublickey(txn) )
				return false;

			return true;
		}
		break;

		case SERVICE_AUTHENTICATE:

			if ( false == handle_service_authenticate(txn, parameters) ) 
				return false;

			break;

		case SERVICE_ADD_USER:
			if ( false == handle_service_adduser(txn, parameters) )
				return false;

			break;
		case SERVICE_UPDATE_USER:
			if ( false == handle_service_updateuser(txn, parameters) )
				return false;

			break;
		default:
			txn.status("Invalid Operation Requested", 400);
			return false;
			break;
	}

	txn.status("Operation Successfully Completed", 200);
	ret = txn.to_string();
	return true;
}

/*				switch (ctxn_ref.state) {
						case CHARESP_STATE_CLIENT_HELLO:
							printf("server_t::do_request(): state client hello\n");

							std::memcpy(&ctxn_ref.client_hello.public_key, &m_keypair.public_key(), sizeof(ctxn_ref.client_hello.public_key));
							ctxn_ref.client_hello.time = now();
							break;

						case CHARESP_STATE_SERVER_HELLO:
							{
								printf("server_t::do_request(): state server hello\n");

								//if (false == handle_server_hello(txn, parameters, ctxn_ref))
								//	break;
								handle_server_hello(txn, parameters, ctxn_ref);
								//txn.status("AUTHENTICATE: CHARESP_STATE_SERVER_HELLO unimplemented");
							}

							break;
						case CHARESP_STATE_CLIENT_AUTHENTICATED:
							printf("server_t::do_request(): state client authenticated\n");

							txn.status("AUTHENTICATE: CHARESP_STATE_CLIENT_AUTHENTICATED unimplemented", 500);
							break;
						case CHARESP_STATE_SERVER_AUTHENTICATED:
							printf("server_t::do_request(): state server authenticated\n");

							txn.status("AUTHENTICATE: CHARESP_STATE_SERVER_AUTHENTICATED unimplemented", 500);
							break;
						default:
							printf("server_t::do_request(): invalid state\n");

							txn.status("AUTHENTICATE: default unimplemented");
							break;
				}
			
				printf("server_t::do_request(): calling into enclave via do_challenge_response()\n");

				if (false == m_enclave.do_challenge_response(user, &ctxn_ref)) {
					txn.status("AUTHENTICATE: error inside enclave", 500);
					return false;
				}


				return true;
			}

			break;*/
