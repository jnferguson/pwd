#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <chrono>
#include <iomanip>
#include <ctime>
#include <mutex>

#include "enclave.hpp"
#include "json.hpp"
#include "base64.hpp"
#include "sha256.hpp"

#include "sgx_replace.hpp"

#ifndef uint128_t 
#include "int128.hpp"
#endif

#include "ecc256_keypair.hpp"
#include "json11.hpp"

typedef std::chrono::duration< uint64_t, std::chrono::seconds >  timeout_t;
typedef std::chrono::time_point< std::chrono::system_clock, std::chrono::seconds > pointintime_t;
typedef std::chrono::time_point< std::chrono::system_clock > timestamp_t;	
typedef std::unordered_map< std::string, std::string > header_map_t;

typedef header_map_t parameter_map_t;

typedef enum {
	SERVICE_GET_PUBLIC_KEY = 0x00,
	SERVICE_AUTHENTICATE = 0x01,
	SERVICE_ADD_USER = 0x02,
	SERVICE_UPDATE_USER = 0x03,
	SERVICE_INVALID_SERVICE = 0x04
} server_opcodes_t;

#define HTTP_CHARACTER_ENCODING "US-ASCII"
#define HTTP_SERVER_NAME "PWDSVC"
#define HTTP_SESSION_ID_NAME "PWDSVCSESSIONID"

static inline std::string http_code_to_status(const uint32_t);
static inline std::string timepoint_to_string(const std::chrono::time_point< std::chrono::system_clock >&);

class json_body_t {
	private:
	protected:
		json_object_t	m_body;

	public:
		json_body_t(void);
		json_body_t(const char* body);

		virtual ~json_body_t(void);

		virtual json_object_t& body(void);
		virtual const std::string name(void);

		//virtual void add(const json_element_t&);
		virtual void append_element(const json_array_t*);
		virtual void append_element(const json_object_t*);
		virtual void append_element(const json_boolean_t*);
		virtual void append_element(const json_decimal_t*);
		virtual void append_element(const json_string_t*);

		virtual const char* operator()(void);
		virtual std::string to_string(void) const;
		virtual std::string to_base64(void) const;
		virtual void clear_elements(void);
};

class response_context_t {
	private:
	protected:
	public:
		uint32_t		code;
		std::string		code_str;
		header_map_t	headers;
		json_body_t		body;
		std::string		body_str;

		response_context_t(void);
		~response_context_t(void);
		void clear(void);
};

class txn_t {
	private:
	protected:
		uint128_t			m_id;
		timestamp_t			m_timestamp;
		response_context_t	m_response;

	public:
		txn_t(void)
			: m_id({ 0x0,0x0 }), m_timestamp(std::chrono::system_clock::now()), m_response(response_context_t())
		{
			return;
		}

		virtual ~txn_t(void);

		virtual void 
		clear(bool reset_id = false) 
		{
			if ( true == reset_id )
				m_id = { 0,0 };

			m_timestamp = std::chrono::system_clock::now(); 
			m_response.clear(); 
			return; 
		}

		virtual const uint128_t id(void) const;
		virtual void id(const uint128_t);

		virtual timestamp_t& timestamp(void);
		virtual void timestamp(const timestamp_t&);
	
		virtual void error(const std::string& msg, const uint32_t code = 401);
		virtual void status(const std::string& msg, const uint32_t code = 200);

		virtual json_body_t& body(void);
		virtual header_map_t& headers(void);
		virtual uint32_t& code(void);

		virtual std::string to_string(void) const;
};



class txn_map_t
{
	private:
		std::unordered_map< uint128_t, txn_t, int128_hasher >	m_map;
		std::mutex												m_mutex;

protected:
	public:
		txn_map_t(void);
		txn_map_t(const txn_map_t&);
		~txn_map_t(void);
		
		void add(const uint128_t&, const txn_t&);
		void add(const txn_t&);

		bool has(const uint128_t&);
		txn_t& operator[](const uint128_t&);

		bool get(const uint128_t&, txn_t&);

		bool erase(const uint128_t&);

		void clear(void);

		std::size_t size(void) const;
};

typedef std::pair< charesp_transaction_t, std::string > transaction_entry_t;
typedef std::unordered_map< uint128_t, transaction_entry_t, int128_hasher > charesp_txn_map_t;

class server_t
{
	private:
	protected:
		enclave_t&			m_enclave;
		std::string			m_public;
		txn_map_t			m_transactions;
		ecc256_keypair_t	m_keypair;
		charesp_txn_map_t	m_charesp_txn_map;
		
		inline static bool has_parameter(const std::string& key, parameter_map_t& map) { if ( map.end() == map.find(key) ) return false; return true; }
		// XXX JF FIXME generate actual random 64 bit number, maybe 128 bit
		uint128_t m_reg128;
		inline uint128_t generate_rand128(void)
		{
			static const uint128_t zero_128 = { 0,0x00 };
			static const uint128_t one_128	= { 0,0x01 };

			if (zero_128 == m_reg128) {
				m_reg128.high	= 0x42;
				m_reg128.low	= 0x42;
			}
			else
				m_reg128 = m_reg128 + one_128;

			return m_reg128;
		}

		bool
		get_client_response_ciphertext(charesp_client_response_t& in, charesp_client_response_t& out, const aes_ctr_128bit_key_t& session_key)
		{
			charesp_client_response_ct_t* const ct = reinterpret_cast< charesp_client_response_ct_t* const >(&in);
			charesp_client_response_ct_t* const pt = reinterpret_cast< charesp_client_response_ct_t* const >(&out);

			::memcpy(&out, &in, sizeof(out));

			if (false == m_keypair.aes_ctr_encrypt(&ct->cipher_text[0], sizeof(ct->cipher_text), reinterpret_cast< uint8_t* >(&pt->cipher_text[0]), sizeof(pt->cipher_text),
				&ct->nonce[0], session_key, 0x20)) // XXX JF FIXME 0x20 - configurable
				return false;

			return true;
		}

		bool
		handle_server_hello(txn_t& txn, parameter_map_t& parameters, charesp_transaction_t& ctxn_ref)
		{
			charesp_server_hello_t		tmp = { 0 };
			charesp_server_hello_ct_t*	ct(reinterpret_cast< charesp_server_hello_ct_t* >(&tmp));
			charesp_server_hello_ct_t*	hct(reinterpret_cast< charesp_server_hello_ct_t* >(&ctxn_ref.server_hello));
			ec256_signature_t			sig = { 0 };
			std::string					svr_pub("");
			ec256_public_key_t			pub_key;
			aes_ctr_128bit_key_t		session_key = { 0 };
			const std::string			user = (parameters.end() == parameters.find("user") ?
				std::string("") : parameters["user"]);
			const std::string			password(parameters.end() == parameters.find("password") ?
				std::string("") : parameters["password"]);
			sha256_t					sha;
			uint32_t					value(0);
			const uint32_t				scratch_len = sizeof(ctxn_ref.client_response.challenge) +
				sizeof(ctxn_ref.client_response.increment) +
				sizeof(ctxn_ref.client_response.nonce);
			uint8_t						scratch[scratch_len] = { 0 };
			sha256_hash_t				hash = { 0 };
			charesp_hmac_msg_t			msg = { 0 };
			charesp_client_response_t	output = { 0 };

			if (0 == m_public.length()) {
				if (false == m_enclave.public_key(svr_pub)) {
					txn.status("AUTHENTICATE: Error retrieving server public key...", 500);
					return false;
				}
			}

			std::memcpy(&pub_key, &svr_pub[0], sizeof(pub_key));


			if (sizeof(charesp_server_hello_t) != sizeof(charesp_server_hello_ct_t)) {
				return false;
			}

			std::memcpy(&sig, &hct->signature, sizeof(sig));
			std::memcpy(ct, hct, sizeof(charesp_server_hello_t));
			std::memset(&ct->signature, 0, sizeof(ct->signature));
			printf("handle_server_hello(): verifying server signature...\n");
			if (false == m_keypair.verify(std::string(reinterpret_cast<const char*>(&ct->cipher_text[0])), pub_key, sig)) {
				printf("handle_server_hello(): server signature failed verification...\n");
				txn.status("AUTHENTICATE: Error verifying server signature", 401);
				return false;
			}

			printf("handle_server_hello(): deriving session key...\n");
			if (false == m_keypair.derive_key(reinterpret_cast< const unsigned char* >(user.c_str()),
				pub_key, session_key))
			{
				txn.status("AUTHENTICATE: Error derriving shared AES key", 401);
				return false;
			}

			printf("handle_server_hello(): validating timestamps...\n");
			// XXX JF FIXME 2 minute timeout -> configurable
			if (120.0 < std::difftime(now(), ct->time)) {
				txn.status("AUTHENTICATE: authentication timed out", 401);
				return false;
			}

			printf("handle_server_hello(): decrypting message...\n");
			if (false == m_keypair.aes_ctr_decrypt(&ct->cipher_text[0], sizeof(ct->cipher_text),
				&hct->cipher_text[0], sizeof(hct->cipher_text),
				&ct->nonce[0], session_key, 0x20))
			{ // XXX JF FIXME inc_bits
				txn.status("AUTHENTICATE: failed to decrypt server hello", 401);
				return false;
			}

			value = ctxn_ref.server_hello.challenge;
			value += ctxn_ref.server_hello.increment;

			printf("handle_server_hello(): read_rand()\n");
			if (SGX_SUCCESS != sgx_replace_t::read_rand(&scratch[0], scratch_len))
				return false;

			::memcpy(&ctxn_ref.client_response.challenge, &scratch[0], sizeof(ctxn_ref.client_response.challenge));
			::memcpy(&ctxn_ref.client_response.increment, &scratch[sizeof(ctxn_ref.client_response.challenge)], sizeof(ctxn_ref.client_response.increment));
			::memcpy(&ctxn_ref.client_response.nonce, &scratch[sizeof(ctxn_ref.client_response.challenge) + sizeof(&ctxn_ref.client_response.increment)], sizeof(ctxn_ref.client_response.nonce));

			msg.client_hello = ctxn_ref.client_hello;
			msg.client_challenge = ctxn_ref.client_response.challenge;
			msg.server_challenge = ctxn_ref.server_hello.challenge;
			msg.server_hello = ctxn_ref.server_hello;

			printf("handle_server_hello(): sha.hmac()\n");
			if (false == sha.hmac(reinterpret_cast<const uint8_t*>(&msg), sizeof(msg),
				reinterpret_cast<const unsigned char*>(password.c_str()),
				password.length(), hash))
			{
				txn.status("AUTHENTICATE: error generating SHA HMAC", 401);
				return false;
			}

			std::memcpy(&ctxn_ref.client_response.hash, &hash, sizeof(ctxn_ref.client_response.hash));

			ctxn_ref.client_response.time = now();

			printf("handle_server_hello(): get_client_response_ciphertext()\n");

			if (false == get_client_response_ciphertext(ctxn_ref.client_response, output, session_key)) {
				txn.status("AUTHENTICATE: CHARESP_STATE_SERVER_HELLO error encrypting client response", 401);
				return false;
			}

			printf("handle_server_hello(): m_keypair.sign()\n");
			if (false == m_keypair.sign(&reinterpret_cast<charesp_client_response_ct_t*>(&output)->cipher_text[0],
				sizeof(reinterpret_cast<charesp_client_response_ct_t*>(&output)->cipher_text),
				sig))
			{
				txn.status("AUTHENTICATE: CHARESP_STATE_SERVER_HELLO error signing client response", 401);
				return false;
			}

			std::memcpy(&output.signature, &sig, sizeof(output.signature));
			std::memcpy(&ctxn_ref.client_response, &output, sizeof(ctxn_ref.client_response));
			ctxn_ref.state = CHARESP_STATE_CLIENT_AUTHENTICATED;

			printf("AUTHENTICATE: CLIENT PUBLIC KEY:\r\ng(x): ");
			for (std::size_t idx = 0; idx < sizeof(ctxn_ref.client_hello.public_key.gx); idx++)
				printf("%x", ctxn_ref.client_hello.public_key.gx[idx]);

			printf(" g(y): ");
			for (std::size_t idx = 0; idx < ctxn_ref.client_hello.public_key.gy[idx]; idx++)
				printf("%x", ctxn_ref.client_hello.public_key.gy[idx]);

			printf("\n");
			printf("AUTHENTICATE: CLIENT SIGNATURE:\r\nx: ");
			for (std::size_t idx = 0; idx < sizeof(ctxn_ref.client_response.signature.x); idx++)
				printf("%x", ctxn_ref.client_response.signature.x[idx]);
			printf(" y: ");
			for (std::size_t idx = 0; idx < sizeof(ctxn_ref.client_response.signature.y); idx++)
				printf("%x", ctxn_ref.client_response.signature.y[idx]);
			printf("\n");

			return true;
		}

		bool handle_service_authenticate(txn_t&, parameter_map_t&);
		bool handle_service_adduser(txn_t&, parameter_map_t&);
		bool handle_service_updateuser(txn_t&, parameter_map_t&);

		bool handle_client_hello(const std::string&, charesp_transaction_t&, txn_t&, parameter_map_t&);
		bool handle_client_response(const std::string&, charesp_transaction_t&, txn_t&, parameter_map_t&);

		bool initialize_transaction(txn_t&, const std::chrono::seconds);
		bool getpublickey(txn_t&);

	public:
		server_t(enclave_t&);
		~server_t(void);
		server_t(const server_t&);
		

		// this function seems horribly wrong like im returning a reference to a stack allocated object but my brain is
		// apparently not braining atm so re-review this when it is.
		transaction_entry_t& get_transaction(const uint128_t& id);

		// XXX JF FIXME infinite loop
		inline uint128_t generate_id(void);
		//inline std::string now(void);
		inline uint64_t now(void);

		bool do_request(const server_opcodes_t, txn_t&, parameter_map_t&, std::string&, const std::chrono::seconds timeout = std::chrono::seconds(60));
};

