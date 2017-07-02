#pragma once

#include <cstdint>
#include <vector>
#include <string>
#include <stdexcept>
#include <array>
#include <ctime>
#include <time.h>
#include <functional>

#include "server.hpp"
#include "ecc256_keypair.hpp"
#include "json.hpp"
#include "base64.hpp"
#include "logger.hpp"

class challenge_response_base_t
{
	private:
	protected:
	public:
		challenge_response_base_t(void) { }
		virtual ~challenge_response_base_t(void) { }
};

class client_hello_t final : public challenge_response_base_t
{
	private:
	protected:
		std::string		m_key;
		uint64_t		m_timestamp;
	public:
		client_hello_t(const std::string& k = std::string(""), uint64_t t = 0) : m_key(k), m_timestamp(t) { }

		const std::string& key(void) const { return m_key; }
		void key(const std::string& k) { m_key = k; return; }

		const uint64_t timestamp(void) const { return m_timestamp; }
		void timestamp(const uint64_t t) { m_timestamp = t; }	

	json_string_t  key_to_json(void) { return json_string_t("public_key", m_key.c_str()); }
	json_decimal_t timestamp_to_json(void) { return json_decimal_t("timestamp", m_timestamp); }
};

class server_hello_t final : public challenge_response_base_t 
{
	private:
	protected:
		std::array< uint8_t, CR_NONCE_SIZE >	m_nonce;
		uint64_t								m_time;
		ec256_signature_t						m_signature;
		uint64_t								m_challenge;
		uint64_t								m_increment;

	public:
		server_hello_t(void) { }
		~server_hello_t(void) { }

		std::array< uint8_t, CR_NONCE_SIZE >& nonce(void) { return m_nonce; }
		void nonce(const std::array< uint8_t, CR_NONCE_SIZE >& n) { m_nonce = n; return; }

		uint64_t time(void) const { return m_time; }
		void time(const uint64_t t) { m_time = t; return; }

		ec256_signature_t& signature(void) { return m_signature; }
		void signature(const ec256_signature_t& s) { m_signature = s; return; }

		uint64_t challenge(void) const { return m_challenge; }
		void challenge(const uint64_t c) { m_challenge = c; return; }

		uint64_t increment(void) const { return m_increment; }
		void increment(const uint64_t i) { m_increment = i; return; }
};

class challenge_response_ciphertext_t final : public challenge_response_base_t
{
	private:
	protected:
		std::string	m_ciphertext;
		std::string m_nonce;
		std::string m_signature;
		std::string m_msg;
		uint64_t	m_timestamp;

	public:
	challenge_response_ciphertext_t(void) { }
	~challenge_response_ciphertext_t(void) { }
	
	std::string& ciphertext(void) { return m_ciphertext; }
	void ciphertext(const std::string& ct) { m_ciphertext = ct; return; }

	std::string& nonce(void) { return m_nonce; }
	void nonce(const std::string& n) { m_nonce = n; return; }

	std::string& signature(void) { return m_signature; }
	void signature(const std::string& s) { m_signature = s; return; }

	std::string& message(void) { return m_msg; }
	void message(const std::string& m) { m_msg = m; return; }

	uint64_t timestamp(void) const { return m_timestamp; }
	void timestamp(uint64_t t) { m_timestamp = t; return; }
};

typedef std::function<bool(json11::Json&, response_context_t&, challenge_response_base_t&)> parser_callback_t;

class client_t
{
	private:
	protected:
		uint128_t			m_txn_ids;
		server_t			m_server;
		txn_t				m_txn;
		parameter_map_t		m_parameters;
		ecc256_keypair_t	m_keypair;
		std::string			m_user;
		std::string			m_password;


		bool parse_response(const std::string& resp, response_context_t& ctx, challenge_response_base_t& crb, parser_callback_t& cb) const;
	
		std::string ptr_to_str(void* ptr, std::size_t len);
		ec256_public_key_t get_svc_key(void);

		static std::string trim_whitespace(const std::string& str);

		static bool parse_ciphertext(json11::Json& json, response_context_t& ctx, challenge_response_base_t& crb);

		bool decrypt_server_response(challenge_response_ciphertext_t& cr, charesp_server_response_t& ret, ec256_public_key_t& svc_key, aes_ctr_128bit_key_t& session_key);
		bool decrypt_server_hello(challenge_response_ciphertext_t& cr, charesp_server_hello_t& ret, ec256_public_key_t& svc_key, aes_ctr_128bit_key_t& session_key);

		bool get_server_hello(charesp_transaction_t& ctxn, ec256_public_key_t& svc_key, aes_ctr_128bit_key_t& session_key);
		bool get_client_response(charesp_transaction_t& ctxn, ec256_public_key_t& svc_key, aes_ctr_128bit_key_t& session_key);

		bool put_client_response(charesp_transaction_t& ctxn, ec256_public_key_t& svc_key, aes_ctr_128bit_key_t& session_key);

	public:
		client_t(server_t&);
		client_t(const std::string& u, const std::string& p, server_t& s);
		
		virtual ~client_t(void);

		virtual const std::string& username(void) const;
		virtual void username(const std::string& u);
		virtual const std::string& password(void) const;
		virtual void password(const std::string& p);
		virtual bool do_request(const server_opcodes_t operation);
		virtual txn_t& txn(void);

		virtual parameter_map_t& parameters(void);
		virtual void insert_parameters(const std::string& key, const std::string& value);
		
		virtual std::string get_public_key(bool decode_b64 = true);
		virtual std::string authenticate(void);
		virtual std::string add_user(void);
		virtual std::string update_user(void);
};


