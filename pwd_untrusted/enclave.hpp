#pragma once

#define NOMINMAX

#include <fstream>
#include <string>
#include <vector>
#include <limits>
#include <sys/stat.h>

#include "encrypted_file.hpp"
#include "pwd_u.h"
#include "sgx_urts.h"
#include "sgx_tseal.h"
#include "common.hpp"

class enclave_t
{
	private:
		sgx_enclave_id_t		m_eid;
		sgx_launch_token_t		m_token;
		sgx_misc_attribute_t	m_attr;
		encrypted_file_t		m_efile;

		std::string				m_token_file;
		std::string				m_enclave_file;
		std::string				m_seal_file;
		std::string				m_base;
		bool					m_debug;
		bool					m_init;

	protected:
		bool write_seal_file(std::vector< uint8_t >&);
		bool open_seal_file(std::vector< uint8_t >&);
		bool write_token_file(void);
		bool open_token_file(void);
		bool file_exists(std::string&);


	public:
		enclave_t(std::string& token_file, std::string& seal, std::string& file, std::string& base, bool dbg = false);
		enclave_t(void);
		~enclave_t(void);

		bool destroy(void);
		bool initialize(void);
		bool init_mmap(const std::string&, const std::size_t rep = 8192, bool is_new = false);
		bool flush_mmap(void);

		bool user_add(std::string&, std::string&);
		bool user_update(const std::string&, const std::string&, const std::string&);
		bool password_verify(const std::string&, const std::string&);
		bool user_find(const std::string&, std::string&);

		bool record_encrypt(const std::string&);
		bool encrypt_all_records(void);

		bool public_key(std::string& key);
		bool do_challenge_response(const std::string& user, charesp_transaction_t* ptr);

		void base_path(std::string& f) { m_base = f; return; }
		std::string base_path(void) { return m_base; }

		void token_file(std::string& f) { m_token_file = f; return; }
		std::string token_file(void) { return m_token_file; }

		void seal_file(std::string& f) { m_seal_file = f; return; }
		std::string seal_file(void) { return m_seal_file; }

		void enclave_file(std::string& f) { m_enclave_file = f; return; }
		std::string enclave_file(void) { return m_enclave_file; }

		void debug(bool d) { m_debug = d; return; }
		bool debug(void) { return m_debug; }

};

