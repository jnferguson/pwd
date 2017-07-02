// pwd_untrusted.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "pwd_u.h"
#include "sgx_urts.h"
//#include "sgx_utils/sgx_utils.h"

#include <cstdlib>
#include <iostream>
#include <iomanip>

#include "enclave.hpp"
#include "encrypted_file.hpp"
#include "server.hpp"
#include "client.hpp"
#include "logger.hpp"

void 
ocall_print(const char* str) 
{
	printf("%s\n", str);
	return;
}

void 
log_msg(unsigned int priority, const char* file, unsigned int line, const char* msg)
{
	static const char*	error_string("log_msg(): invalid logging priority requested");
	logging_priority_t	pr(static_cast< logging_priority_t >( priority ));

	if ( pr >= LOG_INVALID_PRIORITY || nullptr == file || nullptr == msg)
		throw std::runtime_error(error_string);

	logger_t::instance().log_wrapper(pr, file, line, msg);
	return;
}

#include <stdio.h>
#include <stdlib.h>

class random_string_t
{
private:
	const std::string	m_alphabet;
	uint32_t			m_seed;
	const uint32_t		m_a;
	const uint32_t		m_m;
	const uint32_t		m_c;

protected:
public:
	random_string_t(void)
		: m_alphabet("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()<>.,?`~-_=+[]{}|"),
		m_seed((uint32_t)time(NULL)), m_a(1103515245), m_m(0xffffffff), m_c(12345)
	{
		return;
	}

	inline std::size_t
		rnd(void)
	{
		m_seed = (m_a * m_seed + m_c) % m_m;
		return m_seed;
	}

	std::string
		str(std::size_t min = 6, std::size_t max = 15)
	{
		std::string ret("");
		std::size_t bounds(rnd() % max);

		if (min && min > bounds) {
			for (std::size_t idx = 0; idx < min; idx++)
				ret += static_cast<char>(m_alphabet[rnd() % m_alphabet.length()]);

			return ret;
		}

		for (std::size_t idx = 0; idx < bounds; idx++)
			ret += static_cast<char>(m_alphabet[rnd() % m_alphabet.length()]);

		return ret;
	}
};


signed int
main(signed int ac, char** av)
{
	std::string work_dir("");
	//std::string input_file("C:\\Users\\justin\\Downloads\\yahoo-disclosure.txt\\usernames-email-dedup.txt");
	enclave_t	enclave;
	server_t	server(enclave);
	client_t	client(server);
	logger_t&	log = logger_t::instance(".\\log", true, false);

	if (2 != ac)
		work_dir = ".\\";
	else
		work_dir = av[1];

	if (2 < work_dir.size() && work_dir.substr(work_dir.size() - 2, std::string::npos).compare("\\"))
		work_dir += "\\";

	enclave.enclave_file(std::string("pwd.signed.dll"));
	enclave.token_file(std::string("pwd.token"));
	enclave.seal_file(std::string("pwd.sealed"));
	enclave.base_path(work_dir);

	if (false == enclave.initialize()) {
		std::cerr << "Failed to initialize enclave" << std::endl;
		return EXIT_FAILURE;
	}

	if (false == enclave.init_mmap(work_dir + "\\users.enc", 8192, false)) {
		std::cerr << "Failed to initialize enclave memory mapping" << std::endl;
		enclave.destroy();
		return EXIT_FAILURE;
	}

	/*if ( false == enclave.encrypt_all_records() ) {
		std::cerr << "Failed to encrypt user database." << std::endl;
		enclave.destroy();
		return EXIT_FAILURE;
	}*/

	printf("Sleeping...\n");
	::Sleep(1000 * ( 60 * 1 ));

	std::cout << "PUBLIC KEY: " << std::endl;
	std::cout << client.get_public_key() << std::endl;


	/*if ( false == enclave.destroy() ) {
		std::cerr << "Failed to destroy enclave" << std::endl;
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;*/

	client.username("justin_zero@asac.co");
	client.password("password");
	std::cout << "ADD_USER: " << std::endl;
	std::cout << client.add_user() << std::endl;

	client.username("justin_zero@asac.co");
	client.password("password");

	std::cout << "Calling authenticate()..." << std::endl;
	try { std::cout << "AUTHENTICATE: " << client.authenticate() << std::endl; }
	catch ( std::exception& e ) { std::cout << "Exception caught: " << e.what() << std::endl; return EXIT_FAILURE; }
	catch ( ... ) { std::cout << "exception caught" << std::endl; return EXIT_FAILURE; }

	if ( false == enclave.destroy() ) {
		std::cerr << "Failed to destroy enclave" << std::endl;
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;

	/*if (false == enclave.encrypt_all_records()) {
		std::cerr << "Failed to encrypt all records" << std::endl;
		enclave.destroy();
		return EXIT_FAILURE;
	}*/

	std::string jf("justin_zero@asac.co"), password("password");

	if (false == enclave.password_verify(jf, password)) {
		std::cerr << "Failed to verify password" << std::endl;
		enclave.destroy();
		return EXIT_FAILURE;
	}

	/*if (false == enclave.user_add(jf, password)) {
		std::cerr << "Failed to add user..." << std::endl;
		enclave.destroy();
		return EXIT_FAILURE;
	}*/

	/*if (false == enclave.encrypt_all_records()) {
		std::cerr << "Failed to encrypt all records" << std::endl;
		return EXIT_FAILURE;
	}*/

/*	std::ifstream ifs(input_file, std::ifstream::in);
	std::string line("");
	uint64_t cnt(0), user_cnt(0);
	random_string_t rnd;

	if (false == ifs.is_open() || true == ifs.bad() || true == ifs.fail()) {
		std::cerr << "Failed to open input file" << std::endl;
		return EXIT_FAILURE;
	}

	while (std::getline(ifs, line)) {
		std::string u(line), p("password"), n(rnd.str());

		if (!line.length()) {
			std::cerr << "skipping empty user..." << std::endl;
			continue;
		}

		if (false == enclave.user_add(line, p)) {
			std::cerr << "Failured to add user: '" << line << "'" << std::endl;
			enclave.flush_mmap();
			return EXIT_FAILURE;
		}

		if (false == enclave.user_update(line, p, n)) {
			std::cerr << "Failed to update user: '" << line << "' old: '" << p << "' new: '" << n << "'" << std::endl;
			enclave.flush_mmap();
			return EXIT_FAILURE;
		}

		if (false == enclave.password_verify(line, n)) {
			std::cerr << "Failed to verify password of user: '" << line << "':'" << n << "'" << std::endl;
			enclave.flush_mmap();
			return EXIT_FAILURE;
		}*/

		/*if (false == enclave.user_find(line, p)) {
			std::cerr << "Failed to find user '" << line << "'..." << std::endl;
			return EXIT_FAILURE;
		}*/

		//std::cout << "user[" << user_cnt++ << "]: u: " << line << ":" << n << std::endl;
		//break;

		/*if (false == enclave.user_add(line, p)) {
			std::cerr << "Failured to add user: '" << line << "'" << std::endl;
			enclave.flush_mmap();
			return EXIT_FAILURE;
		}

		if (false == enclave.user_update(line, p, n)) {
			std::cerr << "Failed to update user: '" << line << "' old: '" << p << "' new: '" << n << "'" << std::endl;
			enclave.flush_mmap();
			return EXIT_FAILURE;
		}

		if (false == enclave.password_verify(line, n)) {
			std::cerr << "Failed to verify password of user: '" << line << "':'" << n << "'" << std::endl;
			enclave.flush_mmap();
			return EXIT_FAILURE;
		}

		if (++cnt >= 8192 * 8192 * 5) {
			if (false == enclave.flush_mmap())
				printf("enclave failed to flush mmap\n");

			cnt = 0;
		}*/

		//std::cout << "user[" << std::dec << user_cnt++ << "]: '" << line << ":" << n << "'" << std::endl;
	//}

	// this is superfluous, the destructor will call this routine if we do not
	// however it seems more consistent this way, so i call it explicitly
	if (false == enclave.destroy()) {
		std::cerr << "Failed to destroy enclave" << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

