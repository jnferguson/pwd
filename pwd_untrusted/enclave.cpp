#include "stdafx.h"
#include "enclave.hpp"


/* This is a ridiculous way to test file existence
 * mostly because I'd also like to test whether its a
 * regular file as well but the macros for that appear to be
 * non-standard. Ideally I'd use the C++14/17 features for this
 * but im stuck with VS2013 because VS2015 has ceased working on
 * my computers.
 */
bool
enclave_t::file_exists(std::string& f)
{
	struct stat b = { 0 };

	if (::stat(f.c_str(), &b))
		return false;

	return true;
}

bool
enclave_t::write_seal_file(std::vector< uint8_t >& data)
{
	std::ofstream	f;
	bool			ret(true);
	std::string		seal_file(m_base + "\\" + m_seal_file); // XXX FIXME platform independent

	f.open(seal_file.c_str(), std::ofstream::out | std::ofstream::binary | std::ofstream::trunc);

	if (false == f.is_open() || true == f.fail() || true == f.bad())
		return false;

	f.write(reinterpret_cast< char* >(data.data()), data.size());

	if (true == f.fail() || true == f.bad())
		ret = false;

	f.flush();
	f.close();
	return ret;
}

bool
enclave_t::open_seal_file(std::vector< uint8_t >& data)
{
	std::ifstream				f;
	std::string					s("");
	std::ifstream::pos_type		pos(0);
	bool						ret(true);
	std::string					seal_file(m_base + "\\" + m_seal_file); // XXX FIXME platform independent

	data.clear();

	if (false == file_exists(seal_file))
		return true;

	f.open(seal_file.c_str(), std::ifstream::in | std::ifstream::binary);

	if (false == f.is_open() || true == f.fail() || true == f.bad())
		return false;

	f.seekg(0, f.end);
	pos = f.tellg();
	f.seekg(0, f.beg);

	if (0 > pos || INT_MAX < static_cast< unsigned int >(pos) ) {
		f.close();
		return false;
	}

	data.clear();
	data.resize(static_cast< unsigned int >(pos));
	f.read(reinterpret_cast< char* >(data.data()), data.size());

	if (f.fail() || f.bad())
		ret = false;

	f.close();
	return ret;
}

bool
enclave_t::write_token_file(void)
{
	std::ofstream	f;
	bool			ret(true);
	std::string		token_file(m_base + "\\" + m_token_file); // XXX FIXME platform independent

	f.open(token_file.c_str(), std::ofstream::out | std::ofstream::binary | std::ofstream::trunc);

	if (false == f.is_open() || true == f.fail() || true == f.bad())
		return false;

	f.write(reinterpret_cast<char*>(&m_token[0]), sizeof(m_token));

	if (true == f.fail() || true == f.bad())
		ret = false;

	f.flush();
	f.close();
	return ret;
}

bool
enclave_t::open_token_file(void)
{
	std::ifstream				f;
	std::string					s("");
	std::ifstream::pos_type		pos(0);
	std::string					token_file(m_base + "\\" + m_token_file); // XXX FIXME platform independent

	if (false == file_exists(m_token_file))
		return true;

	f.open(token_file.c_str(), std::ifstream::in | std::ifstream::binary);

	if (false == f.is_open() || true == f.fail() || true == f.bad())
		return false;

	f.seekg(0, f.end);
	pos = f.tellg();
	f.seekg(0, f.beg);

	if (0 > pos || INT_MAX < static_cast< unsigned int >(pos) ) {
		f.close();
		return false;
	}

	s.resize(static_cast< unsigned int >(pos));
	f.read(&s[0], pos);

	if (f.fail() || f.bad()) {
		f.close();
		return false;
	}

	std::memcpy(m_token, &s[0], (sizeof(m_token) > s.length() ? s.length() : sizeof(m_token)));
	f.close();
	return true;
}

bool
enclave_t::destroy(void)
{
	sgx_status_t			ret(SGX_SUCCESS);
	signed int				uret(0);
	std::vector< uint8_t >	data(0);
	uint32_t				slength(0);
	bool					retval(true);

	ret = destroy_enclave(m_eid, &uret, NULL, 0, &slength);

	// the only circumstances under which this should occur
	// is when something fails in the SGX glue code, because
	// if slength is non-null it should always be set to the requisite 
	// output size
	if (0 == slength || SGX_SUCCESS != ret) 
		return false;

	data.resize(slength);
	std::memset(data.data(), 0, data.size());

	ret = destroy_enclave(m_eid, &uret, data.data(), (uint32_t)data.size(), NULL);

	if (SGX_SUCCESS != ret || 0 != uret) 
		return false;

	if (false == write_seal_file(data)) 
		retval = false;

	::sgx_destroy_enclave(m_eid);
	m_init = false;
	return retval;
}

bool
enclave_t::initialize(void)
{
	int						updated(0);
	int						uret(0);
	sgx_status_t			ret(SGX_SUCCESS);
	std::vector< uint8_t >	data(0);
	std::string				enclave_file(m_base + "\\" + m_enclave_file); // XXX FIXME platform independent


	if (false == open_token_file())
		memset(&m_token[0], 0, sizeof(m_token));

	// apparently for one reason or another if i dont enable debugging this call fails; it might be/is probably linked
	// to the lack of a certificate or whatever signed by intel.
	ret = ::sgx_create_enclavea(enclave_file.c_str(), (m_debug == true ? 1 : 1), &m_token, &updated, &m_eid, &m_attr);

	if (SGX_SUCCESS != ret) 
		return false;

	if (1 == updated) {
		if (false == write_token_file()) {
			::sgx_destroy_enclave(m_eid);
			return false;
		}
	}

	if (false == open_seal_file(data)) {
		::sgx_destroy_enclave(m_eid);
		return false;
	}

	ret = initialize_enclave(m_eid, &uret, (0 == data.size() ? NULL : data.data()), (uint32_t)data.size());

	if (SGX_SUCCESS != ret || 0 != uret) {
		::sgx_destroy_enclave(m_eid);
		return false;
	}

	// id like to add the initialize_cache() call into here, but without some thinking it is going to cause
	// a data corruption issue if it fails so i need to properly think it out some, which is a lot of nonsense
	// for just wanting to avoid a potentially superfluous parameter that makes a clean interface unclean.
	m_init = true;
	return true;
}

bool 
enclave_t::init_mmap(const std::string& p, const std::size_t rep, bool is_new)
{
	signed int				uret(0);
	sgx_status_t			ret(SGX_SUCCESS);
	bool					rv(false);

	rv = m_efile.initialize(p, rep, is_new);

	if (false == rv) 
		return false;

	ret = initialize_mmap(m_eid, &uret, m_efile.base(), m_efile.size(), 0x4000, 0);

	if (SGX_SUCCESS != ret || 0 != uret) 
		return false;

	return true;
}

bool 
enclave_t::user_find(const std::string& u, std::string& p)
{
	signed int		uret(0);
	sgx_status_t	ret(SGX_SUCCESS);
	char			buf[32] = { 0 };

	ret = find_user(m_eid, &uret, u.c_str(), &buf[0], sizeof(buf));

	if (SGX_SUCCESS != ret || 0 != uret)
		return false;

	p = &buf[0];
	return true;
}

bool
enclave_t::user_add(std::string& u, std::string& p)
{
	signed int		uret(0);
	sgx_status_t	ret(SGX_SUCCESS);

	ret = add_user(m_eid, &uret, u.c_str(), p.c_str());
	
	if (SGX_SUCCESS != ret || 0 != uret)
		return false;

	//if (false == m_efile.flush())
	//	printf("flush() failed\n");

	return true;
}

bool 
enclave_t::user_update(const std::string& u, const std::string& o, const std::string& n)
{
	signed int		uret(0);
	sgx_status_t	ret(SGX_SUCCESS);

	ret = update_user(m_eid, &uret, u.c_str(), o.c_str(), n.c_str());

	if (SGX_SUCCESS != ret || 0 != uret)
		return false;

	return true;
}

bool 
enclave_t::password_verify(const std::string& u, const std::string& p)
{
	signed int		uret(0);
	sgx_status_t	ret(SGX_SUCCESS);

	ret = check_password(m_eid, &uret, u.c_str(), p.c_str());

	if (SGX_SUCCESS != ret || 0 != uret)
		return false;

	return true;
}

bool
enclave_t::flush_mmap(void)
{
	return m_efile.flush();
}

enclave_t::enclave_t(std::string& token, std::string& seal, std::string& enclave, std::string& base, bool dbg)
	: m_efile(), m_token_file(token), m_seal_file(seal), m_enclave_file(enclave), m_base(base), m_debug(dbg), m_init(false)
{
	if (false == this->initialize())
		throw std::runtime_error("Failed to initialize enclave");

	return;
}

enclave_t::enclave_t(void) : m_efile(), m_token_file(""), m_seal_file(""), m_enclave_file(""), m_base(""), m_debug(false), m_init(false)
{
	return;
}

enclave_t::~enclave_t(void)
{
	/* 
	 * in the event something fails, we potentially lose our sealed data
	 * it would be nice if intel offered a better API for this set of circumstances
	 * but i guess that is reasonably out of scope and better left to the developer
	 * at present, we just lose the data but we should really
	 * be doing something where the prior seal data is stored-- in the context of our 
	 * current usage where we are using it to store persistent crypto keys a failure here
	 * could plausibly make the data unaccessible because the crypto keys were corrupted in
	 * some form or fashion.
	 */
	if (true == m_init)
		if (false == destroy())
			::sgx_destroy_enclave(m_eid);

	return;
}

bool 
enclave_t::record_encrypt(const std::string& u)
{
	signed int		uret(0);
	sgx_status_t	ret(SGX_SUCCESS);

//	ret = encrypt_record(m_eid, &uret, u.c_str());

	if (SGX_SUCCESS != ret || 0 != uret)
		return false;

	return true;
}

bool 
enclave_t::encrypt_all_records(void)
{
	signed int		uret(0);
	sgx_status_t	ret(SGX_SUCCESS);

	ret = encrypt_records(m_eid, &uret);

	if (SGX_SUCCESS != ret || 0 != uret)
		return false;

	return true;
}

bool
enclave_t::public_key(std::string& key)
{
	signed int		uret(0);
	sgx_status_t	ret(SGX_SUCCESS);

	key.resize(64);
	::memset(&key[0], 0, 64);

	ret = get_public_key(m_eid, &uret, &key[0], key.length());

	if (SGX_SUCCESS != ret || 0 != uret)
		return false;

	return true;
}

bool
enclave_t::do_challenge_response(const std::string& user, charesp_transaction_t* ptr)
{
	signed int		uret(0);
	sgx_status_t	ret(SGX_SUCCESS);

	ret = challenge_response(m_eid, &uret, user.c_str(), ptr, sizeof(charesp_transaction_t));

	if (SGX_SUCCESS != ret || 0 != uret) 
		return false;

	return true;
}