#include "records.hpp"


records_t::records_t(aes_gcm_data_t* aes, void* base, uint64_t len, uint32_t align, uint64_t seed, uint8_t cr_len)
	: m_base(base), m_length(len), m_records(NULL), m_records_end(NULL), m_scratch(NULL), m_sector_size(0),
	m_size(align), m_align(align), m_inv_align(0), m_seed(seed), m_cr_len(cr_len),
	m_aes(aes), m_reykey_max(0xFFFFFFFF), m_cache(NULL)
{
	if (NULL == m_aes)
		throw std::invalid_argument("records_t::records_t(): Invalid AES-GCM key data specified (nullptr)");

	if (0 == m_align) { // raise exception??
		m_align = 0x4000;
		m_size = 0x4000;
	}

	if (sizeof(user_record_t) * 2 > m_size)
		throw std::invalid_argument("records_t::records_t(): Specified memory size is too small");

	m_sector_size	= m_size;
	m_records		= static_cast< user_record_t* >(::calloc(m_sector_size, 1));

	if (NULL == m_records)
		throw std::bad_alloc("records_t::records_t(): Memory allocation failure");

	m_scratch = static_cast< char* >(::calloc(m_sector_size + 8192, 1));

	if (NULL == m_scratch) {
		::free(m_records);
		throw std::bad_alloc("records_t::records_t(): Memory allocation failure");
	}

	m_cache			= new record_cache_t(m_length / m_sector_size, m_size / sizeof(user_record_t), 25 * 1024 * 1024);

	m_size			-= sizeof(user_record_t);
	m_records_end	= m_records + (m_size / sizeof(user_record_t));
	m_align			-= 1;
	m_inv_align		= ~m_align;

	return;

}

records_t::~records_t(void)
{
	m_base = NULL;

	::memset_s(m_records, m_sector_size, 0, m_sector_size);
	::free(m_records);
	m_records = NULL;

	::memset_s(m_scratch, m_sector_size, 0, m_sector_size);
	::free(m_scratch);
	m_scratch = NULL;

	delete m_cache;
	m_cache = NULL;

	return;
}

bool 
records_t::get_challenge(const std::string& u, std::string& challenge)
{
	const uint64_t		c(crc(u));
	const uint32_t		h((hash(u) + m_align) & m_inv_align);
	char*				t(static_cast< char* >(m_base)+h);
	const uint64_t		i(reinterpret_cast<const aes_gcm_record_t*>(t)->block);
	user_record_t*		p(NULL);
	user_record_t*		e(NULL);

	p = m_cache->get(i);

	if (NULL == p) {
		p = m_records;
		e = m_records_end;

		if (false == this->decrypt(reinterpret_cast< const aes_gcm_record_t* >(t)))
			return false;

		m_cache->set(i, p);

	} else
		e = m_cache->end(p);

	while (p < e) {
		if (p->id == c) {
			std::string tmp("");

			tmp.resize(m_cr_len);

			if (SGX_SUCCESS != ::sgx_read_rand(reinterpret_cast< unsigned char* >(&tmp[0]), tmp.length()))
				return false;
		}

		p++;
	}

	return false;
}

bool
records_t::find_user(const std::string& u, user_record_t& o)
{
	const uint64_t		c(crc(u));
	const uint32_t		h((hash(u) + m_align) & m_inv_align);
	char*				t(static_cast< char* >(m_base)+h);
	const uint64_t		i(reinterpret_cast<const aes_gcm_record_t*>(t)->block);
	user_record_t*		p(NULL);
	user_record_t*		e(NULL);

	p = m_cache->get(i);
	
	if (NULL == p) {
		ocall_print("records_t::find_user(): cache miss");
		p = m_records;
		e = m_records_end;

		if (false == this->decrypt(reinterpret_cast< const aes_gcm_record_t*>(t), m_size, m_records, m_sector_size)) {
			ocall_print("records_t::find_user(): decryption failure");
			return false;
		}

		m_cache->set(i, p);

	} else {
		ocall_print("records_t::find_user(): cache hit");
		e = m_cache->end(p);
	}

	while (p < e) {
		if (p->id == c) {
			::memcpy(&o, p, sizeof(user_record_t));
			return true;
		}

		p++;
	}

	return false;
}

bool
records_t::add_user(const std::string& u, const std::string& a, bool* r)
{
	const uint64_t		c(crc(u));
	const uint32_t		h((hash(u) + m_align) & m_inv_align);
	char*				t(static_cast< char* >(m_base)+h);
	const uint64_t		i(reinterpret_cast<const aes_gcm_record_t*>(t)->block);
	user_record_t*		p(NULL);
	user_record_t*		e(m_records_end);
	user_record_t		z;

	::memset_s(&z, sizeof(user_record_t), 0, sizeof(user_record_t));

	p = m_cache->get(i);

	if (NULL != p) {
		//ocall_print("records_t::add_user(): cache hit");
		::memcpy(m_records, p, m_size);
		p = m_records;
	}
	else {
		//ocall_print("records_t::add_user(): cache miss");
		p = m_records;

		if (false == this->decrypt(reinterpret_cast< const aes_gcm_record_t* >(t), m_size, m_records, m_sector_size)) {
			ocall_print("records_t::add_user(): decryption failure");
			return false;
		}
	}

	//ocall_print("records_t::add_user(): while p < e) ...");
	while (p < e) {
		if ( 0 == p->id && ! ::memcmp(p, &z, sizeof(user_record_t)))
			break;

		p++;
	}

	//ocall_print("records_t::add_user(): if p >= e...");
	if (p >= e) {
		ocall_print("records_t::add_user(): CRITICAL ERROR: out of room in specific sector for new user...");
		return false;
	}

	p->id = c;
	::memcpy(&p->pwd[0], a.data(), sizeof(p->pwd));

	//ocall_print("records_t::add_user(): this->encrypt()...");
	if (false == this->encrypt(m_records, m_size, reinterpret_cast<aes_gcm_record_t*>(m_scratch), m_sector_size, i)) {
		ocall_print("records_t::add_user(): failure during re-encryption of record");
		return false;
	}

	//ocall_print("records_t::add_user(): memcpy/evict()...");

	::memcpy(t, m_scratch, m_sector_size);
	m_cache->evict(reinterpret_cast< const aes_gcm_record_t* >(t)->block);

	if (NULL != r) {
		if (a.length() > sizeof(p->pwd))
			*r = true;
		else
			*r = false;
	}

	return true;
}

bool
records_t::update_user(const std::string& u, const std::string& a, bool* r)
{
	const uint64_t		c(crc(u));
	const uint32_t		h((hash(u) + m_align) & m_inv_align);
	char*				t(static_cast< char* >(m_base)+h);
	const uint64_t		b(reinterpret_cast< aes_gcm_record_t* >(t)->block);
	const uint64_t		i(reinterpret_cast<const aes_gcm_record_t*>(t)->block);
	user_record_t*		p(NULL);
	user_record_t*		e(m_records_end);
	user_record_t		z;
	bool				v(false);

	::memset_s(&z, sizeof(user_record_t), 0, sizeof(user_record_t));

	p = m_cache->get(i);

	if (NULL != p) {
		//ocall_print("records_t::update_user(): cache hit");
		::memcpy(m_records, p, m_size);
		p = m_records;
	} else {
		//ocall_print("records_t::update_user(): cache miss");
		p = m_records;

		if (false == this->decrypt(reinterpret_cast< const aes_gcm_record_t* >(t), m_size, m_records, m_sector_size)) {
			ocall_print("records_t::update_user(): decryption failure");
			return false;
		}
	}

	while (p < e) {
		if (p->id == c) {
			::memcpy(&p->pwd[0], a.data(), sizeof(p->pwd));

			if (NULL != r) {
				if (a.length() > sizeof(p->pwd))
					*r = true;
				else
					*r = false;
			}

			v = true;
			
			if (false == this->encrypt(m_records, m_size, reinterpret_cast< aes_gcm_record_t* >(m_scratch), m_sector_size, b)) {
				ocall_print("records_t::update_user(): failed to encrypt record");
				v = false;
				break;
			}

			::memcpy(t, m_scratch, m_sector_size);
			m_cache->evict(reinterpret_cast< const aes_gcm_record_t* >(t)->block);
			break; // XXX JF FIXME side channel - constant time
		}

		p++;
	}

	return v;
}

bool
records_t::check_password(const std::string& u, const std::string& a)
{
	const uint64_t		c(crc(u));
	const uint32_t		h((hash(u) + m_align) & m_inv_align);
	const char*			t(static_cast< char* >(m_base)+h);
	const uint64_t		i(reinterpret_cast< const aes_gcm_record_t* >(t)->block);
	user_record_t*		p(NULL); 
	user_record_t*		e(NULL);

	p = m_cache->get(i);

	if (NULL == p) {
		//ocall_print("records_t::check_password(): cache miss");
		p = m_records;
		e = m_records_end;

		if (false == this->decrypt(reinterpret_cast< const aes_gcm_record_t* >(t), m_size, m_records, m_sector_size)) 
			return false;

		m_cache->set(i, p);

	} else {
		//ocall_print("records_t::check_password(): cache hit");
		e = m_cache->end(p);
	}

	while (p < e) {
		if (p->id == c) {
			if (a[0] == p->pwd[0] &&
					a.length() == ::strlen(reinterpret_cast< char* >(&p->pwd[0])) &&
					!::memcmp(a.data(), &p->pwd[0], a.length()))
				return true;

			return false;
		}

		p++;
	}

	return false;
}

bool
records_t::encrypt_records(void)
{
	char*						ptr(NULL);
	uint64_t					block_number(0);
	sgx_aes_gcm_128bit_tag_t	tag = { 0 };

	for (ptr = static_cast< char* >(m_base); ptr < static_cast< char* >(m_base) + m_length; ptr += m_sector_size) {
		::memcpy(m_records, ptr, m_sector_size);
		
		/* XXX note the m_size vs m_sector_size below; this is only relevant when accessing records that are unencrypted
		 * and being transitioned to encrypted sectors because the two sizes actually are different
		 */
		if (false == this->encrypt(ptr, m_size, reinterpret_cast< aes_gcm_record_t* >(m_records), m_sector_size, block_number)) {
			ocall_print("records_t::encrypt_reads(): failure during encryption");
			return false;
		}

		ocall_print(std::string("records_t::encrypt_records(): encrypted sector number 0x" + itoa_64("%x", block_number)).c_str());
		::memcpy(ptr, m_records, m_sector_size);
		block_number += 1;
	}

	// XXX JF FIXME
	//for (uint64_t idx = 0; idx < m_cache->total(); idx++)
	//	m_cache->evict(idx);

	::memset_s(m_records, m_sector_size, 0, m_sector_size);
	::memset_s(m_scratch, m_sector_size, 0, m_sector_size);
	return true;
}