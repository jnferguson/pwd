#pragma once

#include <stdint.h>
#include <string>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "crc64.hpp"
#include "pwd_t.h"
#include "util.hpp"
//#include "aes.hpp"
#include "sgx_tcrypto.h"
#include "sgx_trts.h"
#include "sgx_tae_service.h"
#include "common.hpp"
#include "record_cache.hpp"

#define STANDARD_IV_LENGTH (96/8)
#define STANDARD_AES_GCM_MAC_LENGTH sizeof(sgx_aes_gcm_128bit_tag_t)

typedef struct {
	uint8_t		iv[STANDARD_IV_LENGTH];
	uint8_t		mac[STANDARD_AES_GCM_MAC_LENGTH];
	uint64_t	block;
	uint8_t		data[];
} aes_gcm_record_t;

class aes_gcm_data_t {
	public:
		sgx_aes_gcm_128bit_key_t	key;
		uint8_t						iv[STANDARD_IV_LENGTH];
		uint32_t					count;

		aes_gcm_data_t(void) :count(0) 
		{
			::memset_s(&key[0], sizeof(sgx_aes_gcm_128bit_key_t), 0, sizeof(sgx_aes_gcm_128bit_key_t));
			::memset_s(&iv[0], sizeof(iv), 0, sizeof(iv));
			return;
		} 

		~aes_gcm_data_t(void)
		{
			::memset_s(&key[0], sizeof(sgx_aes_gcm_128bit_key_t), 0, sizeof(sgx_aes_gcm_128bit_key_t));
			::memset_s(&iv[0], sizeof(iv), 0, sizeof(iv));
			count = 0;
			return;
		}
};


class records_t
{
	private:
		/* untrusted/outside enclave related */
		void*						m_base;
		uint64_t					m_length;

		/* Temporary records related */
		user_record_t*				m_records;
		user_record_t*				m_records_end;
		char*						m_scratch;
		uint64_t					m_sector_size;

		/* Pointer arithmetic related */
		uint32_t					m_size;
		uint32_t					m_align;
		uint32_t					m_inv_align;

		/* Challenge-response related */
		uint8_t						m_cr_len;

		/* CRC64 related */
		uint64_t					m_seed;

		/* AES related */
		aes_gcm_data_t*				m_aes;
		uint32_t					m_reykey_max;

		/* LRU cache related */
		record_cache_t*				m_cache;

	protected:
		// This method needs a fair amount of work-- a rekey is a pretty sensitive operation right?
		// If something fails we potentially bork the database, so we probably want to make a copy of the original
		// so we can quickly fail over back to the original if need be. Furthermore, we might want to do something
		// like pre-generate the next key so that we get something like 8 billion encryptions before we have to think
		// about whether ::sgx_read_rand() can fail, which shouldn't really happen in practice but if we can eliminate
		// it then its just one less thing that can fail.
		// Currently we throw the new AES GCM data, which is bad form, but that way the caller can propagate up the new
		// key and unwind what we've done, or as I suggested more likely fail over to the original database. Rekeying is
		// an expensive operation, but its actually relatively quick overall in that encrypting all records takes maybe a 
		// minute or two and decrypting all records presumably takes about the same. That said, because of the nature of what
		// we are doing, if I ever do make this multi-threaded then we encounter a fair amount of potential problems and we are
		// blocking all login attempts and similar during that period, which is less than ideal-- as part of the copyfile ocall
		// we might decide that it makes a lot of sense to operate on the copy that way we are not blocking logins if we go
		// multi-threaded later.
		//
		// XXX JF FIXME - test
		inline bool
		rekey(void)
		{
			const std::size_t			sz(m_size + sizeof(user_record_t));
			uint64_t					block(0);
			aes_gcm_data_t				tmp;
			char*						ptr(NULL);
			uint64_t					block_number(0);

			// XXX JF FIXME - CopyFile ocall concept

			::memset(&tmp, 0, sizeof(aes_gcm_data_t));

			// XXX JF FIXME - next_key concept 
			if (SGX_SUCCESS != ::sgx_read_rand(reinterpret_cast< unsigned char* >(&tmp.key), sizeof(tmp.key)))
				return false;
			if (SGX_SUCCESS != ::sgx_read_rand(reinterpret_cast< unsigned char* >(&tmp.iv[0]), sizeof(tmp.iv)))
				return false;

			for (ptr = static_cast< char* >(m_base); ptr < static_cast< char* >(m_base)+m_length; ptr += sz) {
				aes_gcm_record_t*			g(reinterpret_cast< aes_gcm_record_t* >(ptr));
				sgx_aes_gcm_128bit_tag_t	t = { 0 };

				if (false == this->decrypt(reinterpret_cast< const aes_gcm_record_t* >(ptr)))
					throw tmp; // XXX JF FIXME

				if (++tmp.count == m_reykey_max) // this shouldnt be possible
					ocall_print("records_t::rekey(): rekey required during rekey...PANIC!");

				increment_iv(&tmp);

				if (SGX_SUCCESS != ::sgx_rijndael128GCM_encrypt(&tmp.key, reinterpret_cast< const uint8_t* >(m_records),
													m_size, reinterpret_cast< uint8_t* >(m_scratch),
													&tmp.iv[0], sizeof(tmp.iv), NULL, 0, &t))
					throw tmp; // XXX JF FIXME

				if (sizeof(g->mac) != sizeof(t) || sizeof(tmp.iv) != sizeof(g->iv))
					throw tmp; // XXX JF FIXME

				::memcpy(&g->mac[0], &t, sizeof(g->mac));
				::memcpy(&g->iv[0], &m_aes->iv[0], sizeof(g->iv));
				::memcpy(&g->data[0], m_scratch, m_size);
			}

			::memcpy(&m_aes->key[0], &tmp.key[0], sizeof(m_aes->key));
			::memcpy(&m_aes->iv[0], &tmp.iv[0], sizeof(m_aes->iv));
			return true;
		}

		inline void 
		increment_iv(aes_gcm_data_t* aes = NULL)
		{
			aes_gcm_data_t*			ptr = (NULL == aes ? m_aes : aes);
			std::size_t				idx = sizeof(ptr->iv) - 1;
			static const char		zero[11] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

			while (0 != idx && 0xFF == ptr->iv[idx--]) 
				ptr->iv[idx] = 0x00;
			
			// While this logic handles a potential rollover and all zero IV
			// what action that is to occur in this sort of context is intended
			// to be handled by the related encryption code paths and all we ensure 
			// is that the IV itself is non-zero; in practice this should be fine
			// because we randomly initialize the IV and perform 2^32-1 possible
			// encryptions before rekeying so we should never encounter an instance
			// where the nonce is reused or rolls over into a previously used value
			if (0 != idx)
				ptr->iv[idx]++;
			else if (0 == idx && 0 == ::memcmp(&ptr->iv[1], &zero[0], sizeof(zero)))
				ptr->iv[sizeof(ptr->iv) - 1] = 1;
			else
				ptr->iv[idx]++;
				
			return;
		}

		inline bool
		decrypt(const aes_gcm_record_t* input, uint64_t in_size, void* output, uint64_t out_size) //const aes_gcm_record_t* gcm)
		{

			if (NULL == input || NULL == output || out_size < in_size) 
				return false;

			if (input->block == 0x15f85) {
				ocall_print("records_t::decrypt(): pre-decryption");
				std::string str("BLOCK NUMBER: 0x");
				str += itoa_64("%x", input->block);
				str += " IV: 0x";
				for (std::size_t idx = 0; idx < sizeof(input->iv); idx++)
					str += itoa_8("%x", input->iv[idx]);
				str += " KEY: 0x";
				for (std::size_t idx = 0; idx < sizeof(m_aes->key); idx++)
					str += itoa_8("%x", m_aes->key[idx]);
				str += " MAC: 0x";
				for (std::size_t idx = 0; idx < sizeof(input->mac); idx++)
					str += itoa_8("%x", input->mac[idx]);
				ocall_print(str.c_str());
			}

			sgx_status_t stat = SGX_SUCCESS;
			if (SGX_SUCCESS != (stat = ::sgx_rijndael128GCM_decrypt(&m_aes->key, reinterpret_cast<const uint8_t*>(&input->data[0]), in_size,
															static_cast<uint8_t*>(output), &input->iv[0],
															sizeof(input->iv), reinterpret_cast<const uint8_t*>(&input->block),
															sizeof(input->block),
															reinterpret_cast<const sgx_aes_gcm_128bit_tag_t*>(&input->mac[0])))) {

				ocall_print(std::string("records_t::decrypt(): decryption failure 0x" + itoa_64("%x", stat)).c_str());
				ocall_print("records_t::decrypt(): return false");
				return false;
			}

			return true;
		}

		inline bool
		decrypt(const aes_gcm_record_t* gcm)
		{
			ocall_print("records_t::decrypt(): entry");

			if (NULL == gcm) {
				ocall_print("records_t::decrypt(): NULL == gcm");
				ocall_print("records_t::decrypt(): return false");
				return false;
			}

			::memcpy(m_scratch, gcm, m_size);

			ocall_print("records_t::decrypt(): pre-decryption");
			std::string str("BLOCK NUMBER: 0x");
			str += itoa_64("%x", gcm->block);
			str += " IV: 0x";
			for (std::size_t idx = 0; idx < sizeof(gcm->iv); idx++)
				str += itoa_8("%x", gcm->iv[idx]);
			str += " KEY: 0x";
			for (std::size_t idx = 0; idx < sizeof(m_aes->key); idx++)
				str += itoa_8("%x", m_aes->key[idx]);
			str += " MAX: 0x";
			for (std::size_t idx = 0; idx < sizeof(gcm->mac); idx++)
				str += itoa_8("%x", gcm->mac[idx]);
			ocall_print(str.c_str());

			sgx_status_t stat = SGX_SUCCESS;
			if (SGX_SUCCESS != (stat = ::sgx_rijndael128GCM_decrypt(&m_aes->key, reinterpret_cast<const uint8_t*>(&gcm->data[0]), m_size,
													reinterpret_cast<uint8_t*>(m_records), &gcm->iv[0], sizeof(gcm->iv),
													reinterpret_cast<const uint8_t*>(&gcm->block), sizeof(gcm->block),
													(const sgx_aes_gcm_128bit_tag_t*)&gcm->mac[0]))) {
				ocall_print(std::string("records_t::decrypt(): decryption failure 0x" + itoa_64("%x", stat)).c_str());
				ocall_print("records_t::decrypt(): return false");
				return false;
		}

			ocall_print("records_t::decrypt(): return true");
			return true;
		}

		inline bool
		encrypt(const void* input, uint64_t in_size, aes_gcm_record_t* output, uint64_t out_size, uint64_t block) 
		{
			sgx_aes_gcm_128bit_tag_t t = { 0 };

			if (NULL == input || NULL == output || out_size < in_size) 
				return false;

			if (++m_aes->count == m_reykey_max) 
				if (false == this->rekey()) 
					throw std::runtime_error("records_t::encrypt(): rekey maximum encryptions threshold encountered and rekeying failed");

			increment_iv();

			//ocall_print("records_t::encrypt(): pre-encryption...");
			// The MAC is not included in the resulting cipher-text; At the time of this writing (4-April-2017), 
			// the input and output buffer lengths are treated internally as the same
			if (SGX_SUCCESS != ::sgx_rijndael128GCM_encrypt(&m_aes->key, static_cast< const uint8_t* >(input), in_size,
															reinterpret_cast<uint8_t*>(&output->data[0]), &m_aes->iv[0], 
															sizeof(m_aes->iv), 
															reinterpret_cast<const uint8_t*>(&block), sizeof(block), &t))
			{
				ocall_print("records_t::encrypt(): encryption failure");
				ocall_print("records_t::decrypt(): return false");
				return false;
			}


			if (sizeof(output->mac) != sizeof(t) || sizeof(m_aes->iv) != sizeof(output->iv))
				return false;

			output->block = block;
			::memcpy(&output->mac[0], &t, sizeof(output->mac));
			::memcpy(&output->iv[0], &m_aes->iv[0], sizeof(output->iv));
			//::memcpy(&output->data[0], m_scratch, m_size);

			/*if (block == 0x15f85) {
				std::string str("BLOCK NUMBER: 0x");
			
				str += itoa_64("%x", output->block);
				str += " IV: 0x";
				for (std::size_t idx = 0; idx < sizeof(output->iv); idx++)
					str += itoa_8("%x", output->iv[idx]);
				str += " KEY: 0x";
				for (std::size_t idx = 0; idx < sizeof(m_aes->key); idx++)
					str += itoa_8("%x", m_aes->key[idx]);
				str += " MAC: 0x";
				for (std::size_t idx = 0; idx < sizeof(output->mac); idx++)
					str += itoa_8("%x", output->mac[idx]);

				ocall_print(str.c_str());
			}*/
			return true;
		}

/*		inline bool
		encrypt(uint64_t block)
		{
			return this->encrypt(m_scratch, m_size, reinterpret_cast< aes_gcm_record_t* >(m_records), m_size, block);
		}*/

/*		inline bool
		encrypt(void* data, uint64_t block)
		{
			aes_gcm_record_t*			g(reinterpret_cast< aes_gcm_record_t* >(data));
			sgx_aes_gcm_128bit_tag_t	t = { 0 };

			//ocall_print("records_t::encrypt(): entry");

			if (data != m_records)
				::memcpy(m_records, data, m_size);

			if (++m_aes->count == m_reykey_max) {
				ocall_print("records_t::encrypt(): rekey count reached");
				if (false == this->rekey()) {
					ocall_print("records_t::encrypt(): failed during rekeying");
					throw std::runtime_error("records_t::encrypt(): rekey maximum encryptions threshold encountered and rekeying failed");
				}
			}

			increment_iv();

			//ocall_print("records_t::encrypt(): pre-encryption...");
			// The MAC is not included in the resulting cipher-text; At the time of this writing (4-April-2017), 
			// the input and output buffer lengths are treated internally as the same
			if (SGX_SUCCESS != ::sgx_rijndael128GCM_encrypt(&m_aes->key, reinterpret_cast< const uint8_t* >(m_records),
															m_size, reinterpret_cast< uint8_t* >(m_scratch),
															&m_aes->iv[0], sizeof(m_aes->iv),
															reinterpret_cast< uint8_t* >(&block), sizeof(block), &t))
			{
				ocall_print("records_t::encrypt(): encryption failure");
				ocall_print("records_t::decrypt(): return false");
				return false;
			}

			if (sizeof(g->mac) != sizeof(t) || sizeof(m_aes->iv) != sizeof(g->iv)) {
				ocall_print("records_t::encrypt(): sizeof() != sizeof()...");
				ocall_print("records_t::decrypt(): return false");
				return false;
			}

			g->block = block;
			::memcpy(&g->mac[0], &t, sizeof(g->mac));
			::memcpy(&g->iv[0], &m_aes->iv[0], sizeof(g->iv));
			::memcpy(&g->data[0], m_scratch, m_size);

			std::string str("BLOCK NUMBER: 0x");
			str += itoa_64("%x", g->block);
			str += " IV: 0x";
			for (std::size_t idx = 0; idx < sizeof(g->iv); idx++)
				str += itoa_8("%x", g->iv[idx]);
			str += " KEY: 0x";
			for (std::size_t idx = 0; idx < sizeof(m_aes->key); idx++)
				str += itoa_8("%x", m_aes->key[idx]);
			str += " MAX: 0x";
			for (std::size_t idx = 0; idx < sizeof(g->mac); idx++)
				str += itoa_8("%x", g->mac[idx]);
			ocall_print(str.c_str());
			//ocall_print("records_t::encrypt(): Encryption completed successfully");

			//ocall_print("records_t::encrypt(): return true");
			return true;
		}

		inline bool
		encrypt(void* data)
		{
			aes_gcm_record_t*			g(reinterpret_cast< aes_gcm_record_t* >(data));
			sgx_aes_gcm_128bit_tag_t	t = { 0 };

			ocall_print("records_t::encrypt(): entry");

			::memcpy(m_records, data, m_size);

			if (++m_aes->count == m_reykey_max) {
				ocall_print("records_t::encrypt(): rekey count reached");
				if (false == this->rekey()) {
					ocall_print("records_t::encrypt(): failed during rekeying");
					throw std::runtime_error("records_t::encrypt(): rekey maximum encryptions threshold encountered and rekeying failed");
				}
			}

			increment_iv();

			ocall_print("records_t::encrypt(): pre-encryption...");
			// The MAC is not included in the resulting cipher-text; At the time of this writing (4-April-2017), 
			// the input and output buffer lengths are treated internally as the same
			if (SGX_SUCCESS != ::sgx_rijndael128GCM_encrypt(&m_aes->key, reinterpret_cast<const uint8_t*>(m_records),
															m_size, reinterpret_cast<uint8_t*>(m_scratch),
															&m_aes->iv[0], sizeof(m_aes->iv), 
															reinterpret_cast< uint8_t* >(&g->block), sizeof(g->block), &t))
			{
				ocall_print("records_t::encrypt(): encryption failure");
				ocall_print("records_t::decrypt(): return false");
				return false;
			}

			std::string str("BLOCK NUMBER: 0x");
			str += itoa_64("%x", g->block);
			str += " IV: 0x";
			for (std::size_t idx = 0; idx < sizeof(m_aes->iv); idx++)
				str += itoa_8("%x", m_aes->iv[idx]);
			str += " KEY: 0x";
			for (std::size_t idx = 0; idx < sizeof(m_aes->key); idx++)
				str += itoa_8("%x", m_aes->key[idx]);
			str += " MAX: 0x";
			for (std::size_t idx = 0; idx < sizeof(g->mac); idx++)
				str += itoa_8("%x", g->mac[idx]);
			ocall_print(str.c_str());
			ocall_print("records_t::encrypt(): Encryption completed successfully");

			if (sizeof(g->mac) != sizeof(t) || sizeof(m_aes->iv) != sizeof(g->iv)) {
				ocall_print("records_t::encrypt(): sizeof() != sizeof()...");
				ocall_print("records_t::decrypt(): return false");
				return false;
			}

			::memcpy(&g->mac[0], &t, sizeof(g->mac));
			::memcpy(&g->iv[0], &m_aes->iv[0], sizeof(g->iv));
			::memcpy(&g->data[0], m_scratch, m_size);
			ocall_print("records_t::encrypt(): return true");
			return true;
		}*/

	public:
		records_t(aes_gcm_data_t* aes, void* base = NULL, uint64_t len = 0, uint32_t align = 0x4000, uint64_t seed = 0x0ULL, uint8_t cr_len = 0x10);
		~records_t(void);

		inline uint64_t
		crc(const std::string& key) const
		{
			return crc64(m_seed, key);
		}

		// djb2
		inline uint32_t
		hash(const std::string& key) const
		{
			const char* ptr(key.c_str());
			uint32_t	ret(0);

			for (std::size_t idx = 0; idx < key.length(); idx++)
				ret = ((ret << 5) + ret) + ptr[idx];

			return ret;
		}

		bool find_user(const std::string&, user_record_t&);
		bool check_password(const std::string&, const std::string&);
		bool get_challenge(const std::string&, std::string&);

		bool add_user(const std::string&, const std::string&, bool* r = NULL);
		bool update_user(const std::string&, const std::string&, bool* r = NULL);
		

		bool encrypt_records(void);
};

