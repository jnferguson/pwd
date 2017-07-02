#pragma once
#include <string>
#include <cstdint>
#include <cstdlib>
#include <stdexcept>

#include <Windows.h>
#pragma comment(lib, "advapi32.lib")

class encrypted_file_t
{
	private:
		std::string		m_file;
		HANDLE			m_handle;
		HANDLE			m_mapping;
		LPVOID			m_base;
		const SIZE_T	m_size;

	protected:
		inline uint64_t get_random_64bit_address(void);

	public:
		encrypted_file_t(void);
		~encrypted_file_t(void);

		void* base(void) const { return m_base; }
		uint64_t size(void) const { return m_size; }
		std::string file(void) const { return m_file; }

		bool flush(std::size_t sz = 0x00);
		bool get_file_size(LARGE_INTEGER* fs);

		bool initialize_file(const std::string& path, bool first = false);
		bool initialize(const std::string& path, uint64_t rep = 1024, bool is_new = false);
};

