#include "stdafx.h"
#include "encrypted_file.hpp"

/*DWORD
encrypted_file_t::get_page_size(void)
{
	SYSTEM_INFO si = { 0 };

	::GetSystemInfo(&si);
	return si.dwPageSize;
}*/

uint64_t
encrypted_file_t::get_random_64bit_address(void)
{
	uint64_t	ret(0);
	HCRYPTPROV	provider(NULL);


	if (FALSE == ::CryptAcquireContextW(&provider, 0, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
		throw std::runtime_error("Error calling ::CryptAcquireContext()");

	if (FALSE == ::CryptGenRandom(provider, sizeof(uint64_t), reinterpret_cast< BYTE* >(&ret)))  {
		::CryptReleaseContext(provider, 0);
		throw std::runtime_error("Error calling ::CryptGenRandom()");
	}

	::CryptReleaseContext(provider, 0);

	// So windows refuses to map an address any higher
	// than 0x0000ffff00000000, likely because there is
	// some sort of kernel mapping there or similar; this is fine
	// I just wanted to introduce some amount of entropy given that
	// I was introducing a substantial decrease to the address space of
	// the process.
	// I may elect to revist this in the future because its only 16-bits of entropy.
	// In remedial testing, this seems to always work/map on 64-bit.
	return ret & 0x0000ffff00000000;
}

encrypted_file_t::encrypted_file_t(void)
			: m_file(""), m_handle(INVALID_HANDLE_VALUE), m_mapping(NULL), m_base(NULL), m_size(0x100000000ULL) /*, 
			m_guard_one(NULL), m_guard_two(NULL), m_page_size(get_page_size())	*/	
{
	return;
}

encrypted_file_t::~encrypted_file_t(void)
{
	if (NULL != m_base) {
		::FlushViewOfFile(m_base, 0x0);
		::UnmapViewOfFile(m_base);
		m_base = NULL;
	}

	if (NULL != m_mapping) {
		::CloseHandle(m_mapping);
		m_mapping = NULL;
	}

	if (INVALID_HANDLE_VALUE != m_handle) {
		::CloseHandle(m_handle);
		m_handle = INVALID_HANDLE_VALUE;
	}

	/*if (NULL != m_guard_one) {
		::VirtualFree(m_guard_one, 0, MEM_RELEASE);
		m_guard_one = NULL;
	}

	if (NULL != m_guard_two) {
		::VirtualFree(m_guard_two, 0, MEM_RELEASE);
		m_guard_two = NULL;
	}*/

	return;

}

bool
encrypted_file_t::flush(std::size_t sz)
{
	if (0 != ::FlushViewOfFile(m_base, sz))
		return true;

	return false;
}

bool
encrypted_file_t::get_file_size(LARGE_INTEGER* fs)
{
	if (NULL == fs)
		return false;

	if (FALSE == ::GetFileSizeEx(m_handle, fs))
		return false;

	if (static_cast< ULONGLONG >(m_size) != fs->QuadPart)
		return false;

	return true;
}

/*bool
encrypted_file_t::create_guard_pages(void)
{
	LPVOID tmp(NULL);

	m_guard_one = static_cast< char* >(m_base)-m_page_size;

	tmp = ::VirtualAllocEx(::GetCurrentProcess(), m_guard_one, m_page_size, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);

	if (NULL == tmp || tmp != m_guard_one) 
		return false;

	m_guard_two = static_cast< char* >(m_base)+m_size;

	tmp = ::VirtualAllocEx(::GetCurrentProcess(), m_guard_two, m_page_size, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);

	if (NULL == tmp || tmp != m_guard_two) 
		return false;


	return true;
}*/

bool
encrypted_file_t::initialize_file(const std::string& path, bool first)
{
	LARGE_INTEGER li = { 0 };

	if (INVALID_HANDLE_VALUE != m_handle)
		::CloseHandle(m_handle);

	if (true == first) {
		m_handle = ::CreateFileA(path.c_str(), FILE_GENERIC_READ | FILE_GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_FLAG_RANDOM_ACCESS, NULL);

		if (INVALID_HANDLE_VALUE == m_handle)
			return false;

		li.QuadPart = m_size;

		if (FALSE == ::SetFilePointerEx(m_handle, li, NULL, FILE_BEGIN)) {
			::CloseHandle(m_handle);
			m_handle = INVALID_HANDLE_VALUE;
			return false;
		}

		if (FALSE == ::SetEndOfFile(m_handle)) {
			::CloseHandle(m_handle);
			m_handle = INVALID_HANDLE_VALUE;
			return false;
		}

		::CloseHandle(m_handle);
	}

	m_handle = ::CreateFileA(path.c_str(), FILE_GENERIC_READ | FILE_GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_RANDOM_ACCESS, NULL);

	if (INVALID_HANDLE_VALUE == m_handle)
		return false;


	return true;
}

bool
encrypted_file_t::initialize(const std::string& path, uint64_t rep, bool is_new)
{
	uint64_t		base(get_random_64bit_address());
	ULARGE_INTEGER	file_size = { 0 };

	if ( false == initialize_file(path, is_new) ) 
		return false;

	if (false == get_file_size(reinterpret_cast<LARGE_INTEGER*>(&file_size))) {
		::CloseHandle(m_handle);
		m_handle = INVALID_HANDLE_VALUE;
		return false;
	}

	m_mapping = ::CreateFileMappingA(m_handle, NULL, PAGE_READWRITE, file_size.HighPart, file_size.LowPart, NULL);

	if (NULL == m_mapping) {
		::CloseHandle(m_handle);
		m_handle = INVALID_HANDLE_VALUE;
		return false;
	}

	for (std::size_t idx = 0; idx < rep; idx++) {
		m_base = ::MapViewOfFileEx(m_mapping, FILE_MAP_WRITE | FILE_MAP_READ, /*FILE_MAP_COPY,*/ 
									0x00, 0x00, file_size.QuadPart, reinterpret_cast< LPVOID >(base));

		if (NULL == base && ERROR_INVALID_PARAMETER == ::GetLastError())
			base = get_random_64bit_address();
		else if (m_size >= reinterpret_cast< uint64_t >(m_base)) // XXX JF FIXME - still valid after 0xFFFFFFFF+1 ?
			base = get_random_64bit_address();
		else
			break;
	}

	if (NULL == m_base) {
		::CloseHandle(m_mapping);
		::CloseHandle(m_handle);
		m_mapping = NULL;
		m_handle = INVALID_HANDLE_VALUE;
		return false;
	}

	/*if (false == create_guard_pages()) {
		::CloseHandle(m_mapping);
		::CloseHandle(m_handle);
		m_mapping = NULL;
		m_handle = INVALID_HANDLE_VALUE;
		return false;
	}*/


	m_file = path;
	return true;
}
