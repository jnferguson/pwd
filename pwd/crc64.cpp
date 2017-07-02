#include "crc64.hpp"


uint64_t
crc64(uint64_t crc, const unsigned char *s, uint64_t l)
{
	for (uint64_t idx = 0; idx < l; idx++)
		crc = crc64_tab[static_cast< uint8_t >(crc ^ s[idx])] ^ (crc >> 8);

	return crc;
}

uint64_t
crc64(uint64_t crc, const std::string& s)
{
	const uint64_t sz(s.length());

	for (uint64_t idx = 0; idx < sz; idx++)
		crc = crc64_tab[static_cast< uint8_t >(crc ^ s[idx])] ^ (crc >> 8);

	return crc;
}
