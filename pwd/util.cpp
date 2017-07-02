#include "util.hpp"

std::string
itoa_pointer(void* v)
{
	char buf[8192] = { 0 };
	signed int len = snprintf(&buf[0], sizeof(buf), "%p", v);

	if (0 > len)
		throw - 1;

	return std::string(&buf[0], len);
}

std::string
itoa_64(const char* fmt, uint64_t v)
{
	char buf[8192] = { 0 };
	signed int len = snprintf(&buf[0], sizeof(buf), fmt, v);

	if (0 > len)
		throw - 1;

	return std::string(&buf[0], len);
}

std::string
itoa_8(const char* fmt, uint8_t v)
{
	char buf[8192] = { 0 };
	signed int len = snprintf(&buf[0], sizeof(buf), fmt, v);

	if (0 > len)
		throw - 1;

	return std::string(&buf[0], len);
}

template< typename T >
std::string 
itoa(const char* fmt, T v)
{
	char buf[8192] = { 0 };
	signed int len = snprintf(&buf[0], sizeof(buf), fmt, v);

	if (0 > len)
		throw - 1;

	return std::string(&buf[0], len);
}
