#include "stdafx.h"
#include "int128.hpp"

std::string
uint128_to_string(const uint128_t val)
{
	static uint8_t	buf[512] = { 0 };
	signed int		ret(0x00);

	std::memset(&buf[0], 0, sizeof(buf));

	ret = std::snprintf(reinterpret_cast< char* >(&buf[0]), sizeof(buf), "0x%llx%llx", val.low, val.high);

	if (0 >= ret || ret > sizeof(buf)) // ret > sizeof(buf) because 512 should always be large enough
		throw std::runtime_error("...");

	return std::string(reinterpret_cast< const char* >(&buf[0]), ret);
}