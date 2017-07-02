#pragma once

#include <string>
#include <vector>
#include <cstdint>

// #include "base64.hpp"

#define literal_declare(x, y) (sizeof(wchar_t) == sizeof(y) ? Lx : x)

template< typename T >
std::basic_string< T > to_base64(std::vector< T >& data)
{
	//std::basic_string< T > ret(literal_declare(""));
	return std::basic_string< T >(data.begin(), data.end());
}

template< typename T >
std::basic_string< T > to_base64(std::basic_string< T >& data)
{
	//std::basic_string< T > ret(literal_declare(""));
	return data;
}

template< typename T >
std::basic_string< T > to_base64(const T* data, std::size_t length)
{
	//std::basic_string< T > ret(literal_declare(""));

	if (nullptr == data || 0 == length)
		throw std::invalid_argument("...");

	return data;
}

