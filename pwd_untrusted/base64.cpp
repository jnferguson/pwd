#include "stdafx.h"
#include "base64.hpp"


base64_t::base64_t(void)
	: m_chars("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
{
	std::setlocale(LC_ALL, "C");
	return;
}

base64_t::~base64_t(void)
{
	return;
}

inline bool
base64_t::is_base64(const unsigned char c)
{
	return (std::isalnum(c) || ('+' == c) || ('/' == c));
}

std::string
base64_t::encode(const std::string& input) const
{
	std::string						output("");
	std::size_t						i(0);
	std::array< unsigned char, 3 >	three;
	std::array< unsigned char, 4 >	four;

	for (auto& itr : input) {
		three[i++] = itr;

		if (3 == i) {
			four[0] = (three[0] & 0xFC) >> 2;
			four[1] = ((three[0] & 0x03) << 4) + ((three[1] & 0xF0) >> 4);
			four[2] = ((three[1] & 0x0F) << 2) + ((three[2] & 0xC0) >> 6);
			four[3] = three[2] & 0x3F;

			for (i = 0; i < 4; i++)
				output += m_chars[four[i]];

			i = 0;
		}
	}

	if (0 != i) {
		for ( std::size_t j = i; j < 3; j++ )
			three[ j ] = 0x00;

		four[0] = (three[0] & 0xFC) >> 2;
		four[1] = ((three[0] & 0x03) << 4) + ((three[1] & 0xF0) >> 4);
		four[2] = ((three[1] & 0x0F) << 2) + ((three[2] & 0xC0) >> 6);
		four[3] = three[2] & 0x3F;

		for (std::size_t j = 0; j < i + 1; j++)
			output += m_chars[four[j]];

		while (3 > i++)
			output += '=';
	}

	return output;
}

std::string
base64_t::decode(const std::string& input) const
{
	std::string						output("");
	std::size_t						i(0);
	std::array< unsigned char, 3 >	three;
	std::array< unsigned char, 4 >	four;

	for (auto& itr : input) {
		if (false == is_base64(itr) || '=' == itr)
			break;

		four[i++] = itr;

		if (4 == i) {
			for (i = 0; i < 4; i++)
				four[i] = m_chars.find(four[i]);

			three[0] = (four[0] << 2) + ((four[1] & 0x30) >> 4);
			three[1] = ((four[1] & 0x0F) << 4) + ((four[2] & 0x3C) >> 2);
			three[2] = ((four[2] & 0x03) << 6) + four[3];


			for (i = 0; i < 3; i++)
				output += three[i];

			i = 0;
		}
	}

	if (0 != i) {
		for (std::size_t j = i; j < 4; j++)
			four[j] = 0x00;

		for (std::size_t j = 0; j < 4; j++)
			four[j] = m_chars.find(four[j]);

		three[0] = (four[0] << 2) + ((four[1] & 0x30) >> 4);
		three[1] = ((four[1] & 0x0F) << 4) + ((four[2] & 0x3C) >> 2);
		three[2] = ((four[2] & 0x03) << 6) + four[3];

		for (std::size_t j = 0; j < i - 1; j++)
			output += three[j];
	}

	return output;
}