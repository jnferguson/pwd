#pragma once

#include <cstdint>
#include <cstdlib>
#include <string>
#include <cctype>
#include <array>
#include <clocale>
#include <stdexcept>

/*
base64.cpp and base64.h

Copyright (C) 2004-2008 René Nyffenegger

This source code is provided 'as-is', without any express or implied
warranty. In no event will the author be held liable for any damages
arising from the use of this software.

Permission is granted to anyone to use this software for any purpose,
including commercial applications, and to alter it and redistribute it
freely, subject to the following restrictions:

1. The origin of this source code must not be misrepresented; you must not
claim that you wrote the original source code. If you use this source code
in a product, an acknowledgment in the product documentation would be
appreciated but is not required.

2. Altered source versions must be plainly marked as such, and must not be
misrepresented as being the original source code.

3. This notice may not be removed or altered from any source distribution.

René Nyffenegger rene.nyffenegger@adp-gmbh.ch

*/

// Modified slightly to put it into a class, set locale and C++ STL-ify some of the data structures 27MAY2017 jf

class base64_t {
	private:
		const std::string m_chars;

	protected:
	public:

		base64_t(void);
		~base64_t(void);

		static inline bool is_base64(const unsigned char c);

		std::string encode(const std::string& input) const;

		std::string decode(const std::string&) const;
};

