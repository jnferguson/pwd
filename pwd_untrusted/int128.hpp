#pragma once

#include <cstdint>
#include <string>
#include <limits>

#ifndef uint128_t 

class unsigned_onetwentyeightbit_type
{
	private:
	protected:
		uint64_t m_low;
		uint64_t m_high;
	private:
		unsigned_onetwentyeightbit_type(uint64_t low = 0, uint64_t high = 0) : m_low(low), m_high(0) { }
		~unsigned_onetwentyeightbit_type(void) { }

		inline unsigned_onetwentyeightbit_type&
		operator++(void)
		{
			if ( 0 == std::numeric_limits< uint64_t >::max() - m_low ) {
				if ( 0 == std::numeric_limits< uint64_t >::max() - m_high ) {
					m_low	= 1;
					m_high	= 0;
				}

				m_high += 1;
				m_low = 0;
				return *this;
			}

			m_low += 1;
			return *this;
		}

		inline unsigned_onetwentyeightbit_type&
		operator--(void)
		{
			if ( 0 == m_low ) {
				if ( 0 == m_high ) {
					m_low	= static_cast< uint64_t >( -1 );
					m_high	= static_cast< uint64_t >( -1 );
				}

				m_high	-= 1;
				m_low	= static_cast< uint64_t >( -1 );
				return *this;
			}

			m_low -= 1;
			return *this;
		}

		inline bool 
		operator==(const unsigned_onetwentyeightbit_type& rhs)
		{
			if ( m_low == rhs.m_low && m_high == rhs.m_high )
				return true;

			return false;
		}

		inline bool
		operator==(const uint64_t rhs)
		{
			if ( m_high )
				return false;
			if ( m_low == rhs )
				return true;

			return false;
		}

		inline bool
		operator!=(const unsigned_onetwentyeightbit_type& rhs)
		{
			return !( *this == rhs );
		}

		inline bool
		operator!=(const uint64_t rhs)
		{
			if ( m_high )
				return true;

			return !( *this == rhs );
		}

		inline bool
		operator>=(const unsigned_onetwentyeightbit_type& rhs)
		{
			if ( m_high > rhs.m_high )
				return true;
			else if ( m_high < rhs.m_high )
				return false;

			if ( m_low > rhs.m_low )
				return true;
			else if ( m_low < rhs.m_low )
				return false;

			return true;
		}

		inline bool
		operator>=(const uint64_t rhs)
		{
			unsigned_onetwentyeightbit_type val(rhs, 0);
			return val >= *this;
		}

		inline bool
		operator<=(const unsigned_onetwentyeightbit_type& rhs)
		{
			if ( m_high > rhs.m_high )
				return false;
			else if ( m_high < rhs.m_high )
				return true;

			if ( m_low > rhs.m_low )
				return false;
			else if ( m_low < rhs.m_low )
				return true;

			return true;
		}

		inline bool
		operator<=(const uint64_t rhs)
		{
			unsigned_onetwentyeightbit_type val(rhs, 0);
			return *this <= val;
		}

		inline unsigned_onetwentyeightbit_type
		operator+(const unsigned_onetwentyeightbit_type& rhs)
		{
			unsigned_onetwentyeightbit_type	ret = { 0x00,0x00 };

			if ( std::numeric_limits< uint64_t >::max() - m_low < rhs.m_low ) {
				ret.m_high = m_low + rhs.m_low;
				ret.m_low = 0;
			} else
				ret.m_low = m_low + rhs.m_low;

			// XXX JF FIXME is this a recursive operation? can the first additive overflow
			// that potentially occurs here muck up the low side of the equation??
			ret.m_high += m_high;
			ret.m_high += rhs.m_high;

			return ret;
		}

		inline unsigned_onetwentyeightbit_type
		operator+(const uint64_t rhs)
		{
			unsigned_onetwentyeightbit_type val(rhs, 0);
			return *this + val;
		}

		inline unsigned_onetwentyeightbit_type
		operator+=(const unsigned_onetwentyeightbit_type& rhs)
		{
			unsigned_onetwentyeightbit_type ret = *this + rhs;
			return ret;
		}

		inline unsigned_onetwentyeightbit_type
		operator+=(const uint64_t rhs)
		{
			unsigned_onetwentyeightbit_type val(rhs, 0);
			return *this += val;
		}

		std::string
		to_string(void)
		{
			static uint8_t	buf[ 512 ] = { 0 };
			signed int		ret(0x00);

			std::memset(&buf[ 0 ], 0, sizeof(buf));

			ret = std::snprintf(reinterpret_cast< char* >( &buf[ 0 ] ), sizeof(buf), "0x%llx%llx", m_low, m_high);

			if ( 0 >= ret || ret > sizeof(buf) ) // ret > sizeof(buf) because 512 should always be large enough
				throw std::runtime_error("...");

			return std::string(reinterpret_cast< const char* >( &buf[ 0 ] ), ret);
		}
};

typedef struct {
	uint64_t low;
	uint64_t high;
} unsigned_128_bit_type;

typedef unsigned_128_bit_type uint128_t;

/*uint128_t& operator++(uint128_t& a, signed int)
{
	a = a + 1;
	return a;
}*/

inline bool
operator==(const uint128_t lhs, const uint128_t rhs)
{
	if (lhs.low == rhs.low && lhs.high == lhs.high)
		return true;

	return false;
}

inline bool
operator!=(const uint128_t lhs, const uint128_t rhs)
{
	return !(lhs == rhs);
}

inline bool
operator>=(const uint128_t lhs, const uint128_t rhs)
{
	if (lhs.high > rhs.high)
		return true;
	else if (lhs.high < rhs.high)
		return false;

	if (lhs.low > rhs.low)
		return true;
	else if (lhs.low < rhs.low)
		return false;

	return true;
}

inline bool
operator<=(const uint128_t lhs, const uint128_t rhs)
{
	if (lhs.high > rhs.high)
		return false;
	else if (lhs.high < rhs.high)
		return true;

	if (lhs.low > rhs.low)
		return false;
	else if (lhs.low < rhs.low)
		return true;

	return true;
}

/*inline uint128_t& 
operator+(const uint128_t lhs, signed int rhs)
{
	uint128_t value = { 0x00, rhs };
	return lhs + value;
}*/

inline uint128_t
operator+(const uint128_t lhs, const uint128_t rhs)
{
	uint128_t	ret = { 0x00,0x00 };

	if (std::numeric_limits<uint64_t>::max() - lhs.low < rhs.low) {
		ret.high = lhs.low + rhs.low;
		ret.low = 0;
	}
	else
		ret.low = lhs.low + rhs.low;

	// XXX JF FIXME is this a recursive operation? can the first additive overflow
	// that potentially occurs here muck up the low side of the equation??
	ret.high += lhs.high;
	ret.high += rhs.high;

	return ret;
}

inline uint128_t
operator+=(uint128_t lhs, const uint128_t rhs)
{
	uint128_t ret = lhs + rhs;
	return ret;
}

std::string uint128_to_string(const uint128_t val);

struct int128_hasher {
	std::size_t
		int128_hasher::operator()(const uint128_t& t) const {
		const std::size_t		prime(19937);
		std::hash< uint64_t >	hash;
		const std::size_t		hash_value(hash(t.low) ^ (hash(t.high) << 1));

		return prime * hash_value;
	}
};

#endif
