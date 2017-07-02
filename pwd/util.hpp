#pragma once

#include <string>
#include <stdint.h>
#include <stdio.h>

/* I actually seriously dislike this, I'd prefer to use a variety of features that really
 * only came into existence in c++11, but given the lack of compiler at present this is
 * the easiest way to accomplish the task; this code will be removed in any production
 * version anyway.
 */
#define itoa_ptr(v) itoa< void* >("%p", v)

#define itoa_hex(v) itoa< uint64_t >("%llx", v)
#define itoa_hex_64(v) itoa< uint64_t >("%llx", v)
#define itoa_hex_32(v) itoa< uint32_t >("%lx", v)
#define itoa_hex_16(v) itoa< uint16_t >("%hx", v)
#define itoa_hex_8(v) itoa< uint8_t >("%x", v)

#define itoa_sdec(v) itoa< int64_t >("%lld", v)
#define itoa_dec_s64(v) itoa< int64_t >("%lld", v)
#define itoa_dec_s32(v) itoa< int32_t >("%ld", v)
#define itoa_dec_s16(v) itoa< int16_t >("%hd", v)
#define itoa_dec_s8(v) itoa< int8_t >("%d", v)

#define itoa_udec(v) itoa< uint64_t >("%llu", v)
#define itoa_dec_u64(v) itoa< uint64_t >("%llu", v)
#define itoa_dec_u32(v) itoa< uint32_t >("%lu", v)
#define itoa_dec_u16(v) itoa< uint16_t >("%hu", v)
#define itoa_dec_u8(v) itoa< uint8_t >("%u", v)

template< typename T > std::string itoa(const char*, T);
std::string itoa_64(const char* fmt, uint64_t v);
std::string itoa_8(const char* fmt, uint8_t v);
std::string itoa_pointer(void* v);

