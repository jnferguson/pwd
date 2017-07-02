#include "stdafx.h"
#include "logger.hpp"

logger_t::~logger_t(void)
{
	m_mutex.lock();
	m_handle.flush();
	m_handle.close();
	m_mutex.unlock();
	return;
}

inline std::string
logger_t::timestamp(void)
{
	std::time_t tm = std::time(nullptr);
	std::tm		lt = { 0 };
	char		buf[ 4096 ] = { 0 };
	
	if ( 0 != ::localtime_s(&lt, &tm) )
		throw std::runtime_error("logger_t::timestamp(): Error in ::localtime_s()");

	std::memset(&buf[ 0 ], 0, sizeof(buf));
	
	if ( 0 != ::asctime_s(&buf[ 0 ], sizeof(buf), &lt) )
		throw std::runtime_error("logger_t::timestamp(): Error in ::asctime_s()");

	
	return std::string(&buf[0], ::strlen(&buf[0]));
}

inline std::string
logger_t::priority_to_string(const logging_priority_t& priority)
{
	std::string ret("");

	switch ( priority ) {
		case LOG_DEBUG:
			ret = "DEBUG";
			break;

		case LOG_INFO:
			ret = "INFO";
			break;

		case LOG_ERROR:
			ret = "ERROR";
			break;

		case LOG_CRITICAL:
			ret = "CRITICAL";
			break;

		default:
			throw std::runtime_error("logger_t::priority_to_string(): invalid priority type parameter");
			break;
	}

	return ret;
}

bool
logger_t::initialize(const char* path, bool throw_on_error, bool rotate)
{
	std::lock_guard< std::mutex >	lck(m_mutex);
	std::time_t						tm(std::time(nullptr));
	std::tm							lt = { 0 };
	
	printf("logger_t::initialize(): entry\n");

	if ( 0 != ::localtime_s(&lt, &tm) ) {
		printf("logger_t::initialize(): Error in ::localtime_s()\n");
		return false;
	}

	printf("logger_t::initialize(): after localtime_s()\n");
	if ( nullptr == path ) {
		printf("logger_t::initialize(): error in path\n");
		return false;
	}

	printf("logger_t::initialize(): after nullptr == path\n");
	if (m_file.size() && '/' != m_file[m_file.size()-1] && '\\' != m_file[m_file.size()-1] ) {
	//if ( '/' != m_file[ m_file.size() - 1 ] && '\\' != m_file[ m_file.size() - 1 ] ) {
		printf("logger_t::initialize(): error in file path\n");
		return false;
	}

	m_file += "pwd_service-" + std::to_string(lt.tm_mday) + "-" + std::to_string(lt.tm_mon) + "-" + std::to_string(lt.tm_year) + ".log";

	/* XXX JF FIXME when youre not mentally all over the board, this logic will probably require recursion.

	if ( std::experimental::filesystem::exists(m_file) ) {
	std::size_t idx = 0;

	do {
	std::string tmp_file(m_file + "." + std::to_string(idx));
	}
	}*/

	printf("logger_t::initialize(): after file == test\n");
	m_handle.open(m_file.c_str(), std::ofstream::out | std::ofstream::binary | std::ofstream::trunc);

	if ( !m_handle.is_open() ) {
		printf("logger_t::initialize(): error in open()\n");
		return false;
	}

	printf("logger_t::initialize(): return true\n");
	m_initialized = true;
	return true;
}

logger_t&
logger_t::instance(const char* path, bool throw_on_error, bool rotate)
{
	static logger_t inst;

	if ( false == inst.m_initialized ) {
		printf("logger_t::instance(): initializing\n");
		if ( false == inst.initialize(path, throw_on_error, rotate) )
			throw std::runtime_error("logger_t::instance(): Error while initializing log");
	}


	return inst;
}

void logger_t::set_throw(const bool val) 
{ 
	m_throw = val; 
	return; 
}

bool 
logger_t::set_throw(void) const 
{ 
	return m_throw; 
}

void
logger_t::log_recursive(logging_priority_t priority, const char* file, int line, std::ostringstream& msg)
{
	std::lock_guard< std::mutex >	lck(m_mutex);
	std::string						entry("[" + priority_to_string(priority) + "]: " + timestamp());


	entry += std::string(file) + ':' + std::to_string(line) + " " + msg.str() + "\r\n";
	m_handle.write(entry.c_str(), entry.length());

	if ( true == m_throw ) {
		if ( true == m_handle.bad() || true == m_handle.fail() || true == m_handle.eof() )
			throw std::runtime_error("logger_t::log(): error writing to log file");
	}

	return;
}