#pragma once
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>
#include <ctime>
#include <fstream>
#include <sstream>
#include <mutex>

#include <experimental/filesystem>

#include "common.hpp"

#define DEBUG(...) logger_t::instance().log_wrapper(LOG_DEBUG, __FILE__, __LINE__, __VA_ARGS__)
#define INFO(...)  logger_t::instance().log_wrapper(LOG_INFO, __FILE__, __LINE__, __VA_ARGS__)
#define ERROR(...) logger_t::instance().log_wrapper(LOG_ERROR, __FILE__, __LINE__, __VA_ARGS__)
#define CRITICAL(...) logger_t::instance().log_wrapper(LOG_CRITICAL, __FILE__, __LINE__, __VA_ARGS__)

class logger_t
{
	private:
		logger_t(void) : m_file(""), m_throw(false), m_initialized(false) {}

	protected:
		std::string			m_file;
		std::ofstream		m_handle;
		bool				m_throw;
		bool				m_initialized;
		std::mutex			m_mutex;

		static inline std::string timestamp(void);

		static inline std::string priority_to_string(const logging_priority_t& priority);

		bool initialize(const char* path, bool throw_on_error = false, bool rotate = false);

	public:
		logger_t(logger_t&)				= delete;
		void operator=(logger_t const&) = delete;
	
		~logger_t(void);

		static logger_t& instance(const char* path = nullptr, bool throw_on_error = false, bool rotate = false);

		void set_throw(const bool);
		bool set_throw(void) const;

		// variadic template from https://stackoverflow.com/questions/19415845/a-better-log-macro-using-template-metaprogramming
		// there are no specific licensing notes, so its presumably public domain
		template< typename... Args > void 
		log_wrapper(logging_priority_t priority, const char* file, int line, const Args&... args)
		{
			std::ostringstream msg;
			log_recursive(priority, file, line, msg, args...);
		}


		template<typename T, typename... Args> void 
		log_recursive(logging_priority_t priority, const char* file, int line, std::ostringstream& msg, T value, const Args&... args)
		{
			msg << value;
			log_recursive(priority, file, line, msg, args...);
		}

		void log_recursive(logging_priority_t priority, const char* file, int line, std::ostringstream& msg);
};

