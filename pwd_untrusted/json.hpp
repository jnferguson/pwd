#pragma once
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <stdexcept>

typedef enum {
	JSON_TYPE_STRING = 0x00,
	JSON_TYPE_INTEGER = 0x01,
	JSON_TYPE_ARRAY = 0x02,
	JSON_TYPE_BOOLEAN = 0x03,
	JSON_TYPE_OBJECT = 0x04,
	JSON_TYPE_INVALID = 0x05
} json_type_t;

typedef enum {
	JSON_DECIMAL_SIGNED_TYPE = 0x00,
	JSON_DECIMAL_UNSIGNED_TYPE = 0x01,
	JSON_DECIMAL_FLOATING_TYPE = 0x02,
	JSON_DECIMAL_INVALID_TYPE = 0x03
} json_decimal_type_t;

#ifndef json_decimal_t
class json_decimal_t;
#endif

class json_object_t;
class json_array_t;

class json_element_t {
	private:
	protected:
		json_type_t	m_type;
		std::string m_name;

	public:
		json_element_t(const char* name = nullptr, const json_type_t& type = JSON_TYPE_INVALID)
			: m_type(type), m_name(nullptr == name ? "" : name)
		{}

		virtual ~json_element_t(void) {}

		virtual const std::string& name(void) const { return m_name; }
		virtual void name(const std::string& n) { m_name = n; }
		virtual const json_type_t& type(void) const { return m_type; }
		virtual std::string 
		to_string(void) const 
		{
			if (0 != m_name.length() )
				return "\"" + m_name + "\""; 

			return std::string("");
		}
};

class json_boolean_t : public json_element_t
{
private:
protected:
	bool m_value;

public:
	json_boolean_t(void);
	json_boolean_t(const char*);
	json_boolean_t(const char*, bool);

	virtual ~json_boolean_t(void);

	virtual std::string to_string(void) const;
	virtual const bool& value(void) const;
	virtual void value(bool v) { m_value = v; return; }
};

class json_string_t : public json_element_t
{
private:
protected:
	std::string m_value;

public:
	json_string_t(void);
	json_string_t(const char*);
	json_string_t(const char*, const char*);

	virtual ~json_string_t(void);

	virtual std::string to_string(void) const;
	virtual const std::string& value(void) const;
	virtual void value(const std::string& v) { m_value = v; return; }
};

class integral_t {

private:
protected:
	union { uint64_t integer; double floating_point; }	m_integral;
	json_decimal_type_t									m_type;
public:

	integral_t(void);
	integral_t(uint64_t value = 0, const json_decimal_type_t type = JSON_DECIMAL_UNSIGNED_TYPE);
	integral_t(int64_t value = 0, const json_decimal_type_t type = JSON_DECIMAL_SIGNED_TYPE);
	integral_t(float value = 0.0, const json_decimal_type_t type = JSON_DECIMAL_FLOATING_TYPE);
	integral_t(double value = 0.0, const json_decimal_type_t type = JSON_DECIMAL_FLOATING_TYPE);

	virtual ~integral_t(void);

	virtual std::string to_string(void) const;
	virtual std::string to_hex(void) const;


	virtual uint64_t& integer(void);
	virtual double& floating_point(void);
	virtual json_decimal_type_t& type(void);

	virtual integral_t& operator=(const uint64_t);
	virtual integral_t& operator=(const int64_t);
	virtual integral_t& operator=(const float);
	virtual integral_t& operator=(const double);
};

class json_decimal_t : public json_element_t
{
	private:
	protected:
		integral_t	m_value;

	public:
		json_decimal_t(void);
		json_decimal_t(const char*);
		json_decimal_t(const char*, integral_t&);
		json_decimal_t(const char*, uint64_t);
		json_decimal_t(const char*, int64_t);
		json_decimal_t(const char*, float);
		json_decimal_t(const char*, double);

		virtual ~json_decimal_t(void);

		virtual const integral_t& integral(void) const;
		virtual void integral(const integral_t& v) { m_value = v; return; }

		virtual std::string to_string(void) const;
		virtual std::string to_hex(void) const;
};

class json_container_t : public json_element_t
{
	private:
	protected:
		std::vector< json_element_t* >	m_children;

	public:
		json_container_t(void);
		json_container_t(const char*);
		json_container_t(const char*, const json_type_t&);
	
		virtual ~json_container_t(void);

		virtual void append_element(const json_object_t*);
		virtual void append_element(const json_array_t*);
		virtual void append_element(const json_boolean_t*);
		virtual void append_element(const json_decimal_t*);
		virtual void append_element(const json_string_t*);

		virtual std::vector< json_element_t* >::iterator begin(void) { return m_children.begin(); }
		virtual std::vector< json_element_t* >::iterator end(void) { return m_children.end(); }

		json_element_t&
		at(const std::size_t idx)
		{
			if ( idx >= m_children.size() )
				throw std::runtime_error("json_container_t::at(): invalid index requested");

			return *m_children[ idx ];
		}

		virtual void clear_elements(void);

		virtual std::string to_string(void) const = 0;
		//virtual const json_element_t& element_at(std::size_t);
};

class json_object_t : public json_container_t {
	private:
	protected:
	public:
		json_object_t(void);
		json_object_t(const char*);

		virtual ~json_object_t(void);

		virtual std::string to_string(void) const;
};

class json_array_t : public json_container_t
{
	private:
	protected:
	public:
		json_array_t(void);
		json_array_t(const char* name);
		virtual ~json_array_t(void);

		virtual std::string to_string(void) const;
};