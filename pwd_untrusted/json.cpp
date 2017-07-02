#include "stdafx.h"
#include "json.hpp"

json_boolean_t::json_boolean_t(void)
	: json_element_t("", JSON_TYPE_BOOLEAN), m_value(false)
{
	return;
}

json_boolean_t::json_boolean_t(const char* name)
	: json_element_t(name, JSON_TYPE_BOOLEAN), m_value(false)
{
	return;
}

json_boolean_t::json_boolean_t(const char* name, bool value)
	: json_element_t(name, JSON_TYPE_BOOLEAN), m_value(value)
{
	return;
}

json_boolean_t::~json_boolean_t(void)
{
	return;
}

const bool&
json_boolean_t::value(void) const
{
	return m_value;
}

std::string
json_boolean_t::to_string(void) const
{
	std::string ret(json_element_t::to_string());

	if ( 0 != ret.length() )
		ret += ": ";

	if (true == m_value)
		ret += "\"true\"";
	else
		ret += "\"false\"";

	return ret;
}

integral_t::integral_t(void) : m_type(JSON_DECIMAL_INVALID_TYPE)
{
	m_integral.integer = 0;
	return;
}

integral_t::integral_t(uint64_t value, const json_decimal_type_t type)
	: m_type(type)
{
	m_integral.integer = value;
	return;
}

integral_t::integral_t(int64_t value, const json_decimal_type_t type)
	: m_type(type)
{
	m_integral.integer = value;
	return;
}

integral_t::integral_t(float value, const json_decimal_type_t type)
	: m_type(type)
{
	m_integral.floating_point = value;
	return;
}

integral_t::integral_t(double value, const json_decimal_type_t type)
	: m_type(type)
{
	m_integral.floating_point = value;
	return;
}

integral_t::~integral_t(void)
{
	return;
}

std::string
integral_t::to_string(void) const
{
	char		buf[4096] = { 0 };
	signed int	ret = 0;

	std::memset(&buf[0], 0, sizeof(buf));

	switch (m_type) {
		case JSON_DECIMAL_UNSIGNED_TYPE:
			ret = std::snprintf(&buf[0], sizeof(buf), "%lld", static_cast< int64_t >(m_integral.integer));
			break;
		case JSON_DECIMAL_SIGNED_TYPE:
			ret = std::snprintf(&buf[0], sizeof(buf), "%llu", m_integral.integer);
			break;
		case JSON_DECIMAL_FLOATING_TYPE:
			ret = std::snprintf(&buf[0], sizeof(buf), "%f", m_integral.floating_point);
			break;
		default:
			throw std::runtime_error("integral_t::to_string(): Unknown numeric type encountered");
			break;
	}


	if (0 >= ret || ret > sizeof(buf)) 
		throw std::runtime_error("integral_t::to_string(): Error converting numeric value to string");

	return std::string(&buf[0], ret);
}

std::string
integral_t::to_hex(void) const
{
	char		buf[4096] = { 0 };
	signed int	ret = 0;

	std::memset(&buf[0], 0, sizeof(buf));

	switch (m_type) {
	case JSON_DECIMAL_UNSIGNED_TYPE:
	case JSON_DECIMAL_SIGNED_TYPE:
		ret = std::snprintf(&buf[0], sizeof(buf), "%llx", m_integral.integer);
		break;
	case JSON_DECIMAL_FLOATING_TYPE:
		ret = std::snprintf(&buf[0], sizeof(buf), "%a", m_integral.floating_point);
		break;
	default:
		throw std::runtime_error("...");
		break;
	}

	if (0 >= ret || ret < sizeof(buf))
		throw std::runtime_error("...");

	return std::string(&buf[0], ret);
}

uint64_t&
integral_t::integer(void)
{
	return m_integral.integer;
}

double&
integral_t::floating_point(void)
{
	return m_integral.floating_point;
}

json_decimal_type_t&
integral_t::type(void)
{
	return m_type;
}

integral_t&
integral_t::operator=(const uint64_t v)
{
	m_type = JSON_DECIMAL_UNSIGNED_TYPE;
	m_integral.integer = v;

	return *this;
}

integral_t&
integral_t::operator=(const int64_t v)
{
	m_type = JSON_DECIMAL_SIGNED_TYPE;
	m_integral.integer = static_cast< const uint64_t >(v);

	return *this;
}

integral_t&
integral_t::operator=(const float v)
{
	m_type = JSON_DECIMAL_FLOATING_TYPE;
	m_integral.floating_point = v;

	return *this;
}

integral_t&
integral_t::operator=(const double v)
{
	m_type = JSON_DECIMAL_FLOATING_TYPE;
	m_integral.floating_point = v;

	return *this;
}

json_decimal_t::json_decimal_t(void)
	: json_element_t("", JSON_TYPE_INTEGER), m_value(0Ui64, JSON_DECIMAL_INVALID_TYPE)
{
	return;
}

json_decimal_t::json_decimal_t(const char* name) 
	: json_element_t(name, JSON_TYPE_INTEGER), m_value(0Ui64, JSON_DECIMAL_INVALID_TYPE) 
{
	return;
}

json_decimal_t::json_decimal_t(const char* name, integral_t& value)
	: json_element_t(name, JSON_TYPE_INTEGER), m_value(value)
{
	return;
}

json_decimal_t::json_decimal_t(const char* name, uint64_t value)
	: json_element_t(name, JSON_TYPE_INTEGER), m_value(value)
{
	return;
}

json_decimal_t::json_decimal_t(const char* name, int64_t value)
	: json_element_t(name, JSON_TYPE_INTEGER), m_value(value)
{
	return;
}

json_decimal_t::json_decimal_t(const char* name, float value)
	: json_element_t(name, JSON_TYPE_INTEGER), m_value(value)
{
	return;
}

json_decimal_t::json_decimal_t(const char* name, double value)
	: json_element_t(name, JSON_TYPE_INTEGER), m_value(value)
{
	return;
}

json_decimal_t::~json_decimal_t(void)
{
	return;
}

const integral_t&
json_decimal_t::integral(void) const
{
	return m_value;
}

std::string
json_decimal_t::to_string(void) const
{
	std::string ret(json_element_t::to_string());
	//return json_element_t::to_string()); // +": " + m_value.to_string();
	
	if ( 0 != ret.length() )
		ret += ": ";

	ret += m_value.to_string();
	return ret;
	/*std::string ret(json_element_t::to_string() + ": ");


	ret += m_value.to_string();
	//ret += "\"" + std::string("[VALUE]") + "\""; //m_value.to_string() + "\"";
	return ret;*/
}

std::string
json_decimal_t::to_hex(void) const
{
	std::string ret(json_element_t::to_string() + ": ");

	ret += "\"" + std::string("[VALUE]") + "\""; // m_value.to_hex() + "\"";
	return ret;
}

json_string_t::json_string_t(void) : json_element_t("", JSON_TYPE_STRING)
{
	return;
}

json_string_t::json_string_t(const char* name)
	: json_element_t(name, JSON_TYPE_STRING), m_value("") 
{
	return;
}

json_string_t::json_string_t(const char* name, const char* value)
	: json_element_t(name, JSON_TYPE_STRING), m_value(value)
{
	if (nullptr == value || 0 == ::strlen(value))
		throw std::invalid_argument("");

	return;
}

json_string_t::~json_string_t(void)
{
	return;
}

std::string
json_string_t::to_string(void) const
{
	std::string ret(json_element_t::to_string());

	if ( 0 != ret.length() )
		ret += ": ";

	ret += "\"" + m_value + "\"";
	return ret;
}

const std::string&
json_string_t::value(void) const
{
	return m_value;
}


json_container_t::json_container_t(void)
	: json_element_t("", JSON_TYPE_INVALID)
{
	return;
}

json_container_t::json_container_t(const char* name)
	: json_element_t(name, JSON_TYPE_INVALID)
{
	return;
}

json_container_t::json_container_t(const char* name, const json_type_t& type)
	: json_element_t(name, type)
{
	return;
}

json_container_t::~json_container_t(void)
{
	m_children.clear();
	return;
}

/*const json_element_t&
json_container_t::element_at(std::size_t idx)
{
if (idx > m_children.size())
throw std::invalid_argument("...");

return *m_children[idx];
}*/

void
json_container_t::append_element(const json_decimal_t* val)
{
	m_children.push_back(new json_decimal_t(*val));
	return;
}

void
json_container_t::append_element(const json_boolean_t* val)
{
	m_children.push_back(new json_boolean_t(*val));
	return;
}

void
json_container_t::append_element(const json_array_t* val)
{
	json_container_t*	container(dynamic_cast< json_container_t* >(new json_array_t(*val)));
	json_element_t*		element(dynamic_cast< json_element_t* >(container));

	if (nullptr == element)
		throw std::runtime_error("...");

	m_children.push_back(element);
}

void 
json_container_t::append_element(const json_string_t* val)
{
	m_children.push_back(new json_string_t(*val));
	return;
}

void
json_container_t::append_element(const json_object_t* val)
{
	json_container_t*	container(dynamic_cast< json_container_t* >(new json_object_t(*val)));
	json_element_t*		element(dynamic_cast< json_element_t* >(container));

	if (nullptr == element)
		throw std::runtime_error("...");

	m_children.push_back(element);
	return;
}

/*void
json_container_t::add(const json_element_t* e)
{

	m_children.push_back(e);
	return;
}

void
json_container_t::add(const json_element_t& e, const std::size_t id)
{
	if (id > m_children.size())
		throw std::invalid_argument("...");

	m_children[id] = e;
	return;
}*/

void
json_container_t::clear_elements(void)
{
	for (std::size_t idx = 0; idx < m_children.size(); idx++)
		delete m_children[idx];

	m_children.clear();
	return;
}


json_object_t::json_object_t(void) 
	: json_container_t("", JSON_TYPE_OBJECT) 
{
	return;
}

json_object_t::json_object_t(const char* name) 
	: json_container_t(name, JSON_TYPE_OBJECT) 
{
	return;
}

json_object_t::~json_object_t(void) 
{
	return;
}

std::string
json_object_t::to_string(void) const
{
	std::string ret(json_element_t::to_string()); // +": {");

	if ( 0 != ret.length() )
		ret += ": ";

	ret += "{";

	for (std::size_t idx = 0; idx < m_children.size(); idx++) {
		if (nullptr != dynamic_cast<json_array_t*>(m_children[idx]))
			ret += dynamic_cast<json_array_t*>(m_children[idx])->to_string();
		else if (nullptr != dynamic_cast<json_boolean_t*>(m_children[idx]))
			ret += dynamic_cast<json_boolean_t*>(m_children[idx])->to_string();
		else if (nullptr != dynamic_cast<json_decimal_t*>(m_children[idx])) 
			ret += dynamic_cast<json_decimal_t*>(m_children[idx])->to_string();
		else if (nullptr != dynamic_cast<json_object_t*>(m_children[idx]))
			ret += dynamic_cast<json_object_t*>(m_children[idx])->to_string();
		else if (nullptr != dynamic_cast<json_string_t*>(m_children[idx])) 
			ret += dynamic_cast<json_string_t*>(m_children[idx])->to_string();
		else
			ret += "[UNKNOWN_TYPE]" + m_children[idx]->to_string();

		if (idx < m_children.size() - 1)
			ret += ",";
	}

	ret += "}";
	return ret;
}

json_array_t::json_array_t(void) 
	: json_container_t("", JSON_TYPE_ARRAY) 
{
	return;
}

json_array_t::json_array_t(const char* name) 
	: json_container_t(name, JSON_TYPE_ARRAY) 
{
	return;
}

json_array_t::~json_array_t(void) 
{
	return;
}

std::string
json_array_t::to_string(void) const
{
	std::string ret(json_element_t::to_string()); // +": ["); //+json_object_t::to_string() + "]");
	
	if ( 0 != ret.length() )
		ret += ": ";

	ret += "[";

	for (std::size_t idx = 0; idx < m_children.size(); idx++) {
		if (nullptr != dynamic_cast<json_array_t*>(m_children[idx]))
			ret += dynamic_cast<json_array_t*>(m_children[idx])->to_string();
		else if (nullptr != dynamic_cast<json_boolean_t*>(m_children[idx]))
			ret += dynamic_cast<json_boolean_t*>(m_children[idx])->to_string();
		else if (nullptr != dynamic_cast<json_decimal_t*>(m_children[idx]))
			ret += dynamic_cast<json_decimal_t*>(m_children[idx])->to_string();
		else if (nullptr != dynamic_cast<json_object_t*>(m_children[idx]))
			ret += dynamic_cast<json_object_t*>(m_children[idx])->to_string();
		else if (nullptr != dynamic_cast<json_string_t*>(m_children[idx]))
			ret += dynamic_cast<json_string_t*>(m_children[idx])->to_string();
		else
			ret += "[UNKNOWN_TYPE]" + m_children[idx]->to_string();

		if (idx < m_children.size() - 1)
			ret += ",";
	}

	ret += "]";
	return ret;
}