#include "record_cache.hpp"


list_t::list_t(void) : m_head(NULL), m_tail(NULL)
{
	return;
}

list_t::~list_t(void)
{
	while (NULL != m_head) {
		record_node_t* itr = m_head;

		m_head = itr->nxt;
		itr->dat = NULL;
		itr->pre = NULL;
		::free(itr);
	}

	return;
}

#include "pwd_t.h"
#include "util.hpp"

record_node_t*
list_t::new_node(void* dat)
{
	record_node_t* ret = static_cast< record_node_t* >(::calloc(1, sizeof(record_node_t)));

	if (NULL == ret)
		return NULL;

	ret->dat = dat;
	ret->nxt = NULL;
	ret->pre = NULL;
	return ret;
}

void
list_t::push_front(record_node_t* node)
{

	if (NULL == node)
		return;

	if (NULL == m_head) {
		m_head = node;

		if (NULL == m_tail)
			m_tail = node;

		node->pre = NULL;
		node->nxt = NULL;
		return;
	}

	if (NULL == m_tail)
		m_tail = node;

	node->nxt = m_head;
	m_head->pre = node;
	node->pre = NULL;
	m_head = node;

	return;
}

void
list_t::push_back(record_node_t* node)
{
	if (NULL == node)
		return;

	if (NULL == m_tail) {
		m_tail = node;

		if (NULL == m_head)
			m_head = node;

		node->pre = NULL;
		node->nxt = NULL;
		return;
	}

	if (NULL == m_head)
		m_head = node;

	node->pre	= m_tail;
	m_tail->nxt = node;
	node->nxt	= NULL;
	m_tail		= node;
	//m_tail->nxt = node;

	return;
}

record_node_t*
list_t::pop_front(void)
{
	record_node_t* ret(NULL);

	if (NULL == m_head) {	// empty
		//if (NULL != m_head) XXX JF FIXME TODO logic - shouldnt be possible

		return NULL;
	} if (m_head == m_tail) {	// single node
		ret = m_tail;
		m_tail = NULL;
		m_head = NULL;
	}
	else {
		ret = m_head;
		m_head = ret->nxt;

		if (NULL != m_head)
			m_head->pre = NULL;
	}

	ret->nxt = NULL;
	ret->pre = NULL;
	return ret;
}

record_node_t*
list_t::pop_back(void)
{
	record_node_t* ret(NULL);

	if (NULL == m_tail) {	// empty
		//if (NULL != m_head) XXX JF FIXME TODO logic - shouldnt be possible
	
		return NULL; 
	} if (m_head == m_tail) {	// single node
		ret		= m_tail;
		m_tail	= NULL; 
		m_head	= NULL; 
	} else {
		ret			= m_tail;
		m_tail		= ret->pre;

		if (NULL != m_tail) 
			m_tail->nxt = NULL;
	}

	ret->nxt = NULL;
	ret->pre = NULL;
	return ret;

}

void
list_t::move_front(record_node_t* node)
{
	if (NULL == node)
		return;

	if (NULL != find(node->id))
		unlink(node);

	push_front(node);
	return;
}

void
list_t::move_back(record_node_t* node)
{
	if (NULL == node)
		return;

	if (NULL != find(node->id))
		unlink(node);

	push_back(node);
	return;
}

record_node_t*
list_t::find(void* data, bool f)
{
	record_node_t* node = NULL;

	if (true == f) {
		node = m_head;

		while (NULL != node) {
			if (node->dat == data)
				return node;

			node = node->nxt;
		}
	}
	else {
		node = m_tail;

		while (NULL != node) {
			if (node->dat == data)
				return node;

			node = node->pre;
		}
	}

	return NULL;
}

record_node_t*
list_t::find(uint64_t id, bool f)
{
	record_node_t* node = NULL;

	if (true == f) {
		node = m_head;

		//ocall_print(std::string("list_t::find(): true == f / node: " + itoa_pointer(node)).c_str());

		while (NULL != node) {
			//ocall_print(std::string("list_t::find(): node->id 0x" + itoa_64("%x", node->id) + " id: 0x" + itoa_64("%x", id)).c_str());
			if (node->id == id)
				return node;

			node = node->nxt;
		}
	}
	else {
		node = m_tail;

		//ocall_print(std::string("list_t::find(): false == f / node: " + itoa_pointer(node)).c_str());
		while (NULL != node) {
			if (node->id == id)
				return node;

			node = node->pre;
		}
	}

	//ocall_print("return NULL");
	return NULL;
}

void
list_t::unlink(record_node_t* node)
{
	if (NULL == node || true == empty())
		return;

	if (node->nxt)
		node->nxt->pre = node->pre;
	else {
		m_tail = node->pre;

		if (NULL != m_tail)
			m_tail->nxt = NULL;
	}

	if (node->pre)
		node->pre->nxt = node->nxt;
	else {
		m_head = node->nxt;

		if (NULL != m_head)
			m_head->pre = NULL;
	}

	node->pre = NULL;
	node->nxt = NULL;
	return;
}

#include "pwd_t.h"
#include "util.hpp"

record_cache_t::record_cache_t(uint64_t total_records, uint64_t record_count, uint64_t limit)
		: m_total(total_records), m_number(record_count), 
		m_size(sizeof(user_record_t) * record_count), m_records(NULL), m_vector(NULL)
{
	const uint64_t max(limit / m_size);

	if (sizeof(user_record_t) > UINT64_MAX / m_number)
		throw std::invalid_argument("...");
	if (m_total > UINT64_MAX / sizeof(user_record_t*))
		throw std::invalid_argument("...");

	m_vector = static_cast< user_record_t** >(::calloc(m_total, sizeof(user_record_t*)));

	if (NULL == m_vector) {
		ocall_print(std::string("record_cache_t::record_cache_t(): m_vector size: 0x"+ itoa_64("%x", m_total) + "*" + itoa_64("%x", sizeof(user_record_t*)) + " allocation failure").c_str());
		throw std::bad_alloc("...");
	}

	m_records = ::calloc(max, m_size);

	if (NULL == m_records) {
		ocall_print("record_cache_t::record_cache_t(): m_records allocation failure");
		throw std::bad_alloc("...");
	}

	//ocall_print(std::string("record_cache_t::record_cache_t(): number of nodes: 0x" + itoa_64("%x", m_number)).c_str());

	for (uint64_t idx = 0; idx < m_number; idx++) {
		record_node_t* node = list_t::new_node(reinterpret_cast<char*>(m_records)+(idx * m_size));

		if (NULL == node) {
			ocall_print("record_cache_t::record_cache_t(): list_t::new_node() failed");
			throw std::bad_alloc("...");
		}

		m_free.push_back(node);
	}

//	ocall_print(std::string("record_cache_t::record_cache_t(): in use list size: 0x" + itoa_64("%x", m_list.size()) + " rsize: 0x" + itoa_64("%x", m_list.rsize())).c_str());
//	ocall_print(std::string("record_cache_t::record_cache_t(): free list   size: 0x" + itoa_64("%x", m_free.size()) + " rsize: 0x" + itoa_64("%x", m_free.rsize())).c_str());

/*	ocall_print("record_cache_t::record_cache_t(): free list dump...");
	for (record_node_t* ptr = m_free.front(); ptr != NULL; ptr = ptr->nxt)
		ocall_print(std::string("ptr: " + itoa_pointer(ptr) + " id: 0x" + itoa_64("%x", ptr->id) + " dat: " + itoa_pointer(ptr->dat) + " nxt: " + itoa_pointer(ptr->nxt) + " pre: " + itoa_pointer(ptr->pre)).c_str());
	for (record_node_t* ptr = m_free.back(); ptr != NULL; ptr = ptr->pre)
		ocall_print(std::string("ptr: " + itoa_pointer(ptr) + " id: 0x" + itoa_64("%x", ptr->id) + " dat: " + itoa_pointer(ptr->dat) + " nxt: " + itoa_pointer(ptr->nxt) + " pre: " + itoa_pointer(ptr->pre)).c_str());
*/

	return;
}

record_cache_t::~record_cache_t(void)
{
	::free(m_records);

	m_records = NULL;

	for (uint64_t idx = 0; idx < m_total; idx++)
		m_vector[idx] = NULL;

	::free(m_vector);
	return;
}

void
record_cache_t::evict(uint64_t id)
{
	record_node_t* tmp = m_list.find(id); 

//	ocall_print(std::string("record_cache_t::evict(): in use list size: 0x" + itoa_64("%x", m_list.size()) + " rsize: 0x" + itoa_64("%x", m_list.rsize())).c_str());
//	ocall_print(std::string("record_cache_t::evict(): free list   size: 0x" + itoa_64("%x", m_free.size()) + " rsize: 0x" + itoa_64("%x", m_free.rsize())).c_str());

	if (NULL == tmp) {
		if (NULL != m_vector[id]) {
			ocall_print("record_cache_t::evict(): cache in inconsistent state, item is in vector but not in list");
			throw std::runtime_error("record_cache_t::evict(): ...");
		}

		return;
	}

	m_vector[id]	= NULL;
	tmp->id			= 0;
	
	m_list.unlink(tmp);
//	ocall_print(std::string("record_cache_t::evict(): adding " + itoa_pointer(tmp) + " to free list...").c_str());
	m_free.push_back(tmp);

	return;
}

void
record_cache_t::evict(user_record_t* rec)
{
	record_node_t*	tmp = m_list.find(rec);

//	ocall_print(std::string("record_cache_t::evict(): in use list size: 0x" + itoa_64("%x", m_list.size()) + " rsize: 0x" + itoa_64("%x", m_list.rsize())).c_str());
//	ocall_print(std::string("record_cache_t::evict(): free list   size: 0x" + itoa_64("%x", m_free.size()) + " rsize: 0x" + itoa_64("%x", m_free.rsize())).c_str());

	if (NULL == tmp) {
		for (uint64_t idx = 0; idx < m_total; idx++)
			if (rec == m_vector[idx]) {
				ocall_print("record_cache_t::evict(): inconsistent state; item doesnt exist in list, but does in vector.");
				throw std::runtime_error("record_cache_t::evict(): ...");
			}
		return;
	}

	m_vector[tmp->id] = NULL;
	tmp->id = 0;
	m_list.unlink(tmp);
//	ocall_print(std::string("record_cache_t::evict(): adding " + itoa_pointer(tmp) + " to free list...").c_str());
	m_free.push_back(tmp);
	
	return;
}

void
record_cache_t::purge(uint64_t count)
{
//	ocall_print(std::string("record_cache_t::purge(): in use list size: 0x" + itoa_64("%x", m_list.size()) + " rsize: 0x" + itoa_64("%x", m_list.rsize())).c_str());
//	ocall_print(std::string("record_cache_t::purge(): free list   size: 0x" + itoa_64("%x", m_free.size()) + " rsize: 0x" + itoa_64("%x", m_free.rsize())).c_str());

	if (m_list.empty())
		return;

	for (uint64_t idx = 0; idx < count; idx++) {
		record_node_t* tmp = m_list.back();

		m_list.unlink(tmp);
		m_vector[tmp->id] = NULL;
		tmp->id = 0;
	
//		ocall_print(std::string("record_cache_t::purge(): adding " + itoa_pointer(tmp) + " to free list...").c_str());
		m_free.push_back(tmp);
	}

	return;
}

bool
record_cache_t::set(uint64_t id, user_record_t* ele, bool over)
{
	record_node_t*	tmp = NULL;
	user_record_t*	ptr = m_vector[id];

//	ocall_print(std::string("record_cache_t::set() entry: in use list size: 0x" + itoa_64("%x", m_list.size()) + " rsize: 0x" + itoa_64("%x", m_list.rsize())).c_str());
//	ocall_print(std::string("record_cache_t::set() entry: free list   size: 0x" + itoa_64("%x", m_free.size()) + " rsize: 0x" + itoa_64("%x", m_free.rsize())).c_str());

	if (NULL != ptr) {
		const void* cvptr(ele);

		if (false == over) {
			ocall_print("record_cache_t::set(): overwrite set to false, aborting set operation");
			ocall_print("record_cache_t::set(): return false");
			return false;
		}

		ocall_print("record_cache_t::set(): overwriting pre-existing record");
		m_vector[id] = NULL;
		tmp = m_list.find(ele);

		if (NULL == tmp) {
			ocall_print("record_cache_t::set(): inconsistent cache state, item is in vector but not in list.");
			throw std::runtime_error("...");
		}

		m_list.unlink(tmp);
		tmp->id = 0;
//		ocall_print(std::string("record_cache_t::set(): adding " + itoa_pointer(tmp) + " to free list...").c_str());
		m_free.push_back(tmp);
	}

	if (true == m_free.empty()) 
		purge();

	tmp = m_free.pop_front();

	::memcpy(tmp->dat, ele, m_size);
	m_vector[id]	= reinterpret_cast< user_record_t* >(tmp->dat);
	tmp->id			= id;

//	ocall_print(std::string("record_cache_t::set(): adding " + itoa_pointer(tmp) + " to in use list...").c_str());
	m_list.push_front(tmp);
	return true;
}

user_record_t*
record_cache_t::get(uint64_t id)
{
	record_node_t* tmp = NULL;

//	ocall_print(std::string("record_cache_t::get(): in use list size: 0x" + itoa_64("%x", m_list.size()) + " rsize: 0x" + itoa_64("%x", m_list.rsize())).c_str());
//	ocall_print(std::string("record_cache_t::get(): free list   size: 0x" + itoa_64("%x", m_free.size()) + " rsize: 0x" + itoa_64("%x", m_free.rsize())).c_str());


	if (NULL == m_vector[id]) 
		return NULL;

	tmp = m_list.find(m_vector[id]);

	if (NULL != tmp)
		m_list.move_front(tmp);
	else {
		ocall_print("record_cache_t::get(): inconsistency in between vector and linked list...one is null the other is not, dumping lists...");
		ocall_print(std::string("requested id: 0x" + itoa_64("%x", id) + " dat: " + itoa_pointer(m_vector[id])).c_str());
		for (std::size_t idx = 0; idx < m_total; idx++)
			if (NULL != m_vector[idx])
				ocall_print(std::string("m_vector[0x" + itoa_64("%x", idx) + "]: " + itoa_pointer(m_vector[idx])).c_str());

		for (record_node_t* ptr = m_list.front(); ptr != NULL; ptr = ptr->nxt)
			ocall_print(std::string("[lf] ptr: " + itoa_pointer(ptr) + " id: 0x" + itoa_64("%x", ptr->id) + " dat: " + itoa_pointer(ptr->dat) + " nxt: " + itoa_pointer(ptr->nxt) + " pre: " + itoa_pointer(ptr->pre)).c_str());
		for (record_node_t* ptr = m_list.back(); ptr != NULL; ptr = ptr->pre)
			ocall_print(std::string("[lb] ptr: " + itoa_pointer(ptr) + " id: 0x" + itoa_64("%x", ptr->id) + " dat: " + itoa_pointer(ptr->dat) + " nxt: " + itoa_pointer(ptr->nxt) + " pre: " + itoa_pointer(ptr->pre)).c_str());
		
		for (record_node_t* ptr = m_free.front(); ptr != NULL; ptr = ptr->nxt)
			ocall_print(std::string("[ff] ptr: " + itoa_pointer(ptr) + " id: 0x" + itoa_64("%x", ptr->id) + " dat: " + itoa_pointer(ptr->dat) + " nxt: " + itoa_pointer(ptr->nxt) + " pre: " + itoa_pointer(ptr->pre)).c_str());
		for (record_node_t* ptr = m_free.back(); ptr != NULL; ptr = ptr->pre)
			ocall_print(std::string("[fb] ptr: " + itoa_pointer(ptr) + " id: 0x" + itoa_64("%x", ptr->id) + " dat: " + itoa_pointer(ptr->dat) + " nxt: " + itoa_pointer(ptr->nxt) + " pre: " + itoa_pointer(ptr->pre)).c_str());

		throw std::runtime_error("record_cache_t::get() ...");
	}
	return m_vector[id];
}

