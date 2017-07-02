#pragma once
/* An implementation of a LRU cache utilizing a pre-allocated free list */

#include <stdint.h>
#include <string>
#include <stdlib.h>
#include <string.h>
#include "common.hpp"

struct record_node_t
{
	uint64_t		id;
	void*			dat;
	record_node_t*	nxt;
	record_node_t*	pre;
};

class list_t
{
	private:
		record_node_t*	m_head;
		record_node_t* m_tail;
	protected:
	public:
		list_t(void);
		~list_t(void);

		static record_node_t* new_node(void*);

		void push_front(record_node_t*);
		void push_back(record_node_t*);

		inline record_node_t* front(void) { return m_head; }
		inline record_node_t* back(void) { return m_tail; }
		
		inline uint64_t size(void) const 
		{
			uint64_t ret(0);

			for (record_node_t* ptr = m_head; ptr != NULL; ptr = ptr->nxt)
				ret += 1;

			return ret;
		}

		inline uint64_t rsize(void) const
		{
			uint64_t ret(0);

			for (record_node_t* ptr = m_tail; ptr != NULL; ptr = ptr->pre)
				ret += 1;

			return ret;
		}

		record_node_t* pop_back(void);
		record_node_t* pop_front(void);

		inline bool empty(void) { return NULL == m_head && NULL == m_tail; }

		void move_front(record_node_t*);
		void move_back(record_node_t*);

		record_node_t* find(void*, bool f = true);
		record_node_t* find(uint64_t, bool f = true);

		void unlink(record_node_t*);
};


class record_cache_t
{
	private:
		uint64_t			m_total;
		uint64_t			m_number;
		uint64_t			m_size;
		void*				m_records;
		user_record_t**		m_vector;
		list_t				m_list;
		list_t				m_free;

	protected:
	public:

		record_cache_t(uint64_t, uint64_t, uint64_t limit = 10 * 1024 * 1024);
		~record_cache_t(void);

		inline uint64_t total(void) const { return m_total; }
		inline uint64_t number(void) const { return m_number; }
		inline uint64_t size(void) const { return m_size; }

		inline user_record_t*
		end(uint64_t id)
		{
			char* ret = reinterpret_cast< char* >(get(id));

			if (NULL == ret)
				return NULL;

			ret += m_size;
			return reinterpret_cast< user_record_t* >(ret);
		}

		inline user_record_t*
		end(user_record_t* rec)
		{
			char* ret = reinterpret_cast< char* >(rec);

			if (NULL == rec)
				return NULL;

			ret += m_size;
			return reinterpret_cast< user_record_t* >(ret);
		}

		void evict(uint64_t);
		void evict(user_record_t*);

		void purge(uint64_t count = 1);

		bool set(uint64_t, user_record_t*, bool over = false);
		user_record_t* get(uint64_t);
};

