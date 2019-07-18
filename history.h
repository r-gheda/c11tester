#include "stl-model.h"
#include "common.h"
#include "hashtable.h"
#include "threads-model.h"

class ModelHistory {
public:
	ModelHistory();
	~ModelHistory();

	void enter_function(const uint32_t func_id, thread_id_t tid);
	void exit_function(const uint32_t func_id, thread_id_t tid);

	uint32_t get_func_counter() { return func_counter; }
	void incr_func_counter() { func_counter++; }

	void process_action(ModelAction *act, thread_id_t tid);

	HashTable<const char *, uint32_t, uintptr_t, 4, model_malloc, model_calloc, model_free> * getFuncMap() { return &func_map; }
	ModelVector<const char *> * getFuncMapRev() { return &func_map_rev; }

	ModelVector<FuncNode *> * getFuncNodes() { return &func_nodes; }

	void link_insts(func_inst_list_t * inst_list);
	void print();

	MEMALLOC
private:
	uint32_t func_counter;

	/* map function names to integer ids */ 
	HashTable<const char *, uint32_t, uintptr_t, 4, model_malloc, model_calloc, model_free> func_map;
	/* map integer ids to function names */ 
	ModelVector<const char *> func_map_rev;

	ModelVector<FuncNode *> func_nodes;
};
