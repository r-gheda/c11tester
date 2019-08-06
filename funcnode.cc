#include "funcnode.h"
#include <fcntl.h>

FuncNode::FuncNode() :
	predicate_tree_initialized(false),
	func_inst_map(),
	inst_list(),
	entry_insts(),
	thrd_read_map(),
	predicate_tree_entry()
{}

/* Check whether FuncInst with the same type, position, and location
 * as act has been added to func_inst_map or not. If so, return it;
 * if not, add it and return it.
 *
 * @return FuncInst with the same type, position, and location as act */
FuncInst * FuncNode::get_or_add_inst(ModelAction *act)
{
	ASSERT(act);
	const char * position = act->get_position();

	/* THREAD* actions, ATOMIC_LOCK, ATOMIC_TRYLOCK, and ATOMIC_UNLOCK
	 * actions are not tagged with their source line numbers
	 */
	if (position == NULL)
		return NULL;

	if ( func_inst_map.contains(position) ) {
		FuncInst * inst = func_inst_map.get(position);

		if (inst->get_type() != act->get_type() ) {
			// model_print("action with a different type occurs at line number %s\n", position);
			FuncInst * func_inst = inst->search_in_collision(act);

			if (func_inst != NULL) {
				// return the FuncInst found in the collision list
				return func_inst;
			}

			func_inst = new FuncInst(act, this);
			inst->get_collisions()->push_back(func_inst);
			inst_list.push_back(func_inst);	// delete?

			return func_inst;
		}

		return inst;
	}

	FuncInst * func_inst = new FuncInst(act, this);

	func_inst_map.put(position, func_inst);
	inst_list.push_back(func_inst);

	return func_inst;
}

void FuncNode::add_entry_inst(FuncInst * inst)
{
	if (inst == NULL)
		return;

	mllnode<FuncInst *> * it;
	for (it = entry_insts.begin(); it != NULL; it = it->getNext()) {
		if (inst == it->getVal())
			return;
	}

	entry_insts.push_back(inst);
}

/**
 * @brief Convert ModelAdtion list to FuncInst list 
 * @param act_list A list of ModelActions
 */
void FuncNode::update_tree(action_list_t * act_list)
{
	if (act_list == NULL)
		return;
	else if (act_list->size() == 0)
		return;

	/* build inst_list from act_list for later processing */
	func_inst_list_t inst_list;
	func_inst_list_t read_inst_list;
	HashTable<FuncInst *, uint64_t, uintptr_t, 4> read_val_map;

	for (sllnode<ModelAction *> * it = act_list->begin(); it != NULL; it = it->getNext()) {
		ModelAction * act = it->getVal();
		FuncInst * func_inst = get_or_add_inst(act);

		if (func_inst == NULL)
			continue;

		inst_list.push_back(func_inst);

/*		if (!predicate_tree_initialized) {
			model_print("position: %s ", act->get_position());
			act->print();
		}
*/

		if (func_inst->is_read()) {
			read_inst_list.push_back(func_inst);
			read_val_map.put(func_inst, act->get_reads_from_value());
		}
	}

	update_inst_tree(&inst_list);
	init_predicate_tree(&read_inst_list, &read_val_map);
}

/** 
 * @brief Link FuncInsts in inst_list  - add one FuncInst to another's predecessors and successors
 * @param inst_list A list of FuncInsts
 */
void FuncNode::update_inst_tree(func_inst_list_t * inst_list)
{
	if (inst_list == NULL)
		return;
	else if (inst_list->size() == 0)
		return;

	/* start linking */
	sllnode<FuncInst *>* it = inst_list->begin();
	sllnode<FuncInst *>* prev;

	/* add the first instruction to the list of entry insts */
	FuncInst * entry_inst = it->getVal();
	add_entry_inst(entry_inst);

	it = it->getNext();
	while (it != NULL) {
		prev = it->getPrev();

		FuncInst * prev_inst = prev->getVal();
		FuncInst * curr_inst = it->getVal();

		prev_inst->add_succ(curr_inst);
		curr_inst->add_pred(prev_inst);

		it = it->getNext();
	}
}

/* @param tid thread id
 * Store the values read by atomic read actions into thrd_read_map */
void FuncNode::store_read(ModelAction * act, uint32_t tid)
{
	ASSERT(act);

	void * location = act->get_location();
	uint64_t read_from_val = act->get_reads_from_value();

	/* resize and initialize */
	uint32_t old_size = thrd_read_map.size();
	if (old_size <= tid) {
		thrd_read_map.resize(tid + 1);
		for (uint32_t i = old_size; i < tid + 1;i++)
			thrd_read_map[i] = new read_map_t();
	}

	read_map_t * read_map = thrd_read_map[tid];
	read_map->put(location, read_from_val);

	/* Store the memory locations where atomic reads happen */
	// read_locations.add(location);
}

uint64_t FuncNode::query_last_read(void * location, uint32_t tid)
{
	if (thrd_read_map.size() <= tid)
		return 0xdeadbeef;

	read_map_t * read_map = thrd_read_map[tid];

	/* last read value not found */
	if ( !read_map->contains(location) )
		return 0xdeadbeef;

	uint64_t read_val = read_map->get(location);
	return read_val;
}

/* @param tid thread id
 * Reset read map for a thread. This function shall only be called
 * when a thread exits a function
 */
void FuncNode::clear_read_map(uint32_t tid)
{
	if (thrd_read_map.size() <= tid)
		return;

	thrd_read_map[tid]->reset();
}

void FuncNode::init_predicate_tree(func_inst_list_t * inst_list, HashTable<FuncInst *, uint64_t, uintptr_t, 4> * read_val_map)
{
	if (inst_list == NULL || inst_list->size() == 0)
		return;

/*
	if (predicate_tree_initialized) {
		return;
	}
	predicate_tree_initialized = true;
*/
	// maybe restrict the size of hashtable to save calloc time
	HashTable<void *, FuncInst *, uintptr_t, 4> loc_inst_map(64);

	sllnode<FuncInst *> *it = inst_list->begin();
	FuncInst * entry_inst = it->getVal();

	/* get the unique Predicate pointer, assuming entry instructions have no predicate expression */
	Predicate * curr_pred = NULL;
	PredSetIter * pit = predicate_tree_entry.iterator();
	while (pit->hasNext()) {
		Predicate * p = pit->next();
		p->get_func_inst()->print();
		if (p->get_func_inst() == entry_inst) {
			curr_pred = p;
			break;
		}
	}
	if (curr_pred == NULL) {
		curr_pred = new Predicate(entry_inst);
		predicate_tree_entry.add(curr_pred);
	}

	loc_inst_map.put(entry_inst->get_location(), entry_inst);

	it = it->getNext();
	while (it != NULL) {
		FuncInst * curr_inst = it->getVal();
		bool child_found = false;

		/* check if a child with the same func_inst and corresponding predicate exists */
		ModelVector<Predicate *> * children = curr_pred->get_children();
		for (uint i = 0; i < children->size(); i++) {
			Predicate * child = (*children)[i];
			if (child->get_func_inst() != curr_inst)
				continue;

			PredExprSet * pred_expressions = child->get_pred_expressions();

			/* no predicate, follow the only child */
			if (pred_expressions->getSize() == 0) {
				model_print("no predicate exists: ");
				curr_inst->print();
				curr_pred = child;
				child_found = true;
				break;
			}
		}

		if (!child_found) {
			if ( loc_inst_map.contains(curr_inst->get_location()) ) {
				Predicate * new_pred1 = new Predicate(curr_inst);
				new_pred1->add_predicate(EQUALITY, curr_inst->get_location(), true);

				Predicate * new_pred2 = new Predicate(curr_inst);
				new_pred2->add_predicate(EQUALITY, curr_inst->get_location(), false);

				curr_pred->add_child(new_pred1);
				curr_pred->add_child(new_pred2);

				FuncInst * last_inst = loc_inst_map.get(curr_inst->get_location());
				uint64_t last_read = read_val_map->get(last_inst);
				if ( last_read == read_val_map->get(curr_inst) )
					curr_pred = new_pred1;
				else
					curr_pred = new_pred2;
			} else {
				Predicate * new_pred = new Predicate(curr_inst);
				curr_pred->add_child(new_pred);
				curr_pred = new_pred;
			}
		}

		loc_inst_map.put(curr_inst->get_location(), curr_inst);

		it = it->getNext();
	}

//	model_print("function %s\n", func_name);
//	print_predicate_tree();
}


void FuncNode::print_predicate_tree()
{
	model_print("digraph function_%s {\n", func_name);
	PredSetIter * it = predicate_tree_entry.iterator();

	while (it->hasNext()) {
		Predicate * p = it->next();
		p->print_pred_subtree();
	}
	model_print("}\n");	// end of graph
}

/* @param tid thread id
 * Print the values read by the last read actions for each memory location
 */
/*
void FuncNode::print_last_read(uint32_t tid)
{
	ASSERT(thrd_read_map.size() > tid);
	read_map_t * read_map = thrd_read_map[tid];

	mllnode<void *> * it;
	for (it = read_locations.begin();it != NULL;it=it->getNext()) {
		if ( !read_map->contains(it->getVal()) )
			break;

		uint64_t read_val = read_map->get(it->getVal());
		model_print("last read of thread %d at %p: 0x%x\n", tid, it->getVal(), read_val);
	}
}
*/
