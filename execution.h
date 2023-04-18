/** @file execution.h
 *  @brief Model-checker core
 */

#ifndef __EXECUTION_H__
#define __EXECUTION_H__

#include <cstddef>
#include <inttypes.h>

#include "mymemory.h"
#include "hashtable.h"
#include "config.h"
#include "modeltypes.h"
#include "stl-model.h"
#include "params.h"
#include "mypthread.h"
#include "mutex.h"
#include <condition_variable>
#include "classlist.h"
//#include "action.h"
#include "threads-model.h"

#define INITIAL_THREAD_ID	0
#define MAIN_THREAD_ID		1

struct PendingFutureValue {
	PendingFutureValue(ModelAction *writer, ModelAction *reader) :
		writer(writer), reader(reader)
	{ }
	const ModelAction *writer;
	ModelAction *reader;
};

#ifdef COLLECT_STAT
void print_atomic_accesses();
#endif

/** @brief The central structure for model-checking */
class ModelExecution {
public:
	ModelExecution(ModelChecker *m, Scheduler *scheduler);
	~ModelExecution();

	struct model_params * get_params() const { return params; }
	void setParams(struct model_params * _params) {
		params = _params;
		maxinstr = 5 * params->maxinstr; // set the livelock bound for read nums
		model_print("The limit of read nums is %d. \n", maxinstr);
		history_ = params->history;
		}

	Thread * take_step(ModelAction *curr);

	void print_summary();
	void print_tail();
#if SUPPORT_MOD_ORDER_DUMP
	void dumpGraph(char *filename);
#endif

	void add_thread(Thread *t);
	Thread * get_thread(thread_id_t tid) const;
	Thread * get_thread(const ModelAction *act) const;

	uint32_t get_pthread_counter() { return pthread_counter; }
	void incr_pthread_counter() { pthread_counter++; }
	Thread * get_pthread(pthread_t pid);

	bool is_enabled(Thread *t) const;
	bool is_enabled(thread_id_t tid) const;

	thread_id_t get_next_id();
	unsigned int get_num_threads() const;

	ClockVector * get_cv(thread_id_t tid) const;
	ModelAction * get_parent_action(thread_id_t tid) const;

	ModelAction * get_last_action(thread_id_t tid) const;

	bool check_action_enabled(ModelAction *curr);

	void assert_bug(const char *msg);

	bool have_bug_reports() const;

	SnapVector<bug_message *> * get_bugs() const;

	bool has_asserted() const;
	void set_assert();
	bool is_complete_execution() const;

	bool is_deadlocked() const;

	action_list_t * get_action_trace() { return &action_trace; }
	Fuzzer * getFuzzer();
	CycleGraph * const get_mo_graph() { return mo_graph; }
	HashTable<pthread_cond_t *, cdsc::snapcondition_variable *, uintptr_t, 4> * getCondMap() {return &cond_map;}
	HashTable<pthread_mutex_t *, cdsc::snapmutex *, uintptr_t, 4> * getMutexMap() {return &mutex_map;}
	ModelAction * check_current_action(ModelAction *curr);

	bool isFinished() {return isfinished;}
	void setFinished() {isfinished = true;}
	void restore_last_seq_num();
	void collectActions();
	modelclock_t get_curr_seq_num();
#ifdef TLS
	pthread_key_t getPthreadKey() {return pthreadkey;}
#endif
	//pctwm
	
	void incInstrnum(){
		instrnum++;
	}

	int getInstrnum(){
		return instrnum;
	}

	void print_actset(SnapVector<ModelAction *> * act_set);



	// weak memory function
	SnapVector<ModelAction *> * computeUpdate(ModelAction *rd, ModelAction * curr);
	SnapVector<ModelAction *> * computeUpdate_fence(ModelAction *fence_acq, ModelAction * fence_rel);
	SnapVector<ModelAction*> * updateVec(SnapVector<ModelAction*> *input_vec, ModelAction* curr);
	SnapVector<ModelAction*> * maxVec(SnapVector<ModelAction*> * Eacc, SnapVector<ModelAction*> *local_vec);
	SnapVector<ModelAction *> * computeBag_sc(ModelAction *curr);
	SNAPSHOTALLOC
private:
	int get_execution_number() const;
	bool should_wake_up(const ModelAction * asleep) const;
	void wake_up_sleeping_actions();
	modelclock_t get_next_seq_num();
	bool next_execution();
	bool initialize_curr_action(ModelAction **curr);
	//weak memory
	bool process_read(ModelAction *curr, SnapVector<ModelAction *> * rf_set, bool read_external);\
	//c11tester
	bool process_read(ModelAction *curr, SnapVector<ModelAction *> * rf_set);
	void process_write(ModelAction *curr);
	void process_fence(ModelAction *curr);
	bool process_mutex(ModelAction *curr);
	void process_thread_action(ModelAction *curr);
	void read_from(ModelAction *act, ModelAction *rf);
	bool synchronize(const ModelAction *first, ModelAction *second);
	void add_action_to_lists(ModelAction *act, bool canprune);
	void add_normal_write_to_lists(ModelAction *act);
	void add_write_to_lists(ModelAction *act);
	ModelAction * get_last_fence_release(thread_id_t tid) const;
	ModelAction * get_last_seq_cst_write(ModelAction *curr) const;
	ModelAction * get_last_seq_cst_fence(thread_id_t tid, const ModelAction *before_fence) const;
	ModelAction * get_last_unlock(ModelAction *curr) const;
	SnapVector<ModelAction *> * build_may_read_from(ModelAction *curr, int history);
	ModelAction * process_rmw(ModelAction *curr);
	bool r_modification_order(ModelAction *curr, const ModelAction *rf, SnapVector<ModelAction *> *priorset, bool *canprune);
	void w_modification_order(ModelAction *curr);
	ClockVector * get_hb_from_write(ModelAction *rf) const;
	ModelAction * convertNonAtomicStore(void*);
	ClockVector * computeMinimalCV();
	void removeAction(ModelAction *act);
	void fixupLastAct(ModelAction *act);



#ifdef TLS
	pthread_key_t pthreadkey;
#endif
	ModelChecker *model;
	struct model_params * params;

	/** The scheduler to use: tracks the running/ready Threads */
	Scheduler * const scheduler;


	SnapVector<Thread *> thread_map;
	SnapVector<Thread *> pthread_map;
	uint32_t pthread_counter;

	action_list_t action_trace;


	/** Per-object list of actions. Maps an object (i.e., memory location)
	 * to a trace of all actions performed on the object.
	 * Used only for SC fences, unlocks, & wait.
	 */
	HashTable<const void *, simple_action_list_t *, uintptr_t, 2> obj_map;

	/** Per-object list of actions. Maps an object (i.e., memory location)
	 * to a trace of all actions performed on the object. */
	HashTable<const void *, simple_action_list_t *, uintptr_t, 2> condvar_waiters_map;

	/** Per-object list of actions that each thread performed. */
	HashTable<const void *, SnapVector<action_list_t> *, uintptr_t, 2> obj_thrd_map;

	/** Per-object list of writes that each thread performed. */
	HashTable<const void *, SnapVector<simple_action_list_t> *, uintptr_t, 2> obj_wr_thrd_map;

	HashTable<const void *, ModelAction *, uintptr_t, 4> obj_last_sc_map;


	HashTable<pthread_mutex_t *, cdsc::snapmutex *, uintptr_t, 4> mutex_map;
	HashTable<pthread_cond_t *, cdsc::snapcondition_variable *, uintptr_t, 4> cond_map;

	/**
	 * List of pending release sequences. Release sequences might be
	 * determined lazily as promises are fulfilled and modification orders
	 * are established. Each entry in the list may only be partially
	 * filled, depending on its pending status.
	 */

	SnapVector<ModelAction *> thrd_last_action;
	SnapVector<ModelAction *> thrd_last_fence_release;

	/** A special model-checker Thread; used for associating with
	 *  model-checker-related ModelAcitons */
	Thread *model_thread;

	/** Private data members that should be snapshotted. They are grouped
	 * together for efficiency and maintainability. */
	struct model_snapshot_members * const priv;

	/**
	 * @brief The modification order graph
	 *
	 * A directed acyclic graph recording observations of the modification
	 * order on all the atomic objects in the system. This graph should
	 * never contain any cycles, as that represents a violation of the
	 * memory model (total ordering). This graph really consists of many
	 * disjoint (unconnected) subgraphs, each graph corresponding to a
	 * separate ordering on a distinct object.
	 *
	 * The edges in this graph represent the "ordered before" relation,
	 * such that <tt>a --> b</tt> means <tt>a</tt> was ordered before
	 * <tt>b</tt>.
	 */
	CycleGraph * const mo_graph;

	Fuzzer * fuzzer;

	Thread * action_select_next_thread(const ModelAction *curr, const bool move_flag) const;

	bool isfinished;

	int instrnum, maxinstr, history_;
};

#endif	/* __EXECUTION_H__ */
