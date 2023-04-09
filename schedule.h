/** @file schedule.h
 *	@brief Thread scheduler.
 */

#ifndef __SCHEDULE_H__
#define __SCHEDULE_H__

#include "mymemory.h"
#include "modeltypes.h"
#include "classlist.h"
#include "params.h"
#include <unordered_map>

typedef enum enabled_type {
	THREAD_DISABLED,
	THREAD_ENABLED,
	THREAD_SLEEP_SET
} enabled_type_t;

void enabled_type_to_string(enabled_type_t e, char *str);

/** @brief The Scheduler class performs the mechanics of Thread execution
 * scheduling. */
class Scheduler {
public:
	Scheduler();
	void register_engine(ModelExecution *execution);

	void add_thread(Thread *t);
	void remove_thread(Thread *t);
	void sleep(Thread *t);
	void wake(Thread *t);
	Thread * select_next_thread();
	void set_current_thread(Thread *t);
	Thread * get_current_thread() const;
	void print() const;
	enabled_type_t * get_enabled_array() const { return enabled; };
	void remove_sleep(Thread *t);
	void add_sleep(Thread *t);
	enabled_type_t get_enabled(const Thread *t) const;
	bool is_enabled(const Thread *t) const;
	bool is_enabled(thread_id_t tid) const;
	bool is_sleep_set(const Thread *t) const;
	bool is_sleep_set(thread_id_t tid) const;
	bool all_threads_sleeping() const;
	void set_scheduler_thread(thread_id_t tid);

	// related funcs
	uint64_t scheduler_get_nanotime();

	void setParams(struct model_params * _params);


	void setlowvec(int bugdepth);

	// void set_chg_pts(int bugdepth, int maxscheduler){
	// 	if(bugdepth <= 1){
	// 		chg_pts.resize(1, srand() % maxscheduler);
	// 	}
	// 	else{
	// 		chg_pts.resize(bugdepth - 1);
	// 		for(int i = 0; i < bugdepth - 1; i++){
	// 			int tmp = getRandom(maxscheduler); // [1, MAXSCHEDULER]
	// 			while(chg_pts.find(tmp)){
	// 				tmp = getRandom(maxscheduler);
	// 			}
	// 			chg_pts[i] = tmp;

	// 		}
	// 	}
		
	// }

	//pctwm
	void set_chg_pts_byread(int bugdepth, int maxinstr, int seed);


	//pctwm - return bool: true : threadid in highvec(not change prio yet)
	bool inhighvec(int threadid);



	int getRandom(int range, int seed);


	void print_chg();

	void print_lowvec();

	void incSchelen();
	int getSchelen();

	int find_chgidx(int currlen);

	void highvec_addthread(Thread *t);

	void print_highvec();


	void print_avails(int* availthreads, int availnum);
	int find_highest(int* availthreads, int availnum);
	void movethread(int lowvec_idx, int threadid);
	void pctactive();

	void print_current_avail_threads();

	//weak memory
	int get_highest_thread();

	int get_scecond_high_thread();

			// weak memory model
	void add_external_readnum_thread(uint threadid);

	bool deleteone_external_readnum_thread(uint threadid);

	bool get_external_readnum_thread(uint threadid);

	void print_external_readnum_thread();

	


	SNAPSHOTALLOC
private:
	ModelExecution *execution;
	/** The list of available Threads that are not currently running */
	enabled_type_t *enabled;
	int enabled_len;
	int curr_thread_index;
	void set_enabled(Thread *t, enabled_type_t enabled_status);

	/** The currently-running Thread */
	Thread *current;

	//PCT
	struct model_params * params;

	SnapVector<int> lowvec;
	SnapVector<int> chg_pts;
	int schelen;

	SnapVector<int> highvec;
	int highsize;
	int schelen_limit;
	bool livelock;
	int usingpct;

	// weak memory - save the highest thread - for execution.cc to move
	int highest_id;

	SnapVector<bool> external_readnum_thread;

	std::unordered_map<ModelAction*, float> priority_map;

};

#endif	/* __SCHEDULE_H__ */
