/** @file schedule.h
 *	@brief Thread scheduler.
 */

#ifndef __SCHEDULE_H__
#define __SCHEDULE_H__
#include <cstdlib>
#include "mymemory.h"
#include "modeltypes.h"
#include "classlist.h"
#include "params.h"

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
	uint64_t scheduler_get_nanotime()
	{
		struct timespec currtime;
		clock_gettime(CLOCK_MONOTONIC, &currtime);

		return currtime.tv_nsec;
	}

	void setParams(struct model_params * _params);


	void setlowvec(int bugdepth);

	void set_chg_pts(int bugdepth, int maxscheduler, int seed);

	int getRandom(int range, int seed);


	void print_chg();


	void print_lowvec();

	void incSchelen();

	int getSchelen();

	int find_chgidx(int schelen);

	void highvec_addthread(Thread *t);

	void print_highvec();


	void print_avails(int* availthreads, int availnum);
	int find_highest(int* availthreads, int availnum);
	void movethread(int lowvec_idx, int threadid);
	void pctactive();


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
};

#endif	/* __SCHEDULE_H__ */
