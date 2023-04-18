#include "fuzzer.h"
#include <stdlib.h>
#include "threads-model.h"
#include "model.h"
#include "action.h"

int Fuzzer::selectWrite(ModelAction *read, SnapVector<ModelAction *> * rf_set) {
	int random_index = random() % rf_set->size();
	return random_index;
}

Thread * Fuzzer::selectThread(int * threadlist, int numthreads) {
	int random_index = random() % numthreads;
	int thread = threadlist[random_index];
	thread_id_t curr_tid = int_to_id(thread);
	return model->get_thread(curr_tid);
}

Thread * Fuzzer::selectNotify(simple_action_list_t * waiters) {
	int numwaiters = waiters->size();
	int random_index = random() % numwaiters;
	sllnode<ModelAction*> * it = waiters->begin();
	while(random_index--)
		it=it->getNext();
	Thread *thread = model->get_thread(it->getVal());
	waiters->erase(it);
	return thread;
}

bool Fuzzer::shouldSleep(const ModelAction *sleep) {
	return true;
}

bool Fuzzer::shouldWake(const ModelAction *sleep) {
	struct timespec currtime;
	clock_gettime(CLOCK_MONOTONIC, &currtime);
	uint64_t lcurrtime = currtime.tv_sec * 1000000000 + currtime.tv_nsec;

	return ((sleep->get_time()+sleep->get_value()) < lcurrtime);
}

/* Decide whether wait should spuriously fail or not */
bool Fuzzer::waitShouldFail(ModelAction * wait)
{
	if ((random() & 1) == 0) {
		struct timespec currtime;
        clock_gettime(CLOCK_MONOTONIC, &currtime);
        uint64_t lcurrtime = currtime.tv_sec * 1000000000 + currtime.tv_nsec;

		// The time after which wait fail spuriously, in nanoseconds
		uint64_t time = random() % 1000000;
		wait->set_time(time + lcurrtime);
		return true;
	}

	return false;
}

bool Fuzzer::waitShouldWakeUp(const ModelAction * wait)
{
	struct timespec currtime;
	clock_gettime(CLOCK_MONOTONIC, &currtime);
	uint64_t lcurrtime = currtime.tv_sec * 1000000000 + currtime.tv_nsec;

	return (wait->get_time() < lcurrtime);
}

bool Fuzzer::randomizeWaitTime(ModelAction * timed_wait)
{
	uint64_t abstime = timed_wait->get_time();
	struct timespec currtime;
	clock_gettime(CLOCK_MONOTONIC, &currtime);
	uint64_t lcurrtime = currtime.tv_sec * 1000000000 + currtime.tv_nsec;
	if (abstime <= lcurrtime)
		return false;

	// Shorten wait time
	if ((random() & 1) == 0) {
		uint64_t tmp = abstime - lcurrtime;
		uint64_t time_to_expire = random() % tmp + lcurrtime;
		timed_wait->set_time(time_to_expire);
	}

	return true;
}
