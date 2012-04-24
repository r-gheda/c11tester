#include <stdlib.h>

#include "libthreads.h"
#include "schedule.h"
#include "common.h"
#include "threads.h"

/* global "model" object */
#include "model.h"

#define STACK_SIZE (1024 * 1024)

static void * stack_allocate(size_t size)
{
	return userMalloc(size);
}

static void stack_free(void *stack)
{
	userFree(stack);
}

Thread * thread_current(void)
{
	return model->scheduler->get_current_thread();
}

int Thread::create_context()
{
	int ret;

	ret = getcontext(&context);
	if (ret)
		return ret;

	/* start_routine == NULL means this is our initial context */
	if (!start_routine)
		return 0;

	/* Initialize new managed context */
	stack = stack_allocate(STACK_SIZE);
	context.uc_stack.ss_sp = stack;
	context.uc_stack.ss_size = STACK_SIZE;
	context.uc_stack.ss_flags = 0;
	context.uc_link = &model->system_thread->context;
	makecontext(&context, start_routine, 1, arg);

	return 0;
}

int Thread::swap(Thread *t)
{
	return swapcontext(&this->context, &t->context);
}

void Thread::complete()
{
	if (state != THREAD_COMPLETED) {
		DEBUG("completed thread %d\n", get_id());
		state = THREAD_COMPLETED;
		if (stack)
			stack_free(stack);
	}
}

Thread::Thread(thrd_t *t, void (*func)(), void *a) {
	int ret;

	user_thread = t;
	start_routine = func;
	arg = a;

	/* Initialize state */
	ret = create_context();
	if (ret)
		printf("Error in create_context\n");

	state = THREAD_CREATED;
	id = model->get_next_id();
	*user_thread = id;
}

Thread::Thread(thrd_t *t) {
	/* system thread */
	user_thread = t;
	start_routine = NULL;
	arg = NULL;

	create_context();
	stack = NULL;
	state = THREAD_CREATED;
	id = model->get_next_id();
	*user_thread = id;
	model->add_system_thread(this);
}

Thread::~Thread()
{
	complete();
	model->remove_thread(this);
}

thread_id_t Thread::get_id()
{
	return id;
}

/*
 * Return 1 if found next thread, 0 otherwise
 */
static int thread_system_next(void)
{
	Thread *curr, *next;

	curr = thread_current();
	model->check_current_action();
	if (curr) {
		if (curr->get_state() == THREAD_READY)
			model->scheduler->add_thread(curr);
		else if (curr->get_state() == THREAD_RUNNING)
			/* Stopped while running; i.e., completed */
			curr->complete();
		else
			DEBUG("ERROR: current thread in unexpected state??\n");
	}
	next = model->scheduler->next_thread();
	if (next)
		next->set_state(THREAD_RUNNING);
	DEBUG("(%d, %d)\n", curr ? curr->get_id() : -1, next ? next->get_id() : -1);
	if (!next)
		return 1;
	return model->system_thread->swap(next);
}

static void thread_wait_finish(void)
{

	DBG();

	while (!thread_system_next());
}

/*
 * Main system function
 */
int main()
{
	thrd_t user_thread, main_thread;
	Thread *th;

	model = new ModelChecker();

	th = new Thread(&main_thread);

	do {
		/* Start user program */
		thrd_create(&user_thread, &user_main, NULL);

		/* Wait for all threads to complete */
		thread_wait_finish();
	} while (model->next_execution());

	delete th;
	delete model;

	DEBUG("Exiting\n");
	return 0;
}
