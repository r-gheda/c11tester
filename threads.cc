/** @file threads.cc
 *  @brief Thread functions.
 */

#include <string.h>

#include <threads.h>
#include "mutex.h"
#include "common.h"
#include "threads-model.h"
#include "action.h"

/* global "model" object */
#include "model.h"
#include "execution.h"
#include "schedule.h"
#include "clockvector.h"

#include <dlfcn.h>

#ifdef TLS
uintptr_t get_tls_addr() {
	uintptr_t addr;
	asm ("mov %%fs:0, %0" : "=r" (addr));
	return addr;
}

#include <asm/prctl.h>
#include <sys/prctl.h>
extern "C" {
int arch_prctl(int code, unsigned long addr);
}
static void set_tls_addr(uintptr_t addr) {
	arch_prctl(ARCH_SET_FS, addr);
	asm ("mov %0, %%fs:0" : : "r" (addr) : "memory");
}
#endif

/** Allocate a stack for a new thread. */
static void * stack_allocate(size_t size)
{
	return Thread_malloc(size);
}

/** Free a stack for a terminated thread. */
static void stack_free(void *stack)
{
	Thread_free(stack);
}

/**
 * @brief Get the current Thread
 *
 * Must be called from a user context
 *
 * @return The currently executing thread
 */
Thread * thread_current(void)
{
	ASSERT(model);
	return model->get_current_thread();
}

/**
 * @brief Get the current Thread id
 *
 * Must be called from a user context
 *
 * @return The id of the currently executing thread
 */
thread_id_t thread_current_id(void)
{
	ASSERT(model);
	return model->get_current_thread_id();
}

void modelexit() {
	model->switch_thread(new ModelAction(THREAD_FINISH, std::memory_order_seq_cst, thread_current()));
}

void initMainThread() {
	atexit(modelexit);
	Thread * curr_thread = thread_current();
	model->switch_thread(new ModelAction(THREAD_START, std::memory_order_seq_cst, curr_thread));
}

/**
 * Provides a startup wrapper for each thread, allowing some initial
 * model-checking data to be recorded. This method also gets around makecontext
 * not being 64-bit clean
 */
void thread_startup()
{
	Thread * curr_thread = thread_current();
#ifndef TLS
	/* Add dummy "start" action, just to create a first clock vector */
	model->switch_thread(new ModelAction(THREAD_START, std::memory_order_seq_cst, curr_thread));
#endif

	/* Call the actual thread function */
	if (curr_thread->start_routine != NULL) {
		curr_thread->start_routine(curr_thread->arg);
	} else if (curr_thread->pstart_routine != NULL) {
		// set pthread return value
		void *retval = curr_thread->pstart_routine(curr_thread->arg);
		curr_thread->set_pthread_return(retval);
	}
#ifndef TLS
	/* Finish thread properly */
	model->switch_thread(new ModelAction(THREAD_FINISH, std::memory_order_seq_cst, curr_thread));
#endif
}


static int (*real_epoll_wait_p)(int epfd, struct epoll_event *events, int maxevents, int timeout) = NULL;

int real_epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout) {
	return real_epoll_wait_p(epfd, events, maxevents, timeout);
}

static int (*pthread_mutex_init_p)(pthread_mutex_t *__mutex, const pthread_mutexattr_t *__mutexattr) = NULL;

int real_pthread_mutex_init(pthread_mutex_t *__mutex, const pthread_mutexattr_t *__mutexattr) {
	return pthread_mutex_init_p(__mutex, __mutexattr);
}

static int (*pthread_mutex_lock_p) (pthread_mutex_t *__mutex) = NULL;

int real_pthread_mutex_lock (pthread_mutex_t *__mutex) {
	return pthread_mutex_lock_p(__mutex);
}

static int (*pthread_mutex_unlock_p) (pthread_mutex_t *__mutex) = NULL;

int real_pthread_mutex_unlock (pthread_mutex_t *__mutex) {
	return pthread_mutex_unlock_p(__mutex);
}

static int (*pthread_create_p) (pthread_t *__restrict, const pthread_attr_t *__restrict, void *(*)(void *), void * __restrict) = NULL;

int real_pthread_create (pthread_t *__restrict __newthread, const pthread_attr_t *__restrict __attr, void *(*__start_routine)(void *), void *__restrict __arg) {
	return pthread_create_p(__newthread, __attr, __start_routine, __arg);
}

static int (*pthread_join_p) (pthread_t __th, void ** __thread_return) = NULL;

int real_pthread_join (pthread_t __th, void ** __thread_return) {
	return pthread_join_p(__th, __thread_return);
}

static void (*pthread_exit_p)(void *) __attribute__((noreturn))= NULL;

void real_pthread_exit (void * value_ptr) {
	pthread_exit_p(value_ptr);
}

void real_init_all() {
	char * error;
	if (!real_epoll_wait_p) {
		real_epoll_wait_p = (int (*)(int epfd, struct epoll_event *events, int maxevents, int timeout))dlsym(RTLD_NEXT, "epoll_wait");
		if ((error = dlerror()) != NULL) {
			fputs(error, stderr);
			exit(EXIT_FAILURE);
		}
	}
	if (!pthread_mutex_init_p) {
		pthread_mutex_init_p = (int (*)(pthread_mutex_t *__mutex, const pthread_mutexattr_t *__mutexattr))dlsym(RTLD_NEXT, "pthread_mutex_init");
		if ((error = dlerror()) != NULL) {
			fputs(error, stderr);
			exit(EXIT_FAILURE);
		}
	}
	if (!pthread_mutex_lock_p) {
		pthread_mutex_lock_p = (int (*)(pthread_mutex_t *__mutex))dlsym(RTLD_NEXT, "pthread_mutex_lock");
		if ((error = dlerror()) != NULL) {
			fputs(error, stderr);
			exit(EXIT_FAILURE);
		}
	}
	if (!pthread_mutex_unlock_p) {
		pthread_mutex_unlock_p = (int (*)(pthread_mutex_t *__mutex))dlsym(RTLD_NEXT, "pthread_mutex_unlock");
		if ((error = dlerror()) != NULL) {
			fputs(error, stderr);
			exit(EXIT_FAILURE);
		}
	}
	if (!pthread_create_p) {
		pthread_create_p = (int (*)(pthread_t *__restrict, const pthread_attr_t *__restrict, void *(*)(void *), void *__restrict))dlsym(RTLD_NEXT, "pthread_create");
		if ((error = dlerror()) != NULL) {
			fputs(error, stderr);
			exit(EXIT_FAILURE);
		}
	}
	if (!pthread_join_p) {
		pthread_join_p = (int (*)(pthread_t __th, void ** __thread_return))dlsym(RTLD_NEXT, "pthread_join");
		if ((error = dlerror()) != NULL) {
			fputs(error, stderr);
			exit(EXIT_FAILURE);
		}
	}

	if (!pthread_exit_p) {
		*((void (**)(void *)) &pthread_exit_p) = (void (*)(void *))dlsym(RTLD_NEXT, "pthread_exit");
		if ((error = dlerror()) != NULL) {
			fputs(error, stderr);
			exit(EXIT_FAILURE);
		}
	}
}

#ifdef TLS
void finalize_helper_thread() {
	Thread * curr_thread = thread_current();
	real_pthread_mutex_lock(&curr_thread->mutex);
	curr_thread->tls = (char *) get_tls_addr();
	real_pthread_mutex_unlock(&curr_thread->mutex);
	//Wait in the kernel until it is time for us to finish
	real_pthread_mutex_lock(&curr_thread->mutex2);
	real_pthread_mutex_unlock(&curr_thread->mutex2);
	//return to helper thread function
	setcontext(&curr_thread->context);
}

void * helper_thread(void * ptr) {
	Thread * curr_thread = thread_current();

	//build a context for this real thread so we can take it's context
	int ret = getcontext(&curr_thread->helpercontext);
	ASSERT(!ret);

	//Setup destructor
	if (pthread_setspecific(model->get_execution()->getPthreadKey(), (const void *)4)) {
		printf("Destructor setup failed\n");
		exit(-1);
	}


	/* Initialize new managed context */
	curr_thread->helper_stack = stack_allocate(STACK_SIZE);
	curr_thread->helpercontext.uc_stack.ss_sp = curr_thread->helper_stack;
	curr_thread->helpercontext.uc_stack.ss_size = STACK_SIZE;
	curr_thread->helpercontext.uc_stack.ss_flags = 0;
	curr_thread->helpercontext.uc_link = NULL;
	makecontext(&curr_thread->helpercontext, finalize_helper_thread, 0);

	model_swapcontext(&curr_thread->context, &curr_thread->helpercontext);


	//start the real thread
	thread_startup();

	return NULL;
}

#ifdef TLS
void tlsdestructor(void *v) {
	uintptr_t count = (uintptr_t) v;
	if (count > 1) {
		if (pthread_setspecific(model->get_execution()->getPthreadKey(), (const void *)(count - 1))) {
			printf("Destructor setup failed\n");
			exit(-1);
		}
		return;
	}
	/* Finish thread properly */
	model->switch_thread(new ModelAction(THREAD_FINISH, std::memory_order_seq_cst, thread_current()));
}
#endif

void setup_context() {
	Thread * curr_thread = thread_current();

	/* Add dummy "start" action, just to create a first clock vector */
	model->switch_thread(new ModelAction(THREAD_START, std::memory_order_seq_cst, curr_thread));

	real_init_all();

	/* Initialize our lock */
	real_pthread_mutex_init(&curr_thread->mutex, NULL);
	real_pthread_mutex_init(&curr_thread->mutex2, NULL);
	real_pthread_mutex_lock(&curr_thread->mutex2);

	/* Create the real thread */
	real_pthread_create(&curr_thread->thread, NULL, helper_thread, NULL);
	bool notdone = true;
	while(notdone) {
		real_pthread_mutex_lock(&curr_thread->mutex);
		if (curr_thread->tls != NULL)
			notdone = false;
		real_pthread_mutex_unlock(&curr_thread->mutex);
	}

	set_tls_addr((uintptr_t)curr_thread->tls);
	setcontext(&curr_thread->context);
}
#endif

/**
 * Create a thread context for a new thread so we can use
 * setcontext/getcontext/swapcontext to swap it out.
 * @return 0 on success; otherwise, non-zero error condition
 */
int Thread::create_context()
{
	int ret;

	ret = getcontext(&context);
	if (ret)
		return ret;

	/* Initialize new managed context */
	stack = stack_allocate(STACK_SIZE);
	context.uc_stack.ss_sp = stack;
	context.uc_stack.ss_size = STACK_SIZE;
	context.uc_stack.ss_flags = 0;
	context.uc_link = NULL;
#ifdef TLS
	makecontext(&context, setup_context, 0);
#else
	makecontext(&context, thread_startup, 0);
#endif

	return 0;
}

/**
 * Swaps the current context to another thread of execution. This form switches
 * from a user Thread to a system context.
 * @param t Thread representing the currently-running thread. The current
 * context is saved here.
 * @param ctxt Context to which we will swap. Must hold a valid system context.
 * @return Does not return, unless we return to Thread t's context. See
 * swapcontext(3) (returns 0 for success, -1 for failure).
 */
int Thread::swap(Thread *t, ucontext_t *ctxt)
{
	t->set_state(THREAD_READY);
#ifdef TLS
	set_tls_addr((uintptr_t)model->getInitThread()->tls);
#endif
	return model_swapcontext(&t->context, ctxt);
}

/**
 * Swaps the current context to another thread of execution. This form switches
 * from a system context to a user Thread.
 * @param ctxt System context variable to which to save the current context.
 * @param t Thread to which we will swap. Must hold a valid user context.
 * @return Does not return, unless we return to the system context (ctxt). See
 * swapcontext(3) (returns 0 for success, -1 for failure).
 */
int Thread::swap(ucontext_t *ctxt, Thread *t)
{
	t->set_state(THREAD_RUNNING);
#ifdef TLS
	if (t->tls != NULL)
		set_tls_addr((uintptr_t)t->tls);
#endif
	return model_swapcontext(ctxt, &t->context);
}

int Thread::swap(Thread *t, Thread *t2)
{
	t2->set_state(THREAD_RUNNING);
	if (t == t2)
		return 0;

#ifdef TLS
	if (t2->tls != NULL)
		set_tls_addr((uintptr_t)t2->tls);
#endif
	return model_swapcontext(&t->context, &t2->context);
}

/** Terminate a thread. */
void Thread::complete()
{
	ASSERT(!is_complete());
	DEBUG("completed thread %d\n", id_to_int(get_id()));
	state = THREAD_COMPLETED;
}

void Thread::freeResources() {
	if (stack)
		stack_free(stack);
#ifdef TLS
	if (this != model->getInitThread()) {
		real_pthread_mutex_unlock(&mutex2);
		real_pthread_join(thread, NULL);
		stack_free(helper_stack);
	}
#endif
	state = THREAD_FREED;
}

/**
 * @brief Construct a new model-checker Thread
 *
 * A model-checker Thread is used for accounting purposes only. It will never
 * have its own stack, and it should never be inserted into the Scheduler.
 *
 * @param tid The thread ID to assign
 */
Thread::Thread(thread_id_t tid) :
	local_vec(new SnapVector<ModelAction *> ()),
	parent(NULL),
	acq_fence_cv(new ClockVector()),
	creation(NULL),
	pending(NULL),
	wakeup_state(false),
	start_routine(NULL),
	arg(NULL),
	stack(NULL),
#ifdef TLS
	tls(NULL),
#endif
	user_thread(NULL),
	id(tid),
	state(THREAD_READY),	/* Thread is always ready? */
	last_action_val(0),
	model_thread(true)
{
	// real_memset is not defined when
	// the model thread is constructed
	memset(&context, 0, sizeof(context));
}

/**
 * Construct a new thread.
 * @param t The thread identifier of the newly created thread.
 * @param func The function that the thread will call.
 * @param a The parameter to pass to this function.
 */
Thread::Thread(thread_id_t tid, thrd_t *t, void (*func)(void *), void *a, Thread *parent) :
	local_vec(new SnapVector<ModelAction *> ()),
	parent(parent),
	acq_fence_cv(new ClockVector()),
	creation(NULL),
	pending(NULL),
	wakeup_state(false),
	start_routine(func),
	pstart_routine(NULL),
	arg(a),
#ifdef TLS
	tls(NULL),
#endif
	user_thread(t),
	id(tid),
	state(THREAD_CREATED),
	last_action_val(VALUE_NONE),
	model_thread(false)
{
	int ret;

	/* Initialize state */
	ret = create_context();
	if (ret)
		model_print("Error in create_context\n");

	user_thread->priv = this;	// WL
}

/**
 * Construct a new thread for pthread.
 * @param t The thread identifier of the newly created thread.
 * @param func The function that the thread will call.
 * @param a The parameter to pass to this function.
 */
Thread::Thread(thread_id_t tid, thrd_t *t, void *(*func)(void *), void *a, Thread *parent) :
	local_vec(new SnapVector<ModelAction *> ()),
	parent(parent),
	acq_fence_cv(new ClockVector()),
	creation(NULL),
	pending(NULL),
	wakeup_state(false),
	start_routine(NULL),
	pstart_routine(func),
	arg(a),
#ifdef TLS
	tls(NULL),
#endif
	user_thread(t),
	id(tid),
	state(THREAD_CREATED),
	last_action_val(VALUE_NONE),
	model_thread(false)
{
	int ret;

	/* Initialize state */
	ret = create_context();
	if (ret)
		model_print("Error in create_context\n");
}


/** Destructor */
Thread::~Thread()
{
	if (!is_complete())
		complete();

	delete acq_fence_cv;
}

/** @return The thread_id_t corresponding to this Thread object. */
thread_id_t Thread::get_id() const
{
	return id;
}

/**
 * Set a thread's THREAD_* state (@see thread_state)
 * @param s The state to enter
 */
void Thread::set_state(thread_state s)
{
	ASSERT(s == THREAD_COMPLETED || state != THREAD_COMPLETED);
	state = s;
}

/**
 * Get the Thread that this Thread is immediately waiting on
 * @return The thread we are waiting on, if any; otherwise NULL
 */
Thread * Thread::waiting_on() const
{
	if (!pending)
		return NULL;

	switch (pending->get_type()) {
		case THREAD_JOIN:
		case PTHREAD_JOIN:
			return pending->get_thread_operand();
		case ATOMIC_LOCK:
			return (Thread *)pending->get_mutex()->get_state()->locked;
		default:
			return NULL;
	}
}

/**
 * Check if this Thread is waiting (blocking) on a given Thread, directly or
 * indirectly (via a chain of waiting threads)
 *
 * @param t The Thread on which we may be waiting
 * @return True if we are waiting on Thread t; false otherwise
 */
bool Thread::is_waiting_on(const Thread *t) const
{
	Thread *wait;

	// One thread relocks a recursive mutex
	if (waiting_on() == t && pending->is_lock()) {
		int mutex_type = pending->get_mutex()->get_state()->type;
		if (mutex_type == PTHREAD_MUTEX_RECURSIVE)
			return false;
	}

	for (wait = waiting_on();wait != NULL;wait = wait->waiting_on())
		if (wait == t)
			return true;
	return false;
}


//weak memory 
	/** @brief get the local vector size on this thread */
	uint Thread::get_localvec_size(){
		return local_vec->size();
	}
	

	/** @brief update the local vector on this thread
	 *  @param act The new ModelAction*/
	void Thread::update_local_vec(ModelAction* act){
		bool has_flag = false;
		//int threadid = id_to_int(act->get_tid()); // get the thread id of the current action
		for(uint i = 0; i < get_localvec_size(); i++){
			ModelAction* iteract = (*local_vec)[i];
			if(iteract->get_location() == act->get_location()){ // the same variable
				has_flag = true; // have the variable now
				if(iteract->get_seq_number() > act->get_seq_number()){
					(*local_vec)[i] = act;
				}
				break;
			}
		}
		if(!has_flag){ // does not have this variable yet
			local_vec->push_back(act);
		}
	}

	void Thread::set_local_vec(SnapVector<ModelAction*> * newvec){
		local_vec = new SnapVector<ModelAction *> ();
		local_vec = newvec;
	}

	/** @brief print the local vector*/
	void Thread::print_local_vec(){
		model_print("The size of localvec is %d.", local_vec->size());
		for(uint i = 0; i < local_vec->size(); i++){
			ModelAction* iteract = (*local_vec)[i];
			model_print("[location: %14p,  seq_num: %u. ", iteract->get_location(), iteract->get_seq_number());
			model_print("value: %" PRIx64 "]\t", iteract->get_value());
		}
		model_print("\n");
	}

	void Thread::init_vec(){
		local_vec = new SnapVector<ModelAction *>();
	}

	ModelAction* Thread::get_same_location_act(ModelAction* act){
		
		// model_print("thread localvec size: %d \n", local_vec->size());
		for(uint i = 0; i < local_vec->size(); i++){
			ModelAction* iteract = (*local_vec)[i];
			if(act->get_location() == iteract->get_location()){
				return iteract;
			}
		}
		
		
		return NULL;
		
		
	}
