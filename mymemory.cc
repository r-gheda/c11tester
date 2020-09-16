
#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>
#include <unistd.h>
#include <string.h>
#include <new>

#include "mymemory.h"
#include "snapshot.h"
#include "common.h"
#include "threads-model.h"
#include "model.h"
#include "datarace.h"

#define REQUESTS_BEFORE_ALLOC 1024

size_t allocatedReqs[REQUESTS_BEFORE_ALLOC] = { 0 };
int nextRequest = 0;
int howManyFreed = 0;
mspace sStaticSpace = NULL;

/** Non-snapshotting calloc for our use. */
void *model_calloc(size_t count, size_t size)
{
	return mspace_calloc(sStaticSpace, count, size);
}

/** Non-snapshotting malloc for our use. */
void *model_malloc(size_t size)
{
	return mspace_malloc(sStaticSpace, size);
}

/** Non-snapshotting malloc for our use. */
void *model_realloc(void *ptr, size_t size)
{
	return mspace_realloc(sStaticSpace, ptr, size);
}

/** @brief Snapshotting malloc, for use by model-checker (not user progs) */
void * snapshot_malloc(size_t size)
{
	void *tmp = mspace_malloc(model_snapshot_space, size);
	ASSERT(tmp);
	return tmp;
}

/** @brief Snapshotting calloc, for use by model-checker (not user progs) */
void * snapshot_calloc(size_t count, size_t size)
{
	void *tmp = mspace_calloc(model_snapshot_space, count, size);
	ASSERT(tmp);
	return tmp;
}

/** @brief Snapshotting realloc, for use by model-checker (not user progs) */
void *snapshot_realloc(void *ptr, size_t size)
{
	void *tmp = mspace_realloc(model_snapshot_space, ptr, size);
	ASSERT(tmp);
	return tmp;
}

/** @brief Snapshotting free, for use by model-checker (not user progs) */
void snapshot_free(void *ptr)
{
	mspace_free(model_snapshot_space, ptr);
}

/** Non-snapshotting free for our use. */
void model_free(void *ptr)
{
	mspace_free(sStaticSpace, ptr);
}

/** Bootstrap allocation. Problem is that the dynamic linker calls require
 *  calloc to work and calloc requires the dynamic linker to work. */

#define BOOTSTRAPBYTES 131072
char bootstrapmemory[BOOTSTRAPBYTES];
size_t offset = 0;

void * HandleEarlyAllocationRequest(size_t sz)
{
	/* Align to 8 byte boundary */
	sz = (sz + 7) & ~7;

	if (sz > (BOOTSTRAPBYTES-offset)) {
		model_print("OUT OF BOOTSTRAP MEMORY.  Increase the size of BOOTSTRAPBYTES in mymemory.cc\n");
		exit(EXIT_FAILURE);
	}

	void *pointer = (void *)&bootstrapmemory[offset];
	offset += sz;
	return pointer;
}

/** @brief Global mspace reference for the model-checker's snapshotting heap */
mspace model_snapshot_space = NULL;

/** @brief Snapshotting allocation function for use by the Thread class only */
void * Thread_malloc(size_t size)
{
	return snapshot_malloc(size);
}

/** @brief Snapshotting free function for use by the Thread class only */
void Thread_free(void *ptr)
{
	snapshot_free(ptr);
}

void * (*volatile real_memcpy)(void * dst, const void *src, size_t n) = NULL;
void * (*volatile real_memmove)(void * dst, const void *src, size_t len) = NULL;
void (*volatile real_bzero)(void * dst, size_t len) = NULL;
void * (*volatile real_memset)(void * dst, int c, size_t len) = NULL;

void init_memory_ops()
{
	if (!real_memcpy) {
		real_memcpy = (void * (*)(void * dst, const void *src, size_t n)) 1;
		real_memcpy = (void * (*)(void * dst, const void *src, size_t n))dlsym(RTLD_NEXT, "memcpy");
	}
	if (!real_memmove) {
		real_memmove = (void * (*)(void * dst, const void *src, size_t n)) 1;
		real_memmove = (void * (*)(void * dst, const void *src, size_t n))dlsym(RTLD_NEXT, "memmove");
	}
	if (!real_memset) {
		real_memset = (void * (*)(void * dst, int c, size_t n)) 1;
		real_memset = (void * (*)(void * dst, int c, size_t n))dlsym(RTLD_NEXT, "memset");
	}
	if (!real_bzero) {
		real_bzero = (void (*)(void * dst, size_t len)) 1;
		real_bzero = (void (*)(void * dst, size_t len))dlsym(RTLD_NEXT, "bzero");
	}
}

void * memcpy(void * dst, const void * src, size_t n) {
	if (model && !inside_model) {
		//model_print("memcpy intercepted\n");
		thread_id_t tid = thread_current_id();
		if (((uintptr_t)src&7) == 0 && ((uintptr_t)dst&7) == 0 && (n&7) == 0) {
			for (uint i = 0; i < (n>>3); i++) {
				raceCheckRead64(tid, (void *)(((uint64_t *)src) + i));
				((volatile uint64_t *)dst)[i] = ((uint64_t *)src)[i];
				raceCheckWrite64(tid, (void *)(((uint64_t *)dst) + i));
			}
		} else if (((uintptr_t)src&3) == 0 && ((uintptr_t)dst&3) == 0 && (n&3) == 0) {
			for (uint i = 0; i < (n>>2); i++) {
				raceCheckRead32(tid, (void *)(((uint32_t *)src) + i));
				((volatile uint32_t *)dst)[i] = ((uint32_t *)src)[i];
				raceCheckWrite32(tid, (void *)(((uint32_t *)dst) + i));
			}
		} else if (((uintptr_t)src&1) == 0 && ((uintptr_t)dst&1) == 0 && (n&1) == 0) {
			for (uint i = 0; i < (n>>1); i++) {
				raceCheckRead16(tid, (void *)(((uint16_t *)src) + i));
				((volatile uint16_t *)dst)[i] = ((uint16_t *)src)[i];
				raceCheckWrite16(tid, (void *)(((uint16_t *)dst) + i));
			}
		} else {
			for(uint i=0;i<n;i++) {
				raceCheckRead8(tid, (void *)(((char *)src) + i));
				((volatile char *)dst)[i] = ((char *)src)[i];
				raceCheckWrite8(tid, (void *)(((char *)dst) + i));
			}
		}
	} else {
		if (((uintptr_t)real_memcpy) < 2) {
			for(uint i=0;i<n;i++) {
				((volatile char *)dst)[i] = ((char *)src)[i];
			}
			return dst;
		}

		return real_memcpy(dst, src, n);
	}
	return dst;
}

void * memmove(void * dst, const void * src, size_t n) {
	if (model && !inside_model) {
		thread_id_t tid = thread_current_id();
		if (((uintptr_t)src&7) == 0 && ((uintptr_t)dst&7) == 0 && (n&7) == 0) {
			if (((uintptr_t)dst) < ((uintptr_t)src))
				for (uint i = 0; i < (n>>3); i++) {
					raceCheckRead64(tid, (void *)(((uint64_t *)src) + i));
					((volatile uint64_t *)dst)[i] = ((uint64_t *)src)[i];
					raceCheckWrite64(tid, (void *)(((uint64_t *)dst) + i));
				}
			else
				for (uint i = (n>>3); i != 0;) {
					i--;
					raceCheckRead64(tid, (void *)(((uint64_t *)src) + i));
					((volatile uint64_t *)dst)[i] = ((uint64_t *)src)[i];
					raceCheckWrite64(tid, (void *)(((uint64_t *)dst) + i));
				}
		} else if (((uintptr_t)src&3) == 0 && ((uintptr_t)dst&3) == 0 && (n&3) == 0) {
			if (((uintptr_t)dst) < ((uintptr_t)src))
				for (uint i = 0; i < (n>>2); i++) {
					raceCheckRead32(tid, (void *)(((uint32_t *)src) + i));
					((volatile uint32_t *)dst)[i] = ((uint32_t *)src)[i];
					raceCheckWrite32(tid, (void *)(((uint32_t *)dst) + i));
				}
			else
				for (uint i = (n>>2); i != 0;) {
					i--;
					raceCheckRead32(tid, (void *)(((uint32_t *)src) + i));
					((volatile uint32_t *)dst)[i] = ((uint32_t *)src)[i];
					raceCheckWrite32(tid, (void *)(((uint32_t *)dst) + i));
				}
		} else if (((uintptr_t)src&1) == 0 && ((uintptr_t)dst&1) == 0 && (n&1) == 0) {
			if (((uintptr_t)dst) < ((uintptr_t)src))
				for (uint i = 0; i < (n>>1); i++) {
					raceCheckRead16(tid, (void *)(((uint16_t *)src) + i));
					((volatile uint16_t *)dst)[i] = ((uint16_t *)src)[i];
					raceCheckWrite16(tid, (void *)(((uint16_t *)dst) + i));
				}
			else
				for (uint i = (n>>1); i != 0;) {
					i--;
					raceCheckRead16(tid, (void *)(((uint16_t *)src) + i));
					((volatile uint16_t *)dst)[i] = ((uint16_t *)src)[i];
					raceCheckWrite16(tid, (void *)(((uint16_t *)dst) + i));
				}
		} else {
			if (((uintptr_t)dst) < ((uintptr_t)src))
				for(uint i = 0; i < n; i++) {
					raceCheckRead8(tid, (void *)(((char *)src) + i));
					((volatile char *)dst)[i] = ((char *)src)[i];
					raceCheckWrite8(tid, (void *)(((char *)dst) + i));
				}
			else
				for(uint i = n; i != 0;) {
					i--;
					raceCheckRead8(tid, (void *)(((char *)src) + i));
					((volatile char *)dst)[i] = ((char *)src)[i];
					raceCheckWrite8(tid, (void *)(((char *)dst) + i));
				}
		}
	} else {
		if (((uintptr_t)real_memmove) < 2) {
			if (((uintptr_t)dst) < ((uintptr_t)src))
				for(uint i=0;i<n;i++) {
					((volatile char *)dst)[i] = ((char *)src)[i];
				}
			else
				for(uint i=n;i!=0; ) {
					i--;
					((volatile char *)dst)[i] = ((char *)src)[i];
				}
			return dst;
		}
        return real_memmove(dst, src, n);
	}
	return dst;
}

void * memset(void *dst, int c, size_t n) {
	if (model && !inside_model) {
		thread_id_t tid = thread_current_id();
		uint8_t cs = c&0xff;
		if (((uintptr_t)dst&7) == 0 && (n&7) == 0) {
			for (uint i = 0; i < (n>>3); i++) {
	            uint16_t cs2 = cs << 8 | cs;
	            uint64_t cs3 = cs2 << 16 | cs2;
	            uint64_t cs4 = cs3 << 32 | cs3;
				((volatile uint64_t *)dst)[i] = cs4;
				raceCheckWrite64(tid, (void *)(((uint64_t *)dst) + i));
			}
		} else if (((uintptr_t)dst&3) == 0 && (n&3) == 0) {
			for (uint i = 0; i < (n>>2); i++) {
	            uint16_t cs2 = cs << 8 | cs;
	            uint32_t cs3 = cs2 << 16 | cs2;
				((volatile uint32_t *)dst)[i] = cs3;
				raceCheckWrite32(tid, (void *)(((uint32_t *)dst) + i));
			}
		} else if (((uintptr_t)dst&1) == 0 && (n&1) == 0) {
			for (uint i = 0; i < (n>>1); i++) {
	            uint16_t cs2 = cs << 8 | cs;
				((volatile uint16_t *)dst)[i] = cs2;
				raceCheckWrite16(tid, (void *)(((uint16_t *)dst) + i));
			}
		} else {
			for (uint i=0;i<n;i++) {
				((volatile char *)dst)[i] = cs;
				raceCheckWrite8(tid, (void *)(((char *)dst) + i));
			}
		}
	} else {
		if (((uintptr_t)real_memset) < 2) {
			//stuck in dynamic linker alloc cycle...
			for(size_t s=0;s<n;s++) {
				((volatile char *)dst)[s] = (char) c;
			}
			return dst;
		}
		return real_memset(dst, c, n);
	}
	return dst;
}

void bzero(void *dst, size_t n) {
	if (model && !inside_model) {
		thread_id_t tid = thread_current_id();
		if (((uintptr_t)dst&7) == 0 && (n&7) == 0) {
			for (uint i = 0; i < (n>>3); i++) {
				((volatile uint64_t *)dst)[i] = 0;
				raceCheckWrite64(tid, (void *)(((uint64_t *)dst) + i));
			}
		} else if (((uintptr_t)dst&3) == 0 && (n&3) == 0) {
			for (uint i = 0; i < (n>>2); i++) {
				((volatile uint32_t *)dst)[i] = 0;
				raceCheckWrite32(tid, (void *)(((uint32_t *)dst) + i));
			}
		} else if (((uintptr_t)dst&1) == 0 && (n&1) == 0) {
			for (uint i = 0; i < (n>>1); i++) {
				((volatile uint16_t *)dst)[i] = 0;
				raceCheckWrite16(tid, (void *)(((uint16_t *)dst) + i));
			}
		} else {
			for (uint i=0;i<n;i++) {
				((volatile char *)dst)[i] = 0;
				raceCheckWrite8(tid, (void *)(((char *)dst) + i));
			}
		}
	} else {
		if (((uintptr_t)real_bzero) < 2) {
			for(size_t s=0;s<n;s++) {
				((volatile char *)dst)[s] = 0;
			}
			return;
		}
		real_bzero(dst, n);
	}
}
