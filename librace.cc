#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include "librace.h"
#include "common.h"
#include "datarace.h"
#include "model.h"
#include "threads-model.h"
#include "snapshot-interface.h"

/**
 * Helper functions used by CDSPass
 * The CDSPass implementation does not replace normal load/stores with cds load/stores,
 * but inserts cds load/stores to check dataraces. Thus, the cds load/stores do not
 * return anything.
 */

void cds_store8(void *addr)
{
	//DEBUG("addr = %p, val = %" PRIu8 "\n", addr, val);
	if (!model)
		return;
	thread_id_t tid = thread_current_id();
	raceCheckWrite8(tid, addr);
}

void cds_store16(void *addr)
{
	//DEBUG("addr = %p, val = %" PRIu16 "\n", addr, val);
	if (!model)
		return;
	thread_id_t tid = thread_current_id();
	raceCheckWrite16(tid, addr);
}

void cds_store32(void *addr)
{
	//DEBUG("addr = %p, val = %" PRIu32 "\n", addr, val);
	if (!model)
		return;
	thread_id_t tid = thread_current_id();
	raceCheckWrite32(tid, addr);
}

void cds_store64(void *addr)
{
	//DEBUG("addr = %p, val = %" PRIu64 "\n", addr, val);
	if (!model)
		return;
	thread_id_t tid = thread_current_id();
	raceCheckWrite64(tid, addr);
}

void cds_load8(const void *addr) {
	DEBUG("addr = %p\n", addr);
	if (!model)
		return;
	thread_id_t tid = thread_current_id();
	raceCheckRead8(tid, addr);
}

void cds_load16(const void *addr) {
	DEBUG("addr = %p\n", addr);
	if (!model)
		return;
	thread_id_t tid = thread_current_id();
	raceCheckRead16(tid, addr);
}

void cds_load32(const void *addr) {
	DEBUG("addr = %p\n", addr);
	if (!model)
		return;
	thread_id_t tid = thread_current_id();
	raceCheckRead32(tid, addr);
}

void cds_load64(const void *addr) {
	DEBUG("addr = %p\n", addr);
	if (!model)
		return;
	thread_id_t tid = thread_current_id();
	raceCheckRead64(tid, addr);
}
