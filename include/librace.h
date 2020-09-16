/** @file librace.h
 *  @brief Interface to check normal memory operations for data races.
 */

#ifndef __LIBRACE_H__
#define __LIBRACE_H__

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void cds_store8(void *addr);
void cds_store16(void *addr);
void cds_store32(void *addr);
void cds_store64(void *addr);

void cds_load8(const void *addr);
void cds_load16(const void *addr);
void cds_load32(const void *addr);
void cds_load64(const void *addr);

#ifdef __cplusplus
}
#endif

#endif	/* __LIBRACE_H__ */
