#ifndef VERUS_HASH_H
#define VERUS_HASH_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void verus_hash(const void *input, void *output, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif // VERUS_HASH_H
