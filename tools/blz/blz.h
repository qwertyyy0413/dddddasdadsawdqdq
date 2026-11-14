#ifndef BLZ_H
#define BLZ_H

#include <stddef.h>

__attribute__((visibility("hidden")))
int blz_pack(const char *src, char *dst, int srcSize, int dstCapacity);

__attribute__((visibility("hidden")))
int blz_unpack(const char *src, char *dst, int compressedSize, int dstCapacity);

__attribute__((visibility("hidden")))
int blz_pack_bound(int inputSize);

#endif
