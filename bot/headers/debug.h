#pragma once

#ifndef DEBUG_H
#define DEBUG_H

#ifdef DEBUG
#include <stdio.h>
#define _DBG_PRINT(tag, fmt, ...) \
    fprintf(stderr, "[DEBUG][" tag "] " fmt "\n", ##__VA_ARGS__)
#else
#define _DBG_PRINT(tag, fmt, ...) ((void)0)
#endif

#ifdef MODULE_TAG
#define DEBUG_PRINT(fmt, ...) _DBG_PRINT(MODULE_TAG, fmt, ##__VA_ARGS__)
#endif

#endif // DEBUG_H
