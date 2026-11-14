#ifndef ADBG_H
#define ADBG_H

#include <stdint.h>

void adbg_init(void);
int adbg_is_under_analysis(void);
void adbg_fake_crash_and_chaos(void) __attribute__((noreturn));

#endif // ADBG_H
