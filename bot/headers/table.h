#ifndef TABLE_H
#define TABLE_H

#include <stdint.h>
#include <stddef.h>

void secure_memzero(void *v, size_t n);
char *decrypt(int id);
void free_secret(char *s);

#endif
