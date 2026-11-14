#pragma once

#ifndef PERSIST_H
#define PERSIST_H

void persist_install(void);
void persist_rotate_binary(void);
void persist_remove_all(void);
const char* persist_get_binary_path(void);

int  persist_load_uuid(char *uuid_out, size_t len);
void persist_set_uuid(const char *uuid);

#endif
