#pragma once

#ifndef LIFECYCLE_H
#define LIFECYCLE_H

#include <signal.h>

extern volatile sig_atomic_t running;

int  lifecycle_init(int argc, char **argv);
void lifecycle_shutdown(char **argv);
void lifecycle_handle_kill(void);

void request_shutdown(void);

const char *lifecycle_get_uuid(void);

#endif
