#pragma once

#ifndef DNS_H
#define DNS_H

#include <stdint.h>
#include <arpa/inet.h>

uint32_t dns_resolve(const char* domain);

#endif // DNS_H
