#pragma once

#include <windows.h>
#include <detours.h>
#include <iphlpapi.h>
#include "debug.h"

#include <string>  

void Hook_GetAdaptersInfo();
std::string arrayToHexString(const unsigned char* arr, size_t length);
int wildcard_memcmp(LPCBYTE src, LPCBYTE dst, size_t len, BYTE wildcard = '*');
