#pragma once

#include <windows.h>
#include <detours.h>
#include <iphlpapi.h>
#include "debug.h"

#include <string>  
#include <vector>
#include <iostream>

void Hook_GetAdaptersInfo();
std::string arrayToHexString(const unsigned char* arr, size_t length);
int wildcard_memcmp(LPCBYTE src, LPCBYTE dst, size_t len, BYTE wildcard = '*');

struct DefaultMessage {
	DWORD recog;
	DWORD nSessionID;
	WORD ident;
	WORD param;
	WORD tag;
	WORD series;

	DefaultMessage(WORD ident, WORD param, WORD tag, DWORD nSessionID, DWORD recog, WORD series)
	{
		this->recog = recog; // *(_DWORD *)a7 = a5;
		this->nSessionID = nSessionID;	// *(_DWORD *)(a7 + 4) = a4;
		this->ident = ident; // *(_WORD *)(a7 + 8) = a1;
		this->param = param; // *(_WORD *)(a7 + 10) = a2;
		this->tag = tag; // *(_WORD *)(a7 + 12) = a3;
		this->series = series; // *(_WORD *)(a7 + 14) = a6;
	}
};

void MakeDefaultMsg(DefaultMessage* out, WORD ident, WORD param = 0, WORD tag = 0, DWORD nSessionID = 0, DWORD recog = 0, WORD series = 0);

std::string Encode6BitBuf(const std::vector<uint8_t>& src);
std::vector<uint8_t> Decode6BitBuf(const std::string& src);
