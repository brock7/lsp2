#include "utils.h"
#include <windows.h>
#include <detours.h>
#include <iphlpapi.h>
#include "debug.h"

#include <iostream>  
#include <sstream>  
#include <iomanip>  
#include <string> 

#pragma comment(lib, "detours.lib")
#pragma comment(lib, "IPHLPAPI.lib")

ULONG (WINAPI* Real_GetAdaptersInfo)(_Out_writes_bytes_opt_(*SizePointer) PIP_ADAPTER_INFO AdapterInfo,_Inout_ PULONG SizePointer) = GetAdaptersInfo;

ULONG
WINAPI
Mine_GetAdaptersInfo(
	_Out_writes_bytes_opt_(*SizePointer) PIP_ADAPTER_INFO AdapterInfo,
	_Inout_                         PULONG           SizePointer
)
{
	TRACE("MyLSP.dll: Mine_GetAdaptersInfo()\n"); // 到了这里, 但是还是显示二次验证
	auto result = Real_GetAdaptersInfo(AdapterInfo, SizePointer);
	/*if (result == NO_ERROR && AdapterInfo) { // 设置为全 0 不行
		memset(AdapterInfo->Address, 0, AdapterInfo->AddressLength);
	}*/

	return result;
	//return ERROR_NOT_SUPPORTED;
}

void Hook_GetAdaptersInfo()
{
	TRACE("MyLSP.dll: Hook_GetAdaptersInfo()\n");
	DetourTransactionBegin();
	DetourAttach(&(PVOID&)Real_GetAdaptersInfo, Mine_GetAdaptersInfo);
	auto error = DetourTransactionCommit();

	if (error == NO_ERROR) {
		TRACE("MyLSP.dll: Detoured GetAdaptersInfo().\n");
	}
	else {
		TRACE("MyLSP.dll:Error detouring GetAdaptersInfo(): %ld\n", error);
	}
}

std::string arrayToHexString(const unsigned char* arr, size_t length) {
	std::stringstream ss;

	for (size_t i = 0; i < length; ++i) {
		if (i != 0)
			ss << ",";
		ss << "0x" << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(arr[i]);
	}
	return ss.str();
}

int wildcard_memcmp(LPCBYTE src, LPCBYTE dst, size_t len, BYTE wildcard)
{
	for (size_t i = 0; i < len; i++) {
		if (dst[i] == wildcard || src[i] == dst[i])
			continue;
		else
			return src[i] - dst[i];
	}

	return 0;
}

void MakeDefaultMsg(DefaultMessage* out, WORD ident, WORD param, WORD tag, DWORD nSessionID, DWORD recog, WORD series)
{
	out->recog = recog; // *(_DWORD *)a7 = a5;
	out->nSessionID = nSessionID;	// *(_DWORD *)(a7 + 4) = a4;
	out->ident = ident; // *(_WORD *)(a7 + 8) = a1;
	out->param = param; // *(_WORD *)(a7 + 10) = a2;
	out->tag = tag; // *(_WORD *)(a7 + 12) = a3;
	out->series = series; // *(_WORD *)(a7 + 14) = a6;
}

std::string Encode6BitBuf(const std::vector<uint8_t>& src) {
	size_t size = src.size();
	size_t destLen = (size / 3) * 4 + 10;
	std::string dest(destLen, '\0');
	size_t destPos = 0;
	int resetCount = 0;
	uint8_t chMade = 0, chRest = 0;

	for (size_t i = 0; i < size; ++i) {
		if (destPos >= destLen) {
			break;
		}

		chMade = (chRest | ((src[i] & 0xff) >> (2 + resetCount))) & 0x3f;
		chRest = (((src[i] & 0xff) << (8 - (2 + resetCount))) >> 2) & 0x3f;

		resetCount += 2;
		if (resetCount < 6) {
			dest[destPos] = chMade + 0x3c;
			destPos++;
		}
		else {
			if (destPos < destLen - 1) {
				dest[destPos] = chMade + 0x3c;
				destPos++;
				dest[destPos] = chRest + 0x3c;
				destPos++;
			}
			else {
				dest[destPos] = chMade + 0x3c;
				destPos++;
			}
			resetCount = 0;
			chRest = 0;
		}
	}

	if (resetCount > 0) {
		dest[destPos] = chRest + 0x3c;
		destPos++;
	}

	dest.resize(destPos);
	return dest;
}

const uint8_t decode6BitMask[] = { 0xfc, 0xf8, 0xf0, 0xe0, 0xc0 };

std::vector<uint8_t> Decode6BitBuf(const std::string& src) {
	size_t size = src.size();
	std::vector<uint8_t> dest(size * 3 / 4, 0);
	size_t destPos = 0;
	int bitPos = 2;
	int madeBit = 0;
	uint8_t ch = 0;
	uint8_t chCode = 0;
	uint8_t tmp = 0;

	for (size_t i = 0; i < size; ++i) {
		if (src[i] - 0x3c >= 0) {
			ch = src[i] - 0x3c;
		}
		else {
			destPos = 0;
			break;
		}

		if (destPos >= dest.size()) {
			break;
		}

		if (madeBit + 6 >= 8) {
			chCode = tmp | ((ch & 0x3f) >> (6 - bitPos));
			dest[destPos] = chCode;
			destPos++;
			madeBit = 0;
			if (bitPos < 6) {
				bitPos += 2;
			}
			else {
				bitPos = 2;
				continue;
			}
		}

		tmp = (ch << bitPos) & decode6BitMask[bitPos - 2];
		madeBit += 8 - bitPos;
	}

	dest.resize(destPos);
	return dest;
}
