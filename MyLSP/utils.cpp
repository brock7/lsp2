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
