#include "MyLSP.h"
#include "debug.h"
#include <shlwapi.h>  
#include "utils.h"

#pragma comment(lib, "shlwapi.lib")  

WSPUPCALLTABLE g_pUpCallTable;
WSPPROC_TABLE g_NextProcTable;
TCHAR g_szCurrentApp[MAX_PATH];
char g_szModulePath[MAX_PATH];
FILE* g_logfp = nullptr;

void InitLSP(HANDLE hModule);

BOOL APIENTRY DllMain(HANDLE hModule, DWORD dwReason, LPVOID lpReserved)
{
	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
		InitLSP(hModule);
		break;
	case DLL_PROCESS_DETACH:
		if (g_logfp) {
			fclose(g_logfp);
			g_logfp = nullptr;
		}
		break;
	default:
		break;
	}
	return TRUE;
}

void InitLSP(HANDLE hModule)
{
	::GetModuleFileName(NULL, g_szCurrentApp, MAX_PATH);
	
	GetModuleFileNameA((HMODULE)hModule, g_szModulePath, sizeof(g_szModulePath) - 1);
	::PathRemoveFileSpecA(g_szModulePath);
	char filename[MAX_PATH];
	sprintf(filename, "%s\\Log_%u.log", g_szModulePath, GetCurrentProcessId());
	g_logfp = fopen(filename, "a+");

	//Hook_GetAdaptersInfo();
}

LPWSAPROTOCOL_INFOW GetProvider(LPINT lpnTotalProtocols)
{
	DWORD dwSize = 0;
	int dwError;
	LPWSAPROTOCOL_INFOW pProtoInfo = NULL;

	if(::WSCEnumProtocols(NULL, pProtoInfo, &dwSize, &dwError) == SOCKET_ERROR)
	{
		if(dwError != WSAENOBUFS) return NULL;
	}
	pProtoInfo = (LPWSAPROTOCOL_INFOW)::GlobalAlloc(GPTR, dwSize);
	*lpnTotalProtocols = ::WSCEnumProtocols(NULL, pProtoInfo, &dwSize, &dwError);
	return pProtoInfo;
}

void FreeProvider(LPWSAPROTOCOL_INFOW pProtoInfo)
{
	::GlobalFree(pProtoInfo);
}

int WSPAPI WSPStartup(
					  WORD wVersionRequested,
					  LPWSPDATA lpWSPData,
					  LPWSAPROTOCOL_INFO lpProtocolInfo,
					  WSPUPCALLTABLE UpcallTable,
					  LPWSPPROC_TABLE lpProcTable
					  )
{
	int i;
	ODS1("WSPStartup() Enter. %ws\n", g_szCurrentApp);

	if(lpProtocolInfo->ProtocolChain.ChainLen <= 1)
	{
		return WSAEPROVIDERFAILEDINIT;
	}
	g_pUpCallTable = UpcallTable;

	WSAPROTOCOL_INFOW NextProtocolInfo;
	int nTotalProtos;
	LPWSAPROTOCOL_INFOW pProtoInfo = GetProvider(&nTotalProtos);
	
	DWORD dwBaseEntryId = lpProtocolInfo->ProtocolChain.ChainEntries[1];
	for(i=0; i<nTotalProtos; i++)
	{
		if(pProtoInfo[i].dwCatalogEntryId == dwBaseEntryId)
		{
			memcpy(&NextProtocolInfo, &pProtoInfo[i], sizeof(NextProtocolInfo));
			break;
		}
	}
	if(i >= nTotalProtos)
	{
		ODS(" WSPStartup: Can not find underlying protocol \n");
		return WSAEPROVIDERFAILEDINIT;
	}

	int nError;
	TCHAR szBaseProviderDll[MAX_PATH];
	int nLen = MAX_PATH;

	if(::WSCGetProviderPath(&NextProtocolInfo.ProviderId, szBaseProviderDll, &nLen, &nError) == SOCKET_ERROR)
	{
		ODS1(" WSPStartup: WSCGetProviderPath() failed %d \n", nError);
		return WSAEPROVIDERFAILEDINIT;
	}
	if(!::ExpandEnvironmentStrings(szBaseProviderDll, szBaseProviderDll, MAX_PATH))
	{
		ODS1(" WSPStartup: ExpandEnvironmentStrings() failed %d \n", ::GetLastError());
		return WSAEPROVIDERFAILEDINIT;
	}

	ODS1(" WSPStartup(): LoadLibrary(%ws)\n", szBaseProviderDll);

	HMODULE hModule = ::LoadLibrary(szBaseProviderDll);
	if(hModule == NULL)
	{
		ODS1(" WSPStartup: LoadLibrary() failed %d \n", ::GetLastError());
		return WSAEPROVIDERFAILEDINIT;
	}

	LPWSPSTARTUP pfnWSPStartup = NULL;
	pfnWSPStartup = (LPWSPSTARTUP)::GetProcAddress(hModule, "WSPStartup");
	if(pfnWSPStartup == NULL)
	{
		ODS1(" WSPStartup: GetProcAddress() failed %d \n", ::GetLastError());
		return WSAEPROVIDERFAILEDINIT;
	}

	LPWSAPROTOCOL_INFOW pInfo = lpProtocolInfo;
	if(NextProtocolInfo.ProtocolChain.ChainLen == BASE_PROTOCOL)
		pInfo = &NextProtocolInfo;
	int nRet = pfnWSPStartup(wVersionRequested, lpWSPData, pInfo, UpcallTable, lpProcTable);
	if(nRet != ERROR_SUCCESS)
	{
		ODS1(" WSPStartup: underlying provider's WSPStartup() failed %d \n", nRet);
		return nRet;
	}
	g_NextProcTable = *lpProcTable;
	lpProcTable->lpWSPSocket = WSPSocket;
	lpProcTable->lpWSPCloseSocket = WSPCloseSocket;
	lpProcTable->lpWSPConnect = WSPConnect;
	lpProcTable->lpWSPAccept = WSPAccept;
	lpProcTable->lpWSPSend = WSPSend;
	lpProcTable->lpWSPSendTo = WSPSendTo;
	lpProcTable->lpWSPRecv = WSPRecv;
	lpProcTable->lpWSPRecvFrom = WSPRecvFrom;
	lpProcTable->lpWSPAddressToString = WSPAddressToString;
	lpProcTable->lpWSPAsyncSelect = WSPAsyncSelect;
	lpProcTable->lpWSPBind = WSPBind;
	lpProcTable->lpWSPCancelBlockingCall = WSPCancelBlockingCall;
	lpProcTable->lpWSPCleanup = WSPCleanup;
	lpProcTable->lpWSPDuplicateSocket = WSPDuplicateSocket;
	lpProcTable->lpWSPEnumNetworkEvents = WSPEnumNetworkEvents;
	lpProcTable->lpWSPEventSelect = WSPEventSelect;
	lpProcTable->lpWSPGetOverlappedResult = WSPGetOverlappedResult;
	lpProcTable->lpWSPGetPeerName = WSPGetPeerName;
	lpProcTable->lpWSPGetQOSByName = WSPGetQOSByName;
	lpProcTable->lpWSPGetSockName = WSPGetSockName;
	lpProcTable->lpWSPGetSockOpt = WSPGetSockOpt;
	lpProcTable->lpWSPIoctl = WSPIoctl;
	lpProcTable->lpWSPJoinLeaf = WSPJoinLeaf;
	lpProcTable->lpWSPListen = WSPListen;
	lpProcTable->lpWSPRecvDisconnect = WSPRecvDisconnect;
	lpProcTable->lpWSPSelect = WSPSelect;
	lpProcTable->lpWSPSendDisconnect = WSPSendDisconnect;
	lpProcTable->lpWSPSetSockOpt = WSPSetSockOpt;
	lpProcTable->lpWSPShutdown = WSPShutdown;
	lpProcTable->lpWSPStringToAddress = WSPStringToAddress;
	FreeProvider(pProtoInfo);
	//ODS1("WSPStartup(): g_NextProcTable = %p\n", &g_NextProcTable);
	//for (int i = 0; i < 30; i ++)
	//	ODS1("WSPStartup() g_NextProcTable[i] %p\n", ((ULONG* )&g_NextProcTable)[i]);
	ODS1("WSPStartup() Leave. %ws\n", g_szCurrentApp);
	return nRet;
}
