#define _CRT_SECURE_NO_WARNINGS

#include "manager.h"
#include <stdio.h>

#include <iostream>  
#include <sstream>  
#include <iomanip>  
#include <string> 

static GUID ProviderGuid = {0x8a, 0x88b, 0x888c,{0x8a,0x8a,0x8a,0x8a,0x8a,0x8a,0x8a,0x8a}};

LPWSAPROTOCOL_INFOW GetProvider(LPINT lpnTotalProtocols);
void FreeProvider(LPWSAPROTOCOL_INFOW pProtoInfo);
BOOL InstallProvider(WCHAR *pwszPathName);
BOOL RemoveProvider();

LSPERROR InstallLSP()
{
	TCHAR szPathName[256];
	TCHAR* p;
	if(::GetFullPathName(L"MyLSP.dll", 256, szPathName, &p) != 0)
	{
		if(InstallProvider(szPathName))
		{
			return LSP_SUCCESS;
		} else
		{
			return LSP_ACCESS_DENIED;
		}
	}
	return LSP_NO_SUCH_FILE;
}

LSPERROR RemoveLSP()
{
	if (RemoveProvider())
		return LSP_SUCCESS;
	else
		return LSP_ACCESS_DENIED;
}

//LSPERROR AddRule(const char* name, const char* value)
//{
//	HKEY hKey = 0;
//	DWORD Count = 0, keyType = REG_DWORD, disp = REG_CREATED_NEW_KEY;
//	DWORD len = sizeof(DWORD);
//	char temp[REG_MAX_LENGTH];
//
//	if (strlen(name) > REG_MAX_LENGTH || strlen(value) > REG_MAX_LENGTH)
//	{
//		return LSP_TOO_LONG;
//	}
//
//	if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,"SYSTEM\\CurrentControlSet\\Control\\LSPManager",0, KEY_ALL_ACCESS, &hKey)!= ERROR_SUCCESS)
//	{
//		if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\LSPManager", 0, NULL, 0, KEY_ALL_ACCESS, NULL,&hKey, &disp))
//			return LSP_ACCESS_DENIED;
//		Count = 0;
//	}
//	else
//	{
//		if (RegQueryValueExA(hKey, "NumberOfRules", 0, &keyType, (BYTE*)&Count, &len))
//		{
//			RegCloseKey(hKey);
//			return LSP_ACCESS_DENIED;
//		}
//	}
//
//	keyType = REG_SZ;
//	len = strlen(temp);
//	RegQueryValueExA(hKey, name, 0, &keyType, (BYTE*)temp, &len);
//	if (len != strlen(temp))
//	{
//		RegSetValueExA(hKey, name, 0, REG_SZ, (BYTE*)value, strlen(value));
//	}
//	else
//	{
//		Count = Count + 1;
//		RegSetValueExA(hKey, "NumberOfRules", 0, REG_DWORD,(BYTE*)&Count, sizeof(Count));
//		RegSetValueExA(hKey, name, 0, REG_SZ, (BYTE*)value, strlen(value));
//	}
//	RegCloseKey(hKey);
//	return LSP_SUCCESS;
//}
//
//LSPERROR DeleteRule(const char* name)
//{
//	HKEY hKey = 0;
//	DWORD Count = 0, keyType = REG_SZ;
//	DWORD len = sizeof(DWORD);
//
//	if (strlen(name) > REG_MAX_LENGTH)
//		return LSP_TOO_LONG;
//
//	if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,"SYSTEM\\CurrentControlSet\\Control\\LSPManager",0, KEY_ALL_ACCESS, &hKey)!= ERROR_SUCCESS)
//		return LSP_ACCESS_DENIED;
//
//	RegQueryValueExA(hKey, "NumberOfRules", 0, &keyType, (BYTE*)&Count, &len);
//	if (Count == 0) 
//	{
//		RegCloseKey(hKey);
//		return LSP_NO_SUCH_FILE;
//	}
//	if (RegDeleteValueA(hKey, name)) 
//	{
//		RegCloseKey(hKey);
//		return LSP_NO_SUCH_FILE;
//	}
//	Count = Count - 1;
//	RegSetValueExA(hKey, "NumberOfRules", 0, REG_DWORD,(BYTE*)&Count, sizeof(Count));
//	RegCloseKey(hKey);
//	return LSP_SUCCESS;
//}

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

BOOL InstallProvider(WCHAR *pwszPathName)
{
	WCHAR wszLSPName[] = L"MyLSP.dll";
	LPWSAPROTOCOL_INFOW pProtoInfo;
	int nProtocols;
	WSAPROTOCOL_INFOW OriginalProtocolInfo[3];
	DWORD    dwOrigCatalogId[3];
	int nArrayCount = 0;
	DWORD dwLayeredCatalogId;  
	int dwError;

	pProtoInfo = GetProvider(&nProtocols);
	//BOOL bFindUdp = FALSE;
	BOOL bFindTcp = FALSE;
	//BOOL bFindRaw = FALSE;
	for (int i=0; i<nProtocols; i++)
	{
		if (pProtoInfo[i].iAddressFamily == AF_INET)
		{
			/*if (!bFindUdp && pProtoInfo[i].iProtocol == IPPROTO_UDP)
			{
				memcpy(&OriginalProtocolInfo[nArrayCount], &pProtoInfo[i], sizeof(WSAPROTOCOL_INFOW));
				OriginalProtocolInfo[nArrayCount].dwServiceFlags1 = OriginalProtocolInfo[nArrayCount].dwServiceFlags1 & (~XP1_IFS_HANDLES); 
				dwOrigCatalogId[nArrayCount++] = pProtoInfo[i].dwCatalogEntryId;
				bFindUdp = TRUE;
			}*/
			if (!bFindTcp && pProtoInfo[i].iProtocol == IPPROTO_TCP)
			{
				memcpy(&OriginalProtocolInfo[nArrayCount], &pProtoInfo[i], sizeof(WSAPROTOCOL_INFOW));
				OriginalProtocolInfo[nArrayCount].dwServiceFlags1 = OriginalProtocolInfo[nArrayCount].dwServiceFlags1 & (~XP1_IFS_HANDLES); 
				dwOrigCatalogId[nArrayCount++] = pProtoInfo[i].dwCatalogEntryId;
				bFindTcp = TRUE;
			}
			/*if (!bFindRaw && pProtoInfo[i].iProtocol == IPPROTO_IP)
			{
				memcpy(&OriginalProtocolInfo[nArrayCount], &pProtoInfo[i], sizeof(WSAPROTOCOL_INFOW));
				OriginalProtocolInfo[nArrayCount].dwServiceFlags1 = OriginalProtocolInfo[nArrayCount].dwServiceFlags1 & (~XP1_IFS_HANDLES); 
				dwOrigCatalogId[nArrayCount++] = pProtoInfo[i].dwCatalogEntryId;
				bFindRaw = TRUE;
			}*/
		}
	}

	WSAPROTOCOL_INFOW LayeredProtocolInfo;
	memcpy(&LayeredProtocolInfo, &OriginalProtocolInfo[0], sizeof(WSAPROTOCOL_INFOW));
	wcscpy_s(LayeredProtocolInfo.szProtocol, wszLSPName);
	LayeredProtocolInfo.ProtocolChain.ChainLen = LAYERED_PROTOCOL;
	LayeredProtocolInfo.dwProviderFlags |= PFL_HIDDEN;

	if (::WSCInstallProvider(&ProviderGuid, pwszPathName, &LayeredProtocolInfo, 1, &dwError) == SOCKET_ERROR)
	{
		return FALSE;
	}

	FreeProvider(pProtoInfo);
	pProtoInfo = GetProvider(&nProtocols);
	for(int i=0; i<nProtocols; i++)
	{
		if (memcmp(&pProtoInfo[i].ProviderId, &ProviderGuid, sizeof(ProviderGuid)) == 0)
		{
			dwLayeredCatalogId = pProtoInfo[i].dwCatalogEntryId;
			break;
		}
	}

	WCHAR wszChainName[WSAPROTOCOL_LEN + 1];
	for(int i=0; i<nArrayCount; i++)
	{
		swprintf_s(wszChainName, L"%ws over %ws", wszLSPName, OriginalProtocolInfo[i].szProtocol);
		wcscpy_s(OriginalProtocolInfo[i].szProtocol, wszChainName);
		if (OriginalProtocolInfo[i].ProtocolChain.ChainLen == 1)
		{
			OriginalProtocolInfo[i].ProtocolChain.ChainEntries[1] = dwOrigCatalogId[i];
		}
		else
		{
			for (int j = OriginalProtocolInfo[i].ProtocolChain.ChainLen; j>0; j--)
			{
				OriginalProtocolInfo[i].ProtocolChain.ChainEntries[j] = OriginalProtocolInfo[i].ProtocolChain.ChainEntries[j-1];
			}
		}
		OriginalProtocolInfo[i].ProtocolChain.ChainLen ++;
		OriginalProtocolInfo[i].ProtocolChain.ChainEntries[0] = dwLayeredCatalogId; 
	}

	GUID ProviderChainGuid;
	if (::UuidCreate(&ProviderChainGuid) == RPC_S_OK)
	{
		if (::WSCInstallProvider(&ProviderChainGuid, pwszPathName, OriginalProtocolInfo, nArrayCount, &dwError) == SOCKET_ERROR)
		{
			return FALSE; 
		}
	}
	else
	{
		return FALSE;
	}
	FreeProvider(pProtoInfo);
	pProtoInfo = GetProvider(&nProtocols);
	DWORD dwIds[20];
	int nIndex = 0;

	for(int i=0; i<nProtocols; i++)
	{
		if((pProtoInfo[i].ProtocolChain.ChainLen > 1) && (pProtoInfo[i].ProtocolChain.ChainEntries[0] == dwLayeredCatalogId))
			dwIds[nIndex++] = pProtoInfo[i].dwCatalogEntryId;
	}

	for(int i=0; i<nProtocols; i++)
	{
		if((pProtoInfo[i].ProtocolChain.ChainLen <= 1) || (pProtoInfo[i].ProtocolChain.ChainEntries[0] != dwLayeredCatalogId))
			dwIds[nIndex++] = pProtoInfo[i].dwCatalogEntryId;
	}

	if((dwError = ::WSCWriteProviderOrder(dwIds, nIndex)) != ERROR_SUCCESS)
	{
		return FALSE;
	}
	FreeProvider(pProtoInfo);
	return TRUE;
}

BOOL RemoveProvider()
{
	LPWSAPROTOCOL_INFOW pProtoInfo;
	int nProtocols, i;
	DWORD dwLayeredCatalogId;

	pProtoInfo = GetProvider(&nProtocols);
	int dwError;
	for (i=0; i<nProtocols; i++)
	{
		if (memcmp(&ProviderGuid, &pProtoInfo[i].ProviderId, sizeof(ProviderGuid)) == 0)
		{
			dwLayeredCatalogId = pProtoInfo[i].dwCatalogEntryId;
			break;
		}
	}
	if (i < nProtocols)
	{
		for (i=0; i<nProtocols; i++)
		{
			if ((pProtoInfo[i].ProtocolChain.ChainLen > 1) && (pProtoInfo[i].ProtocolChain.ChainEntries[0] == dwLayeredCatalogId))
			{
				::WSCDeinstallProvider(&pProtoInfo[i].ProviderId, &dwError);
			}
		}
		::WSCDeinstallProvider(&ProviderGuid, &dwError);
	}
	return TRUE;
}

int wildcard_memcmp(LPCBYTE src, LPCBYTE dst, size_t len, BYTE wildcard = '*')
{
	for (size_t i = 0; i < len; i++) {
		if (dst[i] == wildcard || src[i] == dst[i])
			continue;
		else
			return src[i] - dst[i];
	}

	return 0;
}

int test()
{
	//char buf[2] = { 0xbc, 0xa4 };
	//LPCBYTE buf2 = (LPCBYTE)buf;
	//printf("%02x %02x\n", buf2[0], buf2[1]);
	//return 0;
	/*LPCBYTE dest = (LPCBYTE )"#*F^e";
	size_t len = strlen((const char* )dest);
	LPCBYTE src = (LPCBYTE)"X5F^e123";
	if (1) {
		if (wildcard_memcmp((LPCBYTE)src, dest, len) == 0) {

			return 0;
		}
	}*/

	//printf("%d\n", wildcard_memcmp((LPCBYTE)"12345", (LPCBYTE)"12*", 3));

	//wchar_t buf[1024];
	//swprintf_s(buf, L"%ws", L"abc");
	//wprintf(buf);
	auto fp = fopen("log123.log", "a+");
	for (int i = 0; i < 1000; i++) {
		char buf[128];
		sprintf(buf, "abc %d\n", i);
		fwrite(buf, strlen(buf), 1, fp);
		fflush(fp);
		Sleep(1000);
	}
	fclose(fp);
	return 0;
}

#include <winsock2.h>
#include <iphlpapi.h>
#pragma comment(lib, "IPHLPAPI.lib")

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

int get_mac()
{
	/* Declare and initialize variables */

// It is possible for an adapter to have multiple
// IPv4 addresses, gateways, and secondary WINS servers
// assigned to the adapter. 
//
// Note that this sample code only prints out the 
// first entry for the IP address/mask, and gateway, and
// the primary and secondary WINS server for each adapter. 

	PIP_ADAPTER_INFO pAdapterInfo;
	PIP_ADAPTER_INFO pAdapter = NULL;
	DWORD dwRetVal = 0;
	UINT i;

	/* variables used to print DHCP time info */
	struct tm newtime;
	char buffer[32];
	errno_t error;

	ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
	pAdapterInfo = (IP_ADAPTER_INFO*)MALLOC(sizeof(IP_ADAPTER_INFO));
	if (pAdapterInfo == NULL) {
		printf("Error allocating memory needed to call GetAdaptersinfo\n");
		return 1;
	}
	// Make an initial call to GetAdaptersInfo to get
	// the necessary size into the ulOutBufLen variable
	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
		FREE(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO*)MALLOC(ulOutBufLen);
		if (pAdapterInfo == NULL) {
			printf("Error allocating memory needed to call GetAdaptersinfo\n");
			return 1;
		}
	}

	if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
		pAdapter = pAdapterInfo;
		while (pAdapter) {
			printf("\tComboIndex: \t%d\n", pAdapter->ComboIndex);
			printf("\tAdapter Name: \t%s\n", pAdapter->AdapterName);
			printf("\tAdapter Desc: \t%s\n", pAdapter->Description);
			printf("\tAdapter Addr: \t");
			for (i = 0; i < pAdapter->AddressLength; i++) {
				if (i == (pAdapter->AddressLength - 1))
					printf("%.2X\n", (int)pAdapter->Address[i]);
				else
					printf("%.2X-", (int)pAdapter->Address[i]);
			}
			printf("\tIndex: \t%d\n", pAdapter->Index);
			printf("\tType: \t");
			switch (pAdapter->Type) {
			case MIB_IF_TYPE_OTHER:
				printf("Other\n");
				break;
			case MIB_IF_TYPE_ETHERNET:
				printf("Ethernet\n");
				break;
			case MIB_IF_TYPE_TOKENRING:
				printf("Token Ring\n");
				break;
			case MIB_IF_TYPE_FDDI:
				printf("FDDI\n");
				break;
			case MIB_IF_TYPE_PPP:
				printf("PPP\n");
				break;
			case MIB_IF_TYPE_LOOPBACK:
				printf("Lookback\n");
				break;
			case MIB_IF_TYPE_SLIP:
				printf("Slip\n");
				break;
			default:
				printf("Unknown type %ld\n", pAdapter->Type);
				break;
			}

			printf("\tIP Address: \t%s\n",
				pAdapter->IpAddressList.IpAddress.String);
			printf("\tIP Mask: \t%s\n", pAdapter->IpAddressList.IpMask.String);

			printf("\tGateway: \t%s\n", pAdapter->GatewayList.IpAddress.String);
			printf("\t***\n");

			if (pAdapter->DhcpEnabled) {
				printf("\tDHCP Enabled: Yes\n");
				printf("\t  DHCP Server: \t%s\n",
					pAdapter->DhcpServer.IpAddress.String);

				printf("\t  Lease Obtained: ");
				/* Display local time */
				error = _localtime32_s(&newtime, (__time32_t*)&pAdapter->LeaseObtained);
				if (error)
					printf("Invalid Argument to _localtime32_s\n");
				else {
					// Convert to an ASCII representation 
					error = asctime_s(buffer, 32, &newtime);
					if (error)
						printf("Invalid Argument to asctime_s\n");
					else
						/* asctime_s returns the string terminated by \n\0 */
						printf("%s", buffer);
				}

				printf("\t  Lease Expires:  ");
				error = _localtime32_s(&newtime, (__time32_t*)&pAdapter->LeaseExpires);
				if (error)
					printf("Invalid Argument to _localtime32_s\n");
				else {
					// Convert to an ASCII representation 
					error = asctime_s(buffer, 32, &newtime);
					if (error)
						printf("Invalid Argument to asctime_s\n");
					else
						/* asctime_s returns the string terminated by \n\0 */
						printf("%s", buffer);
				}
			}
			else
				printf("\tDHCP Enabled: No\n");

			if (pAdapter->HaveWins) {
				printf("\tHave Wins: Yes\n");
				printf("\t  Primary Wins Server:    %s\n",
					pAdapter->PrimaryWinsServer.IpAddress.String);
				printf("\t  Secondary Wins Server:  %s\n",
					pAdapter->SecondaryWinsServer.IpAddress.String);
			}
			else
				printf("\tHave Wins: No\n");
			pAdapter = pAdapter->Next;
			printf("\n");
		}
		
		return 0;
	}
	else {
		printf("GetAdaptersInfo failed with error: %d\n", dwRetVal);

	}
	if (pAdapterInfo)
		FREE(pAdapterInfo);
	return 0;
}

int test2()
{
	unsigned char str[] = {
		0x55, 0xAA, 0x55, 0xAA, 0x39, 0x9C, 0x68, 0xBD, 0x01, 0x00,
		0x38, 0x00, 0x00, 0x00, 0x23, 0x65, 0x46, 0x61, 0x77, 0x4A,
		0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3D, 0x60, 0x3D, 0x68, 0x52,
		0x75, 0x52, 0x3D, 0x3D, 0x7B, 0x3D, 0x6C, 0x54, 0x5F, 0x41,
		0x62, 0x51, 0x4F, 0x55, 0x4E, 0x59, 0x72, 0x5D, 0x41, 0x59,
		0x60, 0x4D, 0x6E, 0x56, 0x51, 0x51, 0x6B, 0x48, 0x5F, 0x40,
		0x71, 0x47, 0x73, 0x59, 0x65, 0x4C, 0x4F, 0x70, 0x79, 0x21 };

	return sizeof(str);
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

int test3()
{
	unsigned char buf[] = { 0x1, 0x2, 0xaa, 0xbb };
	return printf(arrayToHexString(buf, 4).c_str());
}

void ReplaceSubstrings(std::string& str, const std::string& from, const std::string& to) {
	if (from.empty()) return; // 防止空子字符串导致的无限循环
	size_t start_pos = 0;
	while ((start_pos = str.find(from, start_pos)) != std::string::npos) {
		str.replace(start_pos, from.length(), to);
		start_pos += to.length(); // 从替换后的位置继续搜索
	}
}

int test5()
{
	std::string str = "abcabc\n12312\n";
	ReplaceSubstrings(str, "\n", "\\n");
	printf("%s\n", str.c_str());
	return 0;
}

int main(int argc, char* argv[])
{
	//return strlen(str);
	//return get_mac()
	//return test();

	if (argc > 1 && stricmp(argv[1], "remove") == 0)
		RemoveLSP();
	else
		InstallLSP();
	return 0;
}
