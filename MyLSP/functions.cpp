#include "MyLSP.h"
#include "debug.h"
#include "utils.h"

//DWORD GetInformation()
//{
//	HKEY hKey = 0;
//	DWORD Count = 0, keyType = REG_SZ, i, j, k;
//	DWORD len = sizeof(DWORD);
//	char lpName[30], lpValue[30];
//	DWORD lpNameLen, lpValueLen;
//
//	char ipName[30], ipValue[30];
//	unsigned short portName, portValue;
//
//	lpNameLen = sizeof(lpName);
//	lpValueLen = sizeof(lpValue);
//
//	lanjie = 0;
//
//	if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,"SYSTEM\\CurrentControlSet\\Control\\LSPManager",0, KEY_ALL_ACCESS, &hKey)!= ERROR_SUCCESS)
//	{
//		return 0;
//	}
//	RegQueryValueExA(hKey, "NumberOfRules", 0, &keyType, (BYTE*)&Count, &len);
//	if (Count == 0)
//	{
//		RegCloseKey(hKey);
//		return 0;
//	}
//	for (i=0; i<=Count; i++)
//	{
//		memset(lpName, 0, sizeof(lpName));
//		memset(lpValue,0, sizeof(lpValue));
//		memset(ipName,0, sizeof(ipName));
//		memset(ipValue,0, sizeof(ipValue));
//		lpNameLen = sizeof(lpName);
//		lpValueLen = sizeof(lpValue);
//		portName = portValue = 0;
//		RegEnumValueA(hKey, i, lpName, &lpNameLen, NULL, &keyType, (unsigned char*)lpValue, &lpValueLen);
//		if (strcmp(lpName, "NumberOfRules") == 0) continue;
//		k = 0;
//		for (j=0; lpName[j]!=':'; j++)
//		{
//			ipName[k++] = lpName[j];
//		}
//		j++;
//		k=0;
//		for (j; j<strlen(lpName); j++)
//		{
//			if (lpName[j] == '*')
//			{
//				portName = 0;
//				break;
//			}
//			portName = portName*10 + lpName[j] - '0';
//		}
//
//		k = 0;
//		for (j=0; lpValue[j]!=':'; j++)
//		{
//			ipValue[k++] = lpValue[j];
//		}
//		j++;
//		k=0;
//		for (j; j<strlen(lpValue); j++)
//		{
//			portValue = portValue*10 + lpValue[j] - '0';
//		}
//		if (strlen(ipName) <=5 )
//		{
//			if (portName == 0 ||  nowPort == portName)
//			{
//				lanjie = 1;
//				ChangedPort = portValue;
//				strcpy_s(ChangedIP, ipValue);
//			} else
//			{
//				lanjie = 0;
//			}
//		} else
//		{
//			if (strcmp(ipName, NowIP) == 0)
//			{
//				if (portName == 0 ||  nowPort == portName)
//				{
//					lanjie = 1;
//					ChangedPort = portValue;
//					strcpy_s(ChangedIP, ipValue);
//				} else
//				{
//					lanjie = 0;
//				}
//			} else
//			{
//				lanjie = 0;
//			}
//		}
//		if (lanjie) break;
//	}
//	RegCloseKey(hKey);
//	return 0;
//}

SOCKET
WSPAPI  WSPAccept(
	SOCKET s,
	struct sockaddr FAR * addr,
	LPINT addrlen,
	LPCONDITIONPROC lpfnCondition,
	DWORD_PTR dwCallbackData,
	LPINT lpErrno )
{
	//sockaddr_in *ConnectAddress = (sockaddr_in*)addr;
	// ODS(L"WSPAccept() Enter!");
	return g_NextProcTable.lpWSPAccept(s, addr, addrlen, lpfnCondition, dwCallbackData, lpErrno);
}

INT
WSPAPI WSPAddressToString(
						  LPSOCKADDR lpsaAddress,
						  DWORD dwAddressLength,
						  LPWSAPROTOCOL_INFOW lpProtocolInfo,
						  LPWSTR lpszAddressString,
						  LPDWORD lpdwAddressStringLength,
						  LPINT lpErrno
						  )
{
	// ODS(L"WSPAddressToString() Enter!");
	return g_NextProcTable.lpWSPAddressToString(lpsaAddress,
		dwAddressLength,
		lpProtocolInfo,
		lpszAddressString,
		lpdwAddressStringLength,
		lpErrno);
}

int
WSPAPI WSPAsyncSelect(
					  SOCKET s,
					  HWND hWnd,
					  unsigned int wMsg,
					  long lEvent,
					  LPINT lpErrno
					  )
{
	// ODS(L"WSPAsyncSelect() Enter!");
	return g_NextProcTable.lpWSPAsyncSelect(
		s,
		hWnd,
		wMsg,
		lEvent,
		lpErrno);
}

int
WSPAPI WSPBind(
			   SOCKET s,
			   const struct sockaddr FAR * name,
			   int namelen,
			   LPINT lpErrno
			   )
{
	// ODS(L"WSPBind() Enter!");
	//sockaddr_in *ConnectAddress = (sockaddr_in*)name;
	return g_NextProcTable.lpWSPBind(s, name, namelen, lpErrno);
}

int
WSPAPI WSPCancelBlockingCall(
							 LPINT lpErrno
							 )
{
	// ODS(L"WSPCancelBlockingCall() Enter!");
	return g_NextProcTable.lpWSPCancelBlockingCall(
		lpErrno);
}


int
WSPAPI WSPCleanup(
				  LPINT lpErrno
				  )
{
	// ODS(L"WSPCleanup() Enter!");
	return g_NextProcTable.lpWSPCleanup(
		lpErrno);
}

int
WSPAPI WSPCloseSocket(
					  SOCKET s,
					  LPINT lpErrno
					  )
{
	// ODS(L"WSPCloseSocket() Enter!");
	return g_NextProcTable.lpWSPCloseSocket(s, lpErrno);
}

int
WSPAPI WSPConnect(
				  SOCKET s,
				  const struct sockaddr FAR * name,
				  int namelen,
				  LPWSABUF lpCallerData,
				  LPWSABUF lpCalleeData,
				  LPQOS lpSQOS,
				  LPQOS lpGQOS,
				  LPINT lpErrno
				  )
{
	// ODS(L"WSPConnect() Enter!");
	/*WCHAR temp[1024];
	sockaddr_in *ConnectAddress = (sockaddr_in*)name;
	// ODS(L"WSPConnect() Enter!");
	_stprintf_s(temp, L"Connect to  %s:%d\n", inet_ntoa(ConnectAddress->sin_addr), ntohs(ConnectAddress->sin_port));
	// ODS(temp);

	strcpy_s(NowIP,inet_ntoa(ConnectAddress->sin_addr));
	nowPort = ntohs(ConnectAddress->sin_port);
	GetInformation();

	// ODS(L"After GetInformation!\n")
	if (lanjie == 0)
	{
		return g_NextProcTable.lpWSPConnect(s,
			name,
			namelen,
			lpCallerData,
			lpCalleeData,
			lpSQOS,
			lpGQOS,
			lpErrno);
	}
	// ODS(L"lanjie begin");
	((sockaddr_in*)name)->sin_addr.S_un.S_addr = inet_addr(ChangedIP);
	((sockaddr_in*)name)->sin_port = htons(ChangedPort);
	_stprintf_s(temp, L"After change!Connect to  %s:%d\n", inet_ntoa(((sockaddr_in*)name)->sin_addr), ntohs(ConnectAddress->sin_port));
	// ODS(temp);*/
	return g_NextProcTable.lpWSPConnect(s,
		name,
		namelen,
		lpCallerData,
		lpCalleeData,
		lpSQOS,
		lpGQOS,
		lpErrno);
}

int
WSPAPI WSPDuplicateSocket(
						  SOCKET s,
						  DWORD dwProcessId,
						  LPWSAPROTOCOL_INFOW lpProtocolInfo,
						  LPINT lpErrno
						  )
{
	// ODS(L"WSPDuplicateSocket() Enter!");
	return g_NextProcTable.lpWSPDuplicateSocket(
		s,
		dwProcessId,
		lpProtocolInfo,
		lpErrno);
}

int
WSPAPI WSPEnumNetworkEvents(
							SOCKET s,
							WSAEVENT hEventObject,
							LPWSANETWORKEVENTS lpNetworkEvents,
							LPINT lpErrno
							)
{
	// ODS(L"WSPEnumNetworkEvents() Enter!");
	return g_NextProcTable.lpWSPEnumNetworkEvents(
		s,
		hEventObject,
		lpNetworkEvents,
		lpErrno);
}

int
WSPAPI WSPEventSelect(
					  SOCKET s,
					  WSAEVENT hEventObject,
					  long lNetworkEvents,
					  LPINT lpErrno
					  )
{
	// ODS(L"WSPEventSelect() Enter!");
	return g_NextProcTable.lpWSPEventSelect(
		s,
		hEventObject,
		lNetworkEvents,
		lpErrno);
}

BOOL
WSPAPI WSPGetOverlappedResult(
							  SOCKET s,
							  LPWSAOVERLAPPED lpOverlapped,
							  LPDWORD lpcbTransfer,
							  BOOL fWait,
							  LPDWORD lpdwFlags,
							  LPINT lpErrno
							  )
{
	// ODS(L"WSPGetOverlappedResult() Enter!");

	return g_NextProcTable.lpWSPGetOverlappedResult(
		s,
		lpOverlapped,
		lpcbTransfer,
		fWait,
		lpdwFlags,
		lpErrno);
}

int
WSPAPI WSPGetPeerName(
					  SOCKET s,
struct sockaddr FAR * name,
	LPINT namelen,
	LPINT lpErrno
	)
{
	// ODS(L"WSPGetPeerName() Enter!");

	return g_NextProcTable.lpWSPGetPeerName(
		s,
		name,
		namelen,
		lpErrno);
}

int
WSPAPI WSPGetSockName(
					  SOCKET s,
struct sockaddr FAR * name,
	LPINT namelen,
	LPINT lpErrno
	)
{
	// ODS(L"WSPGetSockName() Enter!");
	return g_NextProcTable.lpWSPGetSockName(
		s,
		name,
		namelen,
		lpErrno);
}

int
WSPAPI WSPGetSockOpt(
					 SOCKET s,
					 int level,
					 int optname,
					 char FAR * optval,
					 LPINT optlen,
					 LPINT lpErrno
					 )
{
	// ODS(L"WSPGetSockOpt() Enter!");
	return g_NextProcTable.lpWSPGetSockOpt(
		s,
		level,
		optname,
		optval,
		optlen,
		lpErrno
		);
}

BOOL
WSPAPI WSPGetQOSByName(
					   SOCKET s,
					   LPWSABUF lpQOSName,
					   LPQOS lpQOS,
					   LPINT lpErrno
					   )
{
	// ODS(L"WSPGetQOSByName() Enter!");
	return g_NextProcTable.lpWSPGetQOSByName(
		s,
		lpQOSName,
		lpQOS,
		lpErrno);
}

int
WSPAPI WSPIoctl(
				SOCKET s,
				DWORD dwIoControlCode,
				LPVOID lpvInBuffer,
				DWORD cbInBuffer,
				LPVOID lpvOutBuffer,
				DWORD cbOutBuffer,
				LPDWORD lpcbBytesReturned,
				LPWSAOVERLAPPED lpOverlapped,
				LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,
				LPWSATHREADID lpThreadId,
				LPINT lpErrno
				)
{
	// ODS(L"WSPIoctl Called!\n");
	return g_NextProcTable.lpWSPIoctl(
		s,
		dwIoControlCode,
		lpvInBuffer,
		cbInBuffer,
		lpvOutBuffer,
		cbOutBuffer,
		lpcbBytesReturned,
		lpOverlapped,
		lpCompletionRoutine,
		lpThreadId,
		lpErrno);
}

SOCKET
WSPAPI WSPJoinLeaf(
				   SOCKET s,
				   const struct sockaddr FAR * name,
				   int namelen,
				   LPWSABUF lpCallerData,
				   LPWSABUF lpCalleeData,
				   LPQOS lpSQOS,
				   LPQOS lpGQOS,
				   DWORD dwFlags,
				   LPINT lpErrno
				   )
{
	// ODS(L"WSPJoinLeaf CALLED\n");
	return g_NextProcTable.lpWSPJoinLeaf(
		s,
		name,
		namelen,
		lpCallerData,
		lpCalleeData,
		lpSQOS,
		lpGQOS,
		dwFlags,
		lpErrno);
}

int
WSPAPI WSPListen(
				 SOCKET s,
				 int backlog,
				 LPINT lpErrno
				 )
{
	// ODS(L"WSPListen() Enter!\n");
	return g_NextProcTable.lpWSPListen(
		s,
		backlog,
		lpErrno);
}

int g_step = 0;

int BeforeRecvFilter(SOCKET s,
	LPWSABUF lpBuffers,
	DWORD dwBufferCount,
	LPDWORD lpNumberOfBytesRecvd,
	LPDWORD lpFlags,
	LPWSAOVERLAPPED lpOverlapped,
	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,
	LPWSATHREADID lpThreadId,
	LPINT lpErrno, 
	LPBOOL lpCont)
{
	return NO_ERROR;
}

int AfterRecvFilter(SOCKET s,
	LPWSABUF lpBuffers,
	DWORD dwBufferCount,
	LPDWORD lpNumberOfBytesRecvd,
	LPDWORD lpFlags,
	LPWSAOVERLAPPED lpOverlapped,
	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,
	LPWSATHREADID lpThreadId,
	LPINT lpErrno, 
	int iNextRetutn)
{
	auto str = arrayToHexString((LPBYTE)lpBuffers->buf, min(lpBuffers->len, 32));
	TRACE("AfterRecvFilter(): lpBuffers->buf = [%s]{%s}\n", std::string(lpBuffers->buf, 32).c_str(), str.c_str());
	return iNextRetutn;

	unsigned char fake_pkt[] = {
		0x55, 0xaa, 0x55, 0xaa, 0x39, 0x9c, 0x68, 0xbd, 0x01, 0x00, 0x38, 0x00, 0x00, 0x00, 0x23, 0x65,
		0x46, 0x61, 0x77, 0x4a, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x3d, 0x60, 0x3d, 0x68, 0x52, 0x75, 0x52,
		0x3d, 0x3d, 0x7b, 0x3d, 0x6c, 0x54, 0x5f, 0x41, 0x62, 0x51, 0x4f, 0x55, 0x4e, 0x59, 0x72, 0x5d,
		0x41, 0x59, 0x60, 0x4d, 0x6e, 0x56, 0x51, 0x51, 0x6b, 0x48, 0x5f, 0x40, 0x71, 0x47, 0x73, 0x59,
		0x65, 0x4c, 0x4f, 0x70, 0x79, 0x21
	};

	if (dwBufferCount == 1) {
		

		//RecvTest(lpBuffers, lpNumberOfBytesRecvd);

		//if (g_step == 1) { // 初步来看, 包是修改了, 但是可能修改的包不对

		//	unsigned char tbuf[33];
		//	LPCBYTE buf = (LPCBYTE)lpBuffers->buf;
		//	memcpy(tbuf, buf, min(lpBuffers->len, sizeof(tbuf) - 1));
		//	tbuf[sizeof(tbuf) - 1] = 0;
		//	auto str = arrayToHexString(tbuf, sizeof(tbuf));
		//	// TRACE("WSPSend(): Buf = %02x,%02x,%02x,%02x,%02x\n", buf[0], buf[1], buf[2], buf[3], buf[4]);
		//	TRACE("WSPRecv(): BufLen = %d, Buf = %s\n", lpBuffers->len, str.c_str());
		//	TRACE("WSPRecv() Replaced!!!!!\n");

		//	memcpy(lpBuffers->buf, fake_pkt, sizeof(fake_pkt));
		//	g_step = 0;
		//	//if (lpErrno)
		//	//	*lpErrno = NO_ERROR;
		//	//return NO_ERROR;
		//}
	}

	return iNextRetutn;
}

int
WSPAPI WSPRecv(
			   SOCKET s,
			   LPWSABUF lpBuffers,
			   DWORD dwBufferCount,
			   LPDWORD lpNumberOfBytesRecvd,
			   LPDWORD lpFlags,
			   LPWSAOVERLAPPED lpOverlapped,
			   LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,
			   LPWSATHREADID lpThreadId,
			   LPINT lpErrno
			   )
{
	TRACE("WSPRecv() Enter! dwBufferCount = %d, lpBuffers->len = %d, lpOverlapped = %p, lpCompletionRoutine = %p, Errno = %d\n", 
		dwBufferCount, lpBuffers->len, lpOverlapped, lpCompletionRoutine, *lpErrno);
	
	BOOL cont = TRUE;
	auto result = BeforeRecvFilter(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped,
		lpCompletionRoutine, lpThreadId, lpErrno, &cont);
	if (!cont)
		return result;

	result = g_NextProcTable.lpWSPRecv(
		s,
		lpBuffers,
		dwBufferCount,
		lpNumberOfBytesRecvd,
		lpFlags,
		lpOverlapped,
		lpCompletionRoutine,
		lpThreadId,
		lpErrno);

	TRACE("WSPRecv(): After Next WSPRecv. lpBuffers->len = %d, lpNumberOfBytesRecvd = %d\n",
		lpBuffers->len, *lpNumberOfBytesRecvd);

	result = AfterRecvFilter(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped,
		lpCompletionRoutine, lpThreadId, lpErrno, result);

	TRACE("WSPRecv() Leave(%x)\n", result);
	return result;
}

int
WSPAPI WSPRecvDisconnect(
						 SOCKET s,
						 LPWSABUF lpInboundDisconnectData,
						 LPINT lpErrno
						 )
{
	// ODS(L"WSPRecvDisconnect() Enter!\n");
	return g_NextProcTable.lpWSPRecvDisconnect(s, lpInboundDisconnectData, lpErrno);
}

int
WSPAPI WSPRecvFrom(
	SOCKET s,
	LPWSABUF lpBuffers,
	DWORD dwBufferCount,
	LPDWORD lpNumberOfBytesRecvd,
	LPDWORD lpFlags,
	struct sockaddr FAR * lpFrom,
	LPINT lpFromlen,
	LPWSAOVERLAPPED lpOverlapped,
	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,
	LPWSATHREADID lpThreadId,
	LPINT lpErrno
	)
{
	// ODS(L"WSPRecvFrom() Enter!\n");
	/*WCHAR temp[1024];
	char *ip = inet_ntoa(((SOCKADDR_IN*)lpFrom)->sin_addr);
	USHORT port = ntohs(((SOCKADDR_IN*)lpFrom)->sin_port);
	_stprintf_s(temp, L"IP is %s, PORT is %d\n", ip, port);*/
	//// ODS(temp);
	return g_NextProcTable.lpWSPRecvFrom(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags,
		lpFrom, lpFromlen, lpOverlapped, lpCompletionRoutine, lpThreadId, lpErrno);
}

int
WSPAPI WSPSelect(
				 int nfds,
				 fd_set FAR * readfds,
				 fd_set FAR * writefds,
				 fd_set FAR * exceptfds,
				 const struct timeval FAR * timeout,
				 LPINT lpErrno
				 )
{
	// ODS(L"WSPSelect() Enter!\n");
	return g_NextProcTable.lpWSPSelect(nfds, readfds, writefds,
		exceptfds, timeout, lpErrno);
}

int
WSPAPI BeforeSendFilter(
	SOCKET s,
	LPWSABUF lpBuffers,
	DWORD dwBufferCount,
	LPDWORD lpNumberOfBytesSent,
	DWORD dwFlags,
	LPWSAOVERLAPPED lpOverlapped,
	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,
	LPWSATHREADID lpThreadId,
	LPINT lpErrno,
	LPBOOL lpCont
)
{
	auto str = arrayToHexString((LPBYTE)lpBuffers->buf, min(lpBuffers->len, 32));
	TRACE("BeforeSendFilter(): lpBuffers->buf = [%s]{%s}\n", std::string(lpBuffers->buf, 32).c_str(), str.c_str());
	return NO_ERROR;

	//LPCBYTE desthead = (LPCBYTE )"#*F^e";
	/*LPCBYTE desthead = (LPCBYTE)"#*<<L<<l<<<<<z";
	size_t headlen = strlen((const char*)desthead);
	LPCBYTE dest = (LPCBYTE)"<<L<<l<<<<<z<>LQ<<<??<UA]MYoQqOsMgMbALV_LgPBmKU_XgGnhmWpi@ToAbM?aEZbMlMsQvUoMmM?MfWraLHBIDROAGU^ijQqarZO<gXoYKMBakPBaKVP`kPcY`VaQoQRqILs]>TcU`XcHpOpicFp`rNRduN@DnOaIiYni>LPydNPE>YSecICA@IBekVQ<lTp]UHPdpGoQqYBaAZa=JIpy@VRyLVQTpPCQhXrQHIoAcJQejR_MKWsUjLrXpHptmGrqFVPuCUbmkOaQ>U?IFXBmiROaINpMfToITFqaiNO=VFqYcIo]AZC\\nQCU@ZA]sWpyJZbMbIRaUVaEjIRA@Xp]fLqatQBATUrE?UoLoO_@kWPeeO`YbWByKRa]]W`QVNpHoW`qGMBe_Hq\\gTQAROAatLRuMPS]jO_=KJPErY_MfUop!";
	size_t destlen = strlen((const char*)dest);*/

	if (dwBufferCount == 1) {

		if (lpBuffers->len == 1 && lpBuffers->buf[0] == '*') {
			lpCont = FALSE;
			return NO_ERROR;
		}
		//if (lpBuffers->len >= destlen + 2) {

		//	// TRACE("WSPSend(): Buf = %02x,%02x,%02x,%02x,%02x\n", buf[0], buf[1], buf[2], buf[3], buf[4]);
		//	if (wildcard_memcmp((LPCBYTE)lpBuffers->buf, desthead, headlen) == 0) {

		//		memcpy(lpBuffers->buf + 2, dest, destlen);
		//		if (g_step == 0)
		//			g_step += 1;
		//		// "U\xaaU\xaa9\x9ch\xbd\x01\x008\x00\x00\x00#eFawJ<<<<<=`=hRuR=={=lT_AbQOUNYr]AY`MnVQQkH_@qGsYeLOpy!"
		//		// "U\xaaU\xaa\xbadW\xb3\x01\x008\x00\x00\x00#O]qvg[{{{{y`=\RRkwdrnLVBQLQbUKPBPsPNynVQakR`q@QoQNUopy!"
		//		TRACE("WSPSend(): discard!!!!!!!!!!!!!!!!!!!!\n");
		//		//TRACE("WSPSend(): Leave \n");
		//		//if (lpNumberOfBytesSent)
		//		//	*lpNumberOfBytesSent = lpBuffers->len;
		//		//if (lpErrno)
		//		//	*lpErrno = NO_ERROR;
		//		//return NO_ERROR;
		//	}
		//}
	}

	return NO_ERROR;
}

int
WSPAPI AfterSendFilter(
	SOCKET s,
	LPWSABUF lpBuffers,
	DWORD dwBufferCount,
	LPDWORD lpNumberOfBytesSent,
	DWORD dwFlags,
	LPWSAOVERLAPPED lpOverlapped,
	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,
	LPWSATHREADID lpThreadId,
	LPINT lpErrno,
	int nResult
)
{
	return nResult;
}

// TODO: 修改发送接收函数, 打印出精准可比较的LOG
// 从LOG输入来看, 可能同时进入, 所以必须支持多线程
int
WSPAPI WSPSend(
			   SOCKET s,
			   LPWSABUF lpBuffers,
			   DWORD dwBufferCount,
			   LPDWORD lpNumberOfBytesSent,
			   DWORD dwFlags,
			   LPWSAOVERLAPPED lpOverlapped,
			   LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,
			   LPWSATHREADID lpThreadId,
			   LPINT lpErrno
			   )
{
	TRACE("WSPSend() Enter! dwBufferCount = %d, lpBuffers->len = %d, lpOverlapped = %p, lpCompletionRoutine = %p, Errno = %d\n",
		dwBufferCount, lpBuffers->len, lpOverlapped, lpCompletionRoutine, *lpErrno);
	BOOL cont = TRUE;

	auto result = BeforeSendFilter(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, 
		lpOverlapped, lpCompletionRoutine, lpThreadId, lpErrno, &cont);
	if (!cont)
		return result;

	result = g_NextProcTable.lpWSPSend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent,
		dwFlags, lpOverlapped, lpCompletionRoutine, lpThreadId, lpErrno);

	result = AfterSendFilter(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags,
		lpOverlapped, lpCompletionRoutine, lpThreadId, lpErrno, result);

	TRACE("WSPSend(): Leave(%x)\n", result);
	return result;
}

int
WSPAPI WSPSendDisconnect(
						 SOCKET s,
						 LPWSABUF lpOutboundDisconnectData,
						 LPINT lpErrno
						 )
{
	// ODS(L"WSPSendDisconnect() Enter!\n");
	return g_NextProcTable.lpWSPSendDisconnect(s, lpOutboundDisconnectData, lpErrno);
}

int WSPAPI WSPSendTo(
		SOCKET    s,
		LPWSABUF   lpBuffers,
		DWORD    dwBufferCount,
		LPDWORD    lpNumberOfBytesSent,
		DWORD    dwFlags,
		const struct sockaddr FAR * lpTo,
		int     iTolen,
		LPWSAOVERLAPPED lpOverlapped,
		LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,
		LPWSATHREADID lpThreadId,
		LPINT    lpErrno )
{
	// ODS(L"SendTo() Enter\n");
	/*sockaddr_in *sa = (sockaddr_in *)lpTo;
	strcpy_s(NowIP,inet_ntoa(sa->sin_addr));
	nowPort = ntohs(sa->sin_port);
	GetInformation();
	if (!lanjie)
	{
		return g_NextProcTable.lpWSPSendTo(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpTo,
			iTolen, lpOverlapped, lpCompletionRoutine, lpThreadId, lpErrno);
	}
	((sockaddr_in*)lpTo)->sin_addr.S_un.S_addr = inet_addr(ChangedIP);
	((sockaddr_in*)lpTo)->sin_port = htons(ChangedPort);*/
	return g_NextProcTable.lpWSPSendTo(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpTo,
		iTolen, lpOverlapped, lpCompletionRoutine, lpThreadId, lpErrno);
}

int
WSPAPI WSPSetSockOpt(
					 SOCKET s,
					 int level,
					 int optname,
					 const char FAR * optval,
					 int optlen,
					 LPINT lpErrno
					 )
{
	// ODS(L"WSPSetSockOpt() Enter\n");
	return g_NextProcTable.lpWSPSetSockOpt(s, level, optname, optval, optlen, lpErrno);
}

int
WSPAPI WSPShutdown(
				   SOCKET s,
				   int how,
				   LPINT lpErrno
				   )
{
	// ODS(L"WSPSetSockOpt Enter\n");
	return g_NextProcTable.lpWSPShutdown(s, how, lpErrno);
}

SOCKET
WSPAPI WSPSocket(
				 int af,
				 int type,
				 int protocol,
				 LPWSAPROTOCOL_INFOW lpProtocolInfo,
				 GROUP g,
				 DWORD dwFlags,
				 LPINT lpErrno
				 )
{
	// ODS(L"WSPSocket(): Enter");
	//// ODS1(L"WSPSocket(): Enter. g_NextProcTable = %p\n", &g_NextProcTable);
	//// ODS1(L"WSPSocket(): g_NextProcTable.lpWSPSocket = %p\n", g_NextProcTable.lpWSPSocket);
	auto result = g_NextProcTable.lpWSPSocket(af, type, protocol,
		lpProtocolInfo, g, dwFlags, lpErrno);
	// ODS(L"WSPSocket() Leave");
	return result;
}

INT
WSPAPI WSPStringToAddress(
						  LPWSTR AddressString,
						  INT AddressFamily,
						  LPWSAPROTOCOL_INFOW lpProtocolInfo,
						  LPSOCKADDR lpAddress,
						  LPINT lpAddressLength,
						  LPINT lpErrno
						  )
{
	// ODS(L"WSPStringToAddress() Enter");
	return g_NextProcTable.lpWSPStringToAddress(AddressString, AddressFamily, 
		lpProtocolInfo, lpAddress, lpAddressLength, lpErrno);
}
