#ifndef __DEBUG_H__
#define __DEBUG_H__

#include <stdio.h>
#include <string.h>

#define LOG_FILE 1
#define DEBUG_VIEW 1

#if LOG_FILE
extern FILE* g_logfp;
inline void WriteLog(const char* str)
{
	fwrite(str, strlen(str), 1, g_logfp);
	fflush(g_logfp);
#if DEBUG_VIEW
	OutputDebugStringA(str);
#endif
}

#else
#define WriteLog OutputDebugStringA
#endif

#ifdef _DEBUG
#define ODS(szOut)\
{\
	WriteLog(szOut);\
}

#define ODS1(szOut, var)\
{						\
	char sz[1024];		\
	sprintf_s(sz, szOut, var);\
	WriteLog(sz);\
}

#define TRACE(fmt, ...)	{ \
	char sz[1024];		\
	sprintf_s(sz, fmt, ##__VA_ARGS__); \
	WriteLog(sz);\
}

#else
#define ODS(szOut)
#define ODS1(szOut, var)
#define TRACE(fmt, ...)
#endif
#endif
