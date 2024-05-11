#ifndef __DEBUG_H__
#define __DEBUG_H__
#ifdef _DEBUG
#define ODS(szOut)\
{\
	OutputDebugStringW(szOut);\
}

#define ODS1(szOut, var)\
{						\
	TCHAR sz[1024];		\
	_stprintf_s(sz, szOut, var);\
	OutputDebugStringW(sz);\
}

#define TRACE(fmt, ...)	{ \
	TCHAR sz[1024];		\
	_stprintf_s(sz, fmt, ##__VA_ARGS__); \
	OutputDebugStringW(sz); \
}

#else
#define ODS(szOut)
#define ODS1(szOut, var)
#define TRACE(fmt, ...)
#endif
#endif
