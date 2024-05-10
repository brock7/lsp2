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
#else
#define ODS(szOut)
#define ODS1(szOut, var)
#endif
#endif
