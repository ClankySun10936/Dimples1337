#pragma once
#include<Windows.h>
#include<WinInet.h>

#pragma comment(lib,"WinInet.lib")
char* HttpGet(const char* URL, const char* SubPath)
{
	HINTERNET hInternet, hConnect, hRequest = NULL;
	DWORD dwOpenRequestsFlags, dwRet = 0;
	unsigned char* pResponseHeaderIInfo = NULL;
	DWORD dwResponseHeaderIInfoSize = 2048;
	BYTE *pBuf = NULL;
	DWORD dwBufSize = 64 * 2048;
	hInternet = InternetOpenA("WinInetGet/0.1", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	hConnect = InternetConnectA(hInternet, URL, INTERNET_DEFAULT_HTTP_PORT, 0, 0, INTERNET_SERVICE_HTTP, 0, 0);
	if (hConnect == NULL) {
		return NULL;
	}
	dwOpenRequestsFlags = INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTP | INTERNET_FLAG_KEEP_CONNECTION | INTERNET_FLAG_NO_AUTH | INTERNET_FLAG_NO_COOKIES | INTERNET_FLAG_NO_UI | INTERNET_FLAG_RELOAD;
	hRequest = HttpOpenRequestA(hConnect, "GET", SubPath, NULL, NULL, NULL, dwOpenRequestsFlags, 0);
	HttpSendRequest(hRequest, NULL, 0, NULL, 0);
	pResponseHeaderIInfo = new unsigned char[dwResponseHeaderIInfoSize];
	RtlZeroMemory(pResponseHeaderIInfo, dwResponseHeaderIInfoSize);
	HttpQueryInfo(hRequest, HTTP_QUERY_RAW_HEADERS_CRLF, pResponseHeaderIInfo, &dwResponseHeaderIInfoSize, NULL);
	pBuf = new BYTE[dwBufSize];
	RtlZeroMemory(pBuf, dwBufSize);
	InternetReadFile(hRequest, pBuf, dwBufSize, &dwRet);
	return (char*)pBuf;
}

