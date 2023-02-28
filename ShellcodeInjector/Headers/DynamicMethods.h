#pragma once

#include<Windows.h>

typedef BOOL
(WINAPI
    * VirtualProtectT)(
        _In_  LPVOID lpAddress,
        _In_  SIZE_T dwSize,
        _In_  DWORD flNewProtect,
        _Out_ PDWORD lpflOldProtect
        );



typedef BOOL
(WINAPI
    * AddVectoredExceptionHandlerT)(
        _In_ ULONG First,
        _In_ PVECTORED_EXCEPTION_HANDLER Handler
        );



typedef BOOL
(WINAPI* CreateProcessAT)(
    _In_opt_ LPCSTR lpApplicationName,
    _Inout_opt_ LPSTR lpCommandLine,
    _In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
    _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
    _In_ BOOL bInheritHandles,
    _In_ DWORD dwCreationFlags,
    _In_opt_ LPVOID lpEnvironment,
    _In_opt_ LPCSTR lpCurrentDirectory,
    _In_ LPSTARTUPINFOA lpStartupInfo,
    _Out_ LPPROCESS_INFORMATION lpProcessInformation
    );



typedef BOOL(WINAPI* WriteProcessMemoryT)
(_In_ HANDLE hProcess,
    _In_ LPVOID lpBaseAddress,
    _In_reads_bytes_(nSize) LPCVOID lpBuffer,
    _In_ SIZE_T nSize,
    _Out_opt_ SIZE_T* lpNumberOfBytesWritten);





typedef BOOL(WINAPI* GetThreadContextT)
(_In_ HANDLE hThread,
    _Inout_ LPCONTEXT lpContext);



typedef DWORD(WINAPI* ResumeThreadT)
(_In_ HANDLE hThread);



typedef DWORD(WINAPI* QueueUserAPCT)(
    _In_ PAPCFUNC pfnAPC,
    _In_ HANDLE hThread,
    _In_ ULONG_PTR dwData
);