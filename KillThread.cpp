#include <stdio.h>
#include "KillThread.h"
#include "ZwQuerySystemInformation.h"
#include <Windows.h>
#include <tlhelp32.h>

typedef struct _THREAD_BASIC_INFORMATION { // Information Class 0

	LONG     ExitStatus;

	PVOID    TebBaseAddress;

	CLIENT_ID ClientId;

	LONG AffinityMask;

	LONG Priority;

	LONG BasePriority;

} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;
typedef enum _THREADINFOCLASS {

	ThreadBasicInformation,

	ThreadTimes,

	ThreadPriority,

	ThreadBasePriority,

	ThreadAffinityMask,

	ThreadImpersonationToken,

	ThreadDescriptorTableEntry,

	ThreadEnableAlignmentFaultFixup,

	ThreadEventPair_Reusable,

	ThreadQuerySetWin32StartAddress,

	ThreadZeroTlsCell,

	ThreadPerformanceCount,

	ThreadAmILastThread,

	ThreadIdealProcessor,

	ThreadPriorityBoost,

	ThreadSetTlsArrayAddress,

	ThreadIsIoPending,

	ThreadHideFromDebugger,

	ThreadBreakOnTermination,

	MaxThreadInfoClass

} THREADINFOCLASS;


extern "C" LONG(__stdcall *ZwQueryInformationThread) (

	IN HANDLE ThreadHandle,

	IN THREADINFOCLASS ThreadInformationClass,

	OUT PVOID ThreadInformation,

	IN ULONG ThreadInformationLength,

	OUT PULONG ReturnLength OPTIONAL

	) = NULL;

BOOL   ShowThreadInfo(DWORD   tid, char * out)
{

	THREAD_BASIC_INFORMATION         tbi;
	PVOID                                               startaddr;
	LONG                                                 status;
	HANDLE                                             thread, process;

	thread = ::OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
	if (thread == NULL)
		return   FALSE;

	status = ZwQueryInformationThread(thread,
		ThreadQuerySetWin32StartAddress,
		&startaddr,
		sizeof(startaddr),
		NULL);

	if (status   <   0)
	{
		CloseHandle(thread);
		return   FALSE;
	};

	//printf(("线程   %08x   的起始地址为   %p\n"),
	//	tid,
	//	startaddr);

	status = ZwQueryInformationThread(thread,
		ThreadBasicInformation,
		&tbi,
		sizeof(tbi),
		NULL);

	if (status   <   0)
	{
		CloseHandle(thread);
		return   FALSE;
	};

	process = ::OpenProcess(PROCESS_ALL_ACCESS,
		FALSE,
		(DWORD)tbi.ClientId.UniqueProcess);

	if (process == NULL)
	{
		DWORD   error = ::GetLastError();
		CloseHandle(thread);
		SetLastError(error);
		return   FALSE;
	};

	TCHAR   modname[0x100];
	::GetModuleFileNameEx(process, NULL, modname, 0x100);

	GetMappedFileName(process,
		startaddr,
		modname,
		0x100);
	char temp[500];
	int tt = WideCharToMultiByte(CP_ACP, 0, modname, -1, NULL, 0, NULL, NULL);
	//将tchar值赋给_char    
	WideCharToMultiByte(CP_ACP, 0, modname, -1, temp, tt, NULL, NULL);
	tt = 0;
	int i = 0;
	while (temp[i] != '\0') {
		if (temp[i] == '\\')tt = i + 1;
		i++;
	}
	for (i = 0; temp[tt + i] != '\0'; i++) {
		out[i] = temp[tt + i];
	}
	out[i] = '\0';

	//printf(("线程   %08x   可执行代码所在模块为   %s\n"),
	//	tid,out);
	//std::wcout << modname << "\n";

	CloseHandle(process);
	CloseHandle(thread);
	return   TRUE;
};


void KillThread()
{
	char killModel[] = "PlatFormSDK.dll";
	HINSTANCE   hNTDLL = ::GetModuleHandle(TEXT("ntdll"));

	(FARPROC&)ZwQueryInformationThread =
		::GetProcAddress(hNTDLL, "ZwQueryInformationThread");

	HANDLE        hThreadSnap = NULL;
	BOOL          bRet = FALSE;
	THREADENTRY32 te32 = { 0 };

	// Take a snapshot of all threads currently in the system.

	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == INVALID_HANDLE_VALUE)
		return;

	// Fill in the size of the structure before using it.

	te32.dwSize = sizeof(THREADENTRY32);
	char name[100];

	if (Thread32First(hThreadSnap, &te32))
	{
		do
		{
			//printf("\find TID=%d\tOwner PID=%d\n", te32.th32ThreadID, te32.th32OwnerProcessID);
			if (ShowThreadInfo(te32.th32ThreadID, name)) {
				if (strcmp(name, killModel) == 0) {
					HANDLE thread = ::OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
					printf("\nkill TID=%d\tOwner PID=%d\n", te32.th32ThreadID, te32.th32OwnerProcessID);
					TerminateThread(thread, 0);
					CloseHandle(thread);
				}
			}
		} while (Thread32Next(hThreadSnap, &te32));
		bRet = TRUE;
	}
	else
		bRet = FALSE;          // could not walk the list of threads

							   // Do not forget to clean up the snapshot object.

	CloseHandle(hThreadSnap);
	FreeLibrary(hNTDLL);
}
