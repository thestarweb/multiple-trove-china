#include "Start.h"
#include <Windows.h>
#include <stdio.h>

PROCESS_INFORMATION pi;
BOOL bStatus = false;
DWORD CreateIt() {
	STARTUPINFO si = { sizeof(si) };

	bStatus = CreateProcess(L"Trove", L"", NULL, NULL, FALSE, DETACHED_PROCESS| CREATE_SUSPENDED, NULL, NULL, &si, &pi);
	if (bStatus) {
		printf("Create whith pid=%d\n", pi.dwProcessId);
		return pi.dwProcessId;
	}
	else
	{
		printf("Fail To Create\n");
		return 0;
	}
}
void RunIt() {
	if (bStatus) {
		printf("Start tid=%d pid=%d\n", pi.dwThreadId, pi.dwProcessId);
		ResumeThread(pi.hThread);
	}
}