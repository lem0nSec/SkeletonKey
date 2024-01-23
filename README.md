# SkeletonKey 💀
__Reproducing the Skeleton Key malware__

## Introduction
Skeleton Key is a 2015 piece of malware which particularly intrigued me during an autonomous research I was carrying out. [Mimikatz](https://github.com/gentilkiwi/mimikatz) is the only tool I found which already covers the technique. Apart from this, searching on the Internet only shows technical descriptions of the malware inner workings but no standalone code is provided. This repository contains this code.

## Usage
Injecting the Skeleton Key into lsass.exe is as easy as launching SkeletonKey.exe and selecting the preferred Windows authentication type to be patched.

```
Usage: SkeletonKey.exe {mode}

Modes:
--KerbAuth      patch Kerberos authentication
--NtlmAuth      patch NTLM authentication
```

## What is Skeleton Key?
Skeleton Key is a malware which was found by the [Dell SecureWorks Counter Threat Unit](https://www.secureworks.com/research/skeleton-key-malware-analysis) in 2015. The malware is an in-memory implant residing inside the lsass.exe process. It mainly tampers with the __Kerberos authentication__ mechanism by injecting a master password (skeleton key) in memory which can be used to authenticate as any user. The fun part is that the original password remains valid. To achieve this, the following steps are required:
- Downgrading algorithm from AES128/256 to RC4;
- Injecting custom handlers which validate the skeleton key against the typed password if the latter does not match the original password;
- Patching pointers to the original RC4 Initialize/Decrypt functions to be the new custom handlers.
More information about the inner working of the SkeletonKey can be found [here](https://www.virusbulletin.com/uploads/pdf/magazine/2016/vb201601-skeleton-key.pdf).

## Differences with the Mimikatz's implementation?
The Mimikatz's SkeletonKey version has been revisited and expanded with two major improvements. First, NTLM patching was added. For systems which are not Kerberos-enabled and use NTLM authentication, the Skeleton Key carries out the following steps:
- Injecting a custom handler to replicate the MsvpPasswordValidate function (ntlmshared.dll) in order to validate the skeleton key against the typed password if the latter does not match the original password;
- Patching the pointer to MsvpPasswordValidate inside the Import Address Table of msv1_0.dll to be a pointer to the custom handler;

![](pictures/ntlm_auth.png)

What happens is that lsass will call our custom MsvpPasswordValidate instead of the real version. The most relevant part of MsvpPasswordValidate is the following call to RtlCompareMemory, which indeed compares the hashed version of the password typed by the user with the hash inside the Security Account Manager (SAM). 

![](pictures/compare_hashes.png)

The custom handler replaces the latter with the hash of the Skeleton Key.

![](pictures/compare.png)


Second, patching of Kerberos authentication does not follow the same pathway of the Mimikatz's implementation. In particular, the RC4 fallback is not triggered by zeroing out the LSA_UNICODE_STRING struct describing the string "kerberos-newer-keys". Rather, the value EncryptionType inside the single AES128 and AES256 packages (KERB_ECRYPT struct) are patched in order for both CDLocateCSystem and SamIRetrieveMultiplePrimaryCredentials to fail when trying to retrieve pointers to these packages. Consequently, the system is forced to rely on RC4 to proceed with the authentication phase. According to Mimikatz, a KERB_ECRYPT struct describes the encryption scheme characteristics, such as pointers to functions the algorithm relies on. 'Initialize' and 'Decrypt' are always called during authentication.


```c
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
```

Multiple KERB_ECRYPT structs exist sequentially, and each of them describes an authentication algorith such as AES or RC4. During authentication, the system tries to retrieve a pointer to the KERB_ECRYPT struct which describes the algorithm to be used. To do this, it performs a lookup of the first value EncryptionType. Since by default the system attemps to resolve the position of AES128 and AES256. The SkeletonKey edits EncryptionType of the AES128 and AES256 KERB_ECRYPT structs to be 0xff.

![](pictures/aes256_patched.png)

