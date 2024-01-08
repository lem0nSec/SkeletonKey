# SkeletonKey 💀
__Reproducing the Skeleton Key malware__

## Introduction
As part of an autonomous research I am carrying out on the Local Security Authority Subsystem Service, Skeleton Key is a 2015 piece of malware which has particularly intrigued me. Since ![Mimikatz](https://github.com/gentilkiwi/mimikatz) is the only tool I found which already covers the technique, I decided to reproduce the malware focusing on improving and adding new features.

## Usage
Injecting the Skeleton Key inside lsass.exe is as easy as launching SkeletonKey.exe and selecting the preferred Windows authentication type to be patched.

```
Usage: SkeletonKey.exe {mode}

Modes:
--KerbAuth      patch Kerberos authentication
--NtlmAuth      patch NTLM authentication
```

## What is Skeleton Key?
Skeleton Key is a malware which was found by the ![Dell SecureWorks Counter Threat Unit](https://www.secureworks.com/research/skeleton-key-malware-analysis) in 2015. This malware is an in-memory implant residing inside the lsass.exe process. It mainly tampers with the __Kerberos authentication__ mechanism by injecting a master password (skeleton key) in memory which can be used to authenticate as any user. The fun part is that the original password remains valid. To achieve this, the following steps are required:
- Downgrading algorithm from AES128/256 to RC4;
- Injecting custom handlers which validate the skeleton key against the typed password if the latter does not match the original password;
- Patching pointers to the original RC4 Initialize/Decrypt functions to be the new custom handlers.
More information about the inner working of the SkeletonKey malware can be found ![here](https://www.virusbulletin.com/uploads/pdf/magazine/2016/vb201601-skeleton-key.pdf).

## Differences with the Mimikatz's implementation?
The mimikatz's SkeletonKey version has been revisited and expanded with two major improvements. First, NTLM patching was added. For systems which are not Kerberos-enabled and use NTLM authentication, the Skeleton Key carries out the following steps:
- Injecting a custom handler to replicate the MsvpPasswordValidate function (ntlmshared.dll) in order to validate the skeleton key against the typed password if the latest does not match the original password;
- Patching the pointer to MsvpPasswordValidate inside the Import Address Table of msv1_0.dll to be a pointer to the custom handler;

![](pictures/ntlm_auth.png)

What happens is that lsass will call our custom MsvpPasswordValidate instead of the real version. The most relevant part of MsvpPasswordValidate is the following call to RtlCompareMemory, which indeed compares the hashed version of the password typed by the user with the hash inside the Security Account Manager (SAM) database. 

![](pictures/compare_memory.png)

The custom handler replaces the latter with the hash of the Skeleton Key.

![](pictures/compare.png)


Second, patching of Kerberos authentication does not follow the same pathway of the Mimikatz's implementation. In particular, the RC4 fallback is not triggered by zeroing out the LSA_UNICODE_STRING struct describing the string "kerberos-newer-keys". Rather, the value EncryptionType inside the single AES128 and AES256 packages (KERB_ECRYPT struct) are patched in order for both CDLocateCSystem and SamIRetrieveMultiplePrimaryCredentials to fail when trying to retrieve pointers to these packages. Consequently, the system is forced to rely on RC4 to proceed with the authentication phase.

