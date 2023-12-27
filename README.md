# SkeletonKey 💀
__Reproducing the Skeleton Key malware__

## Introduction
As part of an autonomous research I am carrying out on the Local Security Authority Subsystem Service, Skeleton Key is a 2015 piece of malware which has particularly intrigued me. Since ![Mimikatz](https://github.com/gentilkiwi/mimikatz) is the only tool I found which already covers the technique, I decided to reproduce the malware focusing on improving and adding new features.

## What is Skeleton Key?
Skeleton Key is a malware which was found by the ![Dell SecureWorks Counter Threat Unit](https://www.secureworks.com/research/skeleton-key-malware-analysis) in 2015. This malware is an in-memory implant residing inside the lsass.exe process. It mainly tampers the __Kerberos authentication__ mechanism by injecting a master password (skeleton key) in memory which can be used to authenticate as any user. To do this, the following steps are required:
- Downgrading algorithm from AES128/256 to RC4;
- Injecting custom handlers which validate the skeleton key against the typed password if the latest does not match the original password;
- Patching pointers to the original RC4 Initialize/Decrypt functions to be new the custom handlers.
More information about the inner working of the SkeletonKey malware can be found ![here](https://www.virusbulletin.com/uploads/pdf/magazine/2016/vb201601-skeleton-key.pdf).

## Differences with the Mimikatz's implementation?
Mimikatz's SkeletonKey version has been revisited and expanded with two major improvements. First, NTLM patching was added. For systems which are not Kerberos-enabled and use NTLM authentication, the Skeleton Key carries out the following steps:
- Injecting a custom handler to replicate the MsvpPasswordValidate function (msv1_0.dll) in order to validate the skeleton key against the typed password if the latest does not match the original password;
- Patching the pointer to MsvpPasswordValidate inside the Import Address Tabled to be a pointer to the custom handler;

Second, patching of Kerberos authentication does not follow the same pathway of the Mimikatz's implementation. In particular, the RC4 fallback is not triggered by zeroing out the LSA_UNICODE_STRING struct describing the string "kerberos-newer-keys". Rather, the value EncryptionType inside the single AES128 and AES256 packages (KERB_ECRYPT struct) are patched in order for both CDLocateCSystem and SamIRetrieveMultiplePrimaryCredentials to fail when trying to retrieve pointers to these packages. Consequently, the system is forced to rely on RC4 to proceed with the authentication phase.