# SkeletonKey 💀
__Reproducing the Skeleton Key malware__

## Introduction
As part of an autonomous research I am carrying out on the Local Security Authority Subsystem Service, Skeleton Key is a piece of malware which particularly intrigues me. That is why I decided to reproduce the inner workings of the malware, also improving and adding new features to the version proposed by ![Mimikatz](https://github.com/gentilkiwi/mimikatz).

## What is Skeleton Key?
Skeleton Key is malware which was found by the ![Dell SecureWorks Counter Threat Unit](https://www.secureworks.com/research/skeleton-key-malware-analysis) in 2015. This malware is an in-memory implant which resides inside the process lsass.exe, tampering Kerberos and NTLM authentication mechanisms by keeping a master password (skeleton key) in memory which can be used to authenticate as any user.