#include <Windows.h>
#include <winternl.h>

// Sandbox Evasion by Sleepy
// For educational use only, Im not responsible for your actions

typedef struct _MYPEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
        union {
        BYTE BitField;
        struct {
            BYTE ImageUsesLargePages : 1;
            BYTE IsProtectedProcess : 1;
            BYTE IsImageDynamicallyRelocated : 1;
            BYTE SkipPatchingUser32Forwarders : 1;
            BYTE IsPackagedProcess : 1;
            BYTE IsAppContainer : 1;
            BYTE IsProtectedProcessLight : 1;
            BYTE IsLongPathAwareProcess : 1;
        };
    };
    union {
    ULONG CrossProcessFlags;
    struct {
        ULONG ProcessInJob : 1;
        ULONG ProcessInitializing : 1;
        ULONG ProcessUsingVEH : 1;
        ULONG ProcessUsingVCH : 1;
        ULONG ProcessUsingFTH : 1;
        ULONG ReservedBits0 : 27;
    };
};
    PVOID Reserved3[2];
    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID Reserved4[3];
    PVOID AtlThunkSListPtr;
    PVOID Reserved5;
    ULONG Reserved6;
    PVOID Reserved7;
    ULONG Reserved8;
    ULONG AtlThunkSListPtr32;
    PVOID Reserved9[45];
    BYTE Reserved10[96];
    PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
    BYTE Reserved11[128];
    PVOID Reserved12[1];
    ULONG SessionId;
} MYPEB;

//struct
MYPEB peb;

typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
    HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

//Global
HANDLE hProcess;

//Function to get isAppContainer
BOOL swap() {
    HMODULE hNtDll = GetModuleHandle("ntdll.dll");
    if (!hNtDll) {
        printf("Failed to load ntdll.dll\n");
        return FALSE;
    }

    pNtQueryInformationProcess NtQueryInformationProcess =
        (pNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");
    if (!NtQueryInformationProcess) {
        printf("Failed to get NtQueryInformationProcess\n");
        return FALSE;
    }

    hProcess = GetCurrentProcess();

    PROCESS_BASIC_INFORMATION proc = {0};
    ULONG returnlen;
    NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &proc, sizeof(PROCESS_BASIC_INFORMATION), &returnlen);
    if (status != 0) {
        printf("NtQueryInformationProcess failed (Status 0x%08X)\n", status);
        return FALSE;
    }
   
    if (!ReadProcessMemory(hProcess, proc.PebBaseAddress, &peb, sizeof(peb), NULL)) return FALSE;

    printf("base: %p\n", proc.PebBaseAddress);
    printf("Container?: %lu\n", (DWORD)peb.IsAppContainer);

    if (peb.IsAppContainer == 1) {
        printf("Sandbox Detected\n");
    } else {
        printf("No sandbox detected\n");
    }

    return TRUE;
}

int main(int argc, char* argv[]) {

if (!swap()) {
    printf("Error %lu\n", GetLastError());
 } 

 return 0;

}
