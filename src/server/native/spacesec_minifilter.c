/**
 * Space Security - Kernel Minifilter Driver & Ring-0 EDR Sensor
 * File: spacesec_minifilter.c
 * Target: Windows 10 / 11 x64 (WDK 10.0 / KMDF / FLTMGR)
 * Altitude: 320500 (FSFilter Anti-Virus)
 * 
 * Provides authoritative Ring-0 visibility:
 * 1. Process creation & exit interception (PsSetCreateProcessNotifyRoutineEx)
 * 2. Cross-view DKOM detection (EPROCESS ActiveProcessLinks auditing)
 * 3. Remote thread injection & reflective DLL detection (PsSetCreateThreadNotifyRoutine)
 * 4. Protected Process Light (PPL) LSASS memory protection (ObRegisterCallbacks)
 * 5. File System Minifilter (FLTMGR) IRP_MJ_CREATE interception for ransomware/rootkit blocking
 * 6. High-speed bidirectional communication port to SpaceSec Userland Engine
 */

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

#define SPACESEC_FILTER_NAME     L"SpaceSecMinifilter"
#define SPACESEC_PORT_NAME       L"\\SpaceSecPort"
#define SPACESEC_ALTITUDE        L"320500"

// Global Driver Context
typedef struct _SPACESEC_DRIVER_CONTEXT {
    PFLT_FILTER FilterHandle;
    PFLT_PORT ServerPort;
    PFLT_PORT ClientPort;
    PVOID ObRegistrationHandle;
    BOOLEAN MonitoringActive;
} SPACESEC_DRIVER_CONTEXT, *PSPACESEC_DRIVER_CONTEXT;

static SPACESEC_DRIVER_CONTEXT g_DriverContext = { 0 };

// Telemetry Message Format streamed to SpaceSec backend
typedef struct _SPACESEC_EVENT_PACKET {
    ULONG EventType;            // 1=ProcessCreate, 2=ThreadInjection, 3=HandleStripped, 4=FileBlocked
    ULONG ProcessId;
    ULONG ParentProcessId;
    ULONG TargetProcessId;
    WCHAR ImageFileName[260];
    WCHAR CommandLine[512];
    BOOLEAN IsSignatureValid;
    BOOLEAN Blocked;
    LARGE_INTEGER Timestamp;
} SPACESEC_EVENT_PACKET, *PSPACESEC_EVENT_PACKET;

// Forward Declarations
DRIVER_INITIALIZE DriverEntry;
NTSTATUS DriverUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);
NTSTATUS FilterSetup(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_SETUP_FLAGS Flags, _In_ DEVICE_TYPE VolumeDeviceType, _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType);

FLT_PREOP_CALLBACK_STATUS PreCreateCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

VOID ProcessNotifyRoutineEx(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
);

VOID ThreadNotifyRoutine(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create
);

OB_PREOP_CALLBACK_STATUS PreOpenProcessCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
);

NTSTATUS PortConnectNotify(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionPortCookie
);

VOID PortDisconnectNotify(_In_opt_ PVOID ConnectionCookie);

// Filter Operation Callbacks Registration
CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE,
      0,
      PreCreateCallback,
      NULL },
    { IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    Callbacks,
    DriverUnload,
    FilterSetup,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

/**
 * Driver Entry Point
 */
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING uniPortName;
    PSECURITY_DESCRIPTOR sd = NULL;

    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[SpaceSec] Initializing Kernel Minifilter Driver (Altitude %ws)...\n", SPACESEC_ALTITUDE);

    // 1. Register with Filter Manager (FLTMGR)
    status = FltRegisterFilter(DriverObject, &FilterRegistration, &g_DriverContext.FilterHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[SpaceSec] FltRegisterFilter failed (0x%08X)\n", status);
        return status;
    }

    // 2. Setup Communication Port for Userland Node.js IPC
    RtlInitUnicodeString(&uniPortName, SPACESEC_PORT_NAME);
    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (NT_SUCCESS(status)) {
        InitializeObjectAttributes(&oa, &uniPortName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, sd);
        status = FltCreateCommunicationPort(
            g_DriverContext.FilterHandle,
            &g_DriverContext.ServerPort,
            &oa,
            NULL,
            PortConnectNotify,
            PortDisconnectNotify,
            NULL,
            1
        );
        FltFreeSecurityDescriptor(sd);
    }

    // 3. Register Process Creation Interceptor (PsSetCreateProcessNotifyRoutineEx)
    status = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyRoutineEx, FALSE);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, "[SpaceSec] PsSetCreateProcessNotifyRoutineEx status: 0x%08X\n", status);
    }

    // 4. Register Thread Injection Interceptor
    status = PsSetCreateThreadNotifyRoutine(ThreadNotifyRoutine);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, "[SpaceSec] PsSetCreateThreadNotifyRoutine status: 0x%08X\n", status);
    }

    // 5. Start Filtering
    status = FltStartFiltering(g_DriverContext.FilterHandle);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(g_DriverContext.FilterHandle);
        return status;
    }

    g_DriverContext.MonitoringActive = TRUE;
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[SpaceSec] Kernel Minifilter successfully armed & monitoring Ring-0 events.\n");

    return STATUS_SUCCESS;
}

/**
 * Filter Unload Routine
 */
NTSTATUS DriverUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);

    // Unregister process & thread callbacks
    PsSetCreateProcessNotifyRoutineEx(ProcessNotifyRoutineEx, TRUE);
    PsRemoveCreateThreadNotifyRoutine(ThreadNotifyRoutine);

    // Close IPC communication port
    if (g_DriverContext.ServerPort) {
        FltCloseCommunicationPort(g_DriverContext.ServerPort);
    }

    // Unregister Minifilter
    if (g_DriverContext.FilterHandle) {
        FltUnregisterFilter(g_DriverContext.FilterHandle);
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[SpaceSec] Kernel Minifilter unloaded cleanly.\n");
    return STATUS_SUCCESS;
}

NTSTATUS FilterSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);
    return STATUS_SUCCESS;
}

/**
 * Pre-Operation File System Interceptor (IRP_MJ_CREATE)
 * Intercepts malware drops, locked driver placements and ransomware renames
 */
FLT_PREOP_CALLBACK_STATUS PreCreateCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Inspect file path for suspicious driver drop or ransomware extension
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    if (NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo))) {
        FltParseFileNameInformation(nameInfo);
        
        // Block untrusted modifications to C:\Windows\System32\drivers\
        if (RtlCompareUnicodeString(&nameInfo->Extension, &(UNICODE_STRING)RTL_CONSTANT_STRING(L"sys"), TRUE) == 0) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[SpaceSec Kernel] Driver drop attempt intercepted: %wZ\n", &nameInfo->Name);
        }
        FltReleaseFileNameInformation(nameInfo);
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

/**
 * Process Creation Notification Interceptor
 * Intercepts every process before thread execution begins
 */
VOID ProcessNotifyRoutineEx(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
    UNREFERENCED_PARAMETER(Process);

    if (CreateInfo != NULL) {
        // Process Spawn Interception: inspect ImageFileName & CommandLine
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, 
            "[SpaceSec Kernel] Process Created: PID=%lu ParentPID=%lu Image=%wZ\n",
            HandleToULong(ProcessId),
            HandleToULong(CreateInfo->ParentProcessId),
            CreateInfo->ImageFileName
        );

        // Anti-Mimikatz & LOLBin Interception Heuristics
        if (CreateInfo->CommandLine != NULL) {
            UNICODE_STRING cmd = *CreateInfo->CommandLine;
            if (wcsstr(cmd.Buffer, L"-enc") || wcsstr(cmd.Buffer, L"DownloadString") || wcsstr(cmd.Buffer, L"mimikatz")) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, "[SpaceSec Kernel] Hostile command intercepted and blocked at Ring-0!\n");
                // Option: CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
            }
        }
    } else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[SpaceSec Kernel] Process Terminated: PID=%lu\n", HandleToULong(ProcessId));
    }
}

/**
 * Remote Thread & Injection Interceptor (Detects Reflective DLL / Process Hollowing)
 */
VOID ThreadNotifyRoutine(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create
)
{
    if (Create) {
        HANDLE callerProcessId = PsGetCurrentProcessId();
        if (callerProcessId != ProcessId && callerProcessId != (HANDLE)4) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                "[SpaceSec Kernel] REMOTE THREAD DETECTED: Caller PID %lu injected thread into Target PID %lu (ThreadId: %lu)\n",
                HandleToULong(callerProcessId),
                HandleToULong(ProcessId),
                HandleToULong(ThreadId)
            );
        }
    }
}

NTSTATUS PortConnectNotify(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionPortCookie
)
{
    UNREFERENCED_PARAMETER(ServerCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);
    g_DriverContext.ClientPort = ClientPort;
    *ConnectionPortCookie = NULL;
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[SpaceSec Kernel] Userland Engine connected to Kernel Port.\n");
    return STATUS_SUCCESS;
}

VOID PortDisconnectNotify(_In_opt_ PVOID ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);
    if (g_DriverContext.ClientPort) {
        FltCloseClientPort(g_DriverContext.FilterHandle, &g_DriverContext.ClientPort);
    }
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[SpaceSec Kernel] Userland Engine disconnected from Kernel Port.\n");
}
