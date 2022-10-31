#pragma once

#include <Windows.h>
#include <psapi.h>

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#if !defined PROCESSINFOCLASS
typedef LONG PROCESSINFOCLASS;
#endif

typedef enum _SECTION_INHERIT {
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT, * PSECTION_INHERIT;


typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _RTL_DRIVE_LETTER_CURDIR {
	USHORT Flags;
	USHORT Length;
	ULONG TimeStamp;
	UNICODE_STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;

typedef struct _SECTION_IMAGE_INFORMATION {
	PVOID EntryPoint;
	ULONG StackZeroBits;
	ULONG StackReserved;
	ULONG StackCommit;
	ULONG ImageSubsystem;
	WORD SubSystemVersionLow;
	WORD SubSystemVersionHigh;
	ULONG Unknown1;
	ULONG ImageCharacteristics;
	ULONG ImageMachineType;
	ULONG Unknown2[3];
} SECTION_IMAGE_INFORMATION, * PSECTION_IMAGE_INFORMATION;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	ULONG MaximumLength;
	ULONG Length;
	ULONG Flags;
	ULONG DebugFlags;
	PVOID ConsoleHandle;
	ULONG ConsoleFlags;
	HANDLE StdInputHandle;
	HANDLE StdOutputHandle;
	HANDLE StdErrorHandle;
	UNICODE_STRING CurrentDirectoryPath;
	HANDLE CurrentDirectoryHandle;
	UNICODE_STRING DllPath;
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
	PVOID Environment;
	ULONG StartingPositionLeft;
	ULONG StartingPositionTop;
	ULONG Width;
	ULONG Height;
	ULONG CharWidth;
	ULONG CharHeight;
	ULONG ConsoleTextAttributes;
	ULONG WindowFlags;
	ULONG ShowWindowFlags;
	UNICODE_STRING WindowTitle;
	UNICODE_STRING DesktopName;
	UNICODE_STRING ShellInfo;
	UNICODE_STRING RuntimeData;
	RTL_DRIVE_LETTER_CURDIR DLCurrentDirectory[0x20];
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _RTL_USER_PROCESS_INFORMATION {
	ULONG Size;
	HANDLE ProcessHandle;
	HANDLE ThreadHandle;
	CLIENT_ID ClientId;
	SECTION_IMAGE_INFORMATION ImageInformation;
} RTL_USER_PROCESS_INFORMATION, * PRTL_USER_PROCESS_INFORMATION;


/* functions */
typedef NTSTATUS(NTAPI* NtCreateSection_t) (
	OUT PHANDLE SectionHandle,
	IN ULONG DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PLARGE_INTEGER MaximumSize OPTIONAL,
	IN ULONG PageAttributess,
	IN ULONG SectionAttributes,
	IN HANDLE FileHandle OPTIONAL
	);
extern NtCreateSection_t NtCreateSection;

typedef NTSTATUS(NTAPI* NtMapViewOfSecion_t) (
	IN HANDLE SectionHandle,
	IN HANDLE ProcessHandle,
	IN OUT PVOID* BaseAddress OPTIONAL,
	IN ULONG ZeroBits OPTIONAL,
	IN ULONG CommitSize,
	IN OUT PLARGE_INTEGER SectionOffset OPTIONAL,
	IN OUT PULONG ViewSize,
	IN SECTION_INHERIT InheritDisposition,
	IN ULONG AllocationType OPTIONAL,
	IN ULONG Protect
	);
extern NtMapViewOfSecion_t NtMapViewOfSection;

typedef NTSTATUS(NTAPI* NtUnmapViewOfSection_t) (
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress
	);
extern NtUnmapViewOfSection_t NtUnmapViewOfSection;

typedef VOID(NTAPI* RtlInitUnicodeString_t) (
	OUT PUNICODE_STRING DestinationString,
	IN PCWSTR SourceString OPTIONAL
	);
extern RtlInitUnicodeString_t RtlInitUnicodeString;

typedef NTSTATUS(NTAPI* RtlCreateProcessParameters_t) (
	OUT PRTL_USER_PROCESS_PARAMETERS* ProcessParameters,
	IN PUNICODE_STRING ImagePathName,
	IN PUNICODE_STRING DllPath OPTIONAL,
	IN PUNICODE_STRING CurrentDirectoryPath OPTIONAL,
	IN PUNICODE_STRING CommandLine OPTIONAL,
	IN PVOID Environment OPTIONAL,
	IN PUNICODE_STRING WindowTitle OPTIONAL,
	IN PUNICODE_STRING DesktopName OPTIONAL,
	IN PUNICODE_STRING ShellInfo OPTIONAL,
	IN PUNICODE_STRING RuntimeData OPTIONAL
	);
extern RtlCreateProcessParameters_t RtlCreateProcessParameters;

typedef NTSTATUS(NTAPI* RtlCreateUserProcess_t) (
	IN PUNICODE_STRING ImagePath,
	IN ULONG ObjectAttributes,
	IN OUT PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
	IN PSECURITY_DESCRIPTOR ProcessSecurityDescriptor OPTIONAL,
	IN PSECURITY_DESCRIPTOR ThreadSecurityDescriptor OPTIONAL,
	IN HANDLE ParentProcess,
	IN BOOLEAN InheritHandles,
	IN HANDLE DebugPort OPTIONAL,
	IN HANDLE ExceptionPort OPTIONAL,
	OUT PRTL_USER_PROCESS_INFORMATION ProcessInformation);
extern RtlCreateUserProcess_t RtlCreateUserProcess;

typedef NTSTATUS(NTAPI* RtlCreateUserThread_t) (
	IN HANDLE ProcessHandle,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
	IN BOOLEAN CreateSuspended,
	IN ULONG StackZeroBits,
	IN OUT PULONG StackReserved,
	IN OUT PULONG StackCommit,
	IN PVOID StartAddress,
	IN PVOID StartParameter OPTIONAL,
	OUT PHANDLE ThreadHandle,
	OUT PCLIENT_ID ClientID
	);
extern RtlCreateUserThread_t RtlCreateUserThread;

typedef NTSTATUS(NTAPI* NtClose_t) (
	IN HANDLE ObjectHandle
	);
extern NtClose_t NtClose;

typedef OBJECT_ATTRIBUTES* POBJECT_ATTRIBUTES;
#define InitializeObjectAttributes( p, n, a, r, s ) { \
		(p)->Length = sizeof( OBJECT_ATTRIBUTES );        \
		(p)->RootDirectory = r;                           \
		(p)->Attributes = a;                              \
		(p)->ObjectName = n;                              \
		(p)->SecurityDescriptor = s;                      \
		(p)->SecurityQualityOfService = NULL;             \
		}


typedef NTSTATUS(NTAPI* ZwCreateSection_t)(
	_Out_ PHANDLE SectionHandle, _In_ ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PLARGE_INTEGER MaximumSize, _In_ ULONG SectionPageProtection,
	_In_ ULONG AllocationAttributes, _In_opt_ HANDLE FileHandle
);
extern ZwCreateSection_t ZwCreateSection;

typedef NTSTATUS(NTAPI* ZwCreateThreadEx_t)(
	_Out_ PHANDLE ThreadHandle, _In_ ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes, _In_ HANDLE ProcessHandle,
	_In_ PVOID StartRoutine, _In_opt_ PVOID Argument, _In_ ULONG CreateFlags,
	_In_opt_ ULONG_PTR ZeroBits, _In_opt_ SIZE_T StackSize,
	_In_opt_ SIZE_T MaximumStackSize, _In_opt_ PVOID AttributeList
);
extern ZwCreateThreadEx_t ZwCreateThreadEx;


typedef NTSTATUS(NTAPI* ZwUnmapViewOfSection_t)
(_In_ HANDLE ProcessHandle, _In_opt_ PVOID BaseAddress);
extern ZwUnmapViewOfSection_t ZwUnmapViewOfSection;

typedef NTSTATUS(NTAPI* ZwOpenProcess_t)
(
	PHANDLE ProcessHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID ClientID
	);
extern ZwOpenProcess_t ZwOpenProcess;

typedef NTSTATUS(NTAPI* NtDelayExecution_t)(
	BOOL Alertable,
	PLARGE_INTEGER DelayInterval
	);
extern NtDelayExecution_t NtDelayExecution;

typedef struct _PROCESS_BASIC_INFORMATION {
	PVOID Reserved1;
	PVOID PebBaseAddress;
	PVOID Reserved2[2];
	ULONG_PTR UniqueProcessId;
	PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;


typedef NTSTATUS(NTAPI* NtResumeThread_t)(
	IN HANDLE ThreadHandle,
	OUT OPTIONAL PULONG SuspendCount
	);
extern NtResumeThread_t NtResumeThread;

typedef HANDLE(WINAPI* CreateFileA_t)(
	IN           LPCSTR                lpFileName,
	IN           DWORD                 dwDesiredAccess,
	IN           DWORD                 dwShareMode,
	IN OPTIONAL  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	IN           DWORD                 dwCreationDisposition,
	IN           DWORD                 dwFlagsAndAttributes,
	IN OPTIONAL  HANDLE                hTemplateFile
);
extern CreateFileA_t pCreateFileA;

typedef BOOL(WINAPI* VirtualProtect_t)(
	LPVOID,
	SIZE_T,
	DWORD,
	PDWORD
);
extern VirtualProtect_t pVirtualProtect;

typedef HANDLE(WINAPI* CreateFileMappingA_t)(
	HANDLE,
	LPSECURITY_ATTRIBUTES,
	DWORD,
	DWORD,
	DWORD,
	LPCSTR
);
extern CreateFileMappingA_t pCreateFileMappingA;

typedef LPVOID(WINAPI* MapViewOfFile_t)(
	HANDLE,
	DWORD,
	DWORD,
	DWORD,
	SIZE_T
);
extern MapViewOfFile_t pMapViewOfFile;

/* helper functions */
void unhookNtdll(HMODULE ntdll);
void loadNtdll(HMODULE ntdll);
void checkNtStatus(NTSTATUS status);
int my_strcmp(const char* p1, const char* p2);
UINT64 GetKernel32();
UINT64 GetSymbolAddress(HANDLE hModule, LPCSTR lpProcName);
PVOID VxMoveMemory(PVOID dest, const PVOID src, SIZE_T len);