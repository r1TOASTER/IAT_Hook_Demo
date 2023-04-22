#include <Windows.h>
#include <stdio.h>
#include <string.h>

DWORD HookedGetCurrentProcessId(void) {
	return 1337;
}

void hook_iat(const char* dllName, const char* funcName) {
	const HANDLE imageBase = GetModuleHandle(NULL);
	PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)imageBase; // dos headers
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + dosHeaders->e_lfanew); // ntHeaders are in e_lfanew

	PIMAGE_IMPORT_DESCRIPTOR importDescriptor = NULL;
	IMAGE_DATA_DIRECTORY importsDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]; // IAT
	importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (DWORD_PTR)imageBase); // img descriptor

	LPCSTR currentLibraryName = NULL;
	HMODULE loadedLibrary = NULL;
	PIMAGE_IMPORT_BY_NAME functionNameStruct = NULL;

	while (importDescriptor->Name) // run until library name is not null, meaning we have libraries
	{

		currentLibraryName = (LPCSTR)importDescriptor->Name + (DWORD_PTR)imageBase; // get name of library
		loadedLibrary = LoadLibraryA(currentLibraryName); // loading the dll library
		
		if (loadedLibrary && (!strcmp(currentLibraryName, dllName)))
		{
			// thunk where the functions are located  (?)
			PIMAGE_THUNK_DATA originalFirstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)imageBase + importDescriptor->OriginalFirstThunk);
			PIMAGE_THUNK_DATA firstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)imageBase + importDescriptor->FirstThunk);

			while (originalFirstThunk->u1.AddressOfData) // run until function name is not null, meaning we have functions
			{
				functionNameStruct = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)imageBase + originalFirstThunk->u1.AddressOfData);

				if (!strcmp(functionNameStruct->Name, funcName)) {

					DWORD oldProtect = 0;

					VirtualProtect(firstThunk, 4096, PAGE_READWRITE, &oldProtect); // change permissions.
					firstThunk->u1.Function = (DWORD_PTR)&HookedGetCurrentProcessId;
					int u = scanf("%s");
					return;
				}
				originalFirstThunk++;
				firstThunk++;

			}
		}
		importDescriptor++;
	}
	MessageBoxW(0, L"Failed", L"Function / Dll not found", MB_OK);
	return;
}

BOOL WINAPI DllMain(
    HINSTANCE hintDLL,
    DWORD fdwReason,
    LPVOID lpReserved)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        hook_iat("KERNEL32.dll", "GetCurrentProcessId");
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return 0;
}