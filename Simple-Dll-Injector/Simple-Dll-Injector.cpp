#include <stdio.h> // FILE, printf, fprintf_s, fopen_s, fclose

#include <Windows.h> // VirtualAllocEx, VirtualFreeEx, WriteProcessMemory, CreateRemoteThread, OpenProcess, CloseHandle, FormatMessageA, GetLastError
#include <TlHelp32.h> // CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32
#include <Psapi.h> // K32GetModuleFileNameExA

typedef void(__cdecl* OnErrorRoutine)(LPVOID lpParameter);

void OnError(
	_In_opt_z_ LPCSTR lpString = nullptr,				// Error message, default: nullptr. If nullptr, gets last WinApi error. If not nullptr, prints provided message to the console.
	_In_opt_ OnErrorRoutine lpOnErrorRoutine = nullptr,	// On error routine, default: nullptr. If not nullptr, runs the routine right before the thread freezes.
	_In_opt_ LPVOID lpParameter = nullptr				// On error routine parameter, default: nullptr. Gets passed to the routine when ran.
) {
	remove("log.log");

	FILE* pFile;
	fopen_s(&pFile, "log.log", "w");

	if (pFile) {
		if (lpString) {
			fprintf_s(pFile, "%s", lpString);
			printf("%s", lpString);
		}
		else {
			DWORD dwErrorCode = GetLastError(); // Last WinApi error.

			CHAR szMessage[256];
			FormatMessageA(
				FORMAT_MESSAGE_FROM_SYSTEM,		// Formatting a system error message.
				nullptr,						// Source is not valid when FORMAT_MESSAGE_FROM_SYSTEM is specified.
				dwErrorCode,					// Error code to get message of.
				LANG_SYSTEM_DEFAULT,			// Default system language.
				szMessage,						// Message buffer.
				sizeof(szMessage),				// Size of message buffer.
				nullptr							// Argument list is not valid when FORMAT_MESSAGE_FROM_SYSTEM is specified.
			);

			fprintf_s(pFile, "%lu : %s", dwErrorCode, szMessage);
			printf("%lu : %s", dwErrorCode, szMessage);
		}

		fclose(pFile);
	}

	if (lpOnErrorRoutine) lpOnErrorRoutine(lpParameter);
	while (true) {} // Freeze console window until abort is raised.
}

DWORD GetProcessId(_In_z_ LPCSTR lpProcessName) {
	HANDLE hSnapshot = CreateToolhelp32Snapshot(
		TH32CS_SNAPPROCESS, // Looking for process snapshots.
		0					// Looking system wide.
	);

	PROCESSENTRY32 pe32 = { NULL };
	pe32.dwSize = sizeof(pe32);

	if (!Process32First(hSnapshot, &pe32)) OnError();

	DWORD dwProcessId = 0;

	do {
		if (!strcmp(lpProcessName, pe32.szExeFile)) {	// Walking the process tree until we find lpProcessName.
			dwProcessId = pe32.th32ProcessID;			// When the process is found, its process id is stored and later returned.
			break;
		}
	} while (Process32Next(hSnapshot, &pe32));
	CloseHandle(hSnapshot);

	if (!dwProcessId) OnError("Process not found!"); // If no process with the provided name is found, error is thrown.

	return dwProcessId;
}

void RelativeToAbsolutePath(
	_Inout_updates_z_(dwSize) LPSTR lpPath,
	_In_ DWORD dwSize
) {
	CHAR szReturn[MAX_PATH];

	if (!K32GetModuleFileNameExA(		// Gets the full path of a module.
		GetCurrentProcess(),			// Current process handle.
		GetModuleHandleA(nullptr),		// Main module of current process, which is the path we want.
		szReturn,						// Return buffer.
		MAX_PATH						// Return buffer size.
	)) OnError();

	for (INT i = lstrlenA(szReturn) - 1; szReturn[i] != '\\'; [&szReturn, &i]() -> void { szReturn[i] = '\0'; i--; }()); // Strips the module name off so we are left with a path to the directory.

	strcat_s(szReturn, lpPath); // Concatenating the name of the module onto the path.
	strcpy_s(lpPath, dwSize, szReturn);	// Copying the complete path into the return buffer.
}

int main() {
	CHAR szPath[MAX_PATH] = "sudo.dll"; // Name of dll to inject.
	RelativeToAbsolutePath(szPath, MAX_PATH);

	DWORD dwProcessId = GetProcessId("devenv.exe"); // Getting process id of target.

	HANDLE hProcess = OpenProcess(
		PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | // Virtual memory access.
		PROCESS_QUERY_INFORMATION |									// Query information access.
		PROCESS_CREATE_THREAD,										// Create thread access, for our injection.
		FALSE,														// No inherit.
		dwProcessId													// Process id of target.
	);

	if (!hProcess) OnError();

	LPVOID lpAllocation = VirtualAllocEx( // Allocating memory for dll path.
		hProcess,					// Target process handle.
		nullptr,					// No desired address.
		lstrlenA(szPath) + 1,		// Path + null terminator.
		MEM_RESERVE | MEM_COMMIT,	// Reserving and committing the memory directly.
		PAGE_READWRITE				// Read and write access to the region, anything else is unnecessary.
	);

	if (!lpAllocation)
		OnError(
			nullptr,
			[](LPVOID lpParameter) -> void { CloseHandle(lpParameter); },
			hProcess
		);

	LPVOID lpszDisposables[2] = { hProcess, lpAllocation };

	if (!WriteProcessMemory( // Writing dll path to allocation.
		hProcess,		// Target process handle
		lpAllocation,	// Allocation address.
		szPath,			// Process path.
		lstrlenA(szPath) + 1, // Length of process path.
		nullptr
	)) OnError(
		nullptr,
		[](LPVOID lpParameter) -> void {
			LPVOID* lpszDisposables = (LPVOID*)lpParameter;
			VirtualFreeEx(lpszDisposables[0], lpszDisposables[1], 0, MEM_RELEASE);
			CloseHandle(lpszDisposables[0]);
		},
		lpszDisposables
	);

	FARPROC lpLoadLibraryA = GetProcAddress(GetModuleHandleA("KERNEL32.DLL"), "LoadLibraryA"); // Address of LoadLibraryA.
	if (!lpLoadLibraryA)
		OnError(
			nullptr,
			[](LPVOID lpParameter) -> void {
				LPVOID* lpszDisposables = (LPVOID*)lpParameter;
				VirtualFreeEx(lpszDisposables[0], lpszDisposables[1], 0, MEM_RELEASE);
				CloseHandle(lpszDisposables[0]);
			},
			lpszDisposables
		);

	HANDLE hThread = CreateRemoteThread(
		hProcess,	// Target process handle.
		nullptr,	// Default security descriptor.
		0,			// Default stack size.
		(LPTHREAD_START_ROUTINE)lpLoadLibraryA,	// LoadLibraryA
		lpAllocation,							// Path string.
		0,			// Default creation flags.
		nullptr		// No thread id.
	);

	if (!hThread)
		OnError(
			nullptr,
			[](LPVOID lpParameter) -> void {
				LPVOID* lpszDisposables = (LPVOID*)lpParameter;
				VirtualFreeEx(lpszDisposables[0], lpszDisposables[1], 0, MEM_RELEASE);
				CloseHandle(lpszDisposables[0]);
			},
			lpszDisposables
		);

	CloseHandle(hThread);

	Sleep(200); // Wait for LoadLibraryA to finish in remote process.

	if (!VirtualFreeEx(
		hProcess,		// Target process handle.
		lpAllocation,	// Allocation address.
		0,				// 0 due to MEM_RELEASE.
		MEM_RELEASE		// Release allocated memory.
	)) OnError(
		nullptr,
		[](LPVOID lpParameter) -> void { CloseHandle(lpParameter); },
		hProcess
	);

	CloseHandle(hProcess); // Close process handle and exit.

	return 0;
}