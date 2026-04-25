#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <stdlib.h>
#include "cJSON.h"

#pragma comment(lib, "iphlpapi.lib") // Telling Visual Studio to link the network library
#pragma comment(lib, "ws2_32.lib")


int getSystemDirectory() {
	WCHAR buffer[MAX_PATH];
	UINT max_size = MAX_PATH;
	UINT chars_written = GetSystemDirectoryW(buffer, max_size);
	if (chars_written == 0) {
		printf("Faild to get system directory. Error: %lu\n", GetLastError());
		return 0;
	}
	else {
		printf("System directory is: %ls\n", buffer);
		return 0;
	}
}

int setDebugPrivileges() {
	HANDLE hcurrProc = GetCurrentProcess();
	// Getting the current process access token
	HANDLE htoken;
	BOOL result = OpenProcessToken(hcurrProc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &htoken);
	if (result == FALSE) {
		printf("Couldn't get Process token. Error: %lu", GetLastError());
		CloseHandle(hcurrProc);
		return -1;
	}

	// Getting the current process privilege value
	LUID procLuid;
	result = LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &procLuid);
	if (result == FALSE) {
		printf("Couldn't get Privilege value. Error: %lu", GetLastError());
		CloseHandle(htoken);
		return -1;
	}

	// setting the LUID_AND_ATTRIBUTES struct
	LUID_AND_ATTRIBUTES luidAttr;
	luidAttr.Luid = procLuid;
	luidAttr.Attributes = SE_PRIVILEGE_ENABLED;

	// setting the TOKEN_PRIVILEGES struct
	TOKEN_PRIVILEGES tokenPriv;
	tokenPriv.PrivilegeCount = 1;
	tokenPriv.Privileges[0] = luidAttr;

	// changing the token privileges
	result = AdjustTokenPrivileges(htoken, FALSE, &tokenPriv, 0, NULL, NULL);
	if (result == FALSE) {
		printf("Failed to Change Token Privileges. Error: %lu", GetLastError());
		CloseHandle(htoken);
		return -1;
	}

	DWORD error = GetLastError();
	if (error == ERROR_NOT_ALL_ASSIGNED) {
		printf("SeDebugPrivilege was NOT assigned!\n");
		CloseHandle(htoken);
		return -1;
	}


	printf("Successfuly changed token privileges\n");
	CloseHandle(htoken);
	return 1;

}


int getProcessDLLs(HANDLE hproc) {
	//first, we will check how many bytes we need in the array.
	DWORD bytesNeeded = 0;
	HMODULE dummyArray[1];

	if (!EnumProcessModules(hproc, dummyArray, sizeof(dummyArray), &bytesNeeded)) {
		printf("Failed to read process modules.\n");
		return -1;
	}

	if (bytesNeeded == 0) {
		printf("No modules found.\n");
		return -1;
	}

	// Now we will retrive all the modules to an array
	HMODULE* modules = (HMODULE*)malloc(bytesNeeded);

	if (modules == NULL) {
		printf("No modules Found.\n");
		return -1;
	}

	if (!EnumProcessModules(hproc, modules, bytesNeeded, &bytesNeeded)) {
		printf("Failed to get Process modules. Error: %lu", GetLastError());
		return -1;
	}

	// Prints all the modules
	int moduleCount = bytesNeeded / sizeof(HMODULE);
	WCHAR buffer[MAX_PATH];
	printf("- Process DLLs:\n");
	for (int i = 0; i < moduleCount; i++) {
		DWORD bytesWritten = GetModuleFileNameExW(hproc, modules[i], buffer, MAX_PATH);
		printf("  %ls\n", buffer);
	}

	free(modules);
	return 1;
}

PMIB_TCPTABLE_OWNER_PID getTcpTable() {

	// getting the needed size of the table
	DWORD tableSize = sizeof(MIB_TCPTABLE_OWNER_PID);
	DWORD result = GetExtendedTcpTable(NULL, &tableSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
	if (result != ERROR_INSUFFICIENT_BUFFER) {
		printf("Failed to get TCP table size. Error %lu", GetLastError());
		return NULL;
	}

	//filling the table (we will use MIB_TCPTABLE_OWNER_PID to find which connection comes from what process
	PMIB_TCPTABLE_OWNER_PID table = (PMIB_TCPTABLE_OWNER_PID)malloc(tableSize);
	if (!table) {
		printf("Malloc faild.\n");
		return NULL;
	}
	result = GetExtendedTcpTable(table, &tableSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
	if (result != NO_ERROR) {
		printf("Failed to get TCP Table. Error %lu", GetLastError());
		return NULL;
	}

	return table;
}

const char* getTcpStateName(DWORD state) {
	switch (state) {
	case MIB_TCP_STATE_CLOSED:      return "CLOSED";
	case MIB_TCP_STATE_LISTEN:      return "LISTEN";
	case MIB_TCP_STATE_SYN_SENT:    return "SYN_SENT";
	case MIB_TCP_STATE_SYN_RCVD:    return "SYN_RECEIVED";
	case MIB_TCP_STATE_ESTAB:       return "ESTABLISHED";
	case MIB_TCP_STATE_FIN_WAIT1:   return "FIN_WAIT_1";
	case MIB_TCP_STATE_FIN_WAIT2:   return "FIN_WAIT_2";
	case MIB_TCP_STATE_CLOSE_WAIT:  return "CLOSE_WAIT";
	case MIB_TCP_STATE_CLOSING:     return "CLOSING";
	case MIB_TCP_STATE_LAST_ACK:    return "LAST_ACK";
	case MIB_TCP_STATE_TIME_WAIT:   return "TIME_WAIT";
	case MIB_TCP_STATE_DELETE_TCB:  return "DELETE_TCB";
	default:                        return "UNKNOWN";
	}
}


BOOL findTcpConnectionOfPid(PMIB_TCPTABLE_OWNER_PID tcpTable, DWORD procPid, cJSON* net_json) {

	DWORD connCount = tcpTable->dwNumEntries;
	BOOL connectionFound = FALSE;
	for (int i = 0; i < connCount; i++) {
		MIB_TCPROW_OWNER_PID currentConn = tcpTable->table[i];

		if (currentConn.dwOwningPid == procPid) {
			connectionFound = TRUE;
			//converting the IPs to their string representation 
			char localIpStr[INET_ADDRSTRLEN], remoteIpStr[INET_ADDRSTRLEN];
			struct in_addr local, remote;
			local.S_un.S_addr = currentConn.dwLocalAddr;
			remote.S_un.S_addr = currentConn.dwRemoteAddr;
			InetNtopA(AF_INET, &local, localIpStr, INET_ADDRSTRLEN);
			InetNtopA(AF_INET, &remote, remoteIpStr, INET_ADDRSTRLEN);

			//adding the data to the json
			cJSON* obj = cJSON_CreateObject();
			cJSON_AddNumberToObject(obj, "local_port", ntohs((u_short)currentConn.dwLocalPort));
			cJSON_AddNumberToObject(obj, "remote_port", ntohs((u_short)currentConn.dwRemotePort));
			cJSON_AddStringToObject(obj, "remote_ip", remoteIpStr);
			cJSON_AddStringToObject(obj, "status", getTcpStateName(currentConn.dwState));

			cJSON_AddItemToArray(net_json, obj);

			//printf("	- Connections state: %s\n", getTcpStateName(currentConn.dwState));
			//printf("	- Local IP: %s\n", localIpStr);
			//printf("	- Local Port: %d\n", ntohs((u_short)currentConn.dwLocalPort));
			//printf("	- Remote IP: %s\n", remoteIpStr);
			//printf("	- Remote Port: %d\n", ntohs((u_short)currentConn.dwRemotePort));
		}
	}

	return connectionFound;
}

void sendDataToPipe(char* data,HANDLE hPipe) {

	//Send the message using WriteFile
	DWORD bytesWritten = 0;
	BOOL result = WriteFile(hPipe, data, strlen(data), &bytesWritten, NULL);
	WriteFile(hPipe, "\n", 1, &bytesWritten, NULL);

	if (result) {
		printf("Sent: %s\n", data);
		printf("Message sent successfully.\n");
	}
	else {
		printf("Failed to send message. Error: %lu\n", GetLastError());
	}

}

int mainDataLoop() {

	// Define the local pipe name
	LPCWSTR pipeName = L"\\\\.\\pipe\\AegisPipe";
	HANDLE hPipe;

	//Connect to the pipe using CreateFileW
	hPipe = CreateFileW(pipeName, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hPipe == INVALID_HANDLE_VALUE) {
		printf("Failed to connect to pipe. Error: %lu\n", GetLastError());
		return;
	}

	//changing to debug privileges (need to run as admin)
	//setDebugPrivileges();

	// create a snapshot of all the processes
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
	if (snapshot == INVALID_HANDLE_VALUE) {
		printf("Could not create snapshot. Error: %lu\n", GetLastError());
		return 0;
	}
	printf("Taken snapshot.\n");

	PMIB_TCPTABLE_OWNER_PID tcpTable = getTcpTable();

	// getting the first process
	PROCESSENTRY32W proc;
	proc.dwSize = sizeof(PROCESSENTRY32W);
	BOOL result = Process32FirstW(snapshot, &proc);
	if (result == FALSE) {
		printf("Could not retrive first process from snapshot. Error: %lu\n", GetLastError());
		CloseHandle(snapshot);
		return 0;
	}

	// iterating over all the procesess captured.
	while (result) {

		//printf("\n==========================================\n");
		//printf("- Process name: %ls\n", proc.szExeFile);
		//printf("- PID: %d\n", proc.th32ProcessID);
		//printf("- Parent PID: %d\n", proc.th32ParentProcessID);
		//printf("- Process Base Priority: %d\n", proc.pcPriClassBase);

		cJSON* root = cJSON_CreateObject();
		// Add basic fields
		cJSON_AddStringToObject(root, "type", "process_telemetry");
		cJSON_AddNumberToObject(root, "pid", proc.th32ProcessID);
		cJSON_AddNumberToObject(root, "parent_pid", proc.th32ParentProcessID);

		char asciiName[MAX_PATH];
		wcstombs(asciiName, proc.szExeFile, MAX_PATH); // converting from UNICODE to ASCII
		cJSON_AddStringToObject(root, "name", asciiName);

		// Create a nested object for IO counters
		cJSON* io_counters = cJSON_CreateObject();
		cJSON_AddNumberToObject(io_counters, "read_bytes", 1024); // dummy values for now.
		cJSON_AddNumberToObject(io_counters, "write_bytes", 2048);
		cJSON_AddItemToObject(root, "io_counters", io_counters); // Attach to root

		//opening process (with direct handle)
		HANDLE hproc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, proc.th32ProcessID);
		if (hproc == NULL) {
			printf("Failed to open process for %ls. Error: %lu\n", proc.szExeFile, GetLastError());
		}
		else {
			WCHAR fullPath[MAX_PATH];
			DWORD pathLen = MAX_PATH;
			BOOL hasPath = QueryFullProcessImageNameW(hproc, 0, fullPath, &pathLen);
			if (!hasPath) {
				printf("Failed to get process's full path. Error: %lu\n", GetLastError());
			}
			printf("- Full Process path: %ls\n", fullPath);

			char asciiPath[MAX_PATH];
			wcstombs(asciiPath, fullPath, MAX_PATH);
			cJSON_AddStringToObject(root, "exe", asciiPath);

			//getProcessDLLs(hproc); // printing DLLs

			if (tcpTable != NULL) {
				// finding tcp connection

				cJSON* net_connections = cJSON_CreateArray();

				BOOL connectionFound = findTcpConnectionOfPid(tcpTable, proc.th32ProcessID, net_connections);
				if (!connectionFound) {
					printf("Proccess dosen't have a tcp connection open.\n");
				}
				cJSON_AddItemToObject(root, "net_connections", net_connections);
			}

			CloseHandle(hproc);
		}

		char* jsonString = cJSON_PrintUnformatted(root);
		sendDataToPipe(jsonString,hPipe);
		free(jsonString);
		cJSON_Delete(root);
		result = Process32NextW(snapshot, &proc);
	}

	free(tcpTable);
	CloseHandle(snapshot);
	CloseHandle(hPipe);
	return 0;
}


int main() {
	mainDataLoop();
	return 0;
}
