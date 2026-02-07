#pragma once
#include "ProcessEnumerator.h"
#include <unordered_set>
#include <unordered_map>
#include <WinTrust.h>
#include <winternl.h>
#include <SoftPub.h>
#include <filesystem>
#include <stdlib.h>
#include "Logger.h"
#include "Whitelist.h"

#pragma comment(lib, "wintrust.lib")

using NtQueryInformationProcess_t = NTSTATUS(NTAPI*)(HANDLE,
    PROCESSINFOCLASS, PVOID, ULONG, PULONG);

class SignatureChecker
{
public:
	ProcessEnumerator procEnum;
	
	void analyseProcessBehavior(std::unordered_map<DWORD, ProcessEnumerator::ProcessInformation> &processSnapshot);
	void parentProcesses(std::unordered_map<DWORD, ProcessEnumerator::ProcessInformation>& processSnapshot);
private:
	Whitelist whitelist;
	std::wstring getCommandLineBuffer(HANDLE hProcess);
	ProcessEnumerator::fileVerification verifyFileSignature(const std::wstring& filePath);
	bool isDirectoryUserWritable(const std::wstring& filePath);
	bool getModules(DWORD pid, ProcessEnumerator& proc, std::unordered_map<DWORD, ProcessEnumerator::ProcessInformation>& processSnapshot);	
};

