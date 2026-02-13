#pragma once
#include "ProcessEnumerator.h"
#include <unordered_map>
#include <WinTrust.h>
#include <winternl.h>
#include <SoftPub.h>
#include <filesystem>
#include <stdlib.h>
#include "Logger.h"
#include <algorithm>
#include "Whitelist.h"

#pragma comment(lib, "wintrust.lib")

using NtQueryInformationProcess_t = NTSTATUS(NTAPI*)(HANDLE,
    PROCESSINFOCLASS, PVOID, ULONG, PULONG);

class SignatureChecker
{
public:
	Whitelist whitelist;
	ProcessEnumerator procEnum;
	
	void analyseProcessBehavior(std::unordered_map<DWORD, ProcessEnumerator::ProcessInformation> &processSnapshot);
	void parentProcesses(std::unordered_map<DWORD, ProcessEnumerator::ProcessInformation>& processSnapshot);
private:
	std::unordered_map<std::wstring, ProcessEnumerator::fileVerification> signatureCache;
	std::unordered_map<std::wstring, bool> directoryWritableCache;
	std::unordered_map<std::wstring, bool> fileWritableCache;
	std::unordered_map<DWORD, std::unordered_set<std::wstring>> moduleCache;
	ProcessEnumerator::fileVerification verifyFileSignature(const std::wstring& filePath);
	std::wstring getCommandLineBuffer(HANDLE hProcess);
	bool getCachedDirectory(const std::wstring& dir);
	bool isDirectoryUserWritable(const std::wstring& filePath);
	bool getModules(DWORD pid, ProcessEnumerator& proc, std::unordered_map<DWORD, ProcessEnumerator::ProcessInformation>& processSnapshot);
	bool getFileWritableCache(const std::wstring& dir, const std::wstring& path);
	ProcessEnumerator::fileVerification getCachedSignature(const std::wstring& path);
	std::wstring getExecutableDirectory();
};
