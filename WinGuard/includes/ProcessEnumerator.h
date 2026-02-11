#pragma once
#include <iostream>
#include <Windows.h>
#include <string>
#include <TlHelp32.h>
#include <vector>
#include <unordered_map>
#include <Psapi.h>
#include "Logger.h"
#include "NT_API.h"

#pragma comment(lib, "psapi.lib")

using NtQuerySystemInformation_t = NTSTATUS(NTAPI*)(
    SYSTEM_INFORMATION_CLASS,
    PVOID,
    ULONG,
    PULONG
    );

extern NtQuerySystemInformation_t pNtQuerySystemInformation;

class ProcessEnumerator
{
public:
    enum fileVerification {
        SUCCESS, NO_SIGNATURE, TAMPERED,
        UNTRUSTED_SIGNER, REVOKED, EXPIRED, ADMIN, POLICY_BLOCK,
        CHAIN_FAIL, UNKNOWN
    };

    struct ProcessInformation {
        DWORD pid = 0;
        DWORD ppid = 0;
        std::wstring name = L"";
        std::wstring path = L"";
        fileVerification certStatus = UNKNOWN;
        bool directoryWritable = false;
        bool fileWritable = false;
        int suspicionScore = 0;
        DWORDLONG cycleCounter = 0;
        std::vector<std::wstring> suspicionReason = {};
    };

    std::unordered_map<DWORD, ProcessInformation> processMap;
    void collectProcesses();
    std::wstring getPath(DWORD pid) const;
    bool isRelativePath(const std::wstring& path);
    bool isDLLPathSuspicious(const std::wstring& path);
    void printSuspicious();
private:
    DWORD64 CYCLE_COUNT = 0;
};
