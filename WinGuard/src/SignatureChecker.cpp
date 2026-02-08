#include "SignatureChecker.h"


ProcessEnumerator::fileVerification SignatureChecker::verifyFileSignature(const std::wstring& filePath) {
	WINTRUST_FILE_INFO fileInfo{};
	fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
	fileInfo.pcwszFilePath = filePath.c_str();
	fileInfo.hFile = nullptr;
	fileInfo.pgKnownSubject = nullptr;

	WINTRUST_DATA trustData{};
	trustData.cbStruct = sizeof(WINTRUST_DATA);
	trustData.dwUIChoice = WTD_UI_NONE;
	trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
	trustData.dwUnionChoice = WTD_CHOICE_FILE;
	trustData.dwStateAction = WTD_STATEACTION_VERIFY;
	trustData.pFile = &fileInfo;
	trustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

	GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

	LONG status = WinVerifyTrust(nullptr, &policyGUID, &trustData);

	trustData.dwStateAction = WTD_STATEACTION_CLOSE;
	WinVerifyTrust(nullptr, &policyGUID, &trustData);

	switch (status) {
	case ERROR_SUCCESS:
		return ProcessEnumerator::SUCCESS;
		break;
	case TRUST_E_NOSIGNATURE:
		return ProcessEnumerator::NO_SIGNATURE;
		break;
	case TRUST_E_BAD_DIGEST:
		return ProcessEnumerator::TAMPERED;
		break;
	case CERT_E_UNTRUSTEDROOT:
		return ProcessEnumerator::UNTRUSTED_SIGNER;
		break;
	case CERT_E_REVOKED:
		return ProcessEnumerator::REVOKED;
		break;
	case CERT_E_EXPIRED:
		return ProcessEnumerator::EXPIRED;
		break;
	case TRUST_E_EXPLICIT_DISTRUST:
		return ProcessEnumerator::ADMIN;
		break;
	case CRYPT_E_SECURITY_SETTINGS:
		return ProcessEnumerator::POLICY_BLOCK;
		break;
	case CERT_E_CHAINING:
		return ProcessEnumerator::CHAIN_FAIL;
		break;
	default:
		return ProcessEnumerator::UNKNOWN;
		break;
	}
}

bool SignatureChecker::isDirectoryUserWritable(const std::wstring& filePath) {
	std::wstring testFile = filePath + L"\\.writetests";
	HANDLE hFile = CreateFileW(testFile.c_str(), GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		nullptr, CREATE_NEW, FILE_ATTRIBUTE_TEMPORARY |
		FILE_FLAG_DELETE_ON_CLOSE, nullptr);

	if (hFile == INVALID_HANDLE_VALUE) {
		return false;
	}
	CloseHandle(hFile);
	return true;
}

ProcessEnumerator::fileVerification SignatureChecker::getCachedSignature(const std::wstring& path) {
	auto it = signatureCache.find(path);
	if (it != signatureCache.end()) {
		return it->second;
	}

	auto result = verifyFileSignature(path);

	signatureCache[path] = result;
	return result;
}

bool SignatureChecker::getCachedDirectory(const std::wstring& dir) {
	auto it = directoryWritableCache.find(dir);
	if (it != directoryWritableCache.end())
		return it->second;

	auto result = isDirectoryUserWritable(dir);
	directoryWritableCache[dir] = result;
	return result;
}

bool SignatureChecker::getFileWritableCache(const std::wstring& dir, const std::wstring& path) {

	auto it = fileWritableCache.find(path);
	if (it != fileWritableCache.end())
		return it->second;

	HANDLE hFile = CreateFileW(path.c_str(), FILE_WRITE_DATA | FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	auto result = (hFile != INVALID_HANDLE_VALUE);
	fileWritableCache[path] = result;

	CloseHandle(hFile);

	return result;
}

void SignatureChecker::analyseProcessBehavior(std::unordered_map<DWORD, ProcessEnumerator::ProcessInformation>& processSnapshot) {
	
	
	for (auto& [pid, proc] : processSnapshot) {

		if (proc.path.empty() || proc.path == L"UNKNOWN")
			continue;

		std::wstring path = proc.path;
		std::transform(path.begin(), path.end(), path.begin(), ::tolower);

		if (whitelist.doesContain(proc.path) || whitelist.doesContain(path)) {
			continue;
		}
		
		proc.certStatus = ProcessEnumerator::UNKNOWN;
		proc.directoryWritable = false;
		proc.fileWritable = false;

		ProcessEnumerator::fileVerification verify = getCachedSignature(proc.path);

		proc.certStatus = verify;

		std::wstring directory;
		try {
			directory = std::filesystem::path(proc.path).parent_path().wstring();
		}
		catch (...) {
			directory = L"";
		}

		bool dirWritable = false;
		if (!directory.empty()) {
			dirWritable = getCachedDirectory(directory);
			proc.directoryWritable = dirWritable;
			if (dirWritable) {
				proc.suspicionReason.push_back(std::wstring(L"[!] Directory is user writable: ") + directory);
				proc.suspicionScore += 2;
			}
		}

		bool fileWritable = getFileWritableCache(directory, proc.path);

		proc.fileWritable = fileWritable;
		if (fileWritable) {
			proc.suspicionReason.push_back(std::wstring(L"[!] File is user writable: ") + proc.path);
			proc.suspicionScore += 2;
		}

		getModules(pid, procEnum, processSnapshot);


		if (verify == ProcessEnumerator::SUCCESS) {
			proc.certStatus = ProcessEnumerator::SUCCESS;
		}
		else if (verify == ProcessEnumerator::NO_SIGNATURE) {
			proc.certStatus = ProcessEnumerator::NO_SIGNATURE;
			proc.suspicionScore += 2;
			proc.suspicionReason.push_back(std::wstring(L"[!] File has no signature:") + proc.name);
		}
		else if (verify == ProcessEnumerator::TAMPERED) {
			proc.certStatus = ProcessEnumerator::TAMPERED;
			proc.suspicionScore += 3;
			proc.suspicionReason.push_back(std::wstring(L"[!] File was tampered with: ") + proc.name);
		}
		else if (verify == ProcessEnumerator::UNTRUSTED_SIGNER) {
			proc.certStatus = ProcessEnumerator::UNTRUSTED_SIGNER;
			proc.suspicionScore += 5;
			proc.suspicionReason.push_back(std::wstring(L"[!] File signature is not trusted: ") + proc.name);
		}
		else if (verify == ProcessEnumerator::REVOKED) {
			proc.certStatus = ProcessEnumerator::REVOKED;
			proc.suspicionScore += 3;
			proc.suspicionReason.push_back(std::wstring(L"[!] File signature was revoked: ") + proc.name);
		}
		else if (verify == ProcessEnumerator::EXPIRED) {;
			proc.certStatus = ProcessEnumerator::EXPIRED;
			proc.suspicionScore += 2;
			proc.suspicionReason.push_back(std::wstring(L"[!] File signature has expired: ") + proc.name);
		}
		else if (verify == ProcessEnumerator::ADMIN) {
			proc.certStatus = ProcessEnumerator::ADMIN;
			proc.suspicionScore += 5;
			proc.suspicionReason.push_back(std::wstring(L"[!] File, Certificate, or Publish is explicitly untrusted: ") + proc.name);
		}
		else if (verify == ProcessEnumerator::POLICY_BLOCK) {
			proc.certStatus = ProcessEnumerator::POLICY_BLOCK;
			proc.suspicionScore += 1;
			proc.suspicionReason.push_back(std::wstring(L"[!] File was blocked due to Policy: ") + proc.name);
		}
		else if (verify == ProcessEnumerator::CHAIN_FAIL) {
			proc.certStatus = ProcessEnumerator::CHAIN_FAIL;
			proc.suspicionScore += 3;
			proc.suspicionReason.push_back(std::wstring(L"[!] Windows could not build a valid certificate trust chain: ") + proc.name);
		}
		else {
			std::wcout << "[?] File signature status is unknown: " << proc.name << std::endl;
			proc.certStatus = ProcessEnumerator::UNKNOWN;
			proc.suspicionScore += 1;
			proc.suspicionReason.push_back(std::wstring(L"[?] File signature status is unknown: ") + proc.name);
		}
	}
	return;
}

void SignatureChecker::parentProcesses(std::unordered_map<DWORD, ProcessEnumerator::ProcessInformation>& processSnapshot) {
	std::unordered_map<DWORD, DWORD> topParentCache;
	std::unordered_set<DWORD> visited;
	
	for (auto& [pid, proc] : processSnapshot) {
		
		if (proc.pid == 0)
			continue;
		DWORD current = pid;
		while (true) {
			if (!visited.insert(current).second)
				break;

			auto it = processSnapshot.find(current);
			if (it == processSnapshot.end())
				break;

			auto parentIt = it->second.ppid;
			if (parentIt == 0 || parentIt == current) {
				break;
			}
			current = parentIt;
		}
		topParentCache[pid] = current;
		
	}

	for (auto& [pid, proc] : processSnapshot) {
		if (proc.ppid == 0)
			continue;

		auto first = processSnapshot.find(pid);

		if (first == processSnapshot.end())
			continue;

		auto parentIt = processSnapshot.find(first->second.ppid);
		if (parentIt != processSnapshot.end()) {
			const auto& parent = parentIt->second;

			if (parent.name == L"powershell.exe" || parent.name == L"cmd.exe" || parent.name == L"wscript.exe") {
				proc.suspicionScore += 3;
				proc.suspicionReason.push_back(std::wstring(L"[!] Suspicious Parent: ") + parent.name);
				HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, parent.pid);
				if (!hProcess) {
					continue;
				}

				std::wstring commandLineArg = getCommandLineBuffer(hProcess);
				std::wcout << L"[!] " << parent.name << " Command Line Buffer:" << commandLineArg << std::endl;
				parentIt->second.suspicionReason.push_back(L"[!] " + parent.name + L" Command Line Argument: " + commandLineArg);
				CloseHandle(hProcess);
			}

			if (parent.certStatus == ProcessEnumerator::REVOKED || parent.certStatus == ProcessEnumerator::UNTRUSTED_SIGNER) {
				proc.suspicionScore += 5;
				proc.suspicionReason.push_back(std::wstring(L"[!] Untrusted Parent Signature: ") + parent.name);
			}
		}

		auto topIt = topParentCache.find(pid);
		if (topIt == topParentCache.end())
			continue;

		auto topProcIt = processSnapshot.find(topIt->second);
		if (topProcIt == processSnapshot.end())
			continue;

		auto& topParent = topProcIt->second;

		if (topParent.name == L"powershell.exe" || topParent.name == L"cmd.exe" || topParent.name == L"wscript.exe") {
			proc.suspicionScore += 3;
			proc.suspicionReason.push_back(std::wstring(L"[!] Suspicious top-most parent: ") + topParent.name);
			HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, topParent.pid);
			if (!hProcess) {
				continue;
			}

			std::wstring commandLineArg = getCommandLineBuffer(hProcess);
			topParent.suspicionReason.push_back(L"[!] " + topParent.name + L" Command Line Argument: " + commandLineArg);
			CloseHandle(hProcess);
		}

		if (topParent.certStatus == ProcessEnumerator::REVOKED || topParent.certStatus == ProcessEnumerator::UNTRUSTED_SIGNER) {
			proc.suspicionScore += 5;
			proc.suspicionReason.push_back(std::wstring(L"[!] Untrusted top-most parent signature: ") + topParent.name);
		}
	}
}

bool SignatureChecker::getModules(DWORD pid, ProcessEnumerator& proc, std::unordered_map<DWORD, ProcessEnumerator::ProcessInformation>& processSnapshot) {
	HMODULE hMods[1024];
	HANDLE hProcess;
	DWORD cbNeeded;
	unsigned int i;
	ProcessEnumerator::fileVerification filerVer;

	

	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
		PROCESS_VM_READ, FALSE, pid);

	if (!hProcess) {
		return false;
	}

	auto ProcIt = processSnapshot.find(pid);
	if (ProcIt == processSnapshot.end())
		return false;

	if (EnumProcessModulesEx(hProcess, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL)) {

		for (i = 0; i < (cbNeeded / sizeof(HMODULE)); ++i) {
			TCHAR szModName[MAX_PATH];
			std::wstring lowerModName = szModName;
			std::transform(lowerModName.begin(), lowerModName.end(), lowerModName.begin(), ::tolower);

			if (GetModuleFileNameEx(hProcess, hMods[i], szModName,
				sizeof(szModName) / sizeof(TCHAR))) {

				if (whitelist.doesContain(lowerModName) || whitelist.doesContain(szModName)) {
					continue;
				}

				bool relative = proc.isRelativePath(szModName);
				bool suspicious = proc.isDLLPathSuspicious(szModName);


				if (relative && suspicious) {

					filerVer = getCachedSignature(szModName);

					if (filerVer == ProcessEnumerator::ADMIN) {
						ProcIt->second.suspicionScore += 5;
						ProcIt->second.suspicionReason.push_back(std::wstring(L"[!] DLL File, Certificate, or Publish is explicitly untrusted: ") + szModName);
					}
					else if (filerVer == ProcessEnumerator::UNTRUSTED_SIGNER) {
						ProcIt->second.suspicionScore += 5;
						ProcIt->second.suspicionReason.push_back(std::wstring(L"[!] DLL File signature is not trusted: ") + szModName);
					}
					else if (filerVer == ProcessEnumerator::TAMPERED) {
						ProcIt->second.suspicionScore += 3;
						ProcIt->second.suspicionReason.push_back(std::wstring(L"[!] DLL File has been tampered with: ") + szModName);
					}

					ProcIt->second.suspicionReason.push_back(std::wstring(L"[!] DLL path is extremely suspicous: ") + szModName);
					ProcIt->second.suspicionScore += 4;
					continue;
				}
				else if (suspicious) {
					filerVer = getCachedSignature(szModName);

					if (filerVer == ProcessEnumerator::ADMIN) {
						ProcIt->second.suspicionScore += 5;
						ProcIt->second.suspicionReason.push_back(std::wstring(L"[!] DLL File, Certificate, or Publish is explicitly untrusted: ") + szModName);
					}
					else if (filerVer == ProcessEnumerator::UNTRUSTED_SIGNER) {
						ProcIt->second.suspicionScore += 5;
						ProcIt->second.suspicionReason.push_back(std::wstring(L"[!] DLL File signature is not trusted: ") + szModName);
					}
					else if (filerVer == ProcessEnumerator::TAMPERED) {
						ProcIt->second.suspicionScore += 3;
						ProcIt->second.suspicionReason.push_back(std::wstring(L"[!] DLL File has been tampered with: ") + szModName);
					}

					ProcIt->second.suspicionReason.push_back(std::wstring(L"[!] DLL path is suspicous: ") + szModName);
					ProcIt->second.suspicionScore += 2;
					continue;
				}
				else if (relative) {
					filerVer = getCachedSignature(szModName);

					if (filerVer == ProcessEnumerator::ADMIN) {
						ProcIt->second.suspicionScore += 5;
						ProcIt->second.suspicionReason.push_back(std::wstring(L"[!] DLL File, Certificate, or Publish is explicitly untrusted: ") + szModName);
					}
					else if (filerVer == ProcessEnumerator::UNTRUSTED_SIGNER) {
						ProcIt->second.suspicionScore += 5;
						ProcIt->second.suspicionReason.push_back(std::wstring(L"[!] DLL File signature is not trusted: ") + szModName);
					}
					else if (filerVer == ProcessEnumerator::TAMPERED) {
						ProcIt->second.suspicionScore += 3;
						ProcIt->second.suspicionReason.push_back(std::wstring(L"[!] DLL File has been tampered with: ") + szModName);
					}

					ProcIt->second.suspicionReason.push_back(std::wstring(L"[!] DLL path is relative : ") + szModName);
					ProcIt->second.suspicionScore += 2;
					continue;
				}
			}
		}
	}
	else {
		CloseHandle(hProcess);
		return false;
	}

	CloseHandle(hProcess);
	return true;
}

std::wstring SignatureChecker::getCommandLineBuffer(HANDLE hProcess) {

	HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
	if (!hNtdll)
		return L"";

	auto NtQueryInformationProcess =
		(NtQueryInformationProcess_t)GetProcAddress(hNtdll, "NtQueryInformationProcess");
	if (!NtQueryInformationProcess) {
		return L"";
	}

	PROCESS_BASIC_INFORMATION pbi{};
	NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), nullptr);

	if (!NT_SUCCESS(status) || !pbi.PebBaseAddress) {
		return L"";
	}
	
	PEB peb{};
	if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), nullptr)) {
		return L"";
	}
	if (!peb.ProcessParameters)
		return L"";

	RTL_USER_PROCESS_PARAMETERS params{};
	if (!ReadProcessMemory(hProcess, peb.ProcessParameters, &params, sizeof(params), nullptr)) {
		return L"";
	}

	if (!params.CommandLine.Buffer || params.CommandLine.Length == 0)
		return L"";

	std::wstring commandLine;
	commandLine.resize(params.CommandLine.Length / sizeof(wchar_t));

	if (!ReadProcessMemory(hProcess, params.CommandLine.Buffer, commandLine.data(), params.CommandLine.Length, nullptr)) {
		return L"";
	}
	return commandLine;
}

