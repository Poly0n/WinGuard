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
	trustData.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
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
	case TRUST_E_NOSIGNATURE:
		return ProcessEnumerator::NO_SIGNATURE;
	case TRUST_E_BAD_DIGEST:
		return ProcessEnumerator::TAMPERED;
	case CERT_E_UNTRUSTEDROOT:
		return ProcessEnumerator::UNTRUSTED_SIGNER;
	case CERT_E_REVOKED:
		return ProcessEnumerator::REVOKED;
	case CERT_E_EXPIRED:
		return ProcessEnumerator::EXPIRED;
	case TRUST_E_EXPLICIT_DISTRUST:
		return ProcessEnumerator::ADMIN;
	case CRYPT_E_SECURITY_SETTINGS:
		return ProcessEnumerator::POLICY_BLOCK;
	case CERT_E_CHAINING:
		return ProcessEnumerator::CHAIN_FAIL;
	default:
		return ProcessEnumerator::UNKNOWN;
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

bool SignatureChecker::getFileWritableCache(const std::wstring& path) {

	auto it = fileWritableCache.find(path);
	if (it != fileWritableCache.end())
		return it->second;

	HANDLE hFile = CreateFileW(path.c_str(), FILE_WRITE_DATA | FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	
	bool result = (hFile != INVALID_HANDLE_VALUE);

	if (result) {
		CloseHandle(hFile);
	}

	fileWritableCache[path] = result;

	return result;
}

std::wstring SignatureChecker::getExecutableDirectory() {
	wchar_t buffer[MAX_PATH];
	GetModuleFileNameW(nullptr, buffer, MAX_PATH);

	std::wstring path(buffer);
	size_t pos = path.find_last_of(L"\\/");
	return path.substr(0, pos);
}

void SignatureChecker::analyseProcessBehavior(std::unordered_map<DWORD, ProcessEnumerator::ProcessInformation>& processSnapshot) {

	for (auto& [pid, proc] : processSnapshot) {

		if (proc.path.empty() || proc.path == L"UNKNOWN")
			continue;

		std::wstring path = proc.path;
		std::transform(path.begin(), path.end(), path.begin(), ::towlower);

		if (whitelist.doesContain(proc.path) || whitelist.doesContain(path)) {
			continue;
		}
		
		proc.certStatus = ProcessEnumerator::UNKNOWN;
		proc.directoryWritable = false;
		proc.fileWritable = false;
		proc.suspicionScore = 0;
		proc.suspicionReason = {};

		ProcessEnumerator::fileVerification verify = getCachedSignature(proc.path);

		std::wstring directory;
		try {
			directory = std::filesystem::path(proc.path).parent_path().wstring();
		}
		catch (...) {
			directory = L"";
		}

		bool dirWritable = false;
		bool fileWritable = getFileWritableCache(proc.path);
		bool suspiciousPath = procEnum.isDLLPathSuspicious(proc.path);
		proc.fileWritable = fileWritable;

		if (!directory.empty()) {
			dirWritable = getCachedDirectory(directory);

			proc.directoryWritable = dirWritable;
			if (dirWritable) {
				proc.suspicionReason.push_back(std::wstring(L"[!] Directory is writable: ") + proc.path);
				proc.suspicionScore += 1;
			}
		}


		if (fileWritable) {
			proc.suspicionReason.push_back(std::wstring(L"[!] File is user writable: ") + proc.path);
			proc.suspicionScore += 1;
		}
		
		if (suspiciousPath) {
			proc.suspicionReason.push_back(std::wstring(L"[!] Directory is Suspicious: ") + proc.path);
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
		else if (verify == ProcessEnumerator::EXPIRED) {
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
			proc.suspicionScore += 3;
			proc.suspicionReason.push_back(std::wstring(L"[?] File signature status is unknown: ") + proc.name);
		}

	}
	
	return;
}

void SignatureChecker::parentProcesses(std::unordered_map<DWORD, ProcessEnumerator::ProcessInformation>& processSnapshot) {
	std::unordered_map<DWORD, DWORD> topParentCache;
	
	Logger log(L"logfile.txt");
	
	for (auto& [pid, proc] : processSnapshot) {
		
		if (proc.pid == 0)
			continue;

		DWORD current = pid;
		std::unordered_set<DWORD> visited;

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

		auto& first = proc;
		std::wstring commandLineArg;

		auto parentIt = processSnapshot.find(first.ppid);
		if (parentIt != processSnapshot.end()) {
			auto& parent = parentIt->second;

			std::wstring parentName = !parent.name.empty()
				? parent.name
				: std::filesystem::path(parent.path).filename().wstring();


			if (procEnum.isLOLBin(first.path) && !parent.path.empty() && procEnum.isPathUserLand(parent.path)) {
				if (procEnum.isDLLPathSuspicious(first.path)) {
					proc.suspicionScore += 4;
					proc.suspicionReason.push_back(std::wstring(L"[!] Possibly Malicious LOLBin Parent-Child Relationship: " + first.name + L"<-" + parentName));
				}
				proc.suspicionScore += 2;
				proc.suspicionReason.push_back(std::wstring(L"[!] Possible LOLBin Parent-Child Relationship: " + first.name + L"<-" + parentName));
			}

			if (procEnum.isPathUserLand(first.path) && !procEnum.isPathUserLand(parent.path)) {
				if (procEnum.isDLLPathSuspicious(parent.path)) {
					proc.suspicionScore += 1;
					proc.suspicionReason.push_back(std::wstring(L"[!] Suspicious Parent-Child Relationship: " + parentName + L"->" + first.name));
				}

			}

			if (parent.name == L"powershell.exe" || parent.name == L"cmd.exe" || parent.name == L"wscript.exe") {
				proc.suspicionScore += 1;
				proc.suspicionReason.push_back(std::wstring(L"[!] Suspicious Parent: ") + parent.name + L" From: " + first.name);

				auto commandIt = commandCache.find(parent.pid);
				if (commandIt == commandCache.end()) {
					HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, parent.pid);
					if (!hProcess) {
						continue;
					}

					commandLineArg = getCommandLineBuffer(hProcess);
					commandCache[parent.pid] = commandLineArg;
					CloseHandle(hProcess);

				}
				else {
					commandLineArg = commandIt->second;
				}

				if (procEnum.isCommandSuspicious(commandLineArg)) {
					log.log(CRITICAL, L"[!] Possible malicious command execution: " + commandLineArg);
					std::wcout << L"[!] " << parent.name << " Malicious Command Line Buffer:" << commandLineArg << std::endl;
					parent.suspicionReason.push_back(std::wstring(L"[!] Possible malicious command execution: " + commandLineArg));
					parent.suspicionScore += 2;
				}
				else {
					log.log(WARNING, L"Command Line Argument: " + commandLineArg);
					std::wcout << L"[!] " << parent.name << " Command Line Buffer:" << commandLineArg << std::endl;
					parent.suspicionReason.push_back(L"[!] " + parent.name + L" Command Line Argument: " + commandLineArg);
				}

			}

			if (parent.certStatus == ProcessEnumerator::REVOKED 
				|| parent.certStatus == ProcessEnumerator::UNTRUSTED_SIGNER 
				|| parent.certStatus == ProcessEnumerator::ADMIN) {
				proc.suspicionScore += 4;
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

		std::wstring topName = !topParent.name.empty() ? topParent.name : std::filesystem::path(topParent.path).filename().wstring();

		if (procEnum.isLOLBin(first.path) && !topParent.path.empty() && procEnum.isPathUserLand(topParent.path)) {
			if (procEnum.isDLLPathSuspicious(first.path)) {
				proc.suspicionScore += 4;
				proc.suspicionReason.push_back(std::wstring(L"[!] Possibly Malicious LOLBin Parent-Child Relationship: " + first.name + L"<-" + topName));
			}
			proc.suspicionScore += 2;
			proc.suspicionReason.push_back(std::wstring(L"[!] Possible LOLBin Parent-Child Relationship: " + first.name + L"<-" + topName));
		}

		if (topParent.name == L"powershell.exe" || topParent.name == L"cmd.exe" || topParent.name == L"wscript.exe") {
			proc.suspicionScore += 1;
			proc.suspicionReason.push_back(std::wstring(L"[!] Suspicious top-most parent: ") + topParent.name + L" From: " + topProcIt->second.name);
			
			auto commandIt = commandCache.find(topParent.pid);

			if (commandIt == commandCache.end()) {
				HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, topParent.pid);
				if (!hProcess) {
					continue;
				}

				std::wstring commandLineArg = getCommandLineBuffer(hProcess);
				commandCache[topParent.pid] = commandLineArg;
				CloseHandle(hProcess);
			}
			else {
				commandLineArg = commandIt->second;
			}
			
			if (procEnum.isCommandSuspicious(commandLineArg)) {
				log.log(CRITICAL, L"[!] Possible malicious command execution: " + commandLineArg);
				std::wcout << L"[!] " << topParent.name << " Malicious Command Line Buffer:" << commandLineArg << std::endl;
				topParent.suspicionReason.push_back(std::wstring(L"[!] Possible malicious command execution: " + commandLineArg));
				topParent.suspicionScore += 2;
			}
			else {
				log.log(WARNING, L"Command Line Argument: " + commandLineArg);
				std::wcout << L"[!] " << topParent.name << " Command Line Buffer:" << commandLineArg << std::endl;
				topParent.suspicionReason.push_back(L"[!] " + topParent.name + L" Command Line Argument: " + commandLineArg);
			}

		}

		if (topParent.certStatus == ProcessEnumerator::REVOKED
			|| topParent.certStatus == ProcessEnumerator::UNTRUSTED_SIGNER 
			|| topParent.certStatus == ProcessEnumerator::ADMIN) {
			proc.suspicionScore += 4;
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
	if (ProcIt == processSnapshot.end()) {
		CloseHandle(hProcess);
		return false;
	}		

	if (EnumProcessModulesEx(hProcess, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL)) {

		for (i = 0; i < (cbNeeded / sizeof(HMODULE)); ++i) {
			auto it = moduleCache.find(pid);
			if (it == moduleCache.end()) {
				it = moduleCache.emplace(pid, std::unordered_set<std::wstring>{}).first;
			}

			auto& moduleSet = it->second;
			
			TCHAR szModName[MAX_PATH];

			if (GetModuleFileNameEx(hProcess, hMods[i], szModName,
				sizeof(szModName) / sizeof(TCHAR))) {

				std::wstring moduleName(szModName);
				;

				if (!moduleSet.emplace(moduleName).second) {
					continue;
				}


				if (whitelist.doesContain(moduleName)) {
					continue;
				}

				bool relative = proc.isRelativePath(moduleName);
				bool suspicious = proc.isDLLPathSuspicious(moduleName);
				bool userland = proc.isPathUserLand(moduleName);

				std::wstring moduleDir;

				try {
					moduleDir = std::filesystem::path(moduleName).parent_path().wstring();
				}
				catch (...) {
					moduleDir = L"";
				}

				bool writableDir = !moduleDir.empty() && getCachedDirectory(moduleDir);

				if (userland && writableDir) {
					ProcIt->second.suspicionScore += 2;
					ProcIt->second.suspicionReason.push_back(std::wstring(L"[!] DLL Loaded in Writable Directory in Userland: ") + moduleName);
				}

				if (relative && suspicious) {
					filerVer = getCachedSignature(moduleName);

					if (filerVer == ProcessEnumerator::ADMIN) {
						ProcIt->second.suspicionScore += 5;
						ProcIt->second.suspicionReason.push_back(std::wstring(L"[!] DLL File, Certificate, or Publish is explicitly untrusted: ") + moduleName);
					}
					else if (filerVer == ProcessEnumerator::UNTRUSTED_SIGNER) {
						ProcIt->second.suspicionScore += 5;
						ProcIt->second.suspicionReason.push_back(std::wstring(L"[!] DLL File signature is not trusted: ") + moduleName);
					}
					else if (filerVer == ProcessEnumerator::TAMPERED) {
						ProcIt->second.suspicionScore += 3;
						ProcIt->second.suspicionReason.push_back(std::wstring(L"[!] DLL File has been tampered with: ") + moduleName);
					}
					else {
						ProcIt->second.suspicionReason.push_back(std::wstring(L"[!] DLL path is extremely suspicious: ") + moduleName);
						ProcIt->second.suspicionScore += 4;
						continue;
					}
					
				}
				else if (suspicious) {
					filerVer = getCachedSignature(moduleName);

					if (filerVer == ProcessEnumerator::SUCCESS) {
						ProcIt->second.suspicionScore += .5;
						ProcIt->second.suspicionReason.push_back(std::wstring(L"[!] Signed DLL Path Is Suspicious: ") + moduleName);
					}

					else if (filerVer == ProcessEnumerator::ADMIN) {
						ProcIt->second.suspicionScore += 5;
						ProcIt->second.suspicionReason.push_back(std::wstring(L"[!] DLL File, Certificate, or Publish is explicitly untrusted: ") + moduleName);
					}
					else if (filerVer == ProcessEnumerator::UNTRUSTED_SIGNER) {
						ProcIt->second.suspicionScore += 5;
						ProcIt->second.suspicionReason.push_back(std::wstring(L"[!] DLL File signature is not trusted: ") + moduleName);
					}
					else if (filerVer == ProcessEnumerator::TAMPERED) {
						ProcIt->second.suspicionScore += 3;
						ProcIt->second.suspicionReason.push_back(std::wstring(L"[!] DLL File has been tampered with: ") + moduleName);
					}
					else if (filerVer == ProcessEnumerator::NO_SIGNATURE) {
						ProcIt->second.suspicionReason.push_back(std::wstring(L"[!] DLL Unsigned, path is suspicious: ") + moduleName);
						ProcIt->second.suspicionScore += 2;
					}
					else {
						ProcIt->second.suspicionReason.push_back(std::wstring(L"[!] DLL Path Is Suspicious: ") + moduleName);
						ProcIt->second.suspicionScore += 1;
					}
				}
				else if (relative) {
					filerVer = getCachedSignature(moduleName);

					if (filerVer == ProcessEnumerator::SUCCESS) {
						ProcIt->second.suspicionScore += 1;
						ProcIt->second.suspicionReason.push_back(std::wstring(L"[!] Signed DLL Is Relative: ") + moduleName);
						continue;
					}
					else if (filerVer == ProcessEnumerator::ADMIN) {
						ProcIt->second.suspicionScore += 5;
						ProcIt->second.suspicionReason.push_back(std::wstring(L"[!] DLL File, Certificate, or Publish is explicitly untrusted: ") + moduleName);
						continue;
					}
					else if (filerVer == ProcessEnumerator::UNTRUSTED_SIGNER) {
						ProcIt->second.suspicionScore += 5;
						ProcIt->second.suspicionReason.push_back(std::wstring(L"[!] DLL File signature is not trusted: ") + moduleName);
						continue;
					}
					else if (filerVer == ProcessEnumerator::TAMPERED) {
						ProcIt->second.suspicionScore += 3;
						ProcIt->second.suspicionReason.push_back(std::wstring(L"[!] DLL File has been tampered with: ") + moduleName);
						continue;
					}

					ProcIt->second.suspicionReason.push_back(std::wstring(L"[!] DLL path is relative : ") + moduleName);
					ProcIt->second.suspicionScore += 2;
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

