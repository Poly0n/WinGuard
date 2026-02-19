#include "ProcessEnumerator.h"
#include "MemoryScan.h"

DWORDLONG CYCLE_COUNT = 0;
Logger logger(L"logfile.txt");
MemoryScan memScan;

NtQuerySystemInformation_t getNtQuerySystemInformation() {
	static NtQuerySystemInformation_t p =
		(NtQuerySystemInformation_t)GetProcAddress(
			GetModuleHandleW(L"ntdll.dll"),
			"NtQuerySystemInformation"
		);
	return p;
}

void ProcessEnumerator::collectProcesses() {

	NtQuerySystemInformation_t pNtQuerySystemInformation = getNtQuerySystemInformation();
	if (!pNtQuerySystemInformation) {
		std::wcerr << L"Failed to get NtQuerySystemInformation pointer!" << std::endl;
		return;
	}

	CYCLE_COUNT++;

	ULONG bufferSize = 0x10000;
	std::vector<BYTE> buffer;
	NTSTATUS status = 0;
	ULONG returnLength = 0;

	do {
		buffer.resize(bufferSize);
		status = pNtQuerySystemInformation(
			SystemProcessInformation,
			buffer.data(),
			bufferSize,
			&returnLength
		);

		if (status == 0xC0000004) {
			bufferSize = returnLength > 0 ? returnLength : bufferSize * 2;
		}
		else if (!NT_SUCCESS(status)) {
			std::wcerr << L"NtQuerySystemInformation failed: " << std::hex << status << std::endl;
			return;
		}

	} while (status == 0xC0000004);

	auto* spi = reinterpret_cast<_MY_SYSTEM_PROCESS_INFORMATION*>(buffer.data());

	while (true) {
		DWORD pid = static_cast<DWORD>(reinterpret_cast<uintptr_t>(spi->UniqueProcessId));
		DWORD_PTR ppid = reinterpret_cast<DWORD_PTR>(spi->InheritedFromUniqueProcessId);

		std::wstring name;
		if (spi->ImageName.Buffer)
			name.assign(spi->ImageName.Buffer, spi->ImageName.Length / sizeof(WCHAR));
		else
			name = L"System";

		auto it = processMap.find(static_cast<DWORD>(pid));

		if (it == processMap.end()) {
			ProcessInformation info;
			info.pid = static_cast<DWORD>(pid);
			info.ppid = static_cast<DWORD>(ppid);
			info.path = getPath(static_cast<DWORD>(pid));
			info.name = name;
			info.cycleCounter = CYCLE_COUNT;

			processMap.emplace(static_cast<DWORD>(pid), std::move(info));
		}
		else {
			it->second.cycleCounter = CYCLE_COUNT;
			it->second.ppid = static_cast<DWORD>(ppid);
		}

		if (spi->NextEntryOffset == 0)
			break;

		spi = reinterpret_cast<_MY_SYSTEM_PROCESS_INFORMATION*>(
			reinterpret_cast<BYTE*>(spi) + spi->NextEntryOffset
			);
	}

	for (auto it = processMap.begin(); it != processMap.end();) {
		if (it->second.cycleCounter != CYCLE_COUNT)
			it = processMap.erase(it);
		else
			++it;
	}

}

std::wstring ProcessEnumerator::getPath(DWORD pid) const {
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);

	if (hProcess == NULL) {
		return L"UNKNOWN";
	}

	wchar_t path[MAX_PATH];
	DWORD size = MAX_PATH;

	if (!QueryFullProcessImageNameW(hProcess, 0, path, &size)) {
		CloseHandle(hProcess);
		return L"UNKNOWN";
	}

	CloseHandle(hProcess);
	return std::wstring(path, size);
}

void ProcessEnumerator::printSuspicious() {
	for (auto& [pid, proc] : processMap) {
		if (proc.suspicionScore > 8) {
			std::wcout << "[!] " << proc.name << " is a malicious program" << std::endl;
			std::wcout << L"Conducting Memory Scan On:" << proc.name << std::endl;
			if (!proc.memoryScanned) {
				if (memScan.analyseProcessMem(proc.pid, proc)) {
					std::wcout << L"[+] Memory Read Successful!" << std::endl;
				}
				else {
					std::wcout << L"[-] Memory Read Failed" << std::endl;
				}
				
			}
			proc.memoryScanned = true;

			for (size_t i = 0; i < proc.suspicionReason.size(); ++i) {
				logger.log(WARNING, proc.suspicionReason[i]);
				std::wcout << "\t" << proc.suspicionReason[i] << std::endl;
			}
			
		}
		else if (proc.suspicionScore > 6) {
			std::wcout << L"[!] " << proc.name << L" is a highly suspicious process" << std::endl;
			std::wcout << L"Conducting Memory Scan On:" << proc.name << std::endl;
			if (!proc.memoryScanned) {
				if (memScan.analyseProcessMem(proc.pid, proc)) {
					std::wcout << L"[+] Memory Read Successful!" << std::endl;
				}
				else {
					std::wcout << L"[-] Memory Read Failed" << std::endl;
				}

			}
			proc.memoryScanned = true;
			
			for (size_t i = 0; i < proc.suspicionReason.size(); ++i) {
				logger.log(WARNING, proc.suspicionReason[i]);
				std::wcout << "\t" << proc.suspicionReason[i] << std::endl;
			}
			
		}
		else if (proc.suspicionScore > 4) {
			std::wcout << "[!] " << proc.name << " is a suspicious program" << std::endl;
			for (size_t i = 0; i < proc.suspicionReason.size(); ++i) {
				logger.log(WARNING, proc.suspicionReason[i]);
				std::wcout << "\t" << proc.suspicionReason[i] << std::endl;
			}
		}
	}

	return;
}

bool ProcessEnumerator::isRelativePath(const std::wstring& path) {
	if (path.empty())
		return false;

	if (path.starts_with(L"\\\\"))
		return false;

	if (path.size() > 3 && path[1] == L':' && path[2] == L'\\')
		return false;

	return true;
}

bool ProcessEnumerator::isDLLPathSuspicious(const std::wstring& path) {
	std::wstring lower = path;
	std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

	if (lower.empty())
		return false;

	std::filesystem::path p(lower);

	static const std::vector<std::wstring>susPaths = {
		L"temp",
		L"appdata",
		L"downloads",
		L"programdata",
		L"public"
	};

	for (const auto& part : p) {
		for (const auto& suspect : susPaths) {
			if (_wcsicmp(part.c_str(), suspect.c_str()) == 0) {
				return true;
			}

		}
	}

	return false;
}

std::wstring ProcessEnumerator::getKnownFolder(REFKNOWNFOLDERID folderId) {
	PWSTR path = nullptr;
	std::wstring result;

	if (SUCCEEDED(SHGetKnownFolderPath(folderId, KF_FLAG_DEFAULT, NULL, &path))) {
		result = path;
		CoTaskMemFree(path);
	}

	return result;
}


bool ProcessEnumerator::isPathUserLand(const std::wstring& modName) {
	if (modName.empty())
		return false;

	if (!std::filesystem::exists(modName)) {
		return false;
	}

	std::filesystem::path p;

	try {
		p = std::filesystem::weakly_canonical(modName);
	}
	catch(...) {
		return false;
	}

	std::filesystem::path windowsDir = getKnownFolder(FOLDERID_Windows);
	std::filesystem::path programFiles = getKnownFolder(FOLDERID_ProgramFiles);
	std::filesystem::path programFilesX86 = getKnownFolder(FOLDERID_ProgramFilesX86);
	std::filesystem::path system32 = getKnownFolder(FOLDERID_System);
	std::filesystem::path systemX86 = getKnownFolder(FOLDERID_SystemX86);


	if (p.string().starts_with(windowsDir.string()) ||
		p.string().starts_with(programFiles.string()) ||
		p.string().starts_with(programFilesX86.string()) ||
		p.string().starts_with(system32.string()) ||
		p.string().starts_with(systemX86.string())) {
		return false;
	}

	return true;
}

bool ProcessEnumerator::isLOLBin(const std::wstring& path) {
	std::wstring filename = std::filesystem::path(path).filename().wstring();

	std::transform(filename.begin(), filename.end(), filename.begin(), ::towlower);

	static const std::unordered_set<std::wstring> lolbins = {
		L"rundll32.exe",
		L"mshta.exe",
		L"regsvr32.exe",
		L"wmic.exe",
		L"certutil.exe",
		L"installutil.exe",
		L"msbuild.exe",
		L"cscript.exe",
		L"schtasks.exe",
		L"bitsadmin.exe"
	};

	return lolbins.contains(filename);
}

bool ProcessEnumerator::isCommandSuspicious(const std::wstring& command) {

	std::wstring lower = command;
	std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

	static const std::vector<std::wstring> flags = {
		L"-enc",
		L"-encodedcommand",
		L"-nop",
		L"-w hidden",
		L"-executionpolicy bypass",
		L"iex(",
		L"downloadstring",
		L"cmd /c powershell",
		L"certutil -decode",
		L"bitsadmin",
		L"mshta http",
	};

	for (auto& token : flags) {
		if (lower.find(token) != std::wstring::npos) {
			return true;
		}
	}

	return false;
}
