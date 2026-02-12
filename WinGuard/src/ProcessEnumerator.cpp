#include "ProcessEnumerator.h"

DWORDLONG CYCLE_COUNT = 0;

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
		DWORD_PTR pid = reinterpret_cast<DWORD_PTR>(spi->UniqueProcessId);
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
		return L"";
	}

	CloseHandle(hProcess);
	return std::wstring(path, size);
}

void ProcessEnumerator::printSuspicious() {
	Logger logger(L"logfile.txt");
	for (auto& [pid, proc] : processMap) {
		if (proc.suspicionScore > 8) {
			std::wcout << "[!] " << proc.name << " is a malicious program" << std::endl;
			for (size_t i = 0; i < proc.suspicionReason.size(); ++i) {
				logger.log(WARNING, proc.suspicionReason[i]);
				std::wcout << "\t" << proc.suspicionReason[i] << std::endl;
			}
		}
		else if (proc.suspicionScore > 6) {
			std::wcout << "[!] " << proc.name << " is a highly suspicious process" << std::endl;
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
		return true;
	
	if (path.starts_with(L"\\\\"))
		return false;

	if (path.size() > 2 && path[1] == L':' && path[2] == L'\\')
		return false;

	return true;
}

bool ProcessEnumerator::isDLLPathSuspicious(const std::wstring& path) {
	if (path.empty())
		return false;
	
	if (path.find(L"\\Downloads\\") != std::wstring::npos || 
	path.find(L"\\AppData\\Local\\Temp\\") != std::wstring::npos || 
	path.find(L"\\AppData\\Roaming") != std::wstring::npos ||
	path.find(L"\\Windows\\Temp") != std::wstring::npos || 
	path.find(L"\\ProgramData\\") != std::wstring::npos || 
	path.find(L"\\$Recycle.Bin\\") != std::wstring::npos) {
	
		return true;
	}

	return false;
}

