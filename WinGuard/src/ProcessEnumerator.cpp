#include "ProcessEnumerator.h"

void ProcessEnumerator::collectProcesses() {
	processMap.clear();
	processMap.reserve(512);
	
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
		return;

	PROCESSENTRY32W pe;
	pe.dwSize = sizeof(PROCESSENTRY32W);

	if (Process32FirstW(hSnapshot, &pe)) {
		do {
			ProcessInformation procInfo;

			procInfo.name = pe.szExeFile;
			procInfo.pid = pe.th32ProcessID;
			procInfo.ppid = pe.th32ParentProcessID;
			procInfo.path = getPath(procInfo.pid);

			processMap.emplace(procInfo.pid, std::move(procInfo));

		} while (Process32NextW(hSnapshot, &pe));
	}
	CloseHandle(hSnapshot);
	return;
}

std::wstring ProcessEnumerator::getPath(DWORD pid) const {
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);

	if (hProcess == NULL) {
		return L"UNKNOWN";
	}

	wchar_t path[MAX_PATH];
	DWORD size = MAX_PATH;

	if (!QueryFullProcessImageNameW(hProcess, 0, path, &size)) {
		std::cerr << "[-] QueryFullProcessImageA Failed: " << GetLastError() << std::endl;
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
		path.find(L"\\AppData\\Roaming") != std::wstring::npos) {
		
		return true;
	}

	return false;

}
