#include "MemoryScan.h"

double MemoryScan::calculateEntropy(const BYTE* data, size_t size) {
	if (size == 0)
		return 0.0;

	double entropy = 0.0;
	int counts[256] = { 0 };

	for (size_t i = 0; i < size; ++i) {
		counts[data[i]]++;
	}

	for (int i = 0; i < 256; ++i) {
		if (counts[i] == 0)
			continue;

		double p = static_cast<double>(counts[i]) / size;
		entropy -= p * log2(p);
	}

	return entropy;
}

bool MemoryScan::analyseProcessMem(DWORD pid, ProcessEnumerator::ProcessInformation& procInf) {

	bool suspicious = false;

	BYTE* address = 0;

	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (!hProcess) {
		std::cerr << "[!] AnalyseProcessMem Failed to OpenProcess with error:" << GetLastError() << std::endl;
		return false;
	}

	MEMORY_BASIC_INFORMATION MemBasic;
	
	while (VirtualQueryEx(hProcess, address, &MemBasic, sizeof(MemBasic)) == sizeof(MemBasic)) {
		
		if (MemBasic.State == MEM_COMMIT) {
			if (analyseRegion(MemBasic, procInf, hProcess)) {
				suspicious = true;
			}
		}
		
		address += MemBasic.RegionSize;
	}

	CloseHandle(hProcess);
	return suspicious;
}

bool MemoryScan::analyseRegion(MEMORY_BASIC_INFORMATION& mbi, ProcessEnumerator::ProcessInformation& procInf, HANDLE hProcess) {
	
	if (mbi.RegionSize > 2 * 1024 * 1024 || mbi.Type == MEM_IMAGE) {
		return false;
	}
	
	if (mbi.Protect & PAGE_GUARD)
		return false;

	bool isExecutable =
		(mbi.Protect & PAGE_EXECUTE) ||
		(mbi.Protect & PAGE_EXECUTE_READ);

	if (mbi.Type == MEM_PRIVATE && mbi.Protect & (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
		
		BYTE buffer[4096];
		SIZE_T bytesRead = 0;

		if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer, sizeof(buffer), &bytesRead)) {
			double entropy = calculateEntropy(buffer, bytesRead);

			if (entropy > 7.2) {
				procInf.suspicionScore += 2;
				procInf.suspicionReason.push_back(std::wstring(L"[!] High entropy in process: " + procInf.name));
			}
		}
		
		procInf.suspicionScore += 3;
		procInf.suspicionReason.push_back(std::wstring(L"[!] RWX private memory region detected in: " + procInf.name));

		return true;
	}
	else if (mbi.Type == MEM_PRIVATE && isExecutable) {

		BYTE buffer[4096];
		SIZE_T bytesRead = 0;

		if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer, sizeof(buffer), &bytesRead)) {
			double entropy = calculateEntropy(buffer, bytesRead);

			if (entropy > 7.2) {
				procInf.suspicionScore += 2;
				procInf.suspicionReason.push_back(std::wstring(L"[!] High entropy in process: " + procInf.name));
			}
		}

		procInf.suspicionScore += 2;
		procInf.suspicionReason.push_back(std::wstring(L"[!] Private executable memory detected in: " + procInf.name));

		return true;
	}

	return false;
}
