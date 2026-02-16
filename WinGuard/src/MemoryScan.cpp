#include "MemoryScan.h"

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
			if (analyseRegion(MemBasic, procInf)) {
				suspicious = true;
			}
		}
		
		address += MemBasic.RegionSize;
	}

	CloseHandle(hProcess);
	return suspicious;
}

bool MemoryScan::analyseRegion(MEMORY_BASIC_INFORMATION& mbi, ProcessEnumerator::ProcessInformation& procInf) {
	
	if (mbi.RegionSize > 10000000 && mbi.Type == MEM_IMAGE) {
		return false;
	}
	
	if (mbi.Protect & PAGE_GUARD)
		return false;

	bool isExecutable =
		(mbi.Protect & PAGE_EXECUTE) ||
		(mbi.Protect & PAGE_EXECUTE_READ);

	if (mbi.Type == MEM_PRIVATE && mbi.Protect & (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
		procInf.suspicionScore += 6;
		procInf.suspicionReason.push_back(std::wstring(L"[!] RWX private memory region detected in: " + procInf.name));

		return true;
	}
	else if (mbi.Type == MEM_PRIVATE && isExecutable) {
		procInf.suspicionScore += 4;
		procInf.suspicionReason.push_back(std::wstring(L"[!] Private executable memory detected in: " + procInf.name));
		return true;
	}

	return false;
}
