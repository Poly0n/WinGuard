#pragma once
#include <Windows.h>
#include <winnt.h>
#include <string>
#include "ProcessEnumerator.h"

class MemoryScan
{
public:
	bool analyseProcessMem(DWORD pid, ProcessEnumerator::ProcessInformation& procInf);
private:
	bool analyseRegion(MEMORY_BASIC_INFORMATION& mbi, ProcessEnumerator::ProcessInformation& procInf);
};
