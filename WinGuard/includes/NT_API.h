#pragma once
#include <winternl.h>

typedef struct _MY_SYSTEM_PROCESS_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;

    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;

    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;

    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;

    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;

} MY_SYSTEM_PROCESS_INFORMATION;
