#include <iostream>
#include <Windows.h>
#include <thread>
#include "ProcessEnumerator.h"
#include "SignatureChecker.h"
#include "Logger.h"

bool quit = false;
SignatureChecker sigCheck;
ProcessEnumerator procEnum;

struct RegistryWatchKey {
    HKEY hive;
    std::wstring path;
    std::wstring name;
};

std::vector<RegistryWatchKey> persistenceKeys = {
    { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", L"HKCU Run" },
    { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", L"HKLM Run" },
    { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", L"HKCU RunOnce" },
    { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", L"HKLM RunOnce" }
};

void RegistryWatcherThread()
{
    Logger logger(L"logfile.txt");

    struct KeyInfo {
        HKEY hKey;
        HANDLE hEvent;
        RegistryWatchKey regKey;
        std::unordered_map<std::wstring, std::wstring> values; // snapshot of name -> data
    };

    std::vector<KeyInfo> watchKeys;

    for (auto& key : persistenceKeys) {
        HKEY hKey;
        if (RegOpenKeyExW(key.hive, key.path.c_str(), 0, KEY_READ | KEY_NOTIFY, &hKey) == ERROR_SUCCESS) {

            HANDLE hEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
            if (!hEvent) {
                RegCloseKey(hKey);
                continue;
            }

            std::unordered_map<std::wstring, std::wstring> snapshot;
            DWORD index = 0;
            WCHAR valueName[256];
            WCHAR valueData[1024];
            DWORD nameSize, dataSize, type;

            while (true) {
                nameSize = _countof(valueName);
                dataSize = sizeof(valueData);
                LONG ret = RegEnumValueW(hKey, index, valueName, &nameSize, nullptr, &type, (LPBYTE)valueData, &dataSize);
                if (ret == ERROR_NO_MORE_ITEMS) break;
                if (ret == ERROR_SUCCESS && type == REG_SZ) {
                    snapshot[valueName] = valueData;
                }
                ++index;
            }

            watchKeys.push_back({ hKey, hEvent, key, snapshot });

            RegNotifyChangeKeyValue(hKey, TRUE, REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET, hEvent, TRUE);
        }
        else {
            std::wcout << L"[!] Failed to open registry key: " << key.name << std::endl;
        }
    }

    // Main loop
    while (!quit) {
        if (watchKeys.empty()) {
            Sleep(1000);
            continue;
        }

        std::vector<HANDLE> events;
        for (auto& k : watchKeys) events.push_back(k.hEvent);

        DWORD waitResult = WaitForMultipleObjects((DWORD)events.size(), events.data(), FALSE, 1000);

        if (waitResult >= WAIT_OBJECT_0 && waitResult < WAIT_OBJECT_0 + events.size()) {
            size_t idx = waitResult - WAIT_OBJECT_0;
            auto& keyInfo = watchKeys[idx];

            std::unordered_map<std::wstring, std::wstring> currentValues;
            DWORD index = 0;
            WCHAR valueName[256];
            WCHAR valueData[1024];
            DWORD nameSize, dataSize, type;

            while (true) {
                nameSize = _countof(valueName);
                dataSize = sizeof(valueData);
                LONG ret = RegEnumValueW(keyInfo.hKey, index, valueName, &nameSize, nullptr, &type, (LPBYTE)valueData, &dataSize);
                if (ret == ERROR_NO_MORE_ITEMS) break;
                if (ret == ERROR_SUCCESS && type == REG_SZ) {
                    currentValues[valueName] = valueData;
                }
                ++index;
            }

            for (auto& [name, data] : currentValues) {
                if (keyInfo.values.find(name) == keyInfo.values.end()) {
                    std::wcout << L"[!] New startup entry detected in " << keyInfo.regKey.name
                        << L": " << name << L" -> " << data << std::endl;

                    std::wstring logMessage = L"New startup entry detected: " + keyInfo.regKey.name + L" " + name + L" -> " + data;

                    logger.log(WARNING, logMessage); 

                }
            }

            keyInfo.values = currentValues;

            RegNotifyChangeKeyValue(keyInfo.hKey, TRUE, REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET, keyInfo.hEvent, TRUE);
        }
    }

    for (auto& k : watchKeys) {
        CloseHandle(k.hEvent);
        RegCloseKey(k.hKey);
    }
}

void ClearConsole()
{
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	if (hConsole == INVALID_HANDLE_VALUE) return;

	CONSOLE_SCREEN_BUFFER_INFO csbi;
	DWORD count;
	DWORD cellCount;

	if (!GetConsoleScreenBufferInfo(hConsole, &csbi)) return;

	cellCount = csbi.dwSize.X * csbi.dwSize.Y;

	FillConsoleOutputCharacter(hConsole, L' ', cellCount, { 0,0 }, &count);
	FillConsoleOutputAttribute(hConsole, csbi.wAttributes, cellCount, { 0,0 }, &count);
	SetConsoleCursorPosition(hConsole, { 0,0 });
}



void clearThread() {
    while (!quit) {
       ClearConsole();
       std::cout << " __      __.___         ________                       .___   \n"
           "/  \\    /  \\   | ____  /  _____/ __ _______ _______  __| _//\\      \n"
           "\\   \\/\\/   /   |/    \\/   \\  ___|  |  \\__  \\_  __ \\/ __ |  \\/ \n"
           " \\        /|   |   |  \\    \\_\\  \  |  // __ \\|  | \\/ /_/ |  /\\  \n"
           "  \\__/\\  / |___|___|  /\______  /____/(____  /__|  \\____ |  \\/     \n"
           "       \\/           \\/       \\/           \\/          \\/         \n";
       std::this_thread::sleep_for(std::chrono::seconds(10));
    }
}

int main() {
    std::cout << "\t\t\t\tAll suspicious activity is in the timed logfile.txt!" << std::endl;
    Sleep(3000);

    std::thread consoleGraphics(clearThread);
    std::thread regWatcher(RegistryWatcherThread);

    while (!quit) {

        procEnum.collectProcesses();
        if (procEnum.processMap.empty()) {
            std::wcout << L"[!] No Processes Collected\n";
        }

        sigCheck.analyseProcessBehavior(procEnum.processMap);
        sigCheck.parentProcesses(procEnum.processMap);
        procEnum.printSuspicious();
        procEnum.processMap.clear();
        Sleep(500);
    }

    quit = true;
    regWatcher.join();
    consoleGraphics.join();

    return 0;
}
