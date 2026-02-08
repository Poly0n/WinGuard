#pragma once
#include <fstream>
#include <string>

class Whitelist {
public:
    void addWhiteList(const std::wstring& process) {
        std::wifstream in("whitelist.txt");
        std::wstring line;

        while (std::getline(in, line)) {
            if (line == process) {
                return;
            }
        }
        in.close();

        std::wofstream out("whitelist.txt", std::ios::app);
        if (out.is_open()) {
            out << process << L'\n';
        }
    }

    bool doesContain(const std::wstring& process) {
        std::wifstream in("whitelist.txt");
        std::wstring line;

        while (std::getline(in, line)) {
            if (line == process) {
                return true;
            }
        }
        return false;
    }
};