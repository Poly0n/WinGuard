#pragma once
#include <ctime>
#include <fstream>
#include <iostream>
#include <string>
#include <sstream>

enum LogLevel { DEBUG, INFO, WARNING, ERR, CRITICAL };

class Logger
{
public:
	Logger(const std::wstring& filename) {
		logFile.open(filename, std::ios::app);
		if (!logFile.is_open()) {
			std::cerr << "Error opening log file." << std::endl;
		}
	}

	~Logger() { logFile.close(); }

	void log(LogLevel level, const std::wstring& message) {
		time_t now = time(nullptr);
		struct tm buf;
		if (localtime_s(&buf, &now) != 0) {
			std::cerr << "Failed to get local time" << std::endl;
		}
		char timestamp[20];
		strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &buf);
		
		std::wstringstream logEntry;
		logEntry << L"[" << timestamp << L"] " << levelToString(level) << L": "
			<< message << std::endl;

		if (logFile.is_open()) {
			logFile << logEntry.str();
			logFile.clear();
		}
	}
private:
	std::wofstream logFile;
	std::wstring levelToString(LogLevel level) {
		switch (level) {
		case DEBUG:
			return L"DEBUG";
		case INFO:
			return L"INFO";
		case WARNING:
			return L"WARNING";
		case ERR:
			return L"ERROR";
		case CRITICAL:
			return L"CRITICAL";
		default:
			return L"UNKNOWN";
		}
	}
};

