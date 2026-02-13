
# <p align="center"><img width="582" height="119" alt="winguard_logo" src="https://github.com/user-attachments/assets/fc2fb2de-f743-4af6-acbb-34f69ef3bce8" /></p><p align="center">![Platform](https://img.shields.io/badge/platform-Windows-blue)  ![Language](https://img.shields.io/badge/language-C%2B%2B20-orange)</p>
 
> WinGuard is an educational / experimental EDR and is not intended to replace enterprise-grade security software.

<b>Basic Windows EDR (Endpoint Detection and Response) To Help Monitor And Log Any Suspicious Processes Or Commands Running On Your PC.</b>

## **Key Features**
### Process & Execution Monitoring
  - Dumps any command line buffers that a process may try to run
  - Detects any abnormal parent processes (spawning PowerShell, CMD, or WScript)
  - Verifies running processes and DLLs for signature abnormalities (no signature, tampered file, untrusted signature, etc.)
### File System Analysis
  - Scans for processes and DLLs running from abnormal directories (%TEMP%, %APPDATA%, etc.)
  - Detects processes, DLLs, and directories running that are user-writable
### Persistence Detection
  - Scans for changes in the Registry for persistence
### Logging Capabilities
  - Ability to log the exact time a detection occurs
  - Ability to white-list any app using the *whitelist.txt* file

## **Example Detections**

<p align="center">
<img width="900" height="700" alt="Malware Spawning ugate.exe" src="https://github.com/user-attachments/assets/7da2d672-2ab6-45d8-8683-fa00131f00f8" />
</p>
<p align="center">
<sub><b>Malware Spawning ugate.exe and Executing Malicious JavaScript Files</b></sub>
</p>
<p align="center">
<img width="900" height="700" alt="2026-02-07 19_31_39-Greenshot" src="https://github.com/user-attachments/assets/556ed176-c089-406a-937b-f3ebb3e65d79" />
</p>
<p align="center">
<sub><b>Malware Running Malicious DLLs and PYDs From AppData</b></sub>
</p>

## **Example Log**
<p align="center">
<img width="900" height="653" alt="Log File Of Malware Activity" src="https://github.com/user-attachments/assets/029a7d7f-e8a9-403d-8a77-1b2f2d9169bd" />
</p>
<p align="center">
<sub><b>Log Of Malwares Malicious DLLs and PowerShell Commands</b></sub>
</p>

## Installation
```bash
# Clone Repository
git clone https://github.com/Poly0n/WinGuard.git
cd WinGuard cd WinGuard

# g++ Build
g++ -DUNICODE -D_UNICODE -std=c++20 -O2 -Iincludes -o WinGuard src/*.cpp -lwintrust -lole32 -luuid

# MSVC Build
msbuild WinGuard.slnx /p:Configuration=Release /p:Platform=x64
```

## **Updates**
### Improved Performance
- Uses NtQuerySystemInformation instead of CreateToolhelp32Snapshot
- Improved caching system for reduced redundant scanning operations
- Improved DLL enumeration and scanning
- Added security checks on any command line buffers that run to determine if they're malicious or not

### Bugs
- Added accurate parent-child process tracking
- Fixed Command Line Buffers sometimes not getting logged
- Improved scoring system to reduce false positives

## **Disclaimer**
When running you will most likely get a couple false positives when starting, due to things like OneDrive or WinGuard with their funky DLLs or directories. If that happens put their full file path on the whitelist.txt.
```bash
# Example
C:\Users\Bobby\AppData\Local\Microsoft\OneDrive\22.007.0112.0002\FileCoAuth.exe
```
