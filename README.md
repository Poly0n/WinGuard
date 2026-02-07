# WinGuard

A basic Windows security tool acting as an EDR (Endpoint Detection and Response) to help monitor and log any suspicious processes or commands running on your PC.

## **Key Features**
  - *Verifies Running Processes and DLLs For Signature Abnormalities (No Signature, Tampered File, Untrusted Signature, etc.)*
  - *Detecs Any Abnormal Parent Processses (Parent Spawning A Powershell, CMD, WScript Window)*
  - *Scans For Processes and DLLs Running From Abnormal Directories (%TEMP%, %APPDATA%, etc.)*
  - *Detects Processes and DLLs Running That Are User-Writable*

# Install
```bash
g++ -DUNICODE -D_UNICODE -std=c++20 -O2 -Iincludes -o WinGuard src/*.cpp -lwintrust -lole32 -luuid
```
