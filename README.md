# WinGuard
Windows Security Tool

# Install
```bash
g++ -DUNICODE -D_UNICODE -std=c++20 -O2 -Iincludes -o WinGuard src/*.cpp -lwintrust -lole32 -luuid
```
