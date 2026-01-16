@echo off
echo ================================
echo Compiling Educational Backdoor
echo ================================
echo.

echo [1] Compiling DEBUG version (with symbols for easier IDA analysis)...
gcc simple_backdoor.c -o simple_backdoor_debug.exe -lws2_32 -g -Wall
if %ERRORLEVEL% EQU 0 (
    echo [+] SUCCESS: simple_backdoor_debug.exe created!
) else (
    echo [-] FAILED to compile debug version
)

echo.
echo [2] Compiling RELEASE version (stripped, more realistic)...
gcc simple_backdoor.c -o simple_backdoor_release.exe -lws2_32 -O2 -s
if %ERRORLEVEL% EQU 0 (
    echo [+] SUCCESS: simple_backdoor_release.exe created!
) else (
    echo [-] FAILED to compile release version
)

echo.
echo [3] Compiling STANDARD version...
gcc simple_backdoor.c -o simple_backdoor.exe -lws2_32
if %ERRORLEVEL% EQU 0 (
    echo [+] SUCCESS: simple_backdoor.exe created!
) else (
    echo [-] FAILED to compile standard version
)

echo.
echo ================================
echo Compilation Complete!
echo ================================
echo.
echo Files created:
dir /B *.exe 2>nul
pause
