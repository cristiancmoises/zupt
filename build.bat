@echo off
echo Zupt v0.4 Build Script for Windows
where gcc >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    gcc -Wall -Wextra -O2 -std=c11 -Iinclude ^
        src\zupt_main.c src\zupt_format.c src\zupt_lz.c src\zupt_lzh.c src\zupt_xxh.c ^
        src\zupt_sha256.c src\zupt_aes256.c src\zupt_crypto.c src\zupt_predict.c ^
        -lm -o zupt.exe
    if %ERRORLEVEL% EQU 0 (echo [OK] zupt.exe) else (echo [FAIL])
    exit /b %ERRORLEVEL%
)
where cl >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    cl /nologo /W4 /O2 /Iinclude /D_CRT_SECURE_NO_WARNINGS ^
       src\zupt_main.c src\zupt_format.c src\zupt_lz.c src\zupt_lzh.c src\zupt_xxh.c ^
       src\zupt_sha256.c src\zupt_aes256.c src\zupt_crypto.c src\zupt_predict.c ^
       /Fe:zupt.exe & del *.obj 2>nul
    exit /b 0
)
echo No C compiler found.
exit /b 1
