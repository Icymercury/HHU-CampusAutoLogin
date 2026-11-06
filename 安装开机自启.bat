@echo off
net session >nul 2>&1
if errorlevel 1 (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs" 2>nul
    exit /b
)
cd /d "%~dp0"
start /wait "" CampusAutoLogin.exe --install
