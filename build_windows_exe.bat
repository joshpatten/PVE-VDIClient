@echo off
REM Build script for BIA VDI Client Windows Executable
REM This script requires PyInstaller to be installed
REM Run this from the project root directory

echo =========================================
echo BIA VDI Client - Windows Build Script
echo =========================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.x from https://www.python.org
    echo Make sure to check "Add Python to PATH" during installation
    pause
    exit /b 1
)

echo [1/3] Installing/checking PyInstaller...
pip install pyinstaller -q
if errorlevel 1 (
    echo ERROR: Failed to install PyInstaller
    pause
    exit /b 1
)

echo [2/3] Installing project dependencies...
call requirements.bat
if errorlevel 1 (
    echo ERROR: Failed to install dependencies
    pause
    exit /b 1
)

echo [3/3] Building executable...
python build_windows_exe.py
if errorlevel 1 (
    echo ERROR: Build failed
    pause
    exit /b 1
)

echo.
echo Build complete! Check the dist folder for BIA-VDIClient.exe
pause
