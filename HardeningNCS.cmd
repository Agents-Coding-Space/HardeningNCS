@echo off
rem ==============================================================================
rem File: HardeningNCS.cmd
rem Description: Click-to-run launcher and CLI wrapper for HardeningNCS.
rem              Validates powershell.exe availability and passes CLI parameters.
rem ==============================================================================

setlocal

rem Check if powershell.exe is available in PATH
where powershell.exe >nul 2>nul
if %errorlevel% neq 0 (
    echo ===============================================================================
    echo [ERROR] powershell.exe was not found in your system PATH.
    echo HardeningNCS requires Windows PowerShell 2.0 or higher to execute.
    echo Please ensure PowerShell is installed and properly configured in PATH.
    echo ===============================================================================
    pause
    exit /b 1
)

rem Invoke HardeningNCS.ps1 forwarding all passed arguments
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0HardeningNCS.ps1" %*
set "EXIT_CODE=%errorlevel%"

endlocal & exit /b %EXIT_CODE%
