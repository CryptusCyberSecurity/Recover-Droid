@echo off
title Recover Droid Data Recovery Tool
cd /d "%~dp0"
cls
echo =================================================================
echo.
echo   ██████╗ ███████╗ ██████╗  ██████╗ ██╗   ██╗███████╗██████╗ ██████╗ 
echo   ██╔══██╗██╔════╝██╔════╝ ██╔═══██╗██║   ██║██╔════╝██╔══██╗██╔══██╗
echo   ██████╔╝█████╗  ██║      ██║   ██║██║   ██║█████╗  ██████╔╝██████╔╝
echo   ██╔══██╗██╔══╝  ██║      ██║   ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗██╔══██╗
echo   ██║  ██║███████╗╚██████╗ ╚██████╔╝ ╚████╔╝ ███████╗██║  ██║██║  ██║
echo   ╚═╝  ╚═╝╚══════╝ ╚═════╝  ╚═════╝   ╚═══╝  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝
echo.
echo   Recover Droid - Professional Data Recovery & Forensics Tool
echo =================================================================
echo.
echo   Welcome! You can now run the recovery commands below.
echo.
echo   Available Commands:
echo     1. List all connected drives:
echo        .\recover-droid.exe list
echo.
echo     2. Scan a drive (e.g. drive E:) for deleted files:
echo        .\recover-droid.exe scan \\.\E:
echo.
echo     3. Recover file ID 1 to C:\Recovered:
echo        .\recover-droid.exe recover \\.\E: 1 C:\Recovered
echo.
echo     4. Perform signature-based carving (e.g. drive E:) to C:\Recovered:
echo        .\recover-droid.exe carve \\.\E: C:\Recovered
echo.
echo =================================================================
echo  IMPORTANT: Please run this file as ADMINISTRATOR to access raw USBs!
echo =================================================================
echo.
cmd /k