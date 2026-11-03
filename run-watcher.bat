@echo off
chcp 65001 > nul
cd /d "%~dp0"
if exist "bin\Release\net8.0-windows\AnzenSecurityWatcher.exe" (
    start "" "bin\Release\net8.0-windows\AnzenSecurityWatcher.exe"
) else (
    dotnet run --configuration Release
)
