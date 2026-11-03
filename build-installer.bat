@echo off
chcp 65001 > nul
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0build-installer.ps1" %*
if %ERRORLEVEL% neq 0 (
    echo.
    echo [ERROR] インストーラーのビルドに失敗しました。
    pause
    exit /b %ERRORLEVEL%
)
echo.
pause
