@echo off
chcp 65001 >nul 2>&1
cd /d "%~dp0"
setlocal enabledelayedexpansion

rem ===================================================================
rem  一键生成「漏洞扫描器.exe」图形界面主程序（--windowed，无 cmd 黑窗口）
rem  双击本文件即可；需要 Python 3.8+ 与联网（首次自动安装 PyInstaller）
rem  只想生成图形界面版（更快）：在命令行执行 python build_exe.py --gui-only
rem ===================================================================

set "PYCMD="
set "CHK=%TEMP%\~vulnscan_build_pychk.txt"

call :try py -3
if not defined PYCMD call :try python ""
if not defined PYCMD call :try python3 ""
if not defined PYCMD call :findinstalled

if not defined PYCMD goto :nopy

echo.
echo [OK] Python  : %PYCMD%
echo [OK] 目录    : %CD%
echo.
echo 正在生成 exe（图形界面版 + 可选命令行版），请稍候...
echo -------------------------------------------------------------------
%PYCMD% build_exe.py
set "BUILDERR=!errorlevel!"
echo.
if not "%BUILDERR%"=="0" (
  echo [ERROR] 生成失败，错误码 %BUILDERR%。请检查上方输出。
  echo.
  pause
  exit /b %BUILDERR%
)
echo [OK] 已生成：%CD%\漏洞扫描器.exe
echo      图形界面主程序，双击后打开应用窗口，在窗口内执行扫描并查看历次记录。
echo      命令行版（可选）：%CD%\漏洞扫描器-命令行版.exe
echo      报告和扫描历史保存在 %CD%\reports
echo.
pause
exit /b 0

rem ===================================================================
:try
set "PYTEST="
if exist "%CHK%" del "%CHK%" >nul 2>&1
%~1 %~2 -c "print(1)" > "%CHK%" 2>nul
if exist "%CHK%" set /p PYTEST=<"%CHK%"
if "%PYTEST%"=="1" set "PYCMD=%~1 %~2"
exit /b 0

:findinstalled
for /d %%d in ("%LOCALAPPDATA%\Programs\Python\Python3*") do (
  if exist "%%d\python.exe" if not defined PYCMD call :tryexe "%%d\python.exe"
)
for /d %%d in ("C:\Program Files\Python3*") do (
  if exist "%%d\python.exe" if not defined PYCMD call :tryexe "%%d\python.exe"
)
for /d %%d in ("C:\Python3*") do (
  if exist "%%d\python.exe" if not defined PYCMD call :tryexe "%%d\python.exe"
)
exit /b 0

:tryexe
set "PYTEST="
if exist "%CHK%" del "%CHK%" >nul 2>&1
"%~1" -c "print(1)" > "%CHK%" 2>nul
if exist "%CHK%" set /p PYTEST=<"%CHK%"
if "%PYTEST%"=="1" set "PYCMD=%~1"
exit /b 0

:nopy
echo.
echo [ERROR] 未找到可用的 Python 3 解释器。
echo 请安装 Python 3.8+（https://www.python.org/downloads/），
echo 安装时勾选 "Add python.exe to PATH"，然后重新双击本文件。
echo.
pause
exit /b 1
