@echo off
chcp 65001 >nul 2>&1
cd /d "%~dp0"
setlocal enabledelayedexpansion

rem ===================================================================
rem  源码方式启动图形界面（不出现 cmd 黑窗口，用 pythonw.exe 拉起）
rem  双击本文件 -> 打开应用窗口 -> 填写目标 -> 开始扫描
rem  命令行用法：漏洞扫描器-命令行版.exe 或 python scan.py 192.168.1.10
rem ===================================================================

set "PYEXE="
call :findpy python
if not defined PYEXE call :findpy python3
if not defined PYEXE call :findinstalled
if not defined PYEXE goto :nopy

rem 优先用同目录的 pythonw.exe，避免额外弹出控制台窗口
set "PYW=!PYEXE:python.exe=pythonw.exe!"
if not exist "!PYW!" set "PYW=!PYEXE!"
start "" "!PYW!" "%~dp0scan_gui.py" %*
exit /b 0

rem ===================================================================
rem 找到真实解释器（跳过 Microsoft Store 的 WindowsApps 占位程序）
rem ===================================================================
:findpy
for /f "delims=" %%p in ('where %~1 2^>nul') do call :pick "%%p"
exit /b 0

:pick
if defined PYEXE exit /b 0
if not exist "%~1" exit /b 0
echo %~1 | find /i "WindowsApps" >nul
if not errorlevel 1 exit /b 0
for /f "delims=" %%e in ('"%~1" -c "import sys;print(sys.executable)" 2^>nul') do (
  if not defined PYEXE set "PYEXE=%%e"
)
exit /b 0

:findinstalled
for /d %%d in ("%LOCALAPPDATA%\Programs\Python\Python3*") do (
  if exist "%%d\python.exe" if not defined PYEXE call :pick "%%d\python.exe"
)
for /d %%d in ("C:\Program Files\Python3*") do (
  if exist "%%d\python.exe" if not defined PYEXE call :pick "%%d\python.exe"
)
for /d %%d in ("C:\Python3*") do (
  if exist "%%d\python.exe" if not defined PYEXE call :pick "%%d\python.exe"
)
exit /b 0

:nopy
echo.
echo [ERROR] 未找到可用的 Python 3 解释器。
echo 可直接双击已生成的「漏洞扫描器.exe」（无需 Python），
echo 或安装 Python 3.8+ 后重新双击本文件。
echo.
pause
exit /b 1
