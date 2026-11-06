@echo off
setlocal

python -m pip install -r requirements-build.txt
if errorlevel 1 exit /b %errorlevel%

python -m PyInstaller --noconfirm WindowsEventAnalyzer.spec
if errorlevel 1 exit /b %errorlevel%

echo.
echo Built dist\WindowsEventAnalyzer.exe
