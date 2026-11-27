@echo off
setlocal

python -m pip install -r requirements-build.txt
if errorlevel 1 exit /b %errorlevel%

python -m PyInstaller --noconfirm WindowsEventAnalyzer.spec
if errorlevel 1 exit /b %errorlevel%

rem Optional code signing. Set SIGN_CERT_THUMBPRINT to the thumbprint of a
rem code-signing certificate installed on this PC (signtool comes with the
rem Windows SDK). Without it the exe is left unsigned.
if defined SIGN_CERT_THUMBPRINT (
    signtool sign /sha1 %SIGN_CERT_THUMBPRINT% /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 dist\WindowsEventAnalyzer.exe
    if errorlevel 1 exit /b %errorlevel%
    signtool verify /pa dist\WindowsEventAnalyzer.exe
    if errorlevel 1 exit /b %errorlevel%
) else (
    echo.
    echo NOTE: SIGN_CERT_THUMBPRINT is not set - the exe is not signed.
)

echo.
echo Built dist\WindowsEventAnalyzer.exe
