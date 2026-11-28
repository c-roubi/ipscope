@echo off
REM ---------------------------------------------------------------
REM  Build IPScope for Windows
REM  Needs: Python 3.10+ (python.org, "Add to PATH" ticked)
REM  Optional: Inno Setup 6 (jrsoftware.org) for the installer
REM ---------------------------------------------------------------
setlocal
cd /d "%~dp0\.."

echo [1/4] Creating build environment...
if not exist .build-venv (
    python -m venv .build-venv || goto :error
)
call .build-venv\Scripts\activate.bat || goto :error

echo [2/4] Installing dependencies...
python -m pip install --upgrade pip >nul
python -m pip install ".[gui]" pyinstaller || goto :error

echo [3/4] Building executables...
pyinstaller packaging\ipscope.spec --noconfirm --clean || goto :error
dist\IPScope\ipscope.exe --version || goto :error

echo [4/4] Building installer...
set ISCC="%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
if exist %ISCC% (
    %ISCC% packaging\installer.iss || goto :error
    echo.
    echo Installer: dist\installer\
) else (
    echo Inno Setup not found - skipping installer. The app is ready in dist\IPScope\
)

echo.
echo Done. Run dist\IPScope\IPScope.exe
exit /b 0

:error
echo.
echo BUILD FAILED - see the messages above.
exit /b 1
