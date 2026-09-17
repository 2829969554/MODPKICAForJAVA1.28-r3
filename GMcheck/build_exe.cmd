@echo off
setlocal
cd /d "%~dp0"
set PYTHONWARNINGS=ignore
echo ============================================
echo   Build standalone EXE for GM PDF verify tools
echo   (needs: Python 3.10+ with pikepdf, cryptography,
echo    asn1crypto, pymupdf, pyinstaller installed)
echo ============================================
echo.
if not exist exe mkdir exe
if not exist build mkdir build

echo [1/3] pdfsig_verify.exe ...
python -m PyInstaller --noconfirm --onefile --distpath exe --workpath build --specpath build --name pdfsig_verify pdfsig_verify.py
if errorlevel 1 goto :err

echo [2/3] verify_gm_pdf.exe ...
python -m PyInstaller --noconfirm --onefile --distpath exe --workpath build --specpath build --name verify_gm_pdf --collect-all pikepdf verify_gm_pdf.py
if errorlevel 1 goto :err

echo [3/3] chain_deep_verify.exe ...
python -m PyInstaller --noconfirm --onefile --distpath exe --workpath build --specpath build --name chain_deep_verify --collect-all pikepdf chain_deep_verify.py
if errorlevel 1 goto :err

echo.
echo Build SUCCESS. EXE files are in .\exe
dir /b exe\*.exe
goto :eof

:err
echo Build FAILED. See messages above.
exit /b 1
