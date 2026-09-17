@echo off
setlocal
cd /d "%~dp0"
set PYTHONWARNINGS=ignore
rem Pick standalone EXE when available, else fall back to python
set "PSV=python pdfsig_verify.py"
set "VGPDF=python verify_gm_pdf.py"
set "CDV=python chain_deep_verify.py"
if exist "%~dp0exe\pdfsig_verify.exe" (
    set "PSV=%~dp0exe\pdfsig_verify.exe"
    set "VGPDF=%~dp0exe\verify_gm_pdf.exe"
    set "CDV=%~dp0exe\chain_deep_verify.exe"
)
echo ============================================
echo   MODPKICA GM PDF Signature Verification
echo ============================================
echo.
echo [1/3] Structure check via verify_gm_pdf
"%VGPDF%" GBT35275-2017.pdf
"%VGPDF%" GBT38540-2020.pdf
echo.
echo [2/3] Full verification of both samples via pdfsig_verify
"%PSV%" "GBT35275-2017.pdf" "GBT38540-2020.pdf"
echo.
echo [3/3] Certificate chain deep verification (offline material)
"%CDV%" "GBT35275-2017.pdf" "GBT38540-2020.pdf"
echo.
echo Done. See report pdf/md files in this folder.
pause