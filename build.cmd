@echo off
rem ============================================================
rem  MODPKICA Java (BC 1.85) Offline One-Click Build Script
rem  Usage:
rem    build.cmd            -> build only
rem    build.cmd 1          -> build, then auto-run command #1
rem    build.cmd 2          -> build, then auto-run command #2
rem    ...                  -> (see numbered list below)
rem  Requirement: JDK 17+ installed, BC185 jars in .\BC185
rem  Output: compiled classes in .\out
rem  NOTE: comments are in English to avoid cmd code page issues
rem ============================================================
setlocal

rem ---- validate optional command number early (1-8) ----
set "RUN=%~1"
if defined RUN (
    set "VALID="
    for /l %%i in (1,1,8) do if "%RUN%"=="%%i" set "VALID=1"
    if not defined VALID (
        echo [ERROR] Invalid command number: %RUN%. Valid range: 1-8.
        exit /b 1
    )
)

rem ---- locate javac / java on PATH ----
where javac >nul 2>nul
if errorlevel 1 (
    echo [ERROR] javac not found. Please install JDK 17+ and add it to PATH.
    exit /b 1
)

rem ---- offline classpath: BC185 + lib (pdfbox for signing) ----
set "BC_CP=BC185\*"
set "LIB_CP=lib\*"
set "RUN_CP=%BC_CP%;%LIB_CP%"

rem ---- clean and recreate output dir ----
if exist out rmdir /s /q out
mkdir out 2>nul

echo ============================================
echo   MODPKICA Java One-Click Build (offline)
echo ============================================

echo [1/2] Compiling shared library and all 7 main programs...
javac -encoding UTF-8 -cp "%RUN_CP%" -d out src\modpkica\*.java
if errorlevel 1 (
    echo [ERROR] Compilation FAILED. See messages above.
    echo         Build aborted. Command #%1 was NOT executed.
    exit /b 1
)

echo [2/2] Verifying class output...
if not exist out\modpkica\MAIN.class (
    echo [ERROR] MAIN.class not generated. Build failed.
    exit /b 1
)
if not exist out\modpkica\Admin.class (
    echo [ERROR] Admin.class not generated. Build failed.
    exit /b 1
)
if not exist out\modpkica\MakeRoot.class (
    echo [ERROR] MakeRoot.class not generated. Build failed.
    exit /b 1
)
if not exist out\modpkica\MakeCert.class (
    echo [ERROR] MakeCert.class not generated. Build failed.
    exit /b 1
)
if not exist out\modpkica\RootGetCrl.class (
    echo [ERROR] RootGetCrl.class not generated. Build failed.
    exit /b 1
)
if not exist out\modpkica\CertVerify.class (
    echo [ERROR] CertVerify.class not generated. Build failed.
    exit /b 1
)
if not exist out\modpkica\Auto.class (
    echo [ERROR] Auto.class not generated. Build failed.
    exit /b 1
)
if not exist out\modpkica\WebAdmin.class (
    echo [ERROR] WebAdmin.class not generated. Build failed.
    exit /b 1
)

echo.
echo Build SUCCESS. Classes are in .\out
echo.
echo How to run (set MODPKICA_BASE to your PKI root first):
echo   set MODPKICA_BASE=C:\path\to\your\pki_root
echo.
echo   [1] java "-Dfile.encoding=UTF-8" -cp "out;%RUN_CP%" modpkica.MAIN
echo       (GUI auto starts at http://localhost:8080)
echo   [2] java "-Dfile.encoding=UTF-8" -cp "out;%RUN_CP%" modpkica.WebAdmin
echo       (GUI only)
echo   [3] java "-Dfile.encoding=UTF-8" -cp "out;%RUN_CP%" modpkica.Admin
echo   [4] java "-Dfile.encoding=UTF-8" -cp "out;%RUN_CP%" modpkica.MakeRoot "CN=Root,O=Org,C=CN" 2048 sha256 RSA
echo   [5] java "-Dfile.encoding=UTF-8" -cp "out;%RUN_CP%" modpkica.MakeCert "CN=www.test.com" 2048 sha256 1 1 0 1 "www.test.com" null null root RSA
echo   [6] java "-Dfile.encoding=UTF-8" -cp "out;%RUN_CP%" modpkica.RootGetCrl
echo   [7] java "-Dfile.encoding=UTF-8" -cp "out;%RUN_CP%" modpkica.CertVerify cert.crt
echo   [8] java "-Dfile.encoding=UTF-8" -cp "out;%RUN_CP%" modpkica.Auto revoke 1234567890 1
echo.
echo Auto-run: build.cmd [1-8]  -> compile first, then run command #N automatically.
echo           (If compilation fails, the command is NOT executed.)
echo.
echo Note: PKI folder layout (CERTS.txt, ROOT, CA, CERT, KEY, OCSP,
echo       TIMSTAMP, WebPublic, CONFIG.txt, logs.log) is created at MODPKICA_BASE.

rem ---- auto-run selected command number (validated above) ----
if defined RUN (
    echo.
    echo ============================================
    echo   Auto-running command #%RUN% ...
    echo ============================================
    call :run_%RUN%
)
exit /b 0

:run_1
java "-Dfile.encoding=UTF-8" -cp "out;BC185\*;lib\*" modpkica.MAIN
goto :eof

:run_2
java "-Dfile.encoding=UTF-8" -cp "out;BC185\*;lib\*" modpkica.WebAdmin
goto :eof

:run_3
java "-Dfile.encoding=UTF-8" -cp "out;BC185\*;lib\*" modpkica.Admin
goto :eof

:run_4
java "-Dfile.encoding=UTF-8" -cp "out;BC185\*;lib\*" modpkica.MakeRoot "CN=Root,O=Org,C=CN" 2048 sha256 RSA
goto :eof

:run_5
java "-Dfile.encoding=UTF-8" -cp "out;BC185\*;lib\*" modpkica.MakeCert "CN=www.test.com" 2048 sha256 1 1 0 1 "www.test.com" null null root RSA
goto :eof

:run_6
java "-Dfile.encoding=UTF-8" -cp "out;BC185\*;lib\*" modpkica.RootGetCrl
goto :eof

:run_7
java "-Dfile.encoding=UTF-8" -cp "out;BC185\*;lib\*" modpkica.CertVerify cert.crt
goto :eof

:run_8
java "-Dfile.encoding=UTF-8" -cp "out;BC185\*;lib\*" modpkica.Auto revoke 1234567890 1
goto :eof
