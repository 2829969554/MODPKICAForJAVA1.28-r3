@echo off
rem ============================================================
rem  MODPKICA Java (BC 1.85) Offline One-Click Build Script
rem  Usage: double-click build.cmd or run in cmd
rem  Requirement: JDK 17+ installed, BC185 jars in .\BC185
rem  Output: compiled classes in .\out
rem  NOTE: comments are in English to avoid cmd code page issues
rem ============================================================
setlocal

rem ---- locate javac / java on PATH ----
where javac >nul 2>nul
if errorlevel 1 (
    echo [ERROR] javac not found. Please install JDK 17+ and add it to PATH.
    exit /b 1
)

rem ---- offline BC classpath (wildcard supported by javac/java) ----
set "BC_CP=BC185\*"

rem ---- clean and recreate output dir ----
if exist out rmdir /s /q out
mkdir out 2>nul

echo ============================================
echo   MODPKICA Java One-Click Build (offline)
echo ============================================

echo [1/2] Compiling shared library and all 7 main programs...
javac -encoding UTF-8 -cp "%BC_CP%" -d out src\modpkica\*.java
if errorlevel 1 (
    echo [ERROR] Compilation FAILED. See messages above.
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
echo   java "-Dfile.encoding=UTF-8" -cp "out;%BC_CP%" modpkica.MAIN   (GUI auto starts at http://localhost:8080)
echo   java "-Dfile.encoding=UTF-8" -cp "out;%BC_CP%" modpkica.WebAdmin  (GUI only)
echo   java "-Dfile.encoding=UTF-8" -cp "out;%BC_CP%" modpkica.Admin
echo   java "-Dfile.encoding=UTF-8" -cp "out;%BC_CP%" modpkica.MakeRoot "CN=Root,O=Org,C=CN" 2048 sha256 RSA
echo   java "-Dfile.encoding=UTF-8" -cp "out;%BC_CP%" modpkica.MakeCert "CN=www.test.com" 2048 sha256 1 1 0 1 "www.test.com" null null root RSA
echo   java "-Dfile.encoding=UTF-8" -cp "out;%BC_CP%" modpkica.RootGetCrl
echo   java "-Dfile.encoding=UTF-8" -cp "out;%BC_CP%" modpkica.CertVerify cert.crt
echo   java "-Dfile.encoding=UTF-8" -cp "out;%BC_CP%" modpkica.Auto revoke 1234567890 1
echo.
echo Note: PKI folder layout (CERTS.txt, ROOT, CA, CERT, KEY, OCSP,
echo       TIMSTAMP, WebPublic, CONFIG.txt, logs.log) is created at MODPKICA_BASE.

endlocal
