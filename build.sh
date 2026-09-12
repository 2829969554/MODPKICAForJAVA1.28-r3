#!/bin/bash
# ============================================================
# MODPKICA Java (BC 1.85) Offline One-Click Build Script
# Usage: bash build.sh or chmod +x ./build.sh && ./build.sh
# Requirement: JDK 17+ installed, BC185 jars in ./BC185
# Output: compiled classes in ./out
# ============================================================
set -euo pipefail

# ---- locate javac / java on PATH ----
if ! command -v javac &> /dev/null
then
    echo "[ERROR] javac not found. Please install JDK 17+ and add it to PATH."
    exit 1
fi

# ---- offline BC classpath (wildcard for javac/java) ----
BC_CP="BC185/*"

# ---- clean and recreate output dir ----
if [ -d "out" ]; then
    rm -rf out
fi
mkdir -p out

echo "============================================"
echo "MODPKICA Java One-Click Build (offline)"
echo "============================================"
echo "[1/2] Compiling shared library and all 7 main programs..."

javac -encoding UTF-8 -cp "${BC_CP}" -d out src/modpkica/*.java

if [ $? -ne 0 ]; then
    echo "[ERROR] Compilation FAILED. See messages above."
    exit 1
fi

echo "[2/2] Verifying class output..."
if [ ! -f out/modpkica/MAIN.class ]; then
    echo "[ERROR] MAIN.class not generated. Build failed."
    exit 1
fi
if [ ! -f out/modpkica/Admin.class ]; then
    echo "[ERROR] Admin.class not generated. Build failed."
    exit 1
fi
if [ ! -f out/modpkica/MakeRoot.class ]; then
    echo "[ERROR] MakeRoot.class not generated. Build failed."
    exit 1
fi
if [ ! -f out/modpkica/MakeCert.class ]; then
    echo "[ERROR] MakeCert.class not generated. Build failed."
    exit 1
fi
if [ ! -f out/modpkica/RootGetCrl.class ]; then
    echo "[ERROR] RootGetCrl.class not generated. Build failed."
    exit 1
fi
if [ ! -f out/modpkica/CertVerify.class ]; then
    echo "[ERROR] CertVerify.class not generated. Build failed."
    exit 1
fi
if [ ! -f out/modpkica/Auto.class ]; then
    echo "[ERROR] Auto.class not generated. Build failed."
    exit 1
fi
if [ ! -f out/modpkica/WebAdmin.class ]; then
    echo "[ERROR] WebAdmin.class not generated. Build failed."
    exit 1
fi

echo
echo "Build SUCCESS. Classes are in ./out"
echo
echo "How to run (set MODPKICA_BASE to your PKI root first):"
echo "export MODPKICA_BASE=/path/to/your/pki_root"
echo "java -Dfile.encoding=UTF-8 -cp \"out:${BC_CP}\" modpkica.MAIN (GUI auto starts at http://localhost:8080)"
echo "java -Dfile.encoding=UTF-8 -cp \"out:${BC_CP}\" modpkica.WebAdmin (GUI only)"
echo "java -Dfile.encoding=UTF-8 -cp \"out:${BC_CP}\" modpkica.Admin"
echo "java -Dfile.encoding=UTF-8 -cp \"out:${BC_CP}\" modpkica.MakeRoot \"CN=Root,O=Org,C=CN\" 2048 sha256 RSA"
echo "java -Dfile.encoding=UTF-8 -cp \"out:${BC_CP}\" modpkica.MakeCert \"CN=www.test.com\" 2048 sha256 1 1 0 1 \"www.test.com\" null null root RSA"
echo "java -Dfile.encoding=UTF-8 -cp \"out:${BC_CP}\" modpkica.RootGetCrl"
echo "java -Dfile.encoding=UTF-8 -cp \"out:${BC_CP}\" modpkica.CertVerify cert.crt"
echo "java -Dfile.encoding=UTF-8 -cp \"out:${BC_CP}\" modpkica.Auto revoke 1234567890 1"
echo
echo "Note: PKI folder layout (CERTS.txt, ROOT, CA, CERT, KEY, OCSP,"
echo "TIMSTAMP, WebPublic, CONFIG.txt, logs.log) is created at MODPKICA_BASE."

