#!/usr/bin/env bash
# ============================================================
#  MODPKICA Java (BC 1.85) Offline One-Click Build Script (Linux/macOS)
#  Usage:
#    ./build.sh            -> build only
#    ./build.sh 1          -> build, then auto-run command #1
#    ./build.sh 2          -> build, then auto-run command #2
#    ...                   -> (see numbered list below)
#  Requirement: JDK 17+ installed, BC185 jars in ./BC185
#  Output: compiled classes in ./out
# ============================================================
set -e
cd "$(dirname "$0")"

BC_CP="BC185/*"

# validate optional command number early (1-8)
RUN="${1:-}"
if [ -n "$RUN" ]; then
    case "$RUN" in
        1|2|3|4|5|6|7|8) : ;;
        *)
            echo "[ERROR] Invalid command number: $RUN. Valid range: 1-8."
            exit 1
            ;;
    esac
fi

if ! command -v javac >/dev/null 2>&1; then
    echo "[ERROR] javac not found. Please install JDK 17+ and add it to PATH."
    exit 1
fi

echo "============================================"
echo "  MODPKICA Java One-Click Build (offline)"
echo "============================================"

echo "[1/2] Compiling shared library and all 7 main programs..."
rm -rf out
mkdir -p out
javac -encoding UTF-8 -cp "$BC_CP" -d out src/modpkica/*.java

echo "[2/2] Verifying class output..."
for cls in MAIN Admin MakeRoot MakeCert RootGetCrl CertVerify Auto WebAdmin; do
    if [ ! -f "out/modpkica/$cls.class" ]; then
        echo "[ERROR] $cls.class not generated. Build failed."
        exit 1
    fi
done

echo
echo "Build SUCCESS. Classes are in ./out"
echo
echo "How to run (set MODPKICA_BASE to your PKI root first):"
echo "  export MODPKICA_BASE=/path/to/your/pki_root"
echo
echo "  [1] java \"-Dfile.encoding=UTF-8\" -cp \"out:$BC_CP\" modpkica.MAIN"
echo "      (GUI auto starts at http://localhost:8080)"
echo "  [2] java \"-Dfile.encoding=UTF-8\" -cp \"out:$BC_CP\" modpkica.WebAdmin"
echo "      (GUI only)"
echo "  [3] java \"-Dfile.encoding=UTF-8\" -cp \"out:$BC_CP\" modpkica.Admin"
echo "  [4] java \"-Dfile.encoding=UTF-8\" -cp \"out:$BC_CP\" modpkica.MakeRoot \"CN=Root,O=Org,C=CN\" 2048 sha256 RSA"
echo "  [5] java \"-Dfile.encoding=UTF-8\" -cp \"out:$BC_CP\" modpkica.MakeCert \"CN=www.test.com\" 2048 sha256 1 1 0 1 \"www.test.com\" null null root RSA"
echo "  [6] java \"-Dfile.encoding=UTF-8\" -cp \"out:$BC_CP\" modpkica.RootGetCrl"
echo "  [7] java \"-Dfile.encoding=UTF-8\" -cp \"out:$BC_CP\" modpkica.CertVerify cert.crt"
echo "  [8] java \"-Dfile.encoding=UTF-8\" -cp \"out:$BC_CP\" modpkica.Auto revoke 1234567890 1"
echo
echo "Auto-run: ./build.sh [1-8]  -> compile first, then run command #N automatically."
echo "          (If compilation fails, the command is NOT executed.)"
echo
echo "Note: PKI folder layout (CERTS.txt, ROOT, CA, CERT, KEY, OCSP,"
echo "      TIMSTAMP, WebPublic, CONFIG.txt, logs.log) is created at MODPKICA_BASE."

# auto-run selected command number (validated above)
if [ -n "$RUN" ]; then
    echo
    echo "============================================"
    echo "  Auto-running command #$RUN ..."
    echo "============================================"
    case "$RUN" in
        1) java "-Dfile.encoding=UTF-8" -cp "out:$BC_CP" modpkica.MAIN ;;
        2) java "-Dfile.encoding=UTF-8" -cp "out:$BC_CP" modpkica.WebAdmin ;;
        3) java "-Dfile.encoding=UTF-8" -cp "out:$BC_CP" modpkica.Admin ;;
        4) java "-Dfile.encoding=UTF-8" -cp "out:$BC_CP" modpkica.MakeRoot "CN=Root,O=Org,C=CN" 2048 sha256 RSA ;;
        5) java "-Dfile.encoding=UTF-8" -cp "out:$BC_CP" modpkica.MakeCert "CN=www.test.com" 2048 sha256 1 1 0 1 "www.test.com" null null root RSA ;;
        6) java "-Dfile.encoding=UTF-8" -cp "out:$BC_CP" modpkica.RootGetCrl ;;
        7) java "-Dfile.encoding=UTF-8" -cp "out:$BC_CP" modpkica.CertVerify cert.crt ;;
        8) java "-Dfile.encoding=UTF-8" -cp "out:$BC_CP" modpkica.Auto revoke 1234567890 1 ;;
    esac
fi
exit 0
