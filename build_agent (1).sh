#!/bin/bash
set -e

SDK_PATH="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-/home/sandipan/android-sdk}}"
BUILD_TOOLS="$SDK_PATH/build-tools/35.0.0"
PLATFORM_JAR="$SDK_PATH/platforms/android-35/android.jar"

echo "[*] Cleaning build directories..."
rm -rf agent/obj agent/bin
mkdir -p agent/obj agent/bin

echo "[*] Compiling Java source..."
javac -d agent/obj -bootclasspath "$PLATFORM_JAR" -source 1.8 -target 1.8 agent/src/com/recover/agent/MainActivity.java

echo "[*] Converting class files to DEX..."
"$BUILD_TOOLS/d8" --output agent/bin/ agent/obj/com/recover/agent/MainActivity.class --lib "$PLATFORM_JAR"

echo "[*] Packaging resource container..."
"$BUILD_TOOLS/aapt" package -f -M agent/AndroidManifest.xml -I "$PLATFORM_JAR" -F agent/bin/RecoverAgent.unaligned.apk agent/bin/

echo "[*] Adding classes.dex to APK package..."
cd agent/bin
zip -u RecoverAgent.unaligned.apk classes.dex
cd ../..

echo "[*] Generating release keystore (if not exists)..."
if [ ! -f agent/agent.keystore ]; then
    keytool -genkeypair -v -keystore agent/agent.keystore -alias agentkey -keyalg RSA -keysize 2048 -validity 10000 -storepass password -keypass password -dname "CN=Recover, O=Recover, C=US"
fi

echo "[*] Signing the APK..."
"$BUILD_TOOLS/apksigner" sign --ks agent/agent.keystore --ks-pass pass:password --key-pass pass:password --out agent/bin/RecoverAgent.apk agent/bin/RecoverAgent.unaligned.apk

echo "[+] APK created successfully: agent/bin/RecoverAgent.apk"
