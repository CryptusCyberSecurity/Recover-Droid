@echo off
setlocal enabledelayedexpansion

rem Check if ANDROID_HOME or ANDROID_SDK_ROOT is set
if "%ANDROID_HOME%"=="" (
    if "%ANDROID_SDK_ROOT%"=="" (
        set "SDK_PATH=%USERPROFILE%\AppData\Local\Android\Sdk"
    ) else (
        set "SDK_PATH=%ANDROID_SDK_ROOT%"
    )
) else (
    set "SDK_PATH=%ANDROID_HOME%"
)

set "BUILD_TOOLS=%SDK_PATH%\build-tools\35.0.0"
set "PLATFORM_JAR=%SDK_PATH%\platforms\android-35\android.jar"

if not exist "%SDK_PATH%" (
    echo [-] Android SDK not found at "%SDK_PATH%"
    echo     Please set the ANDROID_HOME environment variable to your Android SDK.
    exit /b 1
)

echo [*] Cleaning build directories...
if exist agent\obj rmdir /s /q agent\obj
if exist agent\bin rmdir /s /q agent\bin
mkdir agent\obj
mkdir agent\bin

echo [*] Compiling Java source...
javac -d agent\obj -bootclasspath "%PLATFORM_JAR%" -source 1.8 -target 1.8 agent\src\com\recover\agent\MainActivity.java
if !errorlevel! neq 0 exit /b !errorlevel!

echo [*] Converting class files to DEX...
call "%BUILD_TOOLS%\d8.bat" --output agent\bin\ agent\obj\com\recover\agent\MainActivity.class --lib "%PLATFORM_JAR%"
if !errorlevel! neq 0 exit /b !errorlevel!

echo [*] Packaging resource container...
call "%BUILD_TOOLS%\aapt.exe" package -f -M agent\AndroidManifest.xml -I "%PLATFORM_JAR%" -F agent\bin\RecoverAgent.unaligned.apk agent\bin\
if !errorlevel! neq 0 exit /b !errorlevel!

echo [*] Adding classes.dex to APK package...
cd agent\bin
powershell -Command "Expand-Archive -Path RecoverAgent.unaligned.apk -DestinationPath temp_extracted -Force; Copy-Item classes.dex temp_extracted\ -Force; Compress-Archive -Path temp_extracted\* -DestinationPath RecoverAgent.unaligned_new.zip -Force; Move-Item RecoverAgent.unaligned_new.zip RecoverAgent.unaligned.apk -Force; Remove-Item temp_extracted -Recurse -Force"
cd ..\..

echo [*] Generating release keystore (if not exists)...
if not exist agent\agent.keystore (
    keytool -genkeypair -v -keystore agent\agent.keystore -alias agentkey -keyalg RSA -keysize 2048 -validity 10000 -storepass password -keypass password -dname "CN=Recover, O=Recover, C=US"
)

echo [*] Signing the APK...
call "%BUILD_TOOLS%\apksigner.bat" sign --ks agent\agent.keystore --ks-pass pass:password --key-pass pass:password --out agent\bin\RecoverAgent.apk agent\bin\RecoverAgent.unaligned.apk

echo [+] APK created successfully: agent\bin\RecoverAgent.apk
