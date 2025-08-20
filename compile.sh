#!/bin/bash

TOOLCHAINS="$HOME/Android/Sdk/ndk/27.0.12077973/toolchains"

echo "[*] Buiding libhook.so"
$TOOLCHAINS/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android33-clang++ \
    -shared \
    -fPIC \
    -o libhook.so \
    myhooklib/jni/hook.cpp \
    -ldl \
    -landroid \
    -static-libstdc++

if [$? -eq 0]; then
    echo "[*] Build complete: libhook.so"
else
    echo "[!] Build failed: libhook.so"
    exit 1
fi

echo "[*] Pushing libhook.so into the Android device"
adb push libhook.so /sdcard/Download/libhook.so
if [$? -eq 0]; then
    echo "[*] Pushed libhook.so successfully"
else
    echo "[!] Could not push the libhook.so. Check your AVD connection..."
    exit 1
fi


echo "[*] Building injector"
$TOOLCHAINS/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android33-clang++ \
    -fPIE \
    -pie \
    -O2 \
    -std=c++17 \
    -static-libstdc++ \
    injector.cpp \
    -llog \
    -ldl \
    -o injector

if [$? -eq 0]; then
    echo "[*] Build complete: injector"
else
    echo "[!] Build failed: injector"
    exit 1
fi

echo "[*] Pushing injector into the Android device"
adb push injector /sdcard/Download/injector
if [$? -eq 0]; then
    echo "[*] Pushed injector successfully"
else
    echo "[!] Could not push the injector. Check your AVD connection..."
    exit 1
fi
