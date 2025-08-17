#include <android/log.h> // Include the Android log header

// Define a log tag to easily filter your messages
#define LOG_TAG "MyHookLibrary"

// Helper macros for logging
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// This function will run automatically when the library is loaded
extern "C" void __attribute__((constructor)) on_load() {
    // Log the message using the Android logging system
    LOGI("libhook.so loaded successfully and on_load() was called!");
}

extern "C" int hook_main() {
    LOGI("SUCCESS! hook_main() was executed inside audioserver!");
    // You would set up your actual function hooks here.
    return 1337; // Return a unique number to confirm it ran.
}