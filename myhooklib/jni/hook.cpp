#include <android/log.h>
#include <link.h>
#include <string.h>
#include <fstream>
#include <unistd.h> 
#include <dlfcn.h>

#define LOG_TAG "NativeHook"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

typedef enum {
    AUDIO_MODE_NORMAL             = 0,
    AUDIO_MODE_RINGTONE           = 1,
    AUDIO_MODE_IN_CALL            = 2,
    AUDIO_MODE_IN_COMMUNICATION   = 3,
    AUDIO_MODE_CALL_SCREEN        = 4,
} audio_mode_t;

void* original_setMode = nullptr;
void replaced_setMode(void* this_ptr,audio_mode_t mode) {
    LOGI("[HOOK] AudioFlinger::setMode called!");
    LOGI("State of mode of communication: %d",mode);
    ((void (*)(void*, audio_mode_t))original_setMode)(this_ptr, mode);
}
struct PhdrCallbackData {
    const char* lib_name;
    void* base_addr;
};

int find_lib_base_callback(struct dl_phdr_info* info, size_t size, void* data) {
    PhdrCallbackData* callback_data = (PhdrCallbackData*)data;
    if (info->dlpi_name && strstr(info->dlpi_name, callback_data->lib_name)) {
        callback_data->base_addr = (void*)info->dlpi_addr;
        return 1; // Return 1 to stop iterating once found.
    }
    return 0;
}

// extern "C" int hook_main() {
//     LOGI("SUCCESS! hook_main() was executed inside audioserver!");

//     // Find the base address of libaudioflinger.so in memory.
//     PhdrCallbackData data = {"libaudioflinger.so", nullptr};
//     dl_iterate_phdr(find_lib_base_callback, &data);
    
//     if (data.base_addr == nullptr) {
//         LOGI("[ERROR] Could not find base address of libaudioflinger.so");
//         return -1;
//     }
//     LOGI("Found libaudioflinger.so base address at: %p", data.base_addr);
//     long setModeOffset = 0x4DE40; 

//     void* target_address = (void*)((long)data.base_addr + setModeOffset);
//     LOGI("Calculated setMode address at: %p", target_address);
//     int result = DobbyHook(
//         target_address,              // Address of the function to hook
//         (void*)replaced_setMode, // Address of our replacement function
//         &original_setMode        // Address of the pointer to store the original function
//     );

//     if (result == 0) {
//         LOGI("DobbyHook for createTrack installed successfully!");
//     } else {
//         LOGI("[ERROR] DobbyHook failed with code: %d", result);
//         return -1;
//     }

//     return 4040;
// }

// Constructor that runs when the library is first loaded.
__attribute__((constructor))
void on_load() {
    LOGI("libhook.so loaded successfully and on_load() was called!");
    std::ofstream ofs("/data/local/tmp/hookconfirm.txt");
    ofs << "Loaded! PID=" << getpid() << std::endl;
    ofs.close();
    // hook_main();
}