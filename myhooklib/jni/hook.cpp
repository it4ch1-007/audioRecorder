#include <iostream>
// #include <android/log.h>
#include "file_utils.h"
#include <fstream>
#include <string>
#include <vector>
#include <optional>
#include <cstdint>

typedef int32_t status_t;

#define LOG_TAG "NativeHook"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

bool is_mode_enabled = false;
std::vector<std::byte> received_packets, sent_packets;

///TODO: Add hook for the setMode fn 
///TODO: Add the fn to hook and put the pcm packets inside the data file.
status_t newAudioFlingersetMode(void* this_,int mode){
    if(mode==3)
        is_mode_enabled = true;
    status_t result = origAudioflingerSetMode(this_,mode);
    return result;
}
status_t (*origAudioflingerSetMode)(void* this_ptr, int mode) = nullptr;
ssize_t (*origAudioStreamOutWrite)(void* buffer, size_t numBytes) = nullptr;
ssize_t newAudioStreamOutWrite(void* buffer,size_t numBytes){
    if(is_mode_enabled){
        FILE* fptr = fopen("/sdcard/Download/capturedPcm.dat","ab");
        fwrite(buffer,1,numBytes,fptr);
        free(fptr);
    }
    ssize_t result = origAudioStreamOutWrite(buffer,numBytes);
    return result;
}
// void write_files()
// {
//     std::ofstream received_pcm_file("/sdcard/Download/capturedPcm.dat", std::ios::binary);
// }
void hook_main()
{
    // hooking the fn to get the mode value
    const char* libraryPath = "libaudioflinger.so";
    const char* mangledSymbol = "_ZN7android12AudioFlinger7setModeEi";
    NativeHook::Hook(libraryPath,mangledSymbol,(void*)newAudioFlingersetMode,(void**)origAudioflingerSetMode);


    const char* mangledSymbol2 = "_ZN7android14AudioStreamOut5writeEPKvj";
    NativeHook::Hook(libraryPath,mangledSymbol2,(void*)newAudioStreamOutWrite,(void**)origAudioStreamOutWrite);

    // hooking to get the PCM packets that are received
    // hooking to get the PCM packets that are sent from the device to the other end.
    

}

// Constructor that runs when the library is first loaded.
__attribute__((constructor)) void on_load()
{
    // LOGI("libhook.so loaded successfully and on_load() was called!");
    std::ofstream ofs("/data/local/tmp/hookconfirm.txt");
    ofs << "Loaded!" << std::endl;
    ofs.close();
    hook_main();
}