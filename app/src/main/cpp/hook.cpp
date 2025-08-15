////
//// Created by it4ch1 on 8/15/25.
////
//#include "dobby.h"
#include <android/log.h>
//#include <cstdio>
//
#define LOG_TAG "Hook.cpp"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
//
//
//bool is_mode_in_comm_active = false;
//
////We will call the original fns after our hook fns too to ensure the audioserver process does not crash.
//
//void (*original_setMode)(void* thiz,int mode);
//
//void hooked_setMode(void* thiz,int mode){
//    if(mode==2){
//        LOGI("VoIP call detected! (MODE_IN_COMMUNICATION). Recording enabled.");
//        is_mode_in_comm_active  = true;
//    }else{
//        if(is_mode_in_comm_active){
//            LOGI("Call ended. Recording stopped.");
//            is_mode_in_comm_active = false;
//        }
//    }
//
//    original_setMode(thiz,mode);
//}
//
//
//void on_load(){
//    LOGI("Hook library injected into audioserver.Setting up hooks..");
//    const char* testSymbol = "_ZN7android11AudioSystem13releaseOutputEi";
//    void* testSymbolAddr = DobbySymbolResolver("libaudioflnger.so",testSymbol);
//    if(testSymbolAddr){
//        DobbyHook(testSymbolAddr, (dobby_dummy_func_t)hooked_setMode,
//                  reinterpret_cast<void (**)()>((dobby_dummy_func_t) original_setMode));
//        LOGI("Successfully hooked the functions inside libaudioflinger.so library");
//    }else{
//        LOGI("Failed to find the given function's address");
//    }
//}
#include <jni.h>
#include <string>
#include <android/log.h>

#define LOG_TAG "Hook.cpp"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

void on_load(){
    LOGI("LOADED");
}