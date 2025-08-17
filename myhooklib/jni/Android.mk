LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

# Set the name for our final output file
LOCAL_MODULE := hook

# List the C++ source files to compile
LOCAL_SRC_FILES := hook.cpp

# --- CRITICAL CHANGES START HERE ---

# Disable C++ exceptions and RTTI to reduce size and dependencies
LOCAL_CPPFLAGS += -fno-exceptions -fno-rtti

# Tell the linker to NOT include standard libraries by default,
# then explicitly link only the bare minimum we need.
# -llog is for __android_log_print
# -lc is for basic C functions
LOCAL_LDFLAGS += -nostdlib -llog -lc

# --- CRITICAL CHANGES END HERE ---

# Tell the build system to create a shared library (.so file)
include $(BUILD_SHARED_LIBRARY)