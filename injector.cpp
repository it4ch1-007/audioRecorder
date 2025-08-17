#include <iostream>
#include <fstream>
#include <regex>
#include <string>
#include <vector>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <unistd.h>
#include <dlfcn.h>
#include <android/log.h>
#include <sys/user.h>
#include <link.h>
#include <sys/system_properties.h>


#define LIBC_PATH_OLD        "/system/lib64/libc.so"
#define LIBC_PATH_NEW        "/apex/com.android.runtime/lib64/bionic/libc.so"
#define LINKER_PATH_OLD        "/system/lib64/libdl.so"
#define LINKER_PATH_NEW        "/apex/com.android.runtime/lib64/bionic/libdl.so"
#define VNDK_LIB_PATH        "/system/lib64/libRS.so"

#define LOG_TAG "Injector.cpp"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)


//struct PhdrCallbackData {
//    const char *lib_name;
//    void *base_addr;
//};
static int android_os_version = -1;


int GetOSVersion() {
    if (android_os_version != -1) {
        return android_os_version;
    }

    char os_version[PROP_VALUE_MAX + 1];
    int os_version_length = __system_property_get("ro.build.version.release", os_version);
    android_os_version = atoi(os_version);

    return android_os_version;
}

//int find_lib_base_callback(struct dl_phdr_info *info, size_t size, void *data) {
//    PhdrCallbackData *callback_data = (PhdrCallbackData *) data;
//
//    // Check if the library's name contains the name we're searching for.
//    if (info->dlpi_name && strstr(info->dlpi_name, callback_data->lib_name)) {
//        callback_data->base_addr = (void *) info->dlpi_addr;
//        return 1;
//    }
//    return 0;
//}

void *get_remote_lib_address(pid_t pid, const char *lib_name) {
    char maps_path[256];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    std::ifstream maps_file(maps_path);
    std::string line;

    while (getline(maps_file, line)) {
        if (line.find(lib_name) != std::string::npos) {
            return (void *) (std::stoul(line.substr(0, line.find('-')), nullptr, 16));
        }
    }
    return nullptr;
}

void *get_local_lib_address(pid_t pid,const char *lib_name) {
    char maps_path[256];
    LOGD("Reading maps for pid: %d",pid);
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    std::ifstream maps_file(maps_path);
    std::string line;

    while (getline(maps_file, line)) {
        if (line.find(lib_name) != std::string::npos) {
            return (void *) (std::stoul(line.substr(0, line.find('-')), nullptr, 16));
        }
    }
    return nullptr;
}

//void *get_local_lib_address(const char *lib_name) {
//    PhdrCallbackData data;
//    data.lib_name = lib_name;
//    data.base_addr = nullptr;
//
//    dl_iterate_phdr(find_lib_base_callback, &data);
//
//    return data.base_addr;
//}

void* get_remote_function_address(pid_t pid, pid_t local_pid,const char *lib_name, const void *local_function_addr) {
    void *local_lib_addr = get_local_lib_address(local_pid,lib_name);
    LOGD("LOCAL ADDRESS: %p", local_lib_addr);
    if (!local_lib_addr) return nullptr;

    void *remote_lib_addr = get_remote_lib_address(pid, lib_name);
    LOGD("REMOTE ADDRESS: %p", remote_lib_addr);
    if (!remote_lib_addr) {
        LOGD("UNABLE TO GET THE REMOTE LIBRARY ADDRESS !!");
        return nullptr;
    }

    long fn_off = (long) local_function_addr - (long) local_lib_addr;
    LOGD("Function offset: %ld", fn_off);

    return (void *) ((long) remote_lib_addr + fn_off);
}

long execute_remote_function(pid_t pid, void *func_addr, long *params, int num_params,
                             struct user_regs_struct *regs) {
    LOGD("Executing the fn...");
    //setting up the args for the fn
    if (num_params > 0) regs->rdi = params[0];
    if (num_params > 0) regs->rsi = params[1];
    if (num_params > 0) regs->rdx = params[2];
    if (num_params > 0) regs->rcx = params[3];
    if (num_params > 0) regs->r8 = params[4];
    if (num_params > 0) regs->r9 = params[5];
    regs->rip = (unsigned long) func_addr;

    // 2. Set up the stack with a fake return address (0)
    regs->rsp -= sizeof(long); // Make space on the stack
    ptrace(PTRACE_POKEDATA, pid, regs->rsp, 0); // Write 0 as the return address

    // 3. Set the registers for the call
    ptrace(PTRACE_SETREGS, pid, NULL, regs);

    // 4. Continue execution. The target will run the function and then crash
    // when it tries to "return" to address 0.
    ptrace(PTRACE_CONT, pid, NULL, NULL);

    // 5. Wait for the predictable crash (SIGSEGV), which tells us the function is done.
    int status;
    waitpid(pid, &status, WUNTRACED);

    // Optional: Check that it stopped for the reason we expected.
    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSEGV) {
        LOGD("Function execution finished, caught SIGSEGV as expected.");
    } else {
        LOGD("Process stopped for an unexpected reason. Status: %d", status);
    }

    // 6. Get the registers to find the return value in RAX.
    ptrace(PTRACE_GETREGS, pid, NULL, regs);

    return regs->rax;
}

int write_to_remote_address(pid_t pid, void *dest, const void *src, size_t size) {
    for (size_t i = 0; i < size; i += sizeof(long)) {
        if (ptrace(PTRACE_POKEDATA, pid, (char *) dest + i, *(long *) ((char *) src + i)) == -1) {
            LOGD("Failed to write the process' memory");
            return -1;
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 4) {
        LOGD("Usage: injector <pidRemote> <lib_path> <pidLocal>");
        return -1;
    }

    void *handle = dlopen("/data/local/tmp/libhook.so", RTLD_NOW);

    if (!handle) {
        // **CRITICAL:** If handle is NULL, dlopen failed. Print the error.
        LOGD("Error: Failed to load libhook.so -> %s", dlerror());
        return 1; // Exit with an error code
    }

    LOGD("Local address of dlopen- > %p",(void*)dlopen);

    pid_t target_process_pid = atoi(argv[1]);
    pid_t local_process_pid = atoi(argv[3]);
    const char *lib_path = argv[2];

    LOGD("Injecting %s into PID=%d", lib_path, target_process_pid);

    //This system call will pause the process and attach our process to it.
    if (ptrace(PTRACE_ATTACH, target_process_pid, NULL, NULL) < 0) {
        LOGD("Error: PTRACE_ATTACH syscall failed !!");
        return -1;
    }
    wait(nullptr); //Wait for the process to attach to our process
    LOGD("Successfully attached the process.");

    //Save the process original register state so we can restore it later.
    struct user_regs_struct original_regs, temp_regs;
    ptrace(PTRACE_GETREGS, target_process_pid, NULL, &original_regs);
    memcpy(&temp_regs, &original_regs, sizeof(struct user_regs_struct));

    //gets the address if dlopen fn inside the target process's memory
    std::string libDlPath = LINKER_PATH_OLD;
    std::string libCPath = LIBC_PATH_OLD;
    if (GetOSVersion() >= 10) {
        libDlPath = LINKER_PATH_NEW;
        libCPath = LIBC_PATH_NEW;
    }
    void *remote_dlopen_addr = get_remote_function_address(target_process_pid,local_process_pid, libDlPath.c_str(),
                                                           (void *) dlopen);
    if (!remote_dlopen_addr) {
        LOGD("Error: Could not find the dlopen address!!");
        ptrace(PTRACE_DETACH, target_process_pid, NULL, NULL);
        return -1;
    }
    LOGD("Remote dlopen address: %p", remote_dlopen_addr);

    //Now we will do the same thing with the mmap fn
    void *remote_mmap_addr = get_remote_function_address(target_process_pid,local_process_pid, libCPath.c_str(),
                                                         (void *) mmap);
    if (!remote_mmap_addr) {
        LOGD("Error: Could not find remote mmap address");
        ptrace(PTRACE_DETACH, target_process_pid, NULL, NULL);
        return -1;
    }
    LOGD("Remote mmap address: %p", remote_mmap_addr);

    //Calling the fn mmap of the target process' instance
    long mmap_params[] = {0, static_cast<long>(strlen(lib_path) + 1), PROT_READ | PROT_WRITE,
                          MAP_ANONYMOUS | MAP_PRIVATE, 0, 0};
    LOGD("Executing mmap function...");
    void *remote_path_addr = (void *) execute_remote_function(target_process_pid, remote_mmap_addr,
                                                              mmap_params, 6, &temp_regs);
    LOGD("Executed mmap function successfully...: %p",remote_path_addr);
    //writing the library path inside the target process' memory
    write_to_remote_address(target_process_pid, remote_path_addr, lib_path, strlen(lib_path) + 1);
    LOGD("Written the hooking library path to remote process' memory...");

    //Now calling dlopen with the path of our library written into the target process' memory
    long dlopen_params[] = {(long) remote_path_addr, RTLD_NOW};
    void *dlopen_ret = (void *) execute_remote_function(target_process_pid, remote_dlopen_addr,
                                                        dlopen_params, 2, &temp_regs);
    LOGD("Dlopen return-> %p", dlopen_ret);
    if (!dlopen_ret) {
        LOGD("Error: dlopen failed..");
    } else {
        LOGD("Success...Library injected successfully..");
    }

    //The target process would have till now called the dlopen on our library and our hooks will be installed.
    //Now we will restore the state at which the process was before.
//    void *local_lib_handle = dlopen(lib_path, RTLD_LAZY);
//    if (!local_lib_handle) {
//        LOGD("Error: Could not open libhook.so locally to find hook_main: %s", dlerror());
//    } else {
//        // 2. Find the address of hook_main in the LOCAL injector process.
//        void *local_hook_main_addr = dlsym(local_lib_handle, "on_load");
//
//        if (!local_hook_main_addr) {
//            LOGD("Error: Could not find symbol 'hook_main' in local libhook.so");
//        } else {
//            // 3. Now, calculate the REMOTE address using the local address and existing logic.
//            void *remote_hook_main_addr = get_remote_function_address(target_process_pid, lib_path,
//                                                                      local_hook_main_addr);
//
//            if (!remote_hook_main_addr) {
//                LOGD("Error: Could not find remote hook_main address!");
//            } else {
//                LOGD("Remote hook_main address: %p", remote_hook_main_addr);
//                // Execute the remote function with no parameters
//                long hook_main_ret = execute_remote_function(target_process_pid,
//                                                             remote_hook_main_addr, nullptr, 0,
//                                                             &temp_regs);
//                // Use %ld for long decimal, or %lx for long hex
//                LOGD("hook_main returned: %ld (0x%lx)", hook_main_ret, hook_main_ret);
//            }
//        }
//    }

    ptrace(PTRACE_SETREGS, target_process_pid, NULL, &original_regs);
    ptrace(PTRACE_DETACH, target_process_pid, NULL, NULL);
    LOGD("Successfully detached the injector process");
    return 0;
}