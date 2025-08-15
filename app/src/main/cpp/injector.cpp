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


#define LOG_TAG "Injector.cpp"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)


void* get_remote_lib_address(pid_t pid,const char* lib_name){
    //by reading the /proc/pid/maps file to get the base address of the library
    char maps_path[256];
    snprintf(maps_path, sizeof(maps_path),"/proc/%d/maps",pid);

    std::ifstream maps_file(maps_path);
    std::string line;

    while(getline(maps_file,line)){
        if(line.find(lib_name)!=std::string::npos){
            return (void*)(std::stoul(line.substr(0,line.find('-')),nullptr,16));
        }
    }
    return nullptr;
}

void* get_remote_function_address(pid_t pid,const char* lib_name,const void* local_function_addr){
    void* local_lib_addr = dlopen(lib_name,RTLD_LAZY);
    if(!local_lib_addr) return nullptr;

    void* remote_lib_addr = get_remote_lib_address(pid,lib_name);
    if(!remote_lib_addr){
        LOGD(LOG_TAG,"UNABLE TO GE THE REMOTE LIBRARY ADDRESS !!");
        dlclose(local_lib_addr);
        return nullptr;
    }

    long fn_off = (long)local_function_addr - (long)local_lib_addr;
    dlclose(local_lib_addr);

    return (void*)((long)remote_lib_addr + fn_off);
}

long execute_remote_function(pid_t pid,void* func_addr,long* params,int num_params,struct user_regs_struct* regs){
    //setting up the args for the fn
    if(num_params>0) regs->rdi = params[0];
    if(num_params>0) regs->rsi = params[1];
    if(num_params>0) regs->rdx = params[2];
    if(num_params>0) regs->rcx = params[3];
    if(num_params>0) regs->r8 = params[4];
    if(num_params>0) regs->r9 = params[5];

    regs->rip = (unsigned long)func_addr;
    ptrace(PTRACE_SETREGS,pid,NULL,NULL);
    ptrace(PTRACE_CONT,pid,NULL,NULL);

    //wait till the fn is completely executed.
    int status;
    waitpid(pid,&status,WUNTRACED);

    //finding the return value of the fn
    ptrace(PTRACE_GETREGS,pid,NULL,regs);
    return regs->rax;
}

int write_to_remote_address(pid_t pid,void* dest,const void* src,size_t size){
    for(size_t i=0;i<size;i+=sizeof(long)){
        if(ptrace(PTRACE_POKEDATA,pid,(char*)dest+i,*(long*)((char*)src+i))==-1){
            LOGD("Failed to write the process' memory");
            return -1;
        }
    }
    return 0;
}
int main(int argc,char** argv){
    if(argc!=3){
        LOGD(LOG_TAG,"Usage: injector <pid> <lib_path>");
        return -1;
    }

    pid_t target_process_pid = atoi(argv[1]);
    const char* lib_path = argv[2];

    LOGD("Injecting %s into PID=%d",lib_path,target_process_pid);

    //This system call will pause the process and attach our process to it.
    if(ptrace(PTRACE_ATTACH,target_process_pid,NULL,NULL)<0){
        LOGD("Error: PTRACE_ATTACH syscall failed !!");
        return -1;
    }
    wait(nullptr); //Wait for the process to attach to our process
    LOGD("Successfully attached the process.");

    //Save the process original register state so we can restore it later.
    struct user_regs_struct original_regs, temp_regs;
    ptrace(PTRACE_GETREGS,target_process_pid,NULL,&original_regs);
    memcpy(&temp_regs,&original_regs,sizeof(struct user_regs_struct));

    //gets the address if dlopen fn inside the target process's memory
    void* remote_dlopen_addr = get_remote_function_address(target_process_pid,"/system/bin/linker64",(void*)dlopen);
    if(!remote_dlopen_addr){
        LOGD("Error: Could not find the dlopen address!!");
        ptrace(PTRACE_DETACH,target_process_pid,NULL,NULL);
        return -1;
    }
    LOGD("Remote dlopen address: %p",remote_dlopen_addr);

    //Now we will do the same thing with the mmap fn
    void* remote_mmap_addr = get_remote_function_address(target_process_pid,"libc.so",(void*)mmap);
    if(!remote_mmap_addr){
        LOGD("Error: Could not find remote mmap address");
        ptrace(PTRACE_DETACH,target_process_pid,NULL,NULL);
        return -1;
    }

    //Calling the fn mmap of the targte process' instance
    long mmap_params[] = {0, static_cast<long>(strlen(lib_path)+1),PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE,0,0};
    void* remote_path_addr = (void*)execute_remote_function(target_process_pid,remote_mmap_addr,mmap_params,6,&temp_regs);

    //writing the library path inside the target process' memory
    write_to_remote_address(target_process_pid,remote_path_addr,lib_path, strlen(lib_path)+1);

    //Now calling dlopen with the path of our liubrary written into the target process' memory
    long dlopen_params[] = {(long)remote_path_addr,RTLD_NOW};
    void* dlopen_ret = (void*) execute_remote_function(target_process_pid,remote_dlopen_addr,dlopen_params,2,&temp_regs);

    if(!dlopen_ret){
        LOGD("Error: dlopen failed..");
    }
    else{
        LOGD("Success...Library injected successfully..");
    }

    //The target process would have till now called the dlopen on our library and our hooks will be installed.
    //Now we will restore the state at which the process was before.

    ptrace(PTRACE_SETREGS,target_process_pid,NULL,&original_regs);
    ptrace(PTRACE_DETACH,target_process_pid,NULL,NULL);
    LOGD("Successfully detached the injector process");
    return 0;
}