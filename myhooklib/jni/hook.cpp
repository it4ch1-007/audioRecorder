#include <iostream>
#include <android/log.h>
#include <fstream>
#include <string>
#include <vector>
#include <optional>
#include <cstdint>
#include "elfio.hpp"

#define LOG_TAG "NativeHook"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

using namespace ELFIO;
std::optional<uint64_t> find_got_symbol(const std::string& path,const std::string& symbol_name){
    elfio reader;
    if(!reader.load(path)){
        return std::nullopt;
    }

    //Finding the dynamic symbol table
    const symbol_section_accessor* dynsym = nullptr;
    const string_section_accessor* dynstr = nullptr;

    for(const auto& sec: reader.sections){
        if(sec->get_type() ==SHT_DYNSYM){
            dynsym = new symbol_section_accessor(reader,sec);
            const section* str_sec = reader.sections[sec->get_link()];
            dynstr = new string_section_accessor(reader,str_sec);
            break;
        }
    }

    //If both are null
    if(!dynsym || !dynstr){
        delete dynsym;
        delete dynstr;
        return std::nullopt;
    }


    //Now we will iterate over relocation sections
    for(const auto& sec: reader.sections){
        if(sec->get_type()!= SHT_REL && sec->get_type()!=SHT_RELA){
            continue;
        }

        relocation_section_accessor relocs(reader,sec);
        Elf_Xword rel_count = relocs.get_entries_num();

        for(Elf_Xword i=0;i<rel_count;++i){
            Elf64_Addr offset;
            Elf_Word symbol_idx;
            Elf_Word type;
            Elf_Sxword addend;

            if(!relocs.get_entry(i,pffset,symbol_idx,type,addend)){
                continue;
            }

            //Getting the symbol name
            std::string current_symbol_name;
        }
    }
}

// Constructor that runs when the library is first loaded.
__attribute__((constructor))
void on_load() {
    LOGI("libhook.so loaded successfully and on_load() was called!");
    std::ofstream ofs("/data/local/tmp/hookconfirm.txt");
    ofs << "Loaded!" << std::endl;
    ofs.close();
    // hook_main();
}