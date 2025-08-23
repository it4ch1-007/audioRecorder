#include <fcntl.h>
#include <malloc.h>
#include <sys/mman.h>
// #include <android/log.h>
#include <string.h>
#include <sys/stat.h>
#include "file_utils.h"
#include <unistd.h>

#define LOG_TAG "NativeHook"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

using namespace NativeHook;


template <typename T>
inline constexpr auto offsetOf(ElfW(Ehdr) * head, ElfW(Off) off)
{
    return reinterpret_cast<std::conditional_t<std::is_pointer_v<T>, T, T *>>(reinterpret_cast<uintptr_t>(head) + off);
}

// constructor for handling files
FileImg::FileImg(std::string_view base_name) : file(base_name)
{
    if (!findBaseAddr())
    {
        base = nullptr;
        return;
    }

    int fd = open(file.data(), O_RDONLY);
    if (fd < 0)
    {
        return;
    }
    // set the ptr to the end
    size = lseek(fd, 0, SEEK_END);
    if (size <= 0)
    {
        // lseek failed...
        // LOGD("Lseek failed...");
    }

    file_header = reinterpret_cast<decltype(file_header)>(mmap(nullptr, size, PROT_READ, MAP_SHARED, fd, 0));
    close(fd);
    section_header = offsetOf<decltype(section_header)>(file_header, file_header->e_shoff);

    auto shoff = reinterpret_cast<uintptr_t>(section_header);
    char *section_str = offsetOf<char *>(file_header, section_header[file_header->e_shstrndx].sh_offset);

    // iterate over the section  header entries
    for (int i = 0; i < file_header->e_shnum; i++, shoff += file_header->e_shentsize)
    {
        auto *section_h = (ElfW(Shdr) *)shoff;
        char *sname = section_h->sh_name + section_str;
        auto entsize = section_h->sh_entsize;
        switch (section_h->sh_type)
        {
            // in the case of dynamic symbols
        case SHT_DYNSYM:
        {
            if (bias == -4396)
            {
                dynsym = section_h;
                dynsym_offset = section_h->sh_offset;
                dynsym_start = offsetOf<decltype(dynsym_start)>(file_header, dynsym_offset);
            }
            break;
        }
        // in the case of symbol table
        case SHT_SYMTAB:
        {
            if (strcmp(sname, ".symtab") == 0)
            {
                symtab = section_h;
                symtab_offset = section_h->sh_offset;
                symtab_size = section_h->sh_size;
                symtab_count = symtab_size / entsize;
                symtab_start = offsetOf<decltype(symtab_start)>(file_header, symtab_offset);
            }
            break;
        }
        // in the case of string table
        case SHT_STRTAB:
        {
            if (bias == -4396)
            {
                strtab = section_h;
                symstr_offset = section_h->sh_offset;
                strtab_start = offsetOf<decltype(strtab_start)>(file_header, symstr_offset);
            }
            if (strcmp(sname, ".strtab") == 0)
            {
                symstr_offset_for_symtab = section_h->sh_offset;
            }
            break;
        }
        case SHT_PROGBITS:
        {
            if (strtab == nullptr || dynsym == nullptr)
                break;
            if (bias == -4396)
            {
                bias = (off_t)section_h->sh_addr - (off_t)section_h->sh_offset;
            }
            break;
        }
        case SHT_HASH:
        {
            ElfW(Word) *d_un = offsetOf<ElfW(Word)>(file_header, section_h->sh_offset);
            nbucket_ = d_un[0];
            bucket_ = d_un + 2;
            chain_ = bucket_ + nbucket_;
            break;
        }
        case SHT_GNU_HASH:
        {
            auto *d_buf = reinterpret_cast<ElfW(Word) *>(((size_t)file_header) + section_h->sh_offset);
            gnu_nbucket_ = d_buf[0];
            gnu_symndx_ = d_buf[1];
            gnu_bloom_size_ = d_buf[2];
            gnu_shift_ = d_buf[3];
            gnu_bloom_filter_ = reinterpret_cast<decltype(gnu_bloom_filter_)>(d_buf + 4);
            gnu_bucket_ = reinterpret_cast<decltype(gnu_bucket_)>(gnu_bloom_filter_ + gnu_bloom_size_);
            gnu_chain_ = gnu_bucket_ + gnu_nbucket_ - gnu_symndx_;
            break;
        }
        }
    }
}

// Elflookup hash method
ElfW(Addr) FileImg::ElfLookup(std::string_view name, uint32_t hash) const
{
    if (nbucket_ == 0)
        return 0;

    char *strings = (char *)strtab_start;

    for (auto n = bucket_[hash % nbucket_]; n != 0; n = chain_[n])
    {
        auto *sym = dynsym_start + n;
        if (name == strings + sym->st_name)
        {
            return sym->st_value;
        }
    }
    return 0;
}

// GnuLookup hash method
ElfW(Addr) FileImg::GnuLookup(std::string_view name, uint32_t hash) const
{
    static constexpr auto bloom_mask_bits = sizeof(ElfW(Addr)) * 8;
    if (gnu_bucket_ == 0 || gnu_bloom_size_ == 0)
        return 0;

    auto bloom_word = gnu_bloom_filter_[(hash / bloom_mask_bits) % gnu_bloom_size_];
    uintptr_t mask = 0 | (uintptr_t)1 << (hash % bloom_mask_bits) | (uintptr_t)1 << ((hash >> gnu_shift_) % bloom_mask_bits);
    if ((mask & bloom_word) == mask)
    {
        auto sym_index = gnu_bucket_[hash % gnu_nbucket_];
        if (sym_index >= gnu_symndx_)
        {
            char *strings = (char *)strtab_start;
            do
            {
                auto *sym = dynsym_start + sym_index;
                if (((gnu_chain_[sym_index] ^ hash) >> 1) == 0 && name == strings + sym->st_name)
                    return sym->st_value;
            } while ((gnu_chain_[sym_index++] & 1) == 0);
        }
    }
    return 0;
}

// Simple linear lookup method to find symbols
ElfW(Addr) FileImg::LinearLookup(std::string_view name) const
{
    // If there is empty symbol table....
    if (symtabs_.empty())
    {
        symtabs_.reserve(symtab_count);
        if (symtab_start != nullptr && symstr_offset_for_symtab != 0)
        {
            for (ElfW(Off) i = 0; i < symtab_count; i++)
            {
                unsigned int st_type = ELF_ST_TYPE(symtab_start[i].st_info);
                const char *st_name = offsetOf<const char *>(file_header, symstr_offset_for_symtab + symtab_start[i].st_name);
                if ((st_type == STT_FUNC || st_type == STT_OBJECT) && symtab_start[i].st_size)
                {
                    symtabs_.emplace(st_name, &symtab_start[i]);
                }
            }
        }
    }

    if (auto i = symtabs_.find(name); i != symtabs_.end())
    {
        return i->second->st_value;
    }
    else
    {
        return 0;
    }
}

// This is the method that finds the related symbols using the given symbol.
std::string_view FileImg::LinearLookupByPrefix(std::string_view name) const
{
    if (symtabs_.empty())
    {
        symtabs_.reserve(symtab_count);
        if (symtab_start != nullptr && symstr_offset_for_symtab != 0)
        {
            for (ElfW(Off) i = 0; i < symtab_count; i++)
            {
                unsigned int st_type = ELF_ST_TYPE(symtab_start[i].st_info);
                const char *st_name = offsetOf<const char *>(file_header, symstr_offset_for_symtab + symtab_start[i].st_name);
                if ((st_type == STT_FUNC || st_type == STT_OBJECT) && symtab_start[i].st_size)
                {
                    symtabs_.emplace(st_name, &symtab_start[i]);
                }
            }
        }
    }

    auto size = name.size();
    for (auto symtab : symtabs_)
    {
        if (symtab.first.size() < size)
            continue;
        if (symtab.first.substr(0, size) == name)
        {
            return symtab.first;
        }
    }

    return "";
}

// destructor
FileImg::~FileImg()
{
    if (buffer)
    {
        free(buffer);
        buffer = nullptr;
    }
    if (file_header)
    {
        munmap(file_header, size);
    }
}

// The function will use 2 algorithms to find the symbol specified
ElfW(Addr) FileImg::getSymbOffset(std::string_view name, uint32_t gnu_hash, uint32_t elf_hash) const
{
    if (auto offset = GnuLookup(name, gnu_hash); offset > 0)
    {
        return offset;
    }
    if (auto offset = ElfLookup(name, elf_hash); offset > 0)
    {
        return offset;
    }
    if (auto offset = LinearLookup(name); offset > 0)
    {
        return offset;
    }
    else
    {
        return 0;
    }
}

// Finding the base address of all modules inside the process' own memory.
bool FileImg::findBaseAddr()
{
    dl_iterate_phdr(
        [](struct dl_phdr_info *info, size_t size, void *data) -> int
        {
            (void)size;

            if ((info)->dlpi_name == nullptr)
            {
                return 0;
            }
            auto *self = reinterpret_cast<FileImg *>(data);
            if (strstr(info->dlpi_name, self->file.data()))
            {
                self->file = info->dlpi_name;
                self->base = reinterpret_cast<void *>(info->dlpi_addr);
                return 1;
            }
            return 0;
        },
        this);
    return base != 0;
}