#include <link.h>
#include <linux/elf.h>
#include <string>
#include <string_view>
#include <sys/types.h>
#include <unordered_map>
#include <unistd.h>
#include <cstring>
#include <sys/mman.h>

#define SHT_GNU_HASH 0x6ffffff6
namespace NativeHook
{
    class FileImg
    {
    public:
        FileImg(std::string_view file);
        constexpr ElfW(Addr) getAddressFromOffset(ElfW(Addr) Offset) const
        {
            if (base != nullptr && Offset > 0)
            {
                // Address is the library's base address plus the file offset.
                return static_cast<ElfW(Addr)>((uintptr_t)base + Offset);
            }
            return 0;
        }
        template <typename T>
        constexpr T getAddressFromOffset(ElfW(Addr) offset) const
        {
            return reinterpret_cast<T>(getAddressFromOffset(offset));
        }
        // getting the offset of a symbol inside a file.
        constexpr ElfW(Addr) getSymbOffset(std::string_view name) const
        {
            return getSymbOffset(name, GnuHash(name), ElfHash(name));
        }
        // Getting the runtime memory address of that symbol
        constexpr ElfW(Addr) getSymbAddress(std::string_view name) const
        {
            ElfW(Addr) offset = getSymbOffset(name);
            if (offset > 0 && base != nullptr)
            {
                return static_cast<ElfW(Addr)>((uintptr_t)base + offset - bias);
            }
            else
            {
                return 0;
            }
        }
        std::string_view findSymbolName(std::string_view prefix) const
        {
            return LinearLookupByPrefix(prefix);
        }
        template <typename T>
        constexpr T getSymbAddress(std::string_view name) const
        {
            return reinterpret_cast<T>(getSymbAddress(name));
        }
        bool isValid() const { return base != nullptr; }
        const std::string name() const
        {
            return file;
        }

        void InlineHook(void *target, void *newFunc, void **oldFunc)
        {
            if (target == nullptr || newFunc == nullptr || oldFunc == nullptr)
            {
                // LOGD("InlineHook received a null pointer.");
                return;
            }
            // This can be changed according to the arch of the device
            unsigned char patch[12];
            patch[0] = 0x48;
            patch[1] = 0xb8;
            memcpy(patch + 2, &newFunc, 8);
            patch[10] = 0xff;
            patch[11] = 0xe0;
            // Get the page size for this system
            long pageSize = sysconf(_SC_PAGESIZE);
            if (pageSize == -1)
            {
                // LOGD("sysconf failed to get page size");
                return;
            }
            void *pageStart = (void *)((uintptr_t)target & -pageSize);
            if (mprotect(pageStart, pageSize, PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
            {
                // LOGD("mprotect failed to make page writable");
                return;
            }
            if (*oldFunc == nullptr)
            {
                *oldFunc = malloc(12);
                if (*oldFunc != nullptr)
                {
                    memcpy(*oldFunc, target, 12);
                }
                else
                {
                    // LOGD("Failed to allocate memory for trampoline.");
                }
            }
            // Apply the patch to the target function
            memcpy(target, patch, 12);
            // Restore the original memory permissions
            if (mprotect(pageStart, pageSize, PROT_READ | PROT_EXEC) != 0)
            {
                // LOGD("mprotect failed to restore page permissions");
            }
        }
        ~FileImg();

    private:
        ElfW(Addr) getSymbOffset(std::string_view name, uint32_t gnu_hash, uint32_t elf_hash) const;
        ElfW(Addr) ElfLookup(std::string_view name, uint32_t hash) const;
        ElfW(Addr) GnuLookup(std::string_view name, uint32_t hash) const;
        ElfW(Addr) LinearLookup(std::string_view name) const;
        std::string_view LinearLookupByPrefix(std::string_view name) const;
        constexpr static uint32_t ElfHash(std::string_view name);
        constexpr static uint32_t GnuHash(std::string_view name);
        bool findBaseAddr();
        std::string file;
        void *base = nullptr;
        char *buffer = nullptr;
        off_t size = 0;
        off_t bias = -4396;
        ElfW(Ehdr) *file_header = nullptr;
        ElfW(Shdr) *section_header = nullptr;
        ElfW(Shdr) *symtab = nullptr;
        ElfW(Shdr) *strtab = nullptr;
        ElfW(Shdr) *dynsym = nullptr;
        ElfW(Sym) *strtab_start = nullptr;
        ElfW(Sym) *dynsym_start = nullptr;
        ElfW(Sym) *symtab_start = nullptr;
        ElfW(Off) symtab_count = 0;
        ElfW(Off) symstr_offset = 0;
        ElfW(Off) symstr_offset_for_symtab = 0;
        ElfW(Off) symtab_offset = 0;
        ElfW(Off) dynsym_offset = 0;
        ElfW(Off) symtab_size = 0;

        // hash utils
        uint32_t nbucket_{};
        uint32_t *bucket_ = nullptr;
        uint32_t *chain_ = nullptr;
        uint32_t gnu_nbucket_{};
        uint32_t gnu_symndx_{};
        uint32_t gnu_bloom_size_;
        uint32_t gnu_shift_;
        uintptr_t *gnu_bloom_filter_;
        uint32_t *gnu_bucket_;
        uint32_t *gnu_chain_;
        // unordered map that will store symbol table.

        mutable std::unordered_map<std::string_view, ElfW(Sym) *> symtabs_;
    };

    template <typename T>
    void Hook(const char *libraryPath, T symbolOrOffset, void *newFunc, void **oldFunc)
    {
        NativeHook::FileImg lib(libraryPath);
        if (!lib.isValid())
        {
            // LOGD("Library %s does not exist inside the process..",libraryPath);
            return;
        }

        void *targetAddr = nullptr;
        if constexpr (std::is_integral_v<T>)
        {
            // if the offset is given
            targetAddr = lib.getAddressFromOffset(static_cast<ElfW(Addr)>(symbolOrOffset));
        }
        else
        {
            targetAddr = reinterpret_cast<void *>(lib.getSymbAddress(symbolOrOffset));
        }
        if (targetAddr == nullptr)
        {
            return;
        }
        lib.InlineHook(targetAddr, newFunc, oldFunc);
    }

    /*

    * HASHING ALGOS

    */
    constexpr uint32_t FileImg::ElfHash(std::string_view name)
    {
        uint32_t h = 0, g = 0;
        for (unsigned char p : name)
        {
            h = (h << 4) + p;
            g = h & 0xf0000000;
            h ^= g;
            h ^= g >> 24;
        }
        return h;
    }

    constexpr uint32_t FileImg::GnuHash(std::string_view name)
    {
        uint32_t h = 5381;
        for (unsigned char p : name)
        {
            h += (h << 5) + p;
        }
        return h;
    }
}
