#include <link.h>
#include <linux/elf.h>
#include <string>
#include <string_view>
#include <sys/types.h>
#include <unordered_map>

#define SHT_GNU_HASH 0x6ffffff6

namespace NativeHook
{

    class FileImg
    {
    public:
        FileImg(std::string_view file);

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
            return elf;
        }

        !ElfImg();

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

        // hash utils
        uint32_t nbucket_{};
        uint32_t *bucket_ = nullptr;
        uint32_t *chain_ = nullptr;

        uint32_t gnu_nbucket_{};
        uint32_t gnu_symndx_{};
        uint32_t gnu_bloom_size_;
        uint32_t gnu_shift2_;
        uintptr_t *gnu_bloom_filter_;
        uint32_t *gnu_bucket_;
        uint32_t *gnu_chain_;

        // unordered map that will store symbol table.
        mutable std::unordered_map<std::string_view, ElfW(Sym) *> symtabs_;
    };

    /*
     * HASHING ALGOS
     */
    constexpr uint32_t ElfImg::ElfHash(std::string_view name)
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

    constexpr uint32_t ElfImg::GnuHash(std::string_view name)
    {
        uint32_t h = 5381;
        for (unsigned char p : name)
        {
            h += (h << 5) + p;
        }
        return h;
    }
}