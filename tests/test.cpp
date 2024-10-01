#include <doctest/doctest.h>

#include <iostream>
#include <fstream>
#include <string>
#include <cstring> // for memcpy
#include <stdexcept>
#include <filesystem>
#include "libSampleELF.so.h"
#include <ELFPP.hpp>

namespace fs = std::filesystem;

class FileRAII {
public:
    FileRAII(const void* buffer, std::size_t size, const std::string& filename)
        : buffer_(buffer), size_(size), filename_(filename), path_(filename) {
        if (filename.empty()) {
            throw std::invalid_argument("Filename cannot be empty.");
        }
        if (!std::filesystem::path(filename).is_absolute()) {
            path_ = fs::current_path() / filename;
        }
        createFile();
        writeFile();
    }

    ~FileRAII() {
        eraseFile();
    }

private:
    const void* buffer_;
    std::size_t size_;
    std::string filename_;
    fs::path path_;

    void createFile() {
        std::ofstream file(path_, std::ios::binary);
        if (!file) {
            throw std::runtime_error("Failed to create file.");
        }
    }

    void writeFile() {
        std::ofstream file(path_, std::ios::binary);
        if (!file) {
            throw std::runtime_error("Failed to open file for writing.");
        }
        file.write(reinterpret_cast<const char*>(buffer_), size_);
    }

    void eraseFile() {
        std::error_code ec;
        fs::remove(path_, ec);
        if (ec) {
            std::cerr << "Error removing file: " << ec.message() << std::endl;
        }
    }
};

using namespace ELFPP;

TEST_CASE("Open ELF From File")
{
    FileRAII testElf(libSampleELF_so, sizeof(libSampleELF_so), "libSampleElf.so");
    ElfPack<Elf32_Ehdr> elfPack;

    CHECK(ElfOpen("libSampleElf.so", elfPack));
}

TEST_CASE("Open ELF From Memory")
{
    ElfPack<Elf32_Ehdr> elfPack;

    CHECK(ElfOpenFromMemory(libSampleELF_so, elfPack));
}

TEST_CASE("ELF Image Size")
{
    ElfPack<Elf32_Ehdr> elfPack;

    CHECK(ElfOpenFromMemory(libSampleELF_so, elfPack));

    // GNU_RELRO Base:0x13e0 Size:0xC20 => 0x2000
    CHECK(ELFPP::ElfImageSize<Elf32_Phdr>(elfPack) == 0x2000);

    // PT_LOAD Base:0x13e0 Size:F0 => 0x14D0
    CHECK(ELFPP::ElfImageSize<Elf32_Phdr>(elfPack, true) == 0x14D0);
}

#define THUMB_CALL_BIT 1

TEST_CASE("ELF Symbol Lookup")
{
    ElfPack<Elf32_Ehdr> elfPack;

    CHECK(ElfOpenFromMemory(libSampleELF_so, elfPack));

    uint64_t symOff = 0;

    CHECK(ELFPP::ElfLookupSymbol<Elf32_Sym, Elf32_Shdr>(elfPack, "_Z6samplev", &symOff));
    CHECK(symOff == 0x398 + THUMB_CALL_BIT);
}

//// Function to get the name of a dynamic tag
//const char* GetDynamicTagName(Elf32_Sword tag) {
//    switch (tag) {
//    case DT_NULL: return "DT_NULL";
//    case DT_NEEDED: return "DT_NEEDED";
//    case DT_PLTRELSZ: return "DT_PLTRELSZ";
//    case DT_PLTGOT: return "DT_PLTGOT";
//    case DT_HASH: return "DT_HASH";
//    case DT_STRTAB: return "DT_STRTAB";
//    case DT_SYMTAB: return "DT_SYMTAB";
//    case DT_RELA: return "DT_RELA";
//    case DT_RELASZ: return "DT_RELASZ";
//    case DT_RELAENT: return "DT_RELAENT";
//    case DT_STRSZ: return "DT_STRSZ";
//    case DT_SYMENT: return "DT_SYMENT";
//    case DT_INIT: return "DT_INIT";
//    case DT_FINI: return "DT_FINI";
//    case DT_SONAME: return "DT_SONAME";
//    case DT_RPATH: return "DT_RPATH";
//    case DT_SYMBOLIC: return "DT_SYMBOLIC";
//    case DT_REL: return "DT_REL";
//    case DT_RELSZ: return "DT_RELSZ";
//    case DT_RELENT: return "DT_RELENT";
//    case DT_RELCOUNT: return "DT_RELCOUNT";
//    case DT_GNU_HASH: return "DT_GNU_HASH";
//    case DT_PLTREL: return "DT_PLTREL";
//    case DT_DEBUG: return "DT_DEBUG";
//    case DT_TEXTREL: return "DT_TEXTREL";
//    case DT_JMPREL: return "DT_JMPREL";
//    case DT_ENCODING: return "DT_ENCODING";
//        // Add more cases for other dynamic tags as needed
//    default: return "Unknown"; // Return "Unknown" for tags not handled explicitly
//    }
//}
//
//// Function to beautifully print an Elf32_Dyn structure
//void PrintElfDynEntry(Elf32_Dyn* pCurr) {
//    std::cout << "Tag: " << GetDynamicTagName(pCurr->d_tag) << std::endl;
//    std::cout << "Value: " << pCurr->d_un.d_val << std::endl; // Assuming d_un.d_val is the value field, adjust accordingly if it's different
//    // Add more fields to print if needed
//}
//
//void PrintElfDynEntry(Elf32_Dyn& pCurr) {
//    PrintElfDynEntry(&pCurr);
//}

TEST_CASE("ELF Dynamic Table")
{
    ElfPack<Elf32_Ehdr> elfPack;

    CHECK(ElfOpenFromMemory(libSampleELF_so, elfPack));

    auto dynTable = ElfGetDynamicTable<Elf32_Dyn, Elf32_Shdr>(elfPack);

    CHECK(dynTable.find(DT_NULL) != dynTable.end());
}