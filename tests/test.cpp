#include <iostream>
#include <fstream>
#include <string>
#include <cstring> // for memcpy
#include <stdexcept>
#include <filesystem>
#include "libSampleELF.so.h"
#include <ELFPP/ELFPP.hpp>

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

int main()
{
    FileRAII f(libSampleELF_so, sizeof(libSampleELF_so), "sample.sample");
    std::unique_ptr<ELFPP::IELF> elf;
    if(!ELFPP::ElfOpen("sample.sample", elf)) return 0;
    std::cout << std::hex << elf->GetImageSize() << std::endl;
    Shift<>{ 0x10 }.Disp<int>(0);

}