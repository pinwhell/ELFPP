# ELFPP: C++ Library for Portable ELF File Handling

**ELFPP** is a C++ library designed for efficient and platform-independent handling of ELF (Executable and Linkable Format) files. The library provides a set of classes and functions to facilitate the inspection and manipulation of ELF files, covering aspects such as sections, programs, and symbols.

## Features

- **File Mapping:** Efficiently map ELF files into memory, abstracting platform-specific details.
- **Section Handling:** Retrieve, iterate, and lookup ELF sections by index or name.
- **Program Header Exploration:** Explore program headers, including loadable program headers.
- **Symbol Table Interaction:** Traverse symbol tables, lookup symbols by name, and iterate over symbols.

## Usage

### Initialization

```cpp
#include "ELFPP.hpp"
using namespace ELFPP;
// Open ELF file
std::unique_ptr<IELF> elf;
if (ElfOpen("example.elf", elf)) {
    // Access ELF file data through elfPack
}
```

### Section Handling

```cpp

// Iterate over all sections
elf->ForEachSection([](void* section) -> bool {
    // Process each section
    return true; // Continue iteration
});
```

### Symbol Table Interaction

```cpp

// Lookup a symbol by name
uint64_t symbolOffset;
if (elf->LookupSymbol("example_symbol", &symbolOffset)) {
    // Symbol found, use symbolOffset
}
```

### Building

The library is header-only and does not require building. Simply include the ELFPP.hpp header in your C++ project.


### Platform Support

    Windows: Uses WinAPI for file mapping (Windows-specific code inside #ifdef _WIN32).
    Linux: Uses Posix Standard for file open/mapping.
    Other Platforms: Placeholder for platform-specific code; currently throws a compilation error.

### License

This project is licensed under the MIT License - see the LICENSE file for details.
