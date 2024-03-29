#pragma once

#include <iostream>
#include <functional>
#include <string>
#include <memory>
#include <vector>
#include <algorithm>
#include <cstdint>
#include <filesystem>

#ifdef _WIN32 
#include <Windows.h>
#endif

#ifdef __linux__
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#endif


#if __has_include(<elf.h>)
#include <elf.h>
#else

/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_ELF_H
#define _UAPI_LINUX_ELF_H

/* 32-bit ELF base types. */
typedef uint32_t	Elf32_Addr;
typedef uint16_t	Elf32_Half;
typedef uint32_t	Elf32_Off;
typedef int32_t	Elf32_Sword;
typedef uint32_t	Elf32_Word;

/* 64-bit ELF base types. */
typedef uint64_t	Elf64_Addr;
typedef uint16_t	Elf64_Half;
typedef int16_t	Elf64_SHalf;
typedef uint64_t	Elf64_Off;
typedef int32_t	Elf64_Sword;
typedef uint32_t	Elf64_Word;
typedef uint64_t	Elf64_Xword;
typedef int64_t	Elf64_Sxword;

/* These constants are for the segment types stored in the image headers */
#define PT_NULL    0
#define PT_LOAD    1
#define PT_DYNAMIC 2
#define PT_INTERP  3
#define PT_NOTE    4
#define PT_SHLIB   5
#define PT_PHDR    6
#define PT_TLS     7               /* Thread local storage segment */
#define PT_LOOS    0x60000000      /* OS-specific */
#define PT_HIOS    0x6fffffff      /* OS-specific */
#define PT_LOPROC  0x70000000
#define PT_HIPROC  0x7fffffff
#define PT_GNU_EH_FRAME		0x6474e550
#define PT_GNU_PROPERTY		0x6474e553

#define PT_GNU_STACK	(PT_LOOS + 0x474e551)

/*
 * Extended Numbering
 *
 * If the real number of program header table entries is larger than
 * or equal to PN_XNUM(0xffff), it is set to sh_info field of the
 * section header at index 0, and PN_XNUM is set to e_phnum
 * field. Otherwise, the section header at index 0 is zero
 * initialized, if it exists.
 *
 * Specifications are available in:
 *
 * - Oracle: Linker and Libraries.
 *   Part No: 817�1984�19, August 2011.
 *   https://docs.oracle.com/cd/E18752_01/pdf/817-1984.pdf
 *
 * - System V ABI AMD64 Architecture Processor Supplement
 *   Draft Version 0.99.4,
 *   January 13, 2010.
 *   http://www.cs.washington.edu/education/courses/cse351/12wi/supp-docs/abi.pdf
 */
#define PN_XNUM 0xffff

 /* These constants define the different elf file types */
#define ET_NONE   0
#define ET_REL    1
#define ET_EXEC   2
#define ET_DYN    3
#define ET_CORE   4
#define ET_LOPROC 0xff00
#define ET_HIPROC 0xffff

/* This is the info that is needed to parse the dynamic section of the file */
#define DT_NULL		0
#define DT_NEEDED	1
#define DT_PLTRELSZ	2
#define DT_PLTGOT	3
#define DT_HASH		4
#define DT_STRTAB	5
#define DT_SYMTAB	6
#define DT_RELA		7
#define DT_RELASZ	8
#define DT_RELAENT	9
#define DT_STRSZ	10
#define DT_SYMENT	11
#define DT_INIT		12
#define DT_FINI		13
#define DT_SONAME	14
#define DT_RPATH 	15
#define DT_SYMBOLIC	16
#define DT_REL	        17
#define DT_RELSZ	18
#define DT_RELENT	19
#define DT_PLTREL	20
#define DT_DEBUG	21
#define DT_TEXTREL	22
#define DT_JMPREL	23
#define DT_ENCODING	32
#define OLD_DT_LOOS	0x60000000
#define DT_LOOS		0x6000000d
#define DT_HIOS		0x6ffff000
#define DT_VALRNGLO	0x6ffffd00
#define DT_VALRNGHI	0x6ffffdff
#define DT_ADDRRNGLO	0x6ffffe00
#define DT_ADDRRNGHI	0x6ffffeff
#define DT_VERSYM	0x6ffffff0
#define DT_RELACOUNT	0x6ffffff9
#define DT_RELCOUNT	0x6ffffffa
#define DT_FLAGS_1	0x6ffffffb
#define DT_VERDEF	0x6ffffffc
#define	DT_VERDEFNUM	0x6ffffffd
#define DT_VERNEED	0x6ffffffe
#define	DT_VERNEEDNUM	0x6fffffff
#define OLD_DT_HIOS     0x6fffffff
#define DT_LOPROC	0x70000000
#define DT_HIPROC	0x7fffffff

/* This info is needed when parsing the symbol table */
#define STB_LOCAL  0
#define STB_GLOBAL 1
#define STB_WEAK   2

#define STT_NOTYPE  0
#define STT_OBJECT  1
#define STT_FUNC    2
#define STT_SECTION 3
#define STT_FILE    4
#define STT_COMMON  5
#define STT_TLS     6

#define ELF_ST_BIND(x)		((x) >> 4)
#define ELF_ST_TYPE(x)		(((unsigned int) x) & 0xf)
#define ELF32_ST_BIND(x)	ELF_ST_BIND(x)
#define ELF32_ST_TYPE(x)	ELF_ST_TYPE(x)
#define ELF64_ST_BIND(x)	ELF_ST_BIND(x)
#define ELF64_ST_TYPE(x)	ELF_ST_TYPE(x)

typedef struct dynamic {
    Elf32_Sword d_tag;
    union {
        Elf32_Sword	d_val;
        Elf32_Addr	d_ptr;
    } d_un;
} Elf32_Dyn;

typedef struct {
    Elf64_Sxword d_tag;		/* entry tag value */
    union {
        Elf64_Xword d_val;
        Elf64_Addr d_ptr;
    } d_un;
} Elf64_Dyn;

/* The following are used with relocations */
#define ELF32_R_SYM(x) ((x) >> 8)
#define ELF32_R_TYPE(x) ((x) & 0xff)

#define ELF64_R_SYM(i)			((i) >> 32)
#define ELF64_R_TYPE(i)			((i) & 0xffffffff)

typedef struct elf32_rel {
    Elf32_Addr	r_offset;
    Elf32_Word	r_info;
} Elf32_Rel;

typedef struct elf64_rel {
    Elf64_Addr r_offset;	/* Location at which to apply the action */
    Elf64_Xword r_info;	/* index and type of relocation */
} Elf64_Rel;

typedef struct elf32_rela {
    Elf32_Addr	r_offset;
    Elf32_Word	r_info;
    Elf32_Sword	r_addend;
} Elf32_Rela;

typedef struct elf64_rela {
    Elf64_Addr r_offset;	/* Location at which to apply the action */
    Elf64_Xword r_info;	/* index and type of relocation */
    Elf64_Sxword r_addend;	/* Constant addend used to compute value */
} Elf64_Rela;

typedef struct elf32_sym {
    Elf32_Word	st_name;
    Elf32_Addr	st_value;
    Elf32_Word	st_size;
    unsigned char	st_info;
    unsigned char	st_other;
    Elf32_Half	st_shndx;
} Elf32_Sym;

typedef struct elf64_sym {
    Elf64_Word st_name;		/* Symbol name, index in string tbl */
    unsigned char	st_info;	/* Type and binding attributes */
    unsigned char	st_other;	/* No defined meaning, 0 */
    Elf64_Half st_shndx;		/* Associated section index */
    Elf64_Addr st_value;		/* Value of the symbol */
    Elf64_Xword st_size;		/* Associated symbol size */
} Elf64_Sym;


#define EI_NIDENT	16

typedef struct elf32_hdr {
    unsigned char	e_ident[EI_NIDENT];
    Elf32_Half	e_type;
    Elf32_Half	e_machine;
    Elf32_Word	e_version;
    Elf32_Addr	e_entry;  /* Entry point */
    Elf32_Off	e_phoff;
    Elf32_Off	e_shoff;
    Elf32_Word	e_flags;
    Elf32_Half	e_ehsize;
    Elf32_Half	e_phentsize;
    Elf32_Half	e_phnum;
    Elf32_Half	e_shentsize;
    Elf32_Half	e_shnum;
    Elf32_Half	e_shstrndx;
} Elf32_Ehdr;

typedef struct elf64_hdr {
    unsigned char	e_ident[EI_NIDENT];	/* ELF "magic number" */
    Elf64_Half e_type;
    Elf64_Half e_machine;
    Elf64_Word e_version;
    Elf64_Addr e_entry;		/* Entry point virtual address */
    Elf64_Off e_phoff;		/* Program header table file offset */
    Elf64_Off e_shoff;		/* Section header table file offset */
    Elf64_Word e_flags;
    Elf64_Half e_ehsize;
    Elf64_Half e_phentsize;
    Elf64_Half e_phnum;
    Elf64_Half e_shentsize;
    Elf64_Half e_shnum;
    Elf64_Half e_shstrndx;
} Elf64_Ehdr;

/* These constants define the permissions on sections in the program
   header, p_flags. */
#define PF_R		0x4
#define PF_W		0x2
#define PF_X		0x1

typedef struct elf32_phdr {
    Elf32_Word	p_type;
    Elf32_Off	p_offset;
    Elf32_Addr	p_vaddr;
    Elf32_Addr	p_paddr;
    Elf32_Word	p_filesz;
    Elf32_Word	p_memsz;
    Elf32_Word	p_flags;
    Elf32_Word	p_align;
} Elf32_Phdr;

typedef struct elf64_phdr {
    Elf64_Word p_type;
    Elf64_Word p_flags;
    Elf64_Off p_offset;		/* Segment file offset */
    Elf64_Addr p_vaddr;		/* Segment virtual address */
    Elf64_Addr p_paddr;		/* Segment physical address */
    Elf64_Xword p_filesz;		/* Segment size in file */
    Elf64_Xword p_memsz;		/* Segment size in memory */
    Elf64_Xword p_align;		/* Segment alignment, file & memory */
} Elf64_Phdr;

/* sh_type */
#define SHT_NULL	0
#define SHT_PROGBITS	1
#define SHT_SYMTAB	2
#define SHT_STRTAB	3
#define SHT_RELA	4
#define SHT_HASH	5
#define SHT_DYNAMIC	6
#define SHT_NOTE	7
#define SHT_NOBITS	8
#define SHT_REL		9
#define SHT_SHLIB	10
#define SHT_DYNSYM	11
#define SHT_NUM		12
#define SHT_LOPROC	0x70000000
#define SHT_HIPROC	0x7fffffff
#define SHT_LOUSER	0x80000000
#define SHT_HIUSER	0xffffffff

/* sh_flags */
#define SHF_WRITE		0x1
#define SHF_ALLOC		0x2
#define SHF_EXECINSTR		0x4
#define SHF_RELA_LIVEPATCH	0x00100000
#define SHF_RO_AFTER_INIT	0x00200000
#define SHF_MASKPROC		0xf0000000

/* special section indexes */
#define SHN_UNDEF	0
#define SHN_LORESERVE	0xff00
#define SHN_LOPROC	0xff00
#define SHN_HIPROC	0xff1f
#define SHN_LIVEPATCH	0xff20
#define SHN_ABS		0xfff1
#define SHN_COMMON	0xfff2
#define SHN_HIRESERVE	0xffff

typedef struct elf32_shdr {
    Elf32_Word	sh_name;
    Elf32_Word	sh_type;
    Elf32_Word	sh_flags;
    Elf32_Addr	sh_addr;
    Elf32_Off	sh_offset;
    Elf32_Word	sh_size;
    Elf32_Word	sh_link;
    Elf32_Word	sh_info;
    Elf32_Word	sh_addralign;
    Elf32_Word	sh_entsize;
} Elf32_Shdr;

typedef struct elf64_shdr {
    Elf64_Word sh_name;		/* Section name, index in string tbl */
    Elf64_Word sh_type;		/* Type of section */
    Elf64_Xword sh_flags;		/* Miscellaneous section attributes */
    Elf64_Addr sh_addr;		/* Section virtual addr at execution */
    Elf64_Off sh_offset;		/* Section file offset */
    Elf64_Xword sh_size;		/* Size of section in bytes */
    Elf64_Word sh_link;		/* Index of another section */
    Elf64_Word sh_info;		/* Additional section information */
    Elf64_Xword sh_addralign;	/* Section alignment */
    Elf64_Xword sh_entsize;	/* Entry size if section holds table */
} Elf64_Shdr;

#define	EI_MAG0		0		/* e_ident[] indexes */
#define	EI_MAG1		1
#define	EI_MAG2		2
#define	EI_MAG3		3
#define	EI_CLASS	4
#define	EI_DATA		5
#define	EI_VERSION	6
#define	EI_OSABI	7
#define	EI_PAD		8

#define	ELFMAG0		0x7f		/* EI_MAG */
#define	ELFMAG1		'E'
#define	ELFMAG2		'L'
#define	ELFMAG3		'F'
#define	ELFMAG		"\177ELF"
#define	SELFMAG		4

#define	ELFCLASSNONE	0		/* EI_CLASS */
#define	ELFCLASS32	1
#define	ELFCLASS64	2
#define	ELFCLASSNUM	3

#define ELFDATANONE	0		/* e_ident[EI_DATA] */
#define ELFDATA2LSB	1
#define ELFDATA2MSB	2

#define EV_NONE		0		/* e_version, EI_VERSION */
#define EV_CURRENT	1
#define EV_NUM		2

#define ELFOSABI_NONE	0
#define ELFOSABI_LINUX	3

#ifndef ELF_OSABI
#define ELF_OSABI ELFOSABI_NONE
#endif

/*
 * Notes used in ET_CORE. Architectures export some of the arch register sets
 * using the corresponding note types via the PTRACE_GETREGSET and
 * PTRACE_SETREGSET requests.
 * The note name for all these is "LINUX".
 */
#define NT_PRSTATUS	1
#define NT_PRFPREG	2
#define NT_PRPSINFO	3
#define NT_TASKSTRUCT	4
#define NT_AUXV		6
 /*
  * Note to userspace developers: size of NT_SIGINFO note may increase
  * in the future to accomodate more fields, don't assume it is fixed!
  */
#define NT_SIGINFO      0x53494749
#define NT_FILE         0x46494c45
#define NT_PRXFPREG     0x46e62b7f      /* copied from gdb5.1/include/elf/common.h */
#define NT_PPC_VMX	0x100		/* PowerPC Altivec/VMX registers */
#define NT_PPC_SPE	0x101		/* PowerPC SPE/EVR registers */
#define NT_PPC_VSX	0x102		/* PowerPC VSX registers */
#define NT_PPC_TAR	0x103		/* Target Address Register */
#define NT_PPC_PPR	0x104		/* Program Priority Register */
#define NT_PPC_DSCR	0x105		/* Data Stream Control Register */
#define NT_PPC_EBB	0x106		/* Event Based Branch Registers */
#define NT_PPC_PMU	0x107		/* Performance Monitor Registers */
#define NT_PPC_TM_CGPR	0x108		/* TM checkpointed GPR Registers */
#define NT_PPC_TM_CFPR	0x109		/* TM checkpointed FPR Registers */
#define NT_PPC_TM_CVMX	0x10a		/* TM checkpointed VMX Registers */
#define NT_PPC_TM_CVSX	0x10b		/* TM checkpointed VSX Registers */
#define NT_PPC_TM_SPR	0x10c		/* TM Special Purpose Registers */
#define NT_PPC_TM_CTAR	0x10d		/* TM checkpointed Target Address Register */
#define NT_PPC_TM_CPPR	0x10e		/* TM checkpointed Program Priority Register */
#define NT_PPC_TM_CDSCR	0x10f		/* TM checkpointed Data Stream Control Register */
#define NT_PPC_PKEY	0x110		/* Memory Protection Keys registers */
#define NT_386_TLS	0x200		/* i386 TLS slots (struct user_desc) */
#define NT_386_IOPERM	0x201		/* x86 io permission bitmap (1=deny) */
#define NT_X86_XSTATE	0x202		/* x86 extended state using xsave */
#define NT_S390_HIGH_GPRS	0x300	/* s390 upper register halves */
#define NT_S390_TIMER	0x301		/* s390 timer register */
#define NT_S390_TODCMP	0x302		/* s390 TOD clock comparator register */
#define NT_S390_TODPREG	0x303		/* s390 TOD programmable register */
#define NT_S390_CTRS	0x304		/* s390 control registers */
#define NT_S390_PREFIX	0x305		/* s390 prefix register */
#define NT_S390_LAST_BREAK	0x306	/* s390 breaking event address */
#define NT_S390_SYSTEM_CALL	0x307	/* s390 system call restart data */
#define NT_S390_TDB	0x308		/* s390 transaction diagnostic block */
#define NT_S390_VXRS_LOW	0x309	/* s390 vector registers 0-15 upper half */
#define NT_S390_VXRS_HIGH	0x30a	/* s390 vector registers 16-31 */
#define NT_S390_GS_CB	0x30b		/* s390 guarded storage registers */
#define NT_S390_GS_BC	0x30c		/* s390 guarded storage broadcast control block */
#define NT_S390_RI_CB	0x30d		/* s390 runtime instrumentation */
#define NT_ARM_VFP	0x400		/* ARM VFP/NEON registers */
#define NT_ARM_TLS	0x401		/* ARM TLS register */
#define NT_ARM_HW_BREAK	0x402		/* ARM hardware breakpoint registers */
#define NT_ARM_HW_WATCH	0x403		/* ARM hardware watchpoint registers */
#define NT_ARM_SYSTEM_CALL	0x404	/* ARM system call number */
#define NT_ARM_SVE	0x405		/* ARM Scalable Vector Extension registers */
#define NT_ARM_PAC_MASK		0x406	/* ARM pointer authentication code masks */
#define NT_ARM_PACA_KEYS	0x407	/* ARM pointer authentication address keys */
#define NT_ARM_PACG_KEYS	0x408	/* ARM pointer authentication generic key */
#define NT_ARM_TAGGED_ADDR_CTRL	0x409	/* arm64 tagged address control (prctl()) */
#define NT_ARM_PAC_ENABLED_KEYS	0x40a	/* arm64 ptr auth enabled keys (prctl()) */
#define NT_ARC_V2	0x600		/* ARCv2 accumulator/extra registers */
#define NT_VMCOREDD	0x700		/* Vmcore Device Dump Note */
#define NT_MIPS_DSP	0x800		/* MIPS DSP ASE registers */
#define NT_MIPS_FP_MODE	0x801		/* MIPS floating-point mode */
#define NT_MIPS_MSA	0x802		/* MIPS SIMD registers */

  /* Note types with note name "GNU" */
#define NT_GNU_PROPERTY_TYPE_0	5

/* Note header in a PT_NOTE section */
typedef struct elf32_note {
    Elf32_Word	n_namesz;	/* Name size */
    Elf32_Word	n_descsz;	/* Content size */
    Elf32_Word	n_type;		/* Content type */
} Elf32_Nhdr;

/* Note header in a PT_NOTE section */
typedef struct elf64_note {
    Elf64_Word n_namesz;	/* Name size */
    Elf64_Word n_descsz;	/* Content size */
    Elf64_Word n_type;	/* Content type */
} Elf64_Nhdr;

/* .note.gnu.property types for EM_AARCH64: */
#define GNU_PROPERTY_AARCH64_FEATURE_1_AND	0xc0000000

/* Bits for GNU_PROPERTY_AARCH64_FEATURE_1_BTI */
#define GNU_PROPERTY_AARCH64_FEATURE_1_BTI	(1U << 0)

#endif /* _UAPI_LINUX_ELF_H */
#endif

namespace ELFPP {
    class FileMapping {
    public:
        inline FileMapping(const char* filePath)
            : fileHandle(nullptr)
            , fileMapping(nullptr)
            , mapView(nullptr)
        {

            Initialize(filePath);

#if not defined(_WIN32) and not defined(__linux__)
#error "Invalid Plataform"
#endif

        }

        inline ~FileMapping() {

            Deinitialize();
        }

        inline void* GetMapping() const
        {
            return mapView;
        }

        inline size_t GetSize() const
        {
            return fileSize;
        }

    private:
        size_t fileSize;
        union {
            void* fileHandle;
            int fileHandleI;
        };
        void* fileMapping;
        union {
            void* mapView;
            int mapViewI;
        };

#ifdef __linux__
        inline void Initialize(const char* filePath)
        {
            fileSize = std::filesystem::file_size(filePath);

            if ((fileSize > 0) == false)
                throw std::runtime_error("Invalid File Size");

            fileHandleI = open(filePath, O_RDONLY);

            if (fileHandleI < 0)
                throw std::runtime_error("File Open Failed");

            mapView = mmap(nullptr, fileSize, PROT_READ, MAP_SHARED, fileHandleI, 0);

            if (mapViewI == -1)
            {
                close(fileHandleI);
                throw std::runtime_error("File Mapping Failed");
            }
        }

        inline void Deinitialize()
        {
            if (mapViewI != -1 && mapView != nullptr)
            {
                munmap(mapView, fileSize);
            }

            if (fileHandleI > 0)
                close(fileHandleI);
        }
#endif


#ifdef _WIN32
        inline void Initialize(const char* filePath)
        {
            fileHandle = CreateFileA(filePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (fileHandle == INVALID_HANDLE_VALUE)
                throw std::runtime_error("Error opening file");

            fileSize = GetFileSize(fileHandle, nullptr);

            fileMapping = CreateFileMappingA(fileHandle, nullptr, PAGE_READWRITE, 0, 0, nullptr);
            if (fileMapping == nullptr)
            {
                CloseHandle(fileHandle);
                throw std::runtime_error("Error creating file mapping");
            }

            mapView = MapViewOfFile(fileMapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);

            if (mapView == nullptr) {
                CloseHandle(fileMapping);
                CloseHandle(fileHandle);
                throw std::runtime_error("Error mapping view of file");
            }
        }

        inline void Deinitialize()
        {
            if (mapView != nullptr) {
                UnmapViewOfFile(mapView);
            }

            if (fileMapping != nullptr) {
                CloseHandle(fileMapping);
            }

            if (fileHandle != nullptr && fileHandle != INVALID_HANDLE_VALUE) {
                CloseHandle(fileHandle);
            }
        }
#endif
    };

    /**
     * @brief Holds the ELF File Mapping
    */

    template<typename TELFHdr>
    struct ElfPack {

        std::unique_ptr<FileMapping> mapping;

        union {
            /**
             * @brief Pointer to ELF Header
            */
            TELFHdr* header;

            /**
             * @brief ELF File mapping base address
            */
            uintptr_t base;

            /**
             * @brief Pointer to the ELF Mapping
            */
            void* baseV;

            /**
             * @brief Lazy int version of the Mapping Pointer, to easily do checks
            */
            int res;
        };
    };

    /**
     * @brief Initializes the ELF Library, Notify Callback, Cleanup, Frees the ELF library
     * @returns true if all the operations was sucessfully, false otherwise
    */
    template<typename TELFHdr>
    inline bool ElfOpen(const std::string& fullModulePath, ElfPack<TELFHdr>& outElfPack)
    {
        outElfPack.baseV = nullptr;
        outElfPack.mapping.reset();

        try {
            outElfPack.mapping = std::make_unique<FileMapping>(fullModulePath.c_str());
        }
        catch (std::exception& e)
        {
            std::cerr << e.what();
            return false;
        }

        outElfPack.baseV = outElfPack.mapping->GetMapping();

        return true;
    }

    /**
     * @brief Check if ELF file is 64 bits.
     * @returns true if ELF File is 64 bits, false otherwise
    */

    inline bool ElfPeekIs64(const std::string& fullModulePath, bool& outIs64)
    {
        ElfPack<Elf32_Ehdr> elfPack;

        outIs64 = false;

        if (ElfOpen(fullModulePath, elfPack) == false)
            return false;

        outIs64 = elfPack.header->e_ident[EI_CLASS] == ELFCLASS64;

        return true;
    }

    /**
     * @brief Get a ELF Section by its given Index.
     * @param sectionIdx: the given section index
     * @returns a pointer to a section header if valid, nullptr otherwise
    */
    template<typename TELFHdr, typename TELFSHdr>
    inline TELFSHdr* ElfSectionByIndex(const ElfPack<TELFHdr>& libMap, unsigned int sectionIdx)
    {
        if ((sectionIdx < libMap.header->e_shnum) == false)
            return nullptr;

        TELFSHdr* libElfSections = (TELFSHdr*)(libMap.base + libMap.header->e_shoff);

        return libElfSections + sectionIdx;
    }

    /**
     * @brief Traverses all sections within the ELF File
     * @param callback: will be reported, all the given sections
    */
    template<typename TELFHdr, typename TELFSHdr>
    inline void ElfForEachSection(const ElfPack<TELFHdr>& libMap, std::function<bool(TELFSHdr* pCurrentSection)> callback)
    {
        TELFSHdr* libElfSections = (TELFSHdr*)(libMap.base + libMap.header->e_shoff);

        for (int i = 0; i < libMap.header->e_shnum; i++)
        {
            if (callback(libElfSections + i) == false)
                break;
        }
    }

    /**
     * @brief Lookup an ELF Section by its given type
     * @param sectionType: ELF Section Type
     * @returns A pointer to the section if it exists; nullptr otherwise.
    */
    template<typename TELFHdr, typename TELFSHdr>
    inline TELFSHdr* ElfLookupSectionByType(const ElfPack<TELFHdr>& libMap, uint32_t sectionType)
    {
        TELFSHdr* secHeader = nullptr;

        ElfForEachSection<TELFHdr, TELFSHdr>(libMap, [&](TELFSHdr* currSection) {
            if (currSection->sh_type != sectionType)
                return true;

            secHeader = currSection;

            return false;
            });

        return secHeader;
    }

    /**
     * @brief Retrieve the ELF Section Headers Name Blob (shstr) Entry.
     * @returns A pointer to the char blob entry if exist; nullptr otherwise
    */
    template<typename TELFHdr>
    inline const char* ElfGetSectionHeadersStringBlob(const ElfPack<TELFHdr>& libMap)
    {
        if (libMap.header->e_shstrndx == SHN_UNDEF)
            return nullptr;

        const auto* shStrSec = ElfSectionByIndex(libMap, libMap.header->e_shstrndx);

        if (shStrSec == nullptr || shStrSec->sh_offset < 1)
            return nullptr;

        return (const char*)(libMap.base + shStrSec->sh_offset);
    }

    /**
     * @brief Retrieve ELF Section name
     * @param sectionHdr: Pointer to ELF Section Header
     * @returns A Pointer to the section name if exist; nullptr otherwise.
    */
    template<typename TELFHdr, typename TELFSHdr>
    inline const char* ElfGetSectionName(const ElfPack<TELFHdr>& libMap, TELFSHdr* sectionHdr)
    {
        const char* shStrBlob = ElfGetSectionHeadersStringBlob(libMap);

        if (shStrBlob == nullptr)
            return nullptr;

        return shStrBlob + sectionHdr->sh_name;
    }

    /**
     * @brief Lookup a ELF Header by its name
     * @param sectionName: Name of the section (ex: ".rodata", ".text" ...)
     * @returns A Pointer to the ELF Section if found; nullptr otherwise.
    */
    template<typename TELFHdr, typename TELFSHdr>
    inline TELFSHdr* ElfLookupSectionByName(const ElfPack<TELFHdr>& libMap, const std::string& sectionName)
    {
        TELFSHdr* secHeader = nullptr;

        ElfForEachSection(libMap, [&](TELFSHdr* currSection) {
            const char* currSectionName = ElfGetSectionName(libMap, currSection);

            if (currSectionName == nullptr)
                return true;

            if (strcmp(currSectionName, sectionName.c_str()))
                return true;

            secHeader = currSection;

            return false;
            });

        return secHeader;
    }

    /**
     * @brief Retrieve any available Symbol Table ELF Section.
     * @returns A pointer to the Symbol Table ELF Section if exist; nullptr otherwise;
     * @note This function first searches for an SHT_SYMTAB type, and if none is found,
     * it searches for an SHT_DYNSYM type.
    */
    template<typename TELFHdr, typename TELFSHdr>
    inline TELFSHdr* ElfGetSymbolSection(const ElfPack<TELFHdr>& libMap)
    {
        TELFSHdr* result = nullptr;

        result = ElfLookupSectionByType<TELFHdr, TELFSHdr>(libMap, SHT_SYMTAB);

        if (result)
            return result;

        result = ElfLookupSectionByType<TELFHdr, TELFSHdr>(libMap, SHT_DYNSYM);

        if (result)
            return result;

        return result;
    }

    template<typename TELFHdr, typename TELFPHdr>
    inline void ElfForEachProgram(const ElfPack<TELFHdr>& libMap, std::function<bool(TELFPHdr* pCurrenProgram)> callback)
    {
        TELFPHdr* libElfPrograms = (TELFPHdr*)(libMap.base + libMap.header->e_phoff);

        for (int i = 0; i < libMap.header->e_phnum; i++)
        {
            if (callback(libElfPrograms + i) == false)
                break;
        }
    }

    template<typename TELFHdr, typename TELFPHdr>
    inline std::vector<TELFPHdr> ElfGetPrograms(const ElfPack<TELFHdr>& libMap, bool bSort = false)
    {
        std::vector<TELFPHdr> result;

        ElfForEachProgram<TELFHdr, TELFPHdr>(libMap, [&](TELFPHdr* phdr) {

            result.push_back(*phdr);

            return true;
            });

        if (bSort && result.empty() == false)
        {
            std::sort(result.begin(), result.end(), [&](const TELFPHdr& left, const TELFPHdr& right) {
                return left.p_vaddr < right.p_vaddr;
                });
        }

        return result;
    }

    template<typename TELFHdr, typename TELFPHdr>
    inline std::vector<TELFPHdr> ElfGetLoadablePrograms(const ElfPack<TELFHdr>& libMap)
    {
        std::vector<TELFPHdr> allPrograms = ElfGetPrograms(libMap);
        std::vector<TELFPHdr> result;

        for (const auto& program : allPrograms)
        {
            if (program.p_type != PT_LOAD)
                continue;

            result.push_back(program);
        }

        return result;
    }

    /**
     * @brief Traverse the symbol table.
     * @param callback: A callback, for each symbol found, this callback will be invocated with the actual symbol & its name.
     * @returns true if a symbol table to traverse was found, nullptr otherwise.
    */
    template<typename TELFHdr, typename TELFSHdr, typename TELFSym>
    inline bool ElfForEachSymbol(const ElfPack<TELFHdr>& libMap, std::function<bool(TELFSym* pCurrentSym, const char* pCurrSymName)> callback)
    {
        auto* symTable = ElfGetSymbolSection<TELFHdr, TELFSHdr>(libMap);

        if (symTable == nullptr)
            return false;

        auto* strTable = ElfSectionByIndex<TELFHdr, TELFSHdr>(libMap, symTable->sh_link);

        if (strTable == nullptr)
            return false;

        const char* elfStrBlob = (const char*)(libMap.base + strTable->sh_offset);

        int nSyms = symTable->sh_size / sizeof(TELFSym);
        TELFSym* symEntry = (TELFSym*)(libMap.base + symTable->sh_offset);
        TELFSym* symEnd = symEntry + nSyms;

        for (TELFSym* sym = symEntry; sym < symEnd; sym++)
        {
            if ((ELF_ST_BIND(sym->st_info) & (STT_FUNC | STB_GLOBAL)) == 0)
                continue;

            if (callback(sym, elfStrBlob + sym->st_name) == false)
                break;
        }

        return true;
    }

    /**
     * @brief Lookup a symbol by its name.
     * @param symbolName: The Name of the symbol to look for.
     * @param outSymbolOff: (optional) A Pointer to variable where resulting relative displacement of the symbol will be saved if found.
     * @returns true if the symbol was found, false otherwise.
     * @note Symbol lookup may fail for various reasons, such as the absence of a symbol table or the symbol not being present in the symbol table.
    */
    template<typename TELFHdr, typename TELFSHdr, typename TELFSym>
    inline bool ElfLookupSymbol(const ElfPack<TELFHdr>& libMap, const std::string& symbolName, uint64_t* outSymbolOff = nullptr)
    {
        bool bSymbolFound = false;

        if (outSymbolOff)
            *outSymbolOff = 0;

        if (ElfForEachSymbol<TELFHdr, TELFSHdr, TELFSym>(libMap, [&](auto* currSym, const char* currSymName) {
            if (strcmp(currSymName, symbolName.c_str()))
                return true;

            bSymbolFound = true;

            if (outSymbolOff)
                *outSymbolOff = currSym->st_value;

            return false;
            }) == false)
            return false;

            return bSymbolFound;
    }
}