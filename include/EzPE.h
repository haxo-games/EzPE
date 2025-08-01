//  ______     _____  ______
// |  ____|   |  __ \|  ____|
// | |__   ___| |__) | |__
// |  __| |_  /  ___/|  __|    PE header-only utility library
// | |____ / /| |    | |____   version 0.0.0
// |______/___|_|    |______|  https://github.com/haxo-games/EzPE
//
// SPDX-FileCopyrightText: 2024 - 2025 Haxo Games Inc. <https://haxo.games>
// SPDX-License-Identifier: MIT

#pragma once

#include <cstdint>
#include <cstdarg>

#include <fstream>
#include <type_traits>

#include <windows.h>

namespace EzPE
{
    //
    // [SECTION] Types
    //

    enum class PE_Properties : uint8_t
    {
        NONE = 0,
        MAPPED = 1 << 0, // Fully mapped to virtual memory
        DATA = 1 << 1,     // Indicates that sections data should be considered
    };

    class PE
    {
    public:
        //
        // [LOCAL_SECTION] Types
        //

        class Section
        {
        public:
            IMAGE_SECTION_HEADER header;

            Section(PE &_pe)
                : pe(_pe) {};

            Section &name(const char *name)
            {
                memcpy(header.Name, name, (std::min)(static_cast<int>(strlen(name)), 8));
                return *this;
            }

            Section &data(size_t virtual_size, size_t file_size = 0, void *p_init_with = nullptr)
            {
                if (file_size != 0)
                    this->p_init_with = p_init_with;

                if (virtual_size == 0 || virtual_size < file_size)
                    pe.setError("Failed to set section data. Invalid virtual size.");

                header.Misc.VirtualSize = virtual_size;
                header.SizeOfRawData = pe.alignToFile(file_size);

                return *this;
            }

            Section &characteristics(uint32_t input)
            {
                header.Characteristics = input;
                return *this;
            }

            void insert()
            {
                // TODO
            }

        private:
            void *p_init_with;
            PE &pe;
        };

        //
        // [LOCAL_SECTION] Variables and constants
        //

        IMAGE_DOS_HEADER *p_dos_header{};
        uint8_t *p_dos_stub{};
        uint32_t *p_signature{};
        IMAGE_FILE_HEADER *p_file_header{};
        IMAGE_OPTIONAL_HEADER *p_optional_header{};
        IMAGE_SECTION_HEADER *p_first_section_header{};
        uint8_t *p_start_of_data{};
        PE_Properties properties{};

        //
        // [LOCAL_SECTION] Utilities
        //

        PE() {};

        PE(const char *path, PE_Properties specified_properties)
        {
            loadFromFile(path, specified_properties);
        }

        PE(void *module, PE_Properties specified_properties)
        {
            loadFromMemory(module, specified_properties);
        }

        PE(HRSRC h_resource, PE_Properties specified_properties)
        {
            loadFromResource(h_resource, specified_properties);
        }

        PE(const PE &) = delete;
        PE &operator=(const PE &) = delete;

        ~PE()
        {
            clear();
        }

        bool loadFromFile(const char *path, PE_Properties specified_properties)
        {
            if (is_loaded)
            {
                setError("loadFromFile(): PE is already loaded. Explicitly clear it before loading again");
                return false;
            }

            std::ifstream file(path, std::ios::binary | std::ios::ate);
            if (!file.is_open())
            {
                setError("loadFromFile(): Failed to open file");
                return false;
            }

            size_t file_size{static_cast<size_t>(file.tellg())};
            file.seekg(0);

            if (file_size < sizeof(IMAGE_DOS_HEADER))
            {
                setError("loadFromFile(): Based on size, file couldn't possibly hold even a DOS header");
                return false;
            }

            // Allocate memory and read entire file
            p_dos_header = reinterpret_cast<IMAGE_DOS_HEADER *>(new char[file_size]);
            properties = specified_properties;
            is_allocated = true;
            file.read(reinterpret_cast<char *>(p_dos_header), file_size);

            if (file.gcount() != file_size)
            {
                clear();
                setError("loadFromFile(): Failed to read entire file");
                return false;
            }

            file.close();
            is_loaded = validate(file_size);
            return is_loaded;
        }

        bool loadFromMemory(void *module, PE_Properties specified_properties)
        {
            if (is_loaded)
            {
                setError("loadFromMemory(): PE is already loaded. Explicitly clear it before loading again");
                return false;
            }

            const uintptr_t base{reinterpret_cast<uintptr_t>(module)};
            p_dos_header = reinterpret_cast<IMAGE_DOS_HEADER *>(base);

            if (p_dos_header->e_magic != IMAGE_DOS_SIGNATURE)
            {
                setError("loadFromMemory(): Invalid DOS signature \"0x%x\", should be 0x%x", p_dos_header->e_magic, IMAGE_DOS_SIGNATURE);
                clear(false);
                return false;
            }

            p_dos_stub = reinterpret_cast<uint8_t *>(base + sizeof(*p_dos_header));
            p_signature = reinterpret_cast<uint32_t *>(base + p_dos_header->e_lfanew);

            if (*p_signature != IMAGE_NT_SIGNATURE)
            {
                setError("loadFromMemory(): Invalid NT signature \"0x%x\", should be 0x%x", *p_signature, IMAGE_NT_SIGNATURE);
                clear(false);

                return false;
            }

            p_file_header = reinterpret_cast<IMAGE_FILE_HEADER *>(reinterpret_cast<uintptr_t>(p_signature) + sizeof(*p_signature));
            p_optional_header = reinterpret_cast<IMAGE_OPTIONAL_HEADER *>(reinterpret_cast<uintptr_t>(p_file_header) + sizeof(*p_file_header));

            is_loaded = true;
            properties = specified_properties;

            return true;
        }

        bool loadFromResource(HRSRC h_resource, PE_Properties specified_properties)
        {
            if (is_loaded)
            {
                setError("loadFromResource(): PE is already loaded. Explicitly clear it before loading again");
                return false;
            }

            HGLOBAL h_memory{LoadResource(0, h_resource)};

            if (!h_memory)
            {
                setError("loadFromResource(): Failed to get handle from LoadResource()");
                return false;
            }

            DWORD resource_size{SizeofResource(0, h_resource)};
            LPVOID p_resource_data{LockResource(h_memory)};

            if (!p_resource_data || resource_size == 0)
            {
                setError("loadFromResource(): Failed to get size of resource or to lock it");
                return false;
            }

            p_dos_header = reinterpret_cast<IMAGE_DOS_HEADER *>(new char[resource_size]);
            properties = specified_properties;
            is_allocated = true;
            memcpy(p_dos_header, p_resource_data, resource_size);

            is_loaded = validate(resource_size);
            return is_loaded;
        }

        void* getExportedFunction(std::string export_name)
        {
            if (!is_loaded || !p_optional_header)
            {
                setError("getExportedFunction(): PE is not loaded");
                return nullptr;
            }

            if (p_optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0)
            {
                setError("getExportedFunction(): PE has no exported functions");
                return nullptr;
            }

            uintptr_t const base{reinterpret_cast<uintptr_t>(p_dos_header)};

            IMAGE_EXPORT_DIRECTORY* p_export_directory
            {reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(base + p_optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)};
            
            uint32_t* export_names{reinterpret_cast<uint32_t*>(base + p_export_directory->AddressOfNames)};
            uint32_t* export_offsets{reinterpret_cast<uint32_t*>(base + p_export_directory->AddressOfFunctions)};
            uint16_t* export_ordinals{reinterpret_cast<uint16_t*>(base + p_export_directory->AddressOfNameOrdinals)};

            for (int32_t i{0}; i != p_export_directory->NumberOfFunctions; ++i)
            {
                std::string current_export_name{reinterpret_cast<const char*>(base + export_names[i])};

                if (export_name == current_export_name)
                {
                    return reinterpret_cast<void*>(base + export_offsets[export_ordinals[i]]);
                }
            }

            setError("getExportedFunction(): could not find exported function %s", export_name.c_str());
            return nullptr;
        }

        uint32_t alignToSection(uint32_t value)
        {
            if (!is_loaded)
            {
                setError("alignToSection(): PE is not loaded");
                return false;
            }

            return ((value + p_optional_header->SectionAlignment - 1) / p_optional_header->SectionAlignment) * p_optional_header->SectionAlignment;
        }

        uint32_t alignToFile(uint32_t value)
        {
            if (!is_loaded)
            {
                setError("alignToFile(): PE is not loaded");
                return false;
            }

            return ((value + p_optional_header->FileAlignment - 1) / p_optional_header->FileAlignment) * p_optional_header->FileAlignment;
        }

        IMAGE_SECTION_HEADER *findLastFileAlignedSection() const
        {
            if (!is_loaded || p_first_section_header == nullptr)
                return nullptr;

            IMAGE_SECTION_HEADER *p_last_section{};

            for (int i{}; i < p_file_header->NumberOfSections; i++)
            {
                IMAGE_SECTION_HEADER &current_section_header{p_first_section_header[i]};

                if (current_section_header.SizeOfRawData == 0)
                    continue;

                if (p_last_section == nullptr || current_section_header.PointerToRawData > p_last_section->PointerToRawData)
                    p_last_section = &current_section_header;
            }

            return p_last_section;
        }

        IMAGE_SECTION_HEADER *findLastSectionAlignedSection() const
        {
            if (!is_loaded || p_first_section_header == nullptr)
                return nullptr;

            IMAGE_SECTION_HEADER *p_last_section{};

            for (int i{}; i < p_file_header->NumberOfSections; i++)
            {
                IMAGE_SECTION_HEADER &current_section_header{p_first_section_header[i]};

                if (p_last_section == nullptr || current_section_header.VirtualAddress > p_last_section->VirtualAddress)
                    p_last_section = &current_section_header;
            }

            return p_last_section;
        }

        void clear(bool clear_error_string = true)
        {
            if (is_allocated)
            {
                delete[] p_dos_header;
                is_allocated = false;
            }

            if (has_error && clear_error_string)
                setError("");

            // Reset members
            p_dos_header = nullptr;
            p_dos_stub = nullptr;
            p_signature = nullptr;
            p_file_header = nullptr;
            p_optional_header = nullptr;
            p_first_section_header = nullptr;
            p_start_of_data = nullptr;
            properties = PE_Properties::NONE;
            is_loaded = false;
        }

        constexpr bool hasProperty(PE_Properties property) const
        {
            return (static_cast<std::underlying_type_t<PE_Properties>>(properties) & static_cast<std::underlying_type_t<PE_Properties>>(property)) != 0;
        }

        //
        // [LOCAL_SECTION] Getters
        //

        const std::string &getErrorMessage() const
        {
            return error_message;
        }

        bool getHasError() const
        {
            return has_error;
        }

        bool getIsLoaded() const
        {
            return is_loaded;
        }

        //
        // [LOCAL_SECTION] Setters
        //

        void setError(std::string fmt, ...)
        {
            /* Clear error if empty message */
            if (fmt.size() == 0)
            {
                has_error = false;
                error_message.clear();
                return;
            }

            va_list args;
            va_start(args, fmt);

            char *buf{new char[0x1000]};
            vsprintf_s(buf, 0x1000, fmt.c_str(), args);
            error_message = buf;

            delete[] buf;
            va_end(args);
            has_error = true;
        }

    private:
        std::string error_message;
        bool has_error{};
        bool is_loaded{};
        bool is_allocated{};

        //
        // [LOCAL_SECTION] Utilities
        //

        bool validate(size_t size)
        {
            if (p_dos_header->e_magic != IMAGE_DOS_SIGNATURE)
            {
                clear();
                setError("validate(): File's DOS signature is invalid");
                return false;
            }

            size_t file_nt_size{p_dos_header->e_lfanew + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER)};

            if (size < file_nt_size)
            {
                clear();
                setError("validate(): File's size is not large enough to possibly contain all NT headers");
                return false;
            }

            // Set up pointers
            p_dos_stub = reinterpret_cast<uint8_t *>(reinterpret_cast<uintptr_t>(p_dos_header) + sizeof(IMAGE_DOS_HEADER));
            p_signature = reinterpret_cast<uint32_t *>(reinterpret_cast<uintptr_t>(p_dos_header) + p_dos_header->e_lfanew);

            if (*p_signature != IMAGE_NT_SIGNATURE)
            {
                clear();
                setError("validate(): File's NT signature is invalid");
                return false;
            }

            p_file_header = reinterpret_cast<IMAGE_FILE_HEADER *>(reinterpret_cast<uintptr_t>(p_signature) + sizeof(uint32_t));

            size_t theoretical_section_headers_size{p_file_header->NumberOfSections * sizeof(IMAGE_SECTION_HEADER)};
            if (size < file_nt_size + theoretical_section_headers_size)
            {
                clear();
                setError("validate(): File is missing some or all of its section headers");
                return false;
            }

            p_optional_header = reinterpret_cast<IMAGE_OPTIONAL_HEADER *>(reinterpret_cast<uintptr_t>(p_file_header) + sizeof(IMAGE_FILE_HEADER));

            if (p_file_header->NumberOfSections > 0)
            {
                p_first_section_header = reinterpret_cast<IMAGE_SECTION_HEADER *>(reinterpret_cast<uintptr_t>(p_optional_header) + sizeof(IMAGE_OPTIONAL_HEADER));

                if (hasProperty(PE_Properties::DATA))
                {
                    p_start_of_data = reinterpret_cast<uint8_t *>(reinterpret_cast<uintptr_t>(p_first_section_header) + theoretical_section_headers_size);

                    /* Sections data validation depends on if the image was resolved on not */
                    if (hasProperty(PE_Properties::MAPPED))
                    {
                        IMAGE_SECTION_HEADER *p_last_section{findLastSectionAlignedSection()};

                        if (p_last_section == nullptr)
                        {
                            clear();
                            setError("validate(): Failed to get last section aligned section (maybe the PE isn't resolved)");
                            return false;
                        }

                        if (size < p_last_section->VirtualAddress + p_last_section->Misc.VirtualSize)
                        {
                            clear();
                            setError("validate(): File's size is too small to possibly contain all the sections' data");
                            return false;
                        }
                    }
                    else
                    {
                        IMAGE_SECTION_HEADER *p_last_section{findLastFileAlignedSection()};

                        /* It "could" be possible that no section has raw data */
                        if (p_last_section != nullptr && size < p_last_section->PointerToRawData + p_last_section->SizeOfRawData)
                        {
                            clear();
                            setError("validate(): Resource size is too small to possibly contain all the sections' data");
                            return false;
                        }
                    }
                }
            }

            return true;
        }
    };
}