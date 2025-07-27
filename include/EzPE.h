#pragma once

#include <cstdint>

#include <fstream>

#include <windows.h>

namespace EzPE
{
    //
    // [SECTION] Types
    //

    enum class PE_Properties : uint8_t
    {
        NONE = 0,
        RESOLVED = 1 << 0,
        DATA = 1 << 1,
    };

    class PE
    {
    public:
        IMAGE_DOS_HEADER *p_dos_header{};
        uint8_t *p_dos_stub{};
        uint32_t *p_signature{};
        IMAGE_FILE_HEADER *p_file_header{};
        IMAGE_OPTIONAL_HEADER *p_optional_header{};
        IMAGE_SECTION_HEADER *p_first_section_header{};
        uint8_t *p_start_of_data{};
        PE_Properties properties{};

        //
        // [LOCAL_SECTION] Constructors & destructors
        //

        PE(const char *path, PE_Properties specified_properties)
        {
            loadFromFile(path, specified_properties);
        }

        PE(const PE &) = delete;
        PE &operator=(const PE &) = delete;

        ~PE()
        {
            clear();
        }

        //
        // [LOCAL_SECTION] Utilities
        //

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

            std::streampos file_size{file.tellg()};
            file.seekg(0);

            if (file_size < sizeof(IMAGE_DOS_HEADER))
            {
                setError("loadFromFile(): Based on size, file couldn't possibly hold even a DOS header");
                return false;
            }

            // Allocate memory and read entire file
            p_dos_header = reinterpret_cast<IMAGE_DOS_HEADER *>(new char[file_size]);
            is_allocated = true;
            file.read(reinterpret_cast<char *>(p_dos_header), file_size);

            if (file.gcount() != file_size)
            {
                clear();
                setError("loadFromFile(): Failed to read entire file");
                return false;
            }

            if (p_dos_header->e_magic != IMAGE_DOS_SIGNATURE)
            {
                clear();
                setError("loadFromFile(): File's DOS signature is invalid");
                return false;
            }

            std::streampos file_nt_size{p_dos_header->e_lfanew + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER)};

            if (file_size < file_nt_size)
            {
                clear();
                setError("loadFromFile(): File's size is not large enough to possibly contain all NT headers");
                return false;
            }

            // Set up pointers
            p_dos_stub = reinterpret_cast<uint8_t *>(reinterpret_cast<uintptr_t>(p_dos_header) + sizeof(IMAGE_DOS_HEADER));
            p_signature = reinterpret_cast<uint32_t *>(reinterpret_cast<uintptr_t>(p_dos_header) + p_dos_header->e_lfanew);

            if (*p_signature != IMAGE_NT_SIGNATURE)
            {
                clear();
                setError("loadFromFile(): File's NT signature is invalid");
                return false;
            }

            p_file_header = reinterpret_cast<IMAGE_FILE_HEADER *>(reinterpret_cast<uintptr_t>(p_signature) + sizeof(uint32_t));

            std::streampos theoretical_section_headers_size{p_file_header->NumberOfSections * sizeof(IMAGE_SECTION_HEADER)};
            if (file_size < file_nt_size + theoretical_section_headers_size)
            {
                clear();
                setError("loadFromFile(): File is missing some or all of its section headers");
                return false;
            }

            p_optional_header = reinterpret_cast<IMAGE_OPTIONAL_HEADER *>(reinterpret_cast<uintptr_t>(p_file_header) + sizeof(IMAGE_FILE_HEADER));

            if (p_file_header->NumberOfSections > 0)
                p_first_section_header = reinterpret_cast<IMAGE_SECTION_HEADER *>(reinterpret_cast<uintptr_t>(p_optional_header) + sizeof(IMAGE_OPTIONAL_HEADER));

            is_loaded = true;
            properties = specified_properties;
            file.close();
            return true;
        }

        void clear()
        {
            if (is_allocated)
            {
                delete[] p_dos_header;
                is_allocated = false;
            }

            if (has_error)
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

        //
        // [LOCAL_SECTION] Getters
        //

        std::string getErrorMessage()
        {
            return error_message;
        }

        bool getHasError()
        {
            return has_error;
        }

        bool getIsLoaded()
        {
            return is_loaded;
        }

        //
        // [LOCAL_SECTION] Setters
        //

        void setError(std::string message)
        {
            /* Clear error if empty message */
            if (message.size() == 0)
            {
                has_error = false;
                error_message.clear();
                return;
            }

            has_error = true;
            error_message = message;
        }

    private:
        std::string error_message;
        bool has_error{};
        bool is_loaded{};
        bool is_allocated{};
    };
}