#include <yail/detail/wow64.hpp>

#ifdef _WIN64
#include <Windows.h>
#include <TlHelp32.h>
#include <algorithm>
#include <charconv>
#include <cstddef>
#include <cstring>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <vector>
#include <yail/detail/pe.hpp>
#include <yail/detail/pdb.hpp>
#include <yail/detail/process.hpp>
#include <yail/detail/shellcode.hpp>

namespace yail::detail
{
    namespace
    {
        struct Wow64RemoteLoaderData final
        {
            std::uint32_t image_base;
            DWORD nt_headers_rva;
            DWORD original_size_of_image;
            DWORD original_number_of_rva_and_sizes;
            IMAGE_DATA_DIRECTORY original_load_config;
            std::uint32_t fn_load_library_a;
            std::uint32_t fn_get_proc_address;
            std::uint32_t fn_virtual_protect;
            std::uint32_t fn_ldrp_handle_tls_data;
            std::uint32_t fn_rtl_insert_inverted_function_table;
            std::uint32_t options;
        };
        static_assert(sizeof(Wow64RemoteLoaderData) == 48);

        [[nodiscard]]
        bool relocate_wow64_image_for_base(std::uint8_t* local_image, const std::uint32_t target_base)
        {
            const auto* dos_headers = reinterpret_cast<IMAGE_DOS_HEADER*>(local_image);
            auto* nt_headers = reinterpret_cast<IMAGE_NT_HEADERS32*>(local_image + dos_headers->e_lfanew);

            const auto delta = static_cast<std::int64_t>(target_base) - nt_headers->OptionalHeader.ImageBase;
            if (delta == 0)
                return true;

            // ReSharper disable once CppUseStructuredBinding
            const auto& relocation_directory =
                    nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
            if (!relocation_directory.Size)
                return false;

            auto* block = reinterpret_cast<IMAGE_BASE_RELOCATION*>(local_image + relocation_directory.VirtualAddress);
            while (block->SizeOfBlock && block->VirtualAddress)
            {
                const std::size_t count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                auto* info = reinterpret_cast<std::uint16_t*>(block + 1);
                for (std::size_t i = 0; i < count; i++, info++)
                {
                    if (*info >> 0x0C != IMAGE_REL_BASED_HIGHLOW)
                        continue;
                    auto* patch =
                            reinterpret_cast<std::uint32_t*>(local_image + block->VirtualAddress + (*info & 0xFFF));
                    *patch += static_cast<std::uint32_t>(delta);
                }
                block = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<std::uint8_t*>(block)
                                                                 + block->SizeOfBlock);
            }

            nt_headers->OptionalHeader.ImageBase = target_base;
            return true;
        }

        [[nodiscard]]
        std::expected<void, Error> read_remote_memory(const HANDLE process_handle, const std::uintptr_t address,
                                                      void* destination, const std::size_t size)
        {
            SIZE_T bytes_read = 0;
            if (!ReadProcessMemory(process_handle, reinterpret_cast<const void*>(address), destination, size,
                                   &bytes_read)
                || bytes_read != size)
                return std::unexpected(Error::remote_memory_read_failed);
            return {};
        }

        struct Wow64RemotePeHeaders final
        {
            IMAGE_DOS_HEADER dos_headers;
            IMAGE_NT_HEADERS32 nt_headers;
        };

        [[nodiscard]]
        std::expected<Wow64RemotePeHeaders, Error> read_wow64_pe_headers(const HANDLE process_handle,
                                                                         const std::uint32_t module_base)
        {
            Wow64RemotePeHeaders headers{};
            if (const auto read = read_remote_memory(process_handle, module_base, &headers.dos_headers,
                                                     sizeof(headers.dos_headers));
                !read)
                return std::unexpected(read.error());

            if (headers.dos_headers.e_magic != IMAGE_DOS_SIGNATURE || headers.dos_headers.e_lfanew < 0)
                return std::unexpected(Error::invalid_remote_module);

            const auto nt_address =
                    static_cast<std::uintptr_t>(module_base) + static_cast<std::uint32_t>(headers.dos_headers.e_lfanew);
            if (const auto read =
                        read_remote_memory(process_handle, nt_address, &headers.nt_headers, sizeof(headers.nt_headers));
                !read)
                return std::unexpected(read.error());

            if (headers.nt_headers.Signature != IMAGE_NT_SIGNATURE
                || headers.nt_headers.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
                return std::unexpected(Error::invalid_remote_module);

            return headers;
        }

        [[nodiscard]]
        std::expected<std::uint32_t, Error> find_wow64_module_base(const DWORD process_id,
                                                                   const std::string_view module_name)
        {
            UniqueHandle snapshot;
            while (true)
            {
                const HANDLE handle = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_id);
                if (handle != INVALID_HANDLE_VALUE)
                {
                    snapshot.reset(handle);
                    break;
                }
                if (GetLastError() != ERROR_BAD_LENGTH)
                    return std::unexpected(Error::module_enumeration_failed);
            }

            MODULEENTRY32 module_entry{};
            module_entry.dwSize = sizeof(module_entry);
            if (Module32First(snapshot.get(), &module_entry))
            {
                const std::string expected_name{module_name};
                do
                {
                    if (_stricmp(module_entry.szModule, expected_name.c_str()) != 0)
                        continue;

                    const auto base = reinterpret_cast<std::uintptr_t>(module_entry.modBaseAddr);
                    if (base > std::numeric_limits<std::uint32_t>::max())
                        continue;
                    return static_cast<std::uint32_t>(base);
                }
                while (Module32Next(snapshot.get(), &module_entry));
            }

            return std::unexpected(Error::module_not_found);
        }

        template<typename T>
        [[nodiscard]]
        std::expected<std::span<const T>, Error> get_export_table(const std::vector<std::uint8_t>& export_data,
                                                                  const DWORD export_rva, const DWORD table_rva,
                                                                  const std::size_t count)
        {
            if (table_rva < export_rva)
                return std::unexpected(Error::invalid_export_table);
            const std::size_t offset = table_rva - export_rva;
            if (offset > export_data.size() || count > (export_data.size() - offset) / sizeof(T))
                return std::unexpected(Error::invalid_export_table);
            return std::span<const T>{reinterpret_cast<const T*>(export_data.data() + offset), count};
        }

        [[nodiscard]]
        std::expected<std::string_view, Error> get_export_string(const std::vector<std::uint8_t>& export_data,
                                                                 const DWORD export_rva, const DWORD string_rva)
        {
            if (string_rva < export_rva)
                return std::unexpected(Error::invalid_export_string);
            const std::size_t offset = string_rva - export_rva;
            if (offset >= export_data.size())
                return std::unexpected(Error::invalid_export_string);

            const auto* first = reinterpret_cast<const char*>(export_data.data() + offset);
            const auto* last = reinterpret_cast<const char*>(export_data.data() + export_data.size());
            const auto* end = std::find(first, last, '\0');
            if (end == last)
                return std::unexpected(Error::invalid_export_string);
            return std::string_view{first, end};
        }

        [[nodiscard]]
        std::expected<std::uint32_t, Error>
        resolve_wow64_export(const HANDLE process_handle, const DWORD process_id, const std::string_view module_name,
                             const std::string_view export_name,
                             const std::optional<DWORD> export_ordinal = std::nullopt,
                             const std::size_t recursion_depth = 0)
        {
            if (recursion_depth > 8)
                return std::unexpected(Error::forwarded_export_recursion_limit);

            const auto module_base = find_wow64_module_base(process_id, module_name);
            if (!module_base)
                return std::unexpected(module_base.error());
            const auto headers = read_wow64_pe_headers(process_handle, *module_base);
            if (!headers)
                return std::unexpected(headers.error());

            const auto& export_directory_data =
                    headers->nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            if (!export_directory_data.Size)
                return std::unexpected(Error::export_directory_missing);

            std::vector<std::uint8_t> export_data(export_directory_data.Size);
            if (const auto read =
                        read_remote_memory(process_handle, *module_base + export_directory_data.VirtualAddress,
                                           export_data.data(), export_data.size());
                !read)
                return std::unexpected(read.error());
            if (export_data.size() < sizeof(IMAGE_EXPORT_DIRECTORY))
                return std::unexpected(Error::invalid_export_table);

            const auto& export_directory = *reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(export_data.data());
            std::optional<DWORD> function_index;
            if (export_ordinal)
            {
                if (*export_ordinal < export_directory.Base
                    || *export_ordinal - export_directory.Base >= export_directory.NumberOfFunctions)
                    return std::unexpected(Error::export_not_found);
                function_index = *export_ordinal - export_directory.Base;
            }
            else
            {
                const auto names =
                        get_export_table<DWORD>(export_data, export_directory_data.VirtualAddress,
                                                export_directory.AddressOfNames, export_directory.NumberOfNames);
                if (!names)
                    return std::unexpected(names.error());
                const auto ordinals =
                        get_export_table<WORD>(export_data, export_directory_data.VirtualAddress,
                                               export_directory.AddressOfNameOrdinals, export_directory.NumberOfNames);
                if (!ordinals)
                    return std::unexpected(ordinals.error());

                for (std::size_t i = 0; i < names->size(); i++)
                {
                    const auto name = get_export_string(export_data, export_directory_data.VirtualAddress, (*names)[i]);
                    if (!name)
                        return std::unexpected(name.error());
                    if (*name == export_name)
                    {
                        function_index = (*ordinals)[i];
                        break;
                    }
                }
            }

            if (!function_index || *function_index >= export_directory.NumberOfFunctions)
                return std::unexpected(Error::export_not_found);

            const auto functions =
                    get_export_table<DWORD>(export_data, export_directory_data.VirtualAddress,
                                            export_directory.AddressOfFunctions, export_directory.NumberOfFunctions);
            if (!functions)
                return std::unexpected(functions.error());
            const DWORD function_rva = (*functions)[*function_index];
            if (function_rva >= export_directory_data.VirtualAddress
                && function_rva - export_directory_data.VirtualAddress < export_directory_data.Size)
            {
                const auto forwarder =
                        get_export_string(export_data, export_directory_data.VirtualAddress, function_rva);

                if (!forwarder)
                    return std::unexpected(forwarder.error());

                const auto separator = forwarder->find('.');
                if (separator == std::string_view::npos)
                    return std::unexpected(Error::invalid_forwarded_export);

                std::string forwarded_module{forwarder->substr(0, separator)};
                forwarded_module += ".dll";
                const auto forwarded_symbol = forwarder->substr(separator + 1);
                if (forwarded_symbol.starts_with('#'))
                {
                    DWORD forwarded_ordinal = 0;
                    const auto [ptr, error] =
                            std::from_chars(forwarded_symbol.data() + 1,
                                            forwarded_symbol.data() + forwarded_symbol.size(), forwarded_ordinal);
                    if (error != std::errc{} || ptr != forwarded_symbol.data() + forwarded_symbol.size())
                        return std::unexpected(Error::invalid_forwarded_export);
                    return resolve_wow64_export(process_handle, process_id, forwarded_module, {}, forwarded_ordinal,
                                                recursion_depth + 1);
                }
                return resolve_wow64_export(process_handle, process_id, forwarded_module, forwarded_symbol,
                                            std::nullopt, recursion_depth + 1);
            }

            if (function_rva > std::numeric_limits<std::uint32_t>::max() - *module_base)
                return std::unexpected(Error::export_address_out_of_range);
            return *module_base + function_rva;
        }

        struct Wow64NtdllSymbolAddresses final
        {
            std::optional<std::uint32_t> ldrp_handle_tls_data;
            std::optional<std::uint32_t> rtl_insert_inverted_function_table;
        };

        [[nodiscard]] std::expected<Wow64NtdllSymbolAddresses, Error>
        find_wow64_ntdll_symbol_addresses(const HANDLE process_handle, const DWORD process_id)
        {
            const auto module_base = find_wow64_module_base(process_id, "ntdll.dll");
            if (!module_base)
                return std::unexpected(module_base.error());
            const auto headers = read_wow64_pe_headers(process_handle, *module_base);
            if (!headers)
                return std::unexpected(headers.error());

            std::vector<IMAGE_SECTION_HEADER> section_headers(headers->nt_headers.FileHeader.NumberOfSections);
            const auto section_headers_address = static_cast<std::uintptr_t>(*module_base)
                                                 + static_cast<std::uint32_t>(headers->dos_headers.e_lfanew)
                                                 + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER)
                                                 + headers->nt_headers.FileHeader.SizeOfOptionalHeader;
            if (const auto read = read_remote_memory(process_handle, section_headers_address, section_headers.data(),
                                                     section_headers.size() * sizeof(IMAGE_SECTION_HEADER));
                !read)
                return std::unexpected(read.error());

            std::vector<PdbImageSection> sections;
            sections.reserve(section_headers.size());
            for (const auto& section : section_headers)
                sections.push_back(
                        {section.VirtualAddress, std::max(section.Misc.VirtualSize, section.SizeOfRawData)});

            if (headers->nt_headers.OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_DEBUG)
                return std::unexpected(Error::ntdll_debug_directory_missing);
            const auto& debug_data = headers->nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
            if (!debug_data.Size || debug_data.VirtualAddress >= headers->nt_headers.OptionalHeader.SizeOfImage
                || debug_data.Size > headers->nt_headers.OptionalHeader.SizeOfImage - debug_data.VirtualAddress)
                return std::unexpected(Error::ntdll_debug_directory_missing);

            std::vector<IMAGE_DEBUG_DIRECTORY> debug_directories(debug_data.Size / sizeof(IMAGE_DEBUG_DIRECTORY));
            if (debug_directories.empty())
                return std::unexpected(Error::ntdll_debug_directory_missing);
            if (const auto read = read_remote_memory(process_handle, *module_base + debug_data.VirtualAddress,
                                                     debug_directories.data(),
                                                     debug_directories.size() * sizeof(IMAGE_DEBUG_DIRECTORY));
                !read)
                return std::unexpected(read.error());

            for (const auto& directory : debug_directories)
            {
                if (directory.Type != IMAGE_DEBUG_TYPE_CODEVIEW || !directory.SizeOfData
                    || directory.AddressOfRawData >= headers->nt_headers.OptionalHeader.SizeOfImage
                    || directory.SizeOfData
                               > headers->nt_headers.OptionalHeader.SizeOfImage - directory.AddressOfRawData)
                    continue;

                std::vector<std::uint8_t> codeview_data(directory.SizeOfData);
                if (const auto read = read_remote_memory(process_handle, *module_base + directory.AddressOfRawData,
                                                         codeview_data.data(), codeview_data.size());
                    !read)
                    continue;

                const auto identifier = parse_pdb_identifier(codeview_data);
                if (!identifier)
                    continue;
                const auto rvas = download_ntdll_symbol_rvas(*identifier, sections);
                if (!rvas)
                    return std::unexpected(rvas.error());

                Wow64NtdllSymbolAddresses result{};
                if (rvas->ldrp_handle_tls_data
                    && *rvas->ldrp_handle_tls_data <= std::numeric_limits<std::uint32_t>::max() - *module_base)
                    result.ldrp_handle_tls_data = *module_base + *rvas->ldrp_handle_tls_data;
                if (rvas->rtl_insert_inverted_function_table
                    && *rvas->rtl_insert_inverted_function_table
                               <= std::numeric_limits<std::uint32_t>::max() - *module_base)
                    result.rtl_insert_inverted_function_table =
                            *module_base + *rvas->rtl_insert_inverted_function_table;

                if (result.ldrp_handle_tls_data || result.rtl_insert_inverted_function_table)
                    return result;
                return std::unexpected(Error::pdb_symbol_address_out_of_range);
            }

            return std::unexpected(Error::ntdll_codeview_record_missing);
        }
    } // namespace

    std::expected<std::uintptr_t, Error>
    manual_map_injection_into_wow64_process(const std::span<const std::uint8_t>& raw_pe,
                                            const std::uintptr_t process_id, const std::uint32_t options)
    {
        if (const auto architecture = validate_target_machine(process_id, IMAGE_FILE_MACHINE_I386); !architecture)
            return std::unexpected(architecture.error());

        const UniqueHandle process_handle{OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ
                                                              | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION,
                                                      FALSE, static_cast<DWORD>(process_id))};
        if (!process_handle)
            return std::unexpected(Error::process_open_failed);

        const auto* dos_headers = reinterpret_cast<const IMAGE_DOS_HEADER*>(raw_pe.data());
        const auto* nt_headers = reinterpret_cast<const IMAGE_NT_HEADERS32*>(raw_pe.data() + dos_headers->e_lfanew);
        const auto safe_seh_layout = plan_x86_safe_seh(raw_pe);
        if (!safe_seh_layout)
            return std::unexpected(safe_seh_layout.error());
        const std::size_t image_size = safe_seh_layout->expanded_size_of_image;

        auto* const remote_image = static_cast<std::uint8_t*>(VirtualAllocEx(
                process_handle.get(), nullptr, image_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
        if (!remote_image)
            return std::unexpected(Error::image_allocation_failed);

        const auto fail_image = [&](const Error error) -> std::expected<std::uintptr_t, Error>
        {
            VirtualFreeEx(process_handle.get(), remote_image, 0, MEM_RELEASE);
            return std::unexpected(error);
        };

        const auto remote_image_address = reinterpret_cast<std::uintptr_t>(remote_image);
        if (remote_image_address > std::numeric_limits<std::uint32_t>::max() - image_size)
            return fail_image(Error::image_address_out_of_range);

        std::vector<std::uint8_t> local_image(image_size, 0);
        std::copy_n(raw_pe.data(), nt_headers->OptionalHeader.SizeOfHeaders, local_image.data());
        auto* section_header = IMAGE_FIRST_SECTION(nt_headers);
        for (WORD i = 0; i < nt_headers->FileHeader.NumberOfSections; i++, section_header++)
        {
            if (!section_header->SizeOfRawData)
                continue;
            std::copy_n(raw_pe.data() + section_header->PointerToRawData, section_header->SizeOfRawData,
                        local_image.data() + section_header->VirtualAddress);
        }

        if (!relocate_wow64_image_for_base(local_image.data(), static_cast<std::uint32_t>(remote_image_address)))
            return fail_image(Error::relocation_missing);
        write_x86_safe_seh(local_image.data(), remote_image_address, *safe_seh_layout);
        if (!WriteProcessMemory(process_handle.get(), remote_image, local_image.data(), image_size, nullptr))
            return fail_image(Error::image_write_failed);

        Wow64RemoteLoaderData loader_data{};
        loader_data.image_base = static_cast<std::uint32_t>(remote_image_address);
        loader_data.nt_headers_rva = static_cast<DWORD>(dos_headers->e_lfanew);
        loader_data.original_size_of_image = safe_seh_layout->original_size_of_image;
        loader_data.original_number_of_rva_and_sizes = safe_seh_layout->original_number_of_rva_and_sizes;
        loader_data.original_load_config = safe_seh_layout->original_load_config;

        const auto load_library_a = resolve_wow64_export(process_handle.get(), static_cast<DWORD>(process_id),
                                                         "kernel32.dll", "LoadLibraryA");
        if (!load_library_a)
            return fail_image(load_library_a.error());
        loader_data.fn_load_library_a = *load_library_a;

        const auto get_proc_address = resolve_wow64_export(process_handle.get(), static_cast<DWORD>(process_id),
                                                           "kernel32.dll", "GetProcAddress");
        if (!get_proc_address)
            return fail_image(get_proc_address.error());
        loader_data.fn_get_proc_address = *get_proc_address;

        const auto virtual_protect = resolve_wow64_export(process_handle.get(), static_cast<DWORD>(process_id),
                                                          "kernel32.dll", "VirtualProtect");
        if (!virtual_protect)
            return fail_image(virtual_protect.error());
        loader_data.fn_virtual_protect = *virtual_protect;
        loader_data.options = options;

        const auto pdb_symbols =
                find_wow64_ntdll_symbol_addresses(process_handle.get(), static_cast<DWORD>(process_id));
        if (!pdb_symbols)
            return fail_image(pdb_symbols.error());
        if (!pdb_symbols->ldrp_handle_tls_data)
            return fail_image(Error::pdb_symbols_not_found);
        loader_data.fn_ldrp_handle_tls_data = *pdb_symbols->ldrp_handle_tls_data;
        if (pdb_symbols->rtl_insert_inverted_function_table)
            loader_data.fn_rtl_insert_inverted_function_table = *pdb_symbols->rtl_insert_inverted_function_table;

        constexpr std::size_t data_aligned = (sizeof(Wow64RemoteLoaderData) + 0xF) & ~0xF;
        const auto shellcode = yail::detail::x86_remote_shellcode();
        const std::size_t total_shellcode = data_aligned + shellcode.size();
        auto* remote_shellcode = static_cast<std::uint8_t*>(VirtualAllocEx(
                process_handle.get(), nullptr, total_shellcode, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
        if (!remote_shellcode)
            return fail_image(Error::shellcode_allocation_failed);

        const auto fail_shellcode = [&](const Error error) -> std::expected<std::uintptr_t, Error>
        {
            VirtualFreeEx(process_handle.get(), remote_shellcode, 0, MEM_RELEASE);
            return fail_image(error);
        };

        if (reinterpret_cast<std::uintptr_t>(remote_shellcode) > std::numeric_limits<std::uint32_t>::max())
            return fail_shellcode(Error::shellcode_address_out_of_range);

        std::vector<std::uint8_t> shellcode_page(total_shellcode);
        std::copy_n(reinterpret_cast<const std::uint8_t*>(&loader_data), sizeof(loader_data), shellcode_page.data());
        std::copy(shellcode.begin(), shellcode.end(), shellcode_page.data() + data_aligned);
        if (!WriteProcessMemory(process_handle.get(), remote_shellcode, shellcode_page.data(), shellcode_page.size(),
                                nullptr))
            return fail_shellcode(Error::shellcode_write_failed);

        const UniqueHandle thread_handle{
                CreateRemoteThread(process_handle.get(), nullptr, 0,
                                   reinterpret_cast<LPTHREAD_START_ROUTINE>(remote_shellcode + data_aligned),
                                   remote_shellcode, 0, nullptr)};
        if (!thread_handle)
            return fail_shellcode(Error::remote_thread_creation_failed);

        if (WaitForSingleObject(thread_handle.get(), INFINITE) == WAIT_FAILED)
            return fail_shellcode(Error::remote_thread_wait_failed);
        DWORD exit_code = 0;
        if (!GetExitCodeThread(thread_handle.get(), &exit_code))
            return fail_shellcode(Error::remote_thread_query_failed);

        VirtualFreeEx(process_handle.get(), remote_shellcode, 0, MEM_RELEASE);
        if (exit_code != 0)
            return fail_image(Error::remote_shellcode_failed);
        return remote_image_address;
    }
} // namespace yail::detail
#endif
