#include <yail/detail/native_loader.hpp>
#include <winternl.h>
#include <algorithm>
#include <array>
#include <omath/utility/pe_pattern_scan.hpp>
#ifdef YAIL_USE_PDB
#include <vector>
#include <yail/detail/pdb.hpp>
#endif

namespace yail::detail
{
    namespace
    {
        struct LdrDataTableEntryFull final
        {
            LIST_ENTRY in_load_order_links;
            LIST_ENTRY in_memory_order_links;
            LIST_ENTRY in_initialization_order_links;
            PVOID dll_base;
            PVOID entry_point;
            ULONG size_of_image;
            [[maybe_unused]] UNICODE_STRING full_dll_name;
            [[maybe_unused]] UNICODE_STRING base_dll_name;
            [[maybe_unused]] ULONG flags;
            [[maybe_unused]] USHORT obsolete_load_count;
            [[maybe_unused]] USHORT tls_index;
            LIST_ENTRY hash_links;
            [[maybe_unused]] ULONG time_date_stamp;
        };

#ifdef _WIN64
        using LdrpHandleTlsDataFn = NTSTATUS(NTAPI*)(LdrDataTableEntryFull*);
        using RtlInsertInvertedFunctionTableFn = void(NTAPI*)(PVOID image_base, ULONG size_of_image);
#else
        // Modern x86 ntdll uses __fastcall for these internal functions despite the
        // legacy `_Name@N` symbol decoration - args come in ECX/EDX, not on the stack.
        using LdrpHandleTlsDataFn = NTSTATUS(__fastcall*)(LdrDataTableEntryFull*);
        using RtlInsertInvertedFunctionTableFn = void(__fastcall*)(PVOID image_base, ULONG size_of_image);
#endif
        // The shellcode reference implementation used for regeneration lives in tools/generate_shellcode.cpp.

#ifdef YAIL_USE_PDB
        [[nodiscard]] std::expected<NtdllSymbolRvas, Error> load_native_ntdll_symbol_rvas()
        {
            const auto* ntdll = reinterpret_cast<const std::uint8_t*>(GetModuleHandleA("ntdll.dll"));
            if (!ntdll)
                return std::unexpected(Error::ntdll_not_found);

            const auto* dos_headers = reinterpret_cast<const IMAGE_DOS_HEADER*>(ntdll);
            if (dos_headers->e_magic != IMAGE_DOS_SIGNATURE || dos_headers->e_lfanew < 0)
                return std::unexpected(Error::invalid_remote_module);

            const auto* nt_headers = reinterpret_cast<const IMAGE_NT_HEADERS*>(ntdll + dos_headers->e_lfanew);
            if (nt_headers->Signature != IMAGE_NT_SIGNATURE
                || nt_headers->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_DEBUG)
                return std::unexpected(Error::invalid_remote_module);

            const std::size_t image_size = nt_headers->OptionalHeader.SizeOfImage;
            const auto& debug_data = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
            if (!debug_data.Size || debug_data.VirtualAddress >= image_size
                || debug_data.Size > image_size - debug_data.VirtualAddress)
                return std::unexpected(Error::ntdll_debug_directory_missing);

            std::vector<PdbImageSection> sections;
            sections.reserve(nt_headers->FileHeader.NumberOfSections);
            const auto* section = IMAGE_FIRST_SECTION(nt_headers);
            for (WORD i = 0; i < nt_headers->FileHeader.NumberOfSections; i++, section++)
                sections.push_back({section->VirtualAddress, std::max(section->Misc.VirtualSize, section->SizeOfRawData)});

            const auto* debug_directories =
                    reinterpret_cast<const IMAGE_DEBUG_DIRECTORY*>(ntdll + debug_data.VirtualAddress);
            const std::size_t directory_count = debug_data.Size / sizeof(IMAGE_DEBUG_DIRECTORY);
            for (std::size_t i = 0; i < directory_count; i++)
            {
                const auto& directory = debug_directories[i];
                if (directory.Type != IMAGE_DEBUG_TYPE_CODEVIEW || !directory.SizeOfData
                    || directory.AddressOfRawData >= image_size
                    || directory.SizeOfData > image_size - directory.AddressOfRawData)
                    continue;

                const auto identifier = parse_pdb_identifier(
                        {ntdll + directory.AddressOfRawData, static_cast<std::size_t>(directory.SizeOfData)});
                if (identifier)
                    return download_ntdll_symbol_rvas(*identifier, sections);
            }

            return std::unexpected(Error::ntdll_codeview_record_missing);
        }

        [[nodiscard]] const std::expected<NtdllSymbolRvas, Error>& native_ntdll_symbol_rvas()
        {
            static const auto result = load_native_ntdll_symbol_rvas();
            return result;
        }
#endif
    } // namespace

    std::expected<void*, Error> find_ldrp_handle_tls_data()
    {
        constexpr std::array signatures = {
#ifdef _WIN64
            "4C 8B DC 49 89 5B ? 49 89 73 ? 57 41 54 41 55 41 56 41 57 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 84 24 ? ? ? ? 48 8B F9", // Windows 11 24H2
            "48 89 5C 24 ? 48 89 74 24 ? 48 89 7C 24 ? 41 55 41 56 41 57 48 81 EC",
#else
            // x86 - patterns may need updating per Windows build
            "8B FF 55 8B EC 83 EC ? 53 56 57 8B 7D ? 89 4D",
            "8B FF 55 8B EC 51 51 53 56 57 8B F1 89 75",
            "6A ? 68 ? ? ? ? E8 ? ? ? ? 8B C1 89 45 ? 89 45",
#endif
        };

        const auto* ntdll = GetModuleHandleA("ntdll.dll");
#ifdef YAIL_USE_PDB
        if (const auto& symbols = native_ntdll_symbol_rvas(); symbols && symbols->ldrp_handle_tls_data)
            return reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(ntdll)
                                           + *symbols->ldrp_handle_tls_data);
#endif
        for (const auto* sig : signatures)
        {
            if (const auto result = omath::PePatternScanner::scan_for_pattern_in_loaded_module(ntdll, sig))
                return reinterpret_cast<void*>(result.value());
        }

        return std::unexpected(Error::ldrp_handle_tls_data_not_found);
    }

    std::expected<void*, Error> find_rtl_insert_inverted_function_table()
    {
        constexpr std::array signatures = {
#ifdef _WIN64
            "48 8B C4 48 89 58 ? 48 89 68 ? 48 89 70 ? 57 48 83 EC ? 83 60", // Windows 11 24H2
            "4C 8B DC 49 89 5B ? 49 89 73 ? 57 48 83 EC ? 8B FA"
#else
            // x86 - patterns may need updating per Windows build.
            // Win11 24H2 x86 ntdll: __fastcall convention (ECX/EDX), see typedef above.
            "8B FF 55 8B EC 83 EC ? 53 56 57 8D 45 ? 8B FA 50 8D 55", // Win11 24H2
            "8B FF 55 8B EC 51 51 53 56 57 8B 7D ? 8D 45",
            "8B FF 55 8B EC 53 56 57 8B 7D ? 8D 45",
#endif
        };

        const auto* ntdll = GetModuleHandleA("ntdll.dll");
#ifdef YAIL_USE_PDB
        if (const auto& symbols = native_ntdll_symbol_rvas(); symbols && symbols->rtl_insert_inverted_function_table)
            return reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(ntdll)
                                           + *symbols->rtl_insert_inverted_function_table);
#endif
        for (const auto* sig : signatures)
        {
            if (const auto result = omath::PePatternScanner::scan_for_pattern_in_loaded_module(ntdll, sig))
                return reinterpret_cast<void*>(result.value());
        }

        return std::unexpected(Error::rtl_insert_inverted_function_table_not_found);
    }
}
