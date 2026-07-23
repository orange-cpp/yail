#include <algorithm>
#include <array>
#include <cstring>
#include <format>
#include <limits>
#include <yail/detail/pe.hpp>

namespace yail::detail
{
    namespace
    {
        constexpr DWORD safe_seh_load_config_size = 0x48;

        struct X86SafeSehLoadConfig final
        {
            DWORD size;
            std::array<std::uint8_t, 0x3C> unused;
            DWORD handler_table;
            DWORD handler_count;
        };

        static_assert(sizeof(X86SafeSehLoadConfig) == safe_seh_load_config_size);
        static_assert(offsetof(X86SafeSehLoadConfig, handler_table) == 0x40);

        [[nodiscard]]
        constexpr std::uint64_t align_up(const std::uint64_t value, const std::uint64_t alignment)
        {
            return (value + alignment - 1) / alignment * alignment;
        }
    } // namespace

    std::expected<X86SafeSehLayout, std::string> plan_x86_safe_seh(
            const std::span<const std::uint8_t>& raw_pe)
    {
        if (raw_pe.size() < sizeof(IMAGE_DOS_HEADER))
            return std::unexpected("PE image is smaller than its DOS header");

        const auto* dos_headers = reinterpret_cast<const IMAGE_DOS_HEADER*>(raw_pe.data());
        if (dos_headers->e_magic != IMAGE_DOS_SIGNATURE || dos_headers->e_lfanew < 0)
            return std::unexpected("PE image has an invalid DOS header");

        const auto nt_offset = static_cast<std::size_t>(dos_headers->e_lfanew);
        if (nt_offset > raw_pe.size() || raw_pe.size() - nt_offset < sizeof(IMAGE_NT_HEADERS32))
            return std::unexpected("PE image has a truncated NT header");

        const auto* nt_headers = reinterpret_cast<const IMAGE_NT_HEADERS32*>(raw_pe.data() + nt_offset);
        if (nt_headers->Signature != IMAGE_NT_SIGNATURE || nt_headers->FileHeader.Machine != IMAGE_FILE_MACHINE_I386
            || nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
            return std::unexpected("SafeSEH metadata can only be planned for a valid x86 PE image");

        const auto section_table_offset = nt_offset + offsetof(IMAGE_NT_HEADERS32, OptionalHeader)
                                          + nt_headers->FileHeader.SizeOfOptionalHeader;
        const auto section_table_size =
                static_cast<std::size_t>(nt_headers->FileHeader.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER);
        if (section_table_offset > raw_pe.size() || raw_pe.size() - section_table_offset < section_table_size)
            return std::unexpected("PE image has a truncated section table");

        const DWORD original_size = nt_headers->OptionalHeader.SizeOfImage;
        const DWORD section_alignment = nt_headers->OptionalHeader.SectionAlignment;
        if (!original_size || !section_alignment)
            return std::unexpected("PE image has an invalid image size or section alignment");

        const auto* sections =
                reinterpret_cast<const IMAGE_SECTION_HEADER*>(raw_pe.data() + section_table_offset);
        std::uint64_t handler_count = 0;
        for (WORD i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i)
        {
            const auto& section = sections[i];
            if (!(section.Characteristics & IMAGE_SCN_MEM_EXECUTE))
                continue;

            const std::uint64_t start = section.VirtualAddress;
            const std::uint64_t length = std::max(section.Misc.VirtualSize, section.SizeOfRawData);
            const std::uint64_t end = std::min<std::uint64_t>(original_size, start + length);
            if (end > start)
                handler_count += end - start;
        }

        if (!handler_count)
            return std::unexpected("x86 PE image has no executable section bytes");
        if (handler_count > std::numeric_limits<DWORD>::max())
            return std::unexpected("x86 SafeSEH handler table is too large");

        const std::uint64_t table_rva = align_up(original_size, alignof(DWORD));
        const std::uint64_t table_size = handler_count * sizeof(DWORD);
        const std::uint64_t load_config_rva = align_up(table_rva + table_size, alignof(DWORD));
        const std::uint64_t expanded_size =
                align_up(load_config_rva + safe_seh_load_config_size, section_alignment);
        if (expanded_size > std::numeric_limits<DWORD>::max())
            return std::unexpected("x86 image is too large after adding SafeSEH metadata");

        IMAGE_DATA_DIRECTORY original_load_config{};
        if (nt_headers->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG)
        {
            original_load_config =
                    nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
        }

        return X86SafeSehLayout{
                .original_size_of_image = original_size,
                .original_number_of_rva_and_sizes = nt_headers->OptionalHeader.NumberOfRvaAndSizes,
                .original_load_config = original_load_config,
                .table_rva = static_cast<DWORD>(table_rva),
                .handler_count = static_cast<DWORD>(handler_count),
                .load_config_rva = static_cast<DWORD>(load_config_rva),
                .expanded_size_of_image = static_cast<DWORD>(expanded_size),
        };
    }

    void write_x86_safe_seh(std::uint8_t* local_image, const std::uintptr_t target_base,
                            const X86SafeSehLayout& layout)
    {
        const auto* dos_headers = reinterpret_cast<const IMAGE_DOS_HEADER*>(local_image);
        auto* nt_headers = reinterpret_cast<IMAGE_NT_HEADERS32*>(local_image + dos_headers->e_lfanew);
        const auto* sections = IMAGE_FIRST_SECTION(nt_headers);

        auto* output = reinterpret_cast<DWORD*>(local_image + layout.table_rva);
        for (WORD i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i)
        {
            const auto& section = sections[i];
            if (!(section.Characteristics & IMAGE_SCN_MEM_EXECUTE))
                continue;

            const std::uint64_t start = section.VirtualAddress;
            const std::uint64_t length = std::max(section.Misc.VirtualSize, section.SizeOfRawData);
            const std::uint64_t end = std::min<std::uint64_t>(layout.original_size_of_image, start + length);
            for (std::uint64_t rva = start; rva < end; ++rva)
                *output++ = static_cast<DWORD>(rva);
        }
        std::sort(reinterpret_cast<DWORD*>(local_image + layout.table_rva), output);

        auto* load_config =
                reinterpret_cast<X86SafeSehLoadConfig*>(local_image + layout.load_config_rva);
        std::memset(load_config, 0, sizeof(*load_config));
        load_config->size = safe_seh_load_config_size;
        load_config->handler_table = static_cast<DWORD>(target_base + layout.table_rva);
        load_config->handler_count = layout.handler_count;

        nt_headers->OptionalHeader.SizeOfImage = layout.expanded_size_of_image;
        nt_headers->OptionalHeader.NumberOfRvaAndSizes =
                std::max<DWORD>(nt_headers->OptionalHeader.NumberOfRvaAndSizes,
                                IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG + 1);
        nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG] = {
                layout.load_config_rva,
                safe_seh_load_config_size,
        };
    }

    std::optional<WORD> get_pe_machine(const std::span<const std::uint8_t>& raw_pe)
    {
        if (raw_pe.size() < sizeof(IMAGE_DOS_HEADER))
            return std::nullopt;

        const auto dos_headers = reinterpret_cast<const IMAGE_DOS_HEADER*>(raw_pe.data());

        if (dos_headers->e_magic != IMAGE_DOS_SIGNATURE || dos_headers->e_lfanew < 0)
            return std::nullopt;

        constexpr std::size_t nt_prefix_size = sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
        const auto nt_offset = static_cast<std::size_t>(dos_headers->e_lfanew);
        if (nt_offset > raw_pe.size() || raw_pe.size() - nt_offset < nt_prefix_size)
            return std::nullopt;

        const auto* signature = reinterpret_cast<const DWORD*>(raw_pe.data() + nt_offset);
        if (*signature != IMAGE_NT_SIGNATURE)
            return std::nullopt;

        const auto* file_header = reinterpret_cast<const IMAGE_FILE_HEADER*>(signature + 1);
        return file_header->Machine;
    }

    bool relocate_for_base(std::uint8_t* local_image, const std::uintptr_t target_base)
    {
        const auto* dos_headers = reinterpret_cast<IMAGE_DOS_HEADER*>(local_image);
        auto* nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(local_image + dos_headers->e_lfanew);

        const auto delta = static_cast<std::intptr_t>(target_base - nt_headers->OptionalHeader.ImageBase);
        if (delta == 0)
            return true;

        // ReSharper disable once CppUseStructuredBinding
        const auto& relocation_directory = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (!relocation_directory.Size)
            return false;

        auto* block = reinterpret_cast<IMAGE_BASE_RELOCATION*>(local_image + relocation_directory.VirtualAddress);
        while (block->SizeOfBlock && block->VirtualAddress)
        {
            const std::size_t count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            auto* info = reinterpret_cast<std::uint16_t*>(block + 1);
#ifdef _WIN64
            constexpr WORD reloc_entry_type = IMAGE_REL_BASED_DIR64;
#else
            constexpr WORD reloc_entry_type = IMAGE_REL_BASED_HIGHLOW;
#endif
            for (std::size_t i = 0; i < count; i++, info++)
            {
                if (*info >> 0x0C != reloc_entry_type)
                    continue;
                auto* patch = reinterpret_cast<std::uintptr_t*>(local_image + block->VirtualAddress + (*info & 0xFFF));
                *patch += delta;
            }
            block = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<std::uint8_t*>(block)
                                                             + block->SizeOfBlock);
        }

        nt_headers->OptionalHeader.ImageBase = target_base;
        return true;
    }
} // namespace yail::detail
