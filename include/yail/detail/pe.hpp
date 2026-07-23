#pragma once
#include <Windows.h>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>

namespace yail::detail
{
    struct X86SafeSehLayout final
    {
        DWORD original_size_of_image;
        DWORD original_number_of_rva_and_sizes;
        IMAGE_DATA_DIRECTORY original_load_config;
        DWORD table_rva;
        DWORD handler_count;
        DWORD load_config_rva;
        DWORD expanded_size_of_image;
    };

    [[nodiscard]]
    std::optional<WORD> get_pe_machine(const std::span<const std::uint8_t>& raw_pe);

    [[nodiscard]]
    bool relocate_for_base(std::uint8_t* local_image, std::uintptr_t target_base);

    [[nodiscard]]
    std::expected<X86SafeSehLayout, std::string> plan_x86_safe_seh(const std::span<const std::uint8_t>& raw_pe);

    void write_x86_safe_seh(std::uint8_t* local_image, std::uintptr_t target_base,
                            const X86SafeSehLayout& layout);
} // namespace yail::detail
