#pragma once

#include <array>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <yail/error.hpp>

namespace yail::detail
{
    struct PdbIdentifier final
    {
        std::uint32_t guid_data1;
        std::uint16_t guid_data2;
        std::uint16_t guid_data3;
        std::array<std::uint8_t, 8> guid_data4;
        std::uint32_t age;
        std::string file_name;
    };

    struct PdbImageSection final
    {
        std::uint32_t rva;
        std::uint32_t size;
    };

    struct NtdllSymbolRvas final
    {
        std::optional<std::uint32_t> ldrp_handle_tls_data;
        std::optional<std::uint32_t> rtl_insert_inverted_function_table;
    };

    [[nodiscard]]
    std::expected<PdbIdentifier, Error> parse_pdb_identifier(std::span<const std::uint8_t> codeview_data);

    [[nodiscard]]
    std::expected<NtdllSymbolRvas, Error>
    download_ntdll_symbol_rvas(const PdbIdentifier& identifier, std::span<const PdbImageSection> image_sections);
}
