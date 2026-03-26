//
// Created by orange on 3/26/2026.
//
#pragma once
#include <expected>
#include <string>
#include <span>
#include <cstdint>
#include <cstddef>

namespace yail
{
    [[nodiscard]]
    std::expected<uintptr_t, std::string> manual_map_injection_from_raw(
            const std::span<std::uint8_t>& raw_dll, std::uintptr_t process_id);

    [[nodiscard]]
    std::expected<uintptr_t, std::string> manual_map_injection_from_raw(
            const std::span<std::uint8_t>& raw_dll, const std::string_view& process_name);

    [[nodiscard]]
    std::expected<uintptr_t, std::string> manual_map_injection_from_file(
            const std::string_view& dll_path, std::uintptr_t process_id);

    [[nodiscard]]
    std::expected<uintptr_t, std::string> manual_map_injection_from_file(
            const std::string_view& dll_path, const std::string_view& process_name);
}