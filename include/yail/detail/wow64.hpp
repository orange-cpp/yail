#pragma once
#include <cstdint>
#include <expected>
#include <span>
#include <yail/error.hpp>

namespace yail::detail
{
#ifdef _WIN64
    [[nodiscard]]
    std::expected<std::uintptr_t, Error>
    manual_map_injection_into_wow64_process(const std::span<const std::uint8_t>& raw_pe, std::uintptr_t process_id);
#endif
} // namespace yail::detail
