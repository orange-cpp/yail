//
// Created by orange on 3/26/2026.
//
#pragma once
#include <expected>
#include <span>
#include <cstdint>
#include <cstddef>
#include <string_view>
#include <yail/error.hpp>

namespace yail
{
    // Accepts both DLLs and EXEs (matched by the IMAGE_FILE_DLL characteristic).
    // For EXEs, the CRT entry runs to completion and then calls ExitProcess —
    // the host process will terminate when the injected EXE's main() returns.
    // GetModuleHandle(nullptr) inside the injected EXE still resolves to the
    // host process image, not the manually-mapped one.
    // The returned address is not a loader-managed HMODULE. Passing it to
    // FreeLibrary or FreeLibraryAndExitThread is invalid. YAIL does not
    // currently provide manual unmapping.
    // An x64 build can also map x86 images into WOW64 targets in-process.

    [[nodiscard]]
    std::expected<std::uintptr_t, Error> manual_map_injection_from_raw(
            const std::span<const std::uint8_t>& raw_pe, std::uintptr_t process_id);

    [[nodiscard]]
    std::expected<std::uintptr_t, Error> manual_map_injection_from_raw(
            const std::span<const std::uint8_t>& raw_pe, const std::string_view& process_name);

    [[nodiscard]]
    std::expected<std::uintptr_t, Error> manual_map_injection_from_file(
            const std::string_view& pe_path, std::uintptr_t process_id);

    [[nodiscard]]
    std::expected<std::uintptr_t, Error> manual_map_injection_from_file(
            const std::string_view& pe_path, const std::string_view& process_name);
}
