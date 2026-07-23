#pragma once
#include <Windows.h>
#include <cstdint>
#include <expected>
#include <string>

namespace yail::detail
{
    struct RemoteLoaderData final
    {
        std::uint8_t* image_base;
        DWORD nt_headers_rva;
#ifndef _WIN64
        DWORD original_size_of_image;
        DWORD original_number_of_rva_and_sizes;
        IMAGE_DATA_DIRECTORY original_load_config;
#endif

        decltype(&LoadLibraryA) fn_load_library_a;
        decltype(&GetProcAddress) fn_get_proc_address;
#ifdef _WIN64
        decltype(&RtlAddFunctionTable) fn_rtl_add_function_table;
#endif
        decltype(&VirtualProtect) fn_virtual_protect;
        void* fn_ldrp_handle_tls_data;
        void* fn_rtl_insert_inverted_function_table;
    };

    [[nodiscard]]
    std::expected<void*, std::string> find_ldrp_handle_tls_data();

    [[nodiscard]]
    std::expected<void*, std::string> find_rtl_insert_inverted_function_table();
}
