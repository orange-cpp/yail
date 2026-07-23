//
// Created by orange on 3/26/2026.
//
#include <Windows.h>
#include <algorithm>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <format>
#include <fstream>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#include <yail/detail/native_loader.hpp>
#include <yail/detail/pe.hpp>
#include <yail/detail/process.hpp>
#include <yail/detail/shellcode.hpp>
#include <yail/detail/wow64.hpp>
#include <yail/yail.hpp>

namespace yail
{
    static std::expected<std::uintptr_t, std::string>
    manual_map_injection_from_raw_impl(const std::span<const std::uint8_t>& raw_dll,
                                       const std::uintptr_t process_id)
    {
        const auto pe_machine = detail::get_pe_machine(raw_dll);
        if (!pe_machine)
            return std::unexpected("File is not in a Portable Executable format");

#ifdef _WIN64
        if (*pe_machine == IMAGE_FILE_MACHINE_I386)
            return detail::manual_map_injection_into_wow64_process(raw_dll, process_id);
        constexpr WORD expected_machine = IMAGE_FILE_MACHINE_AMD64;
#else
        constexpr WORD expected_machine = IMAGE_FILE_MACHINE_I386;
#endif

        if (*pe_machine != expected_machine)
            return std::unexpected(std::format("Unsupported PE machine 0x{:04x} for this injector", *pe_machine));

        if (const auto architecture = detail::validate_target_machine(process_id, expected_machine); !architecture)
            return std::unexpected(architecture.error());

        // Open target process
        // ReSharper disable once CppLocalVariableMayBeConst
        HANDLE process_handle = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ
                                                    | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION,
                                            FALSE, static_cast<DWORD>(process_id));

        if (!process_handle)
            return std::unexpected(std::format("Failed to open target process (error {})", GetLastError()));

        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(raw_dll.data());
        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(raw_dll.data() + dos->e_lfanew);
        std::size_t image_size = nt->OptionalHeader.SizeOfImage;

#ifndef _WIN64
        const auto safe_seh_layout = detail::plan_x86_safe_seh(raw_dll);
        if (!safe_seh_layout)
        {
            CloseHandle(process_handle);
            return std::unexpected(safe_seh_layout.error());
        }
        image_size = safe_seh_layout->expanded_size_of_image;
#endif

        auto* const remote_image = static_cast<std::uint8_t*>(VirtualAllocEx(
                process_handle, nullptr, image_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
        if (!remote_image)
        {
            CloseHandle(process_handle);
            return std::unexpected(std::format("VirtualAllocEx failed for image (error {})", GetLastError()));
        }

        const auto fail_image = [&](std::string error) -> std::expected<std::uintptr_t, std::string>
        {
            VirtualFreeEx(process_handle, remote_image, 0, MEM_RELEASE);
            CloseHandle(process_handle);
            return std::unexpected(std::move(error));
        };

        // Prepare local copy: headers + sections
        std::vector<std::uint8_t> local_image(image_size, 0);
        std::copy_n(raw_dll.data(), nt->OptionalHeader.SizeOfHeaders, local_image.data());

        auto* section_header = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, section_header++)
        {
            if (!section_header->SizeOfRawData)
                continue;
            std::copy_n(raw_dll.data() + section_header->PointerToRawData, section_header->SizeOfRawData,
                        local_image.data() + section_header->VirtualAddress);
        }

        // Relocate for remote base address
        if (!detail::relocate_for_base(local_image.data(), reinterpret_cast<std::uintptr_t>(remote_image)))
            return fail_image("Image requires relocation but has no relocation directory");

#ifndef _WIN64
        detail::write_x86_safe_seh(local_image.data(), reinterpret_cast<std::uintptr_t>(remote_image),
                                   *safe_seh_layout);
#endif

        // Write image to target
        if (!WriteProcessMemory(process_handle, remote_image, local_image.data(), image_size, nullptr))
            return fail_image("WriteProcessMemory failed for image");

        // Prepare shellcode page: [RemoteLoaderData | padding | shellcode bytes]
#ifdef _WIN64
        const auto native_remote_shellcode = yail::detail::x64_remote_shellcode();
#else
        const auto native_remote_shellcode = yail::detail::x86_remote_shellcode();
#endif
        constexpr std::size_t data_aligned = (sizeof(detail::RemoteLoaderData) + 0xF) & ~0xF;
        const std::size_t total_shellcode = data_aligned + native_remote_shellcode.size();

        auto* remote_shellcode = static_cast<std::uint8_t*>(VirtualAllocEx(
                process_handle, nullptr, total_shellcode, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

        if (!remote_shellcode)
            return fail_image("VirtualAllocEx failed for shellcode");

        // Fill loader data
        // ntdll and kernel32 are mapped at the same base in every process (per boot),
        // so our local function pointers are valid in the target.
        const auto* local_dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(local_image.data());

        detail::RemoteLoaderData loader_data{};
        loader_data.image_base = remote_image;
        loader_data.nt_headers_rva = static_cast<DWORD>(local_dos_header->e_lfanew);
#ifndef _WIN64
        loader_data.original_size_of_image = safe_seh_layout->original_size_of_image;
        loader_data.original_number_of_rva_and_sizes = safe_seh_layout->original_number_of_rva_and_sizes;
        loader_data.original_load_config = safe_seh_layout->original_load_config;
#endif
        loader_data.fn_load_library_a = LoadLibraryA;
        loader_data.fn_get_proc_address = GetProcAddress;
#ifdef _WIN64
        loader_data.fn_rtl_add_function_table = RtlAddFunctionTable;
#endif
        loader_data.fn_virtual_protect = VirtualProtect;
        const auto tls_fn = detail::find_ldrp_handle_tls_data();
        if (!tls_fn)
            return fail_image(tls_fn.error());
        loader_data.fn_ldrp_handle_tls_data = tls_fn.value();
        // RtlInsertInvertedFunctionTable is required on x64 (unwind tables) but optional on
        // x86 - without it, manually-mapped DLLs that throw will crash on dispatch, but DLLs
        // that don't throw load fine. Treat lookup failure as fatal only on x64.
        if (const auto inv_fn = detail::find_rtl_insert_inverted_function_table())
            loader_data.fn_rtl_insert_inverted_function_table = inv_fn.value();
#ifdef _WIN64
        else
            return fail_image(inv_fn.error());
#endif

        // Build local shellcode page
        std::vector<std::uint8_t> shell_code_page(total_shellcode, 0);
        std::copy_n(reinterpret_cast<const std::uint8_t*>(&loader_data), sizeof(loader_data), shell_code_page.data());
        std::ranges::copy(native_remote_shellcode, shell_code_page.data() + data_aligned);

        // Write shellcode page to target
        if (!WriteProcessMemory(process_handle, remote_shellcode, shell_code_page.data(), total_shellcode, nullptr))
        {
            VirtualFreeEx(process_handle, remote_shellcode, 0, MEM_RELEASE);
            return fail_image("WriteProcessMemory failed for shellcode");
        }

        // Create remote thread: entry = shellcode code, param = RemoteLoaderData*
        // ReSharper disable once CppLocalVariableMayBeConst
        HANDLE thread_handle = CreateRemoteThread(
                process_handle, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(remote_shellcode + data_aligned),
                remote_shellcode, // lpParameter -> points to RemoteLoaderData
                0, nullptr);

        if (!thread_handle)
        {
            VirtualFreeEx(process_handle, remote_shellcode, 0, MEM_RELEASE);
            return fail_image(std::format("CreateRemoteThread failed (error {})", GetLastError()));
        }

        WaitForSingleObject(thread_handle, INFINITE);

        DWORD exit_code = 0;
        GetExitCodeThread(thread_handle, &exit_code);
        CloseHandle(thread_handle);

        // Free shellcode page - no longer needed after init
        VirtualFreeEx(process_handle, remote_shellcode, 0, MEM_RELEASE);

        if (exit_code != 0)
            return fail_image(std::format("Remote shellcode failed (exit code {})", exit_code));

        CloseHandle(process_handle);
        return reinterpret_cast<std::uintptr_t>(remote_image);
    }

    std::expected<std::uintptr_t, std::string>
    manual_map_injection_from_raw(const std::span<const std::uint8_t>& raw_dll, const std::uintptr_t process_id)
    {
        return manual_map_injection_from_raw_impl(raw_dll, process_id);
    }

    std::expected<std::uintptr_t, std::string>
    manual_map_injection_from_raw(const std::span<const std::uint8_t>& raw_dll, const std::string_view& process_name)
    {
        const auto pid = detail::get_process_id_by_name(process_name);

        if (!pid)
            return std::unexpected(std::format("Process \"{}\" not found", process_name));

        return manual_map_injection_from_raw(raw_dll, pid.value());
    }

    std::expected<std::uintptr_t, std::string> manual_map_injection_from_file(const std::string_view& dll_path,
                                                                              const std::uintptr_t process_id)
    {
        if (!std::filesystem::exists(dll_path))
            return std::unexpected("File does not exists.");
        std::vector<std::uint8_t> data(static_cast<std::size_t>(std::filesystem::file_size(dll_path)), 0);
        std::ifstream file(std::filesystem::path{dll_path}, std::ios::binary);
        if (!file.is_open())
            return std::unexpected("Failed to open DLL file");

        file.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));
        file.close();

        return manual_map_injection_from_raw_impl({data.data(), data.size()}, process_id);
    }

    std::expected<std::uintptr_t, std::string> manual_map_injection_from_file(const std::string_view& dll_path,
                                                                              const std::string_view& process_name)
    {
        const auto pid = detail::get_process_id_by_name(process_name);
        if (!pid)
            return std::unexpected(std::format("Process \"{}\" not found", process_name));

        return manual_map_injection_from_file(dll_path, pid.value());
    }
} // namespace yail
