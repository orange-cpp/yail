//
// Created by orange on 3/26/2026.
//
#include <Windows.h>
#include <TlHelp32.h>
#include <winternl.h>
#include <omath/utility/pe_pattern_scan.hpp>
#include <yail/yail.hpp>
#include <fstream>
namespace
{
    // Resolve MSVC incremental-link jump stubs (ILT): E9 xx xx xx xx → target

    [[nodiscard]]
    uint8_t* resolve_ilt(void* fn)
    {
        auto* p = static_cast<uint8_t*>(fn);
        if (p[0] == 0xE9)
        {
            const auto rel = *reinterpret_cast<int32_t*>(p + 1);
            return p + 5 + rel;
        }
        return p;
    }
    struct LdrDataTableEntryFull final
    {
        LIST_ENTRY in_load_order_links;
        LIST_ENTRY in_memory_order_links;
        LIST_ENTRY in_initialization_order_links;
        PVOID dll_base;
        PVOID entry_point;
        ULONG size_of_image;
        UNICODE_STRING full_dll_name;
        UNICODE_STRING base_dll_name;
        ULONG flags;
        USHORT obsolete_load_count;
        USHORT tls_index;
        LIST_ENTRY hash_links;
        ULONG time_date_stamp;
    };
    using LdrpHandleTlsDataFn = NTSTATUS(NTAPI*)(LdrDataTableEntryFull*);
    using RtlInsertInvertedFunctionTableFn = void(NTAPI*)(PVOID image_base, ULONG size_of_image);

    [[nodiscard]]
    LdrpHandleTlsDataFn find_ldrp_handle_tls_data()
    {
        const auto result = omath::PePatternScanner::scan_for_pattern_in_loaded_module(
                GetModuleHandleA("ntdll.dll"), "4C 8B DC 49 89 5B ? 49 89 73 ? 57 41 54 41 55 41 56 41 57 48 81 EC ? ? ? ? 48 8B 05 ? ? "
                             "? ? 48 33 C4 48 89 84 24 ? ? ? ? 48 8B F9");

        if (!result)
            throw std::runtime_error{"Failed to find LdrpHandleTlsData"};

        return reinterpret_cast<LdrpHandleTlsDataFn>(result.value());
    }

    [[nodiscard]]
    RtlInsertInvertedFunctionTableFn find_rtl_insert_inverted_function_table()
    {
        const auto result = omath::PePatternScanner::scan_for_pattern_in_loaded_module(
                GetModuleHandleA("ntdll.dll"), "48 8B C4 48 89 58 ? 48 89 68 ? 48 89 70 ? 57 48 83 EC ? 83 60");

        if (!result)
            throw std::runtime_error{"Failed to find RtlInsertInvertedFunctionTable"};

        return reinterpret_cast<RtlInsertInvertedFunctionTableFn>(result.value());
    }
    struct RemoteLoaderData final
    {
        uint8_t* image_base;
        DWORD nt_headers_rva;

        decltype(&LoadLibraryA) fn_load_library_a;
        decltype(&GetProcAddress) fn_get_proc_address;
        decltype(&RtlAddFunctionTable) fn_rtl_add_function_table;
        void* fn_ldrp_handle_tls_data;
        void* fn_rtl_insert_inverted_function_table;
    };
    // Disable all CRT instrumentation so the function is fully self-contained.
    // No __security_check_cookie, no __RTC_*, no __chkstk references.
#pragma runtime_checks("", off)
#pragma optimize("ts", on)
#pragma strict_gs_check(push, off)
    __declspec(safebuffers) __declspec(noinline) DWORD WINAPI remote_shellcode(const RemoteLoaderData* data)
    {
        auto* base = data->image_base;
        auto* nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(base + data->nt_headers_rva);

        // --- Resolve imports ---
        // ReSharper disable once CppUseStructuredBinding
        // ReSharper disable once CppTooWideScopeInitStatement
        const auto& import_dir = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (import_dir.Size)
        {
            const auto* desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + import_dir.VirtualAddress);
            while (desc->Characteristics)
            {
                const HMODULE module_handle = data->fn_load_library_a(reinterpret_cast<LPCSTR>(base + desc->Name));
                if (!module_handle)
                    return 1;

                const auto* original_trunk = reinterpret_cast<IMAGE_THUNK_DATA*>(base + desc->OriginalFirstThunk);
                auto* first_trunk = reinterpret_cast<IMAGE_THUNK_DATA*>(base + desc->FirstThunk);

                while (original_trunk->u1.AddressOfData)
                {
                    FARPROC fn;
                    if (original_trunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
                        fn = data->fn_get_proc_address(module_handle,
                                                       reinterpret_cast<LPCSTR>(original_trunk->u1.Ordinal & 0xFFFF));
                    else
                    {
                        const auto* ibn = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + original_trunk->u1.AddressOfData);
                        fn = data->fn_get_proc_address(module_handle, ibn->Name);
                    }
                    if (!fn)
                        return 2;
                    first_trunk->u1.Function = reinterpret_cast<uintptr_t>(fn);
                    original_trunk++;
                    first_trunk++;
                }
                desc++;
            }
        }

        // --- Handle static TLS ---
        auto& tls_directory = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
        if (tls_directory.Size && data->fn_ldrp_handle_tls_data)
        {
            // Build fake LDR_DATA_TABLE_ENTRY on the stack — zero without memset
            LdrDataTableEntryFull entry;
            auto* raw = reinterpret_cast<volatile uint8_t*>(&entry);
            for (size_t i = 0; i < sizeof(entry); i++)
                raw[i] = 0;

            entry.dll_base = base;
            entry.size_of_image = nt_headers->OptionalHeader.SizeOfImage;
            entry.entry_point = base + nt_headers->OptionalHeader.AddressOfEntryPoint;

            entry.in_load_order_links.Flink = &entry.in_load_order_links;
            entry.in_load_order_links.Blink = &entry.in_load_order_links;
            entry.in_memory_order_links.Flink = &entry.in_memory_order_links;
            entry.in_memory_order_links.Blink = &entry.in_memory_order_links;
            entry.in_initialization_order_links.Flink = &entry.in_initialization_order_links;
            entry.in_initialization_order_links.Blink = &entry.in_initialization_order_links;
            entry.hash_links.Flink = &entry.hash_links;
            entry.hash_links.Blink = &entry.hash_links;

            reinterpret_cast<NTSTATUS(NTAPI*)(LdrDataTableEntryFull*)>(data->fn_ldrp_handle_tls_data)(&entry);
        }

        // --- TLS callbacks ---
        if (tls_directory.Size)
        {
            const auto* tls = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(base + tls_directory.VirtualAddress);
            // ReSharper disable once CppTooWideScopeInitStatement
            const auto* call_backs_addr = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(tls->AddressOfCallBacks);
            for (; call_backs_addr && *call_backs_addr; call_backs_addr++)
                (*call_backs_addr)(base, DLL_PROCESS_ATTACH, nullptr);
        }

        // --- Exception handling ---
        // ReSharper disable once CppTooWideScopeInitStatement
        const auto& [VirtualAddress, Size] = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (Size)
        {
            if (data->fn_rtl_insert_inverted_function_table)
            {
                reinterpret_cast<void(NTAPI*)(PVOID, ULONG)>(data->fn_rtl_insert_inverted_function_table)(
                        base, nt_headers->OptionalHeader.SizeOfImage);
            }
            else
            {
                data->fn_rtl_add_function_table(
                        reinterpret_cast<IMAGE_RUNTIME_FUNCTION_ENTRY*>(base + VirtualAddress),
                        Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY), reinterpret_cast<uintptr_t>(base));
            }
        }

        // --- Call entry point ---
        if (nt_headers->OptionalHeader.AddressOfEntryPoint)
        {
            const auto entry_point = reinterpret_cast<BOOL(WINAPI*)(HMODULE, DWORD, LPVOID)>(
                    base + nt_headers->OptionalHeader.AddressOfEntryPoint);
            entry_point(reinterpret_cast<HMODULE>(base), DLL_PROCESS_ATTACH, nullptr);
        }

        return 0;
    }
    void remote_shellcode_end()
    {
    }

#pragma strict_gs_check(pop)
#pragma runtime_checks("", restore)
#pragma optimize("", on)
    [[nodiscard]]
    bool is_portable_executable(const std::span<uint8_t>& raw_dll)
    {
        const auto dos_headers = reinterpret_cast<const IMAGE_DOS_HEADER*>(raw_dll.data());

        if (dos_headers->e_magic != 0x5A4D)
            return false;

        const auto nt_headers = reinterpret_cast<const IMAGE_NT_HEADERS*>(raw_dll.data() + dos_headers->e_lfanew);

        return nt_headers->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64;
    }

    void relocate_for_base(uint8_t* local_image, const uintptr_t target_base)
    {
        const auto* dos_headers = reinterpret_cast<IMAGE_DOS_HEADER*>(local_image);
        auto* nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(local_image + dos_headers->e_lfanew);

        const auto delta = static_cast<intptr_t>(target_base - nt_headers->OptionalHeader.ImageBase);
        if (delta == 0)
            return;

        // ReSharper disable once CppUseStructuredBinding
        const auto& relocation_directory = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (!relocation_directory.Size)
            return;

        auto* block = reinterpret_cast<IMAGE_BASE_RELOCATION*>(local_image + relocation_directory.VirtualAddress);
        while (block->SizeOfBlock && block->VirtualAddress)
        {
            const size_t count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            auto* info = reinterpret_cast<uint16_t*>(block + 1);
            for (size_t i = 0; i < count; i++, info++)
            {
                if (*info >> 0x0C != IMAGE_REL_BASED_DIR64)
                    continue;
                auto* patch = reinterpret_cast<uintptr_t*>(local_image + block->VirtualAddress + (*info & 0xFFF));
                *patch += delta;
            }
            block = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<uint8_t*>(block) + block->SizeOfBlock);
        }

        nt_headers->OptionalHeader.ImageBase = target_base;
    }
    [[nodiscard]]
    std::optional<std::uintptr_t> get_process_id_by_name(const std::string_view& process_name)
    {
        // ReSharper disable once CppLocalVariableMayBeConst
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE)
            return 0;

        PROCESSENTRY32 pe{};
        pe.dwSize = sizeof(pe);

        std::optional<std::uintptr_t> pid = std::nullopt;
        if (Process32First(snap, &pe))
        {
            do
            {
                if (std::string_view(pe.szExeFile) == process_name)
                {
                    pid = pe.th32ProcessID;
                    break;
                }
            }
            while (Process32Next(snap, &pe));
        }

        CloseHandle(snap);
        return pid;
    }
} // namespace

namespace yail
{
    std::expected<uintptr_t, std::string> manual_map_injection_from_raw(const std::span<std::uint8_t>& raw_dll,
                                                                        const std::uintptr_t process_id)
    {
        if (!is_portable_executable(raw_dll))
            return std::unexpected("File is not in a Portable Executable format");

        // Open target process
        // ReSharper disable once CppLocalVariableMayBeConst
        HANDLE process_handle = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ
                                                     | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION,
                                             FALSE, static_cast<DWORD>(process_id));

        if (!process_handle)
            return std::unexpected("Failed to open target process (error " + std::to_string(GetLastError()) + ")");

        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(raw_dll.data());
        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(raw_dll.data() + dos->e_lfanew);
        const std::size_t image_size = nt->OptionalHeader.SizeOfImage;

        // Allocate image memory in target process
        auto* remote_image = static_cast<uint8_t*>(
                VirtualAllocEx(process_handle, nullptr, image_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

        if (!remote_image)
        {
            CloseHandle(process_handle);
            return std::unexpected("VirtualAllocEx failed for image (error " + std::to_string(GetLastError()) + ")");
        }

        // Prepare local copy: headers + sections
        std::vector<uint8_t> local_image(image_size, 0);
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
        relocate_for_base(local_image.data(), reinterpret_cast<uintptr_t>(remote_image));

        // Write image to target
        if (!WriteProcessMemory(process_handle, remote_image, local_image.data(), image_size, nullptr))
        {
            VirtualFreeEx(process_handle, remote_image, 0, MEM_RELEASE);
            CloseHandle(process_handle);
            return std::unexpected("WriteProcessMemory failed for image");
        }

        // Prepare shellcode page: [RemoteLoaderData | padding | shellcode bytes]
        const auto* shell_code_start = resolve_ilt(reinterpret_cast<void*>(&remote_shellcode));
        const auto* shell_code_end = resolve_ilt(reinterpret_cast<void*>(&remote_shellcode_end));
        auto size_of_shell_code = static_cast<size_t>(shell_code_end - shell_code_start);
        if (size_of_shell_code < 0x100)
            size_of_shell_code = 0x1000; // safety floor

        constexpr size_t data_aligned = (sizeof(RemoteLoaderData) + 0xF) & ~0xF;
        const size_t total_shellcode = data_aligned + size_of_shell_code;

        auto* remote_shellcode = static_cast<uint8_t*>(
                VirtualAllocEx(process_handle, nullptr, total_shellcode, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

        if (!remote_shellcode)
        {
            VirtualFreeEx(process_handle, remote_image, 0, MEM_RELEASE);
            CloseHandle(process_handle);
            return std::unexpected("VirtualAllocEx failed for shellcode");
        }

        // Fill loader data
        // ntdll and kernel32 are mapped at the same base in every process (per boot),
        // so our local function pointers are valid in the target.
        const auto* local_dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(local_image.data());

        RemoteLoaderData loader_data{};
        loader_data.image_base = remote_image;
        loader_data.nt_headers_rva = static_cast<DWORD>(local_dos_header->e_lfanew);
        loader_data.fn_load_library_a = LoadLibraryA;
        loader_data.fn_get_proc_address = GetProcAddress;
        loader_data.fn_rtl_add_function_table = RtlAddFunctionTable;
        loader_data.fn_ldrp_handle_tls_data = reinterpret_cast<void*>(find_ldrp_handle_tls_data());
        loader_data.fn_rtl_insert_inverted_function_table =
                reinterpret_cast<void*>(find_rtl_insert_inverted_function_table());

        // Build local shellcode page
        std::vector<uint8_t> shell_code_page(total_shellcode, 0);
        std::memcpy(shell_code_page.data(), &loader_data, sizeof(loader_data));
        std::memcpy(shell_code_page.data() + data_aligned, shell_code_start, size_of_shell_code);

        // Write shellcode page to target
        if (!WriteProcessMemory(process_handle, remote_shellcode, shell_code_page.data(), total_shellcode, nullptr))
        {
            VirtualFreeEx(process_handle, remote_shellcode, 0, MEM_RELEASE);
            VirtualFreeEx(process_handle, remote_image, 0, MEM_RELEASE);
            CloseHandle(process_handle);
            return std::unexpected("WriteProcessMemory failed for shellcode");
        }

        // Create remote thread: entry = shellcode code, param = RemoteLoaderData*
        // ReSharper disable once CppLocalVariableMayBeConst
        HANDLE thread_handle = CreateRemoteThread(
                process_handle, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(remote_shellcode + data_aligned),
                remote_shellcode, // lpParameter → points to RemoteLoaderData
                0, nullptr);

        if (!thread_handle)
        {
            VirtualFreeEx(process_handle, remote_shellcode, 0, MEM_RELEASE);
            VirtualFreeEx(process_handle, remote_image, 0, MEM_RELEASE);
            CloseHandle(process_handle);
            return std::unexpected("CreateRemoteThread failed (error " + std::to_string(GetLastError()) + ")");
        }

        WaitForSingleObject(thread_handle, INFINITE);

        DWORD exit_code = 0;
        GetExitCodeThread(thread_handle, &exit_code);
        CloseHandle(thread_handle);

        // Free shellcode page — no longer needed after init
        VirtualFreeEx(process_handle, remote_shellcode, 0, MEM_RELEASE);
        CloseHandle(process_handle);

        if (exit_code != 0)
            return std::unexpected("Remote shellcode failed (exit code " + std::to_string(exit_code) + ")");

        return reinterpret_cast<uintptr_t>(remote_image);
    }
    std::expected<uintptr_t, std::string> manual_map_injection_from_raw(const std::span<std::uint8_t>& raw_dll,
                                                                        const std::string_view& process_name)
    {
        const auto pid = get_process_id_by_name(process_name);

        if (!pid)
            return std::unexpected("Process \"" + std::string(process_name) + "\" not found");

        return manual_map_injection_from_raw(raw_dll, pid.value());
    }
    std::expected<uintptr_t, std::string> manual_map_injection_from_file(const std::string_view& dll_path,
                                                                         const std::uintptr_t process_id)
    {
        std::vector<uint8_t> data(std::filesystem::file_size(dll_path), 0);
        std::ifstream file(std::filesystem::path{dll_path}, std::ios::binary);
        if (!file.is_open())
            return std::unexpected("Failed to open DLL file");

        file.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));

        return manual_map_injection_from_raw({data.data(), data.size()}, process_id);
    }
    std::expected<uintptr_t, std::string> manual_map_injection_from_file(const std::string_view& dll_path,
                                                                         const std::string_view& process_name)
    {
        std::vector<uint8_t> data(std::filesystem::file_size(dll_path), 0);
        std::ifstream file(std::filesystem::path{dll_path}, std::ios::binary);
        if (!file.is_open())
            return std::unexpected("Failed to open DLL file");

        file.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));

        return manual_map_injection_from_raw({data.data(), data.size()}, process_name);
    }
} // namespace yail