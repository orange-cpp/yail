//
// Created by orange on 3/26/2026.
//
#include <Windows.h>
#include <TlHelp32.h>
#include <winternl.h>
#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <cstring>
#include <filesystem>
#include <format>
#include <fstream>
#include <limits>
#include <optional>
#include <string>
#include <vector>
#include <omath/utility/pe_pattern_scan.hpp>
#include <yail/yail.hpp>
#include "shellcode.hpp"
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
    // legacy `_Name@N` symbol decoration — args come in ECX/EDX, not on the stack.
    using LdrpHandleTlsDataFn = NTSTATUS(__fastcall*)(LdrDataTableEntryFull*);
    using RtlInsertInvertedFunctionTableFn = void(__fastcall*)(PVOID image_base, ULONG size_of_image);
#endif

    [[nodiscard]]
    std::expected<LdrpHandleTlsDataFn, std::string> find_ldrp_handle_tls_data()
    {
        constexpr std::array signatures = {
#ifdef _WIN64
            "4C 8B DC 49 89 5B ? 49 89 73 ? 57 41 54 41 55 41 56 41 57 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 84 24 ? ? ? ? 48 8B F9", // Windows 11 24H2
            "48 89 5C 24 ? 48 89 74 24 ? 48 89 7C 24 ? 41 55 41 56 41 57 48 81 EC",
#else
            // x86 — patterns may need updating per Windows build
            "8B FF 55 8B EC 83 EC ? 53 56 57 8B 7D ? 89 4D",
            "8B FF 55 8B EC 51 51 53 56 57 8B F1 89 75",
            "6A ? 68 ? ? ? ? E8 ? ? ? ? 8B C1 89 45 ? 89 45",
#endif
        };

        const auto* ntdll = GetModuleHandleA("ntdll.dll");
        for (const auto* sig : signatures)
            if (const auto result = omath::PePatternScanner::scan_for_pattern_in_loaded_module(ntdll, sig))
                return reinterpret_cast<LdrpHandleTlsDataFn>(result.value());

        return std::unexpected("Failed to find LdrpHandleTlsData");
    }

    [[nodiscard]]
    std::expected<RtlInsertInvertedFunctionTableFn, std::string> find_rtl_insert_inverted_function_table()
    {
        constexpr std::array signatures = {
#ifdef _WIN64
            "48 8B C4 48 89 58 ? 48 89 68 ? 48 89 70 ? 57 48 83 EC ? 83 60", // Windows 11 24H2
            "4C 8B DC 49 89 5B ? 49 89 73 ? 57 48 83 EC ? 8B FA"
#else
            // x86 — patterns may need updating per Windows build.
            // Win11 24H2 x86 ntdll: __fastcall convention (ECX/EDX), see typedef above.
            "8B FF 55 8B EC 83 EC ? 53 56 57 8D 45 ? 8B FA 50 8D 55", // Win11 24H2
            "8B FF 55 8B EC 51 51 53 56 57 8B 7D ? 8D 45",
            "8B FF 55 8B EC 53 56 57 8B 7D ? 8D 45",
#endif
        };

        const auto* ntdll = GetModuleHandleA("ntdll.dll");
        for (const auto* sig : signatures)
            if (const auto result = omath::PePatternScanner::scan_for_pattern_in_loaded_module(ntdll, sig))
                return reinterpret_cast<RtlInsertInvertedFunctionTableFn>(result.value());

        return std::unexpected("Failed to find RtlInsertInvertedFunctionTable");
    }
    struct RemoteLoaderData final
    {
        std::uint8_t* image_base;
        DWORD nt_headers_rva;

        decltype(&LoadLibraryA) fn_load_library_a;
        decltype(&GetProcAddress) fn_get_proc_address;
#ifdef _WIN64
        decltype(&RtlAddFunctionTable) fn_rtl_add_function_table;
#endif
        decltype(&VirtualProtect) fn_virtual_protect;
        void* fn_ldrp_handle_tls_data;
        void* fn_rtl_insert_inverted_function_table;
    };
    // Disabled reference implementation used to regenerate source/shellcode.hpp.
    // Temporarily change this to #if 1, rebuild both architectures, run
    // tools/generate_shellcode.py, then restore #if 0.
#if 0
    // Disable all CRT instrumentation so the function is fully self-contained.
    // No __security_check_cookie, no __RTC_*, no __chkstk references.
#ifdef _MSC_VER
#pragma runtime_checks("", off)
#pragma optimize("ts", on)
#pragma strict_gs_check(push, off)
#endif
    // A dedicated PE section keeps sizing independent from consumer linker ordering.
    __declspec(safebuffers) __declspec(noinline) __declspec(code_seg(".yail$a")) DWORD WINAPI
    remote_shellcode(const RemoteLoaderData* data)
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
                    first_trunk->u1.Function = reinterpret_cast<std::uintptr_t>(fn);
                    original_trunk++;
                    first_trunk++;
                }
                desc++;
            }
        }

        // --- Resolve delay imports ---
        // ReSharper disable once CppUseStructuredBinding
        // ReSharper disable once CppTooWideScopeInitStatement
        const auto& delay_dir = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
        if (delay_dir.Size)
        {
            auto* delay_desc = reinterpret_cast<IMAGE_DELAYLOAD_DESCRIPTOR*>(base + delay_dir.VirtualAddress);
            while (delay_desc->DllNameRVA)
            {
                const HMODULE module_handle = data->fn_load_library_a(
                        reinterpret_cast<LPCSTR>(base + delay_desc->DllNameRVA));
                if (!module_handle)
                    return 3;

                const auto* name_thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(
                        base + delay_desc->ImportNameTableRVA);
                auto* addr_thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(
                        base + delay_desc->ImportAddressTableRVA);

                while (name_thunk->u1.AddressOfData)
                {
                    FARPROC fn;
                    if (name_thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
                        fn = data->fn_get_proc_address(module_handle,
                                                       reinterpret_cast<LPCSTR>(name_thunk->u1.Ordinal & 0xFFFF));
                    else
                    {
                        const auto* ibn = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(
                                base + name_thunk->u1.AddressOfData);
                        fn = data->fn_get_proc_address(module_handle, ibn->Name);
                    }
                    if (!fn)
                        return 4;
                    addr_thunk->u1.Function = reinterpret_cast<std::uintptr_t>(fn);
                    name_thunk++;
                    addr_thunk++;
                }

                delay_desc->ModuleHandleRVA =
                        static_cast<DWORD>(reinterpret_cast<std::uint8_t*>(module_handle) - base);
                delay_desc++;
            }
        }

        // --- Handle static TLS ---
        // ReSharper disable once CppUseStructuredBinding
        const auto& tls_directory = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
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

#ifdef _WIN64
            (reinterpret_cast<NTSTATUS(NTAPI*)(LdrDataTableEntryFull*)>(data->fn_ldrp_handle_tls_data)(&entry));
#else
            (reinterpret_cast<NTSTATUS(__fastcall*)(LdrDataTableEntryFull*)>(data->fn_ldrp_handle_tls_data)(&entry));
#endif
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

#ifdef _WIN64
        // --- Exception handling (x64 unwind tables) ---
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
                        Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY), reinterpret_cast<std::uintptr_t>(base));
            }
        }
#else
        // x86: register module in the inverted function table so RtlIsValidHandler accepts
        // SEH/C++ handlers from this image. Without this, exception dispatch rejects every
        // handler in a manually-mapped DLL and unwinds straight to process termination.
        // Modern x86 ntdll passes args in ECX/EDX (__fastcall), not on the stack.
        if (data->fn_rtl_insert_inverted_function_table)
        {
            reinterpret_cast<void(__fastcall*)(PVOID, ULONG)>(data->fn_rtl_insert_inverted_function_table)(
                    base, nt_headers->OptionalHeader.SizeOfImage);
        }
#endif

        // --- Apply per-section memory protections ---
        {
            auto* section = reinterpret_cast<IMAGE_SECTION_HEADER*>(
                    reinterpret_cast<std::uint8_t*>(&nt_headers->OptionalHeader) + nt_headers->FileHeader.SizeOfOptionalHeader);

            for (std::uint16_t i = 0; i < nt_headers->FileHeader.NumberOfSections; i++, section++)
            {
                if (!section->Misc.VirtualSize)
                    continue;

                DWORD protect = PAGE_NOACCESS;
                const DWORD sc = section->Characteristics;

                if (sc & IMAGE_SCN_MEM_EXECUTE)
                {
                    if (sc & IMAGE_SCN_MEM_WRITE)
                        protect = PAGE_EXECUTE_READWRITE;
                    else if (sc & IMAGE_SCN_MEM_READ)
                        protect = PAGE_EXECUTE_READ;
                    else
                        protect = PAGE_EXECUTE;
                }
                else if (sc & IMAGE_SCN_MEM_WRITE)
                {
                    if (sc & IMAGE_SCN_MEM_READ)
                        protect = PAGE_READWRITE;
                    else
                        protect = PAGE_WRITECOPY;
                }
                else if (sc & IMAGE_SCN_MEM_READ)
                {
                    protect = PAGE_READONLY;
                }

                if (sc & IMAGE_SCN_MEM_NOT_CACHED)
                    protect |= PAGE_NOCACHE;

                DWORD old_protect;
                data->fn_virtual_protect(base + section->VirtualAddress, section->Misc.VirtualSize, protect, &old_protect);
            }
        }

        // --- Call entry point ---
        if (nt_headers->OptionalHeader.AddressOfEntryPoint)
        {
            if (nt_headers->FileHeader.Characteristics & IMAGE_FILE_DLL)
            {
                const auto entry_point = reinterpret_cast<BOOL(WINAPI*)(HMODULE, DWORD, LPVOID)>(
                        base + nt_headers->OptionalHeader.AddressOfEntryPoint);
                entry_point(reinterpret_cast<HMODULE>(base), DLL_PROCESS_ATTACH, nullptr);
            }
            else
            {
                // EXE entry (mainCRTStartup / WinMainCRTStartup) — __cdecl, no args.
                // When the entry returns the CRT calls exit() → ExitProcess, terminating
                // the host process. GetModuleHandle(NULL) still resolves to the host EXE.
                const auto entry_point = reinterpret_cast<int(__cdecl*)()>(
                        base + nt_headers->OptionalHeader.AddressOfEntryPoint);
                entry_point();
            }
        }

        return 0;
    }
    __declspec(noinline) __declspec(code_seg(".yail$z")) std::uint64_t remote_shellcode_end()
    {
        return 0x5941494C5348454Cull;
    }

#ifdef _MSC_VER
#pragma strict_gs_check(pop)
#pragma runtime_checks("", restore)
#pragma optimize("", on)
#endif
#endif
    [[nodiscard]]
    std::optional<WORD> get_pe_machine(const std::span<std::uint8_t>& raw_dll)
    {
        if (raw_dll.size() < sizeof(IMAGE_DOS_HEADER))
            return std::nullopt;

        const auto dos_headers = reinterpret_cast<const IMAGE_DOS_HEADER*>(raw_dll.data());

        if (dos_headers->e_magic != IMAGE_DOS_SIGNATURE || dos_headers->e_lfanew < 0)
            return std::nullopt;

        constexpr std::size_t nt_prefix_size = sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
        const auto nt_offset = static_cast<std::size_t>(dos_headers->e_lfanew);
        if (nt_offset > raw_dll.size() || raw_dll.size() - nt_offset < nt_prefix_size)
            return std::nullopt;

        const auto* signature = reinterpret_cast<const DWORD*>(raw_dll.data() + nt_offset);
        if (*signature != IMAGE_NT_SIGNATURE)
            return std::nullopt;

        const auto* file_header = reinterpret_cast<const IMAGE_FILE_HEADER*>(signature + 1);
        return file_header->Machine;
    }

    [[nodiscard]]
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
            block = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<std::uint8_t*>(block) + block->SizeOfBlock);
        }

        nt_headers->OptionalHeader.ImageBase = target_base;
        return true;
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

    class UniqueHandle final
    {
    public:
        UniqueHandle() = default;
        explicit UniqueHandle(const HANDLE handle) : m_handle(handle) {}
        ~UniqueHandle() { reset(); }

        UniqueHandle(const UniqueHandle&) = delete;
        UniqueHandle& operator=(const UniqueHandle&) = delete;

        UniqueHandle(UniqueHandle&& other) noexcept : m_handle(other.release()) {}
        UniqueHandle& operator=(UniqueHandle&& other) noexcept
        {
            if (this != &other)
            {
                reset();
                m_handle = other.release();
            }
            return *this;
        }

        [[nodiscard]]
        HANDLE get() const { return m_handle; }

        [[nodiscard]]
        explicit operator bool() const { return m_handle && m_handle != INVALID_HANDLE_VALUE; }

        void reset(const HANDLE handle = nullptr)
        {
            if (*this)
                CloseHandle(m_handle);
            m_handle = handle;
        }

        [[nodiscard]]
        HANDLE release()
        {
            const HANDLE handle = m_handle;
            m_handle = nullptr;
            return handle;
        }

    private:
        HANDLE m_handle = nullptr;
    };

    [[nodiscard]]
    std::expected<void, std::string> validate_target_machine(const std::uintptr_t process_id,
                                                             const WORD expected_machine)
    {
        if (process_id > std::numeric_limits<DWORD>::max())
            return std::unexpected("Process id is out of range");

        const UniqueHandle process{OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(process_id))};
        if (!process)
            return std::unexpected(std::format("Failed to query target process (error {})", GetLastError()));

        using IsWow64Process2Fn = BOOL(WINAPI*)(HANDLE, USHORT*, USHORT*);
        const auto kernel32 = GetModuleHandleA("kernel32.dll");
        const auto is_wow64_process_2 = reinterpret_cast<IsWow64Process2Fn>(
                GetProcAddress(kernel32, "IsWow64Process2"));
        if (is_wow64_process_2)
        {
            USHORT process_machine = IMAGE_FILE_MACHINE_UNKNOWN;
            USHORT native_machine = IMAGE_FILE_MACHINE_UNKNOWN;
            if (!is_wow64_process_2(process.get(), &process_machine, &native_machine))
                return std::unexpected(std::format("Failed to query target architecture (error {})", GetLastError()));

            const WORD target_machine = process_machine == IMAGE_FILE_MACHINE_UNKNOWN ? native_machine
                                                                                       : process_machine;
            if (target_machine != expected_machine)
                return std::unexpected(std::format("Target process machine 0x{:04x} does not match PE machine 0x{:04x}",
                                                   target_machine, expected_machine));
            return {};
        }

        BOOL target_is_wow64 = FALSE;
        BOOL self_is_wow64 = FALSE;
        if (!IsWow64Process(process.get(), &target_is_wow64)
            || !IsWow64Process(GetCurrentProcess(), &self_is_wow64))
            return std::unexpected(std::format("Failed to query target architecture (error {})", GetLastError()));

#ifdef _WIN64
        const WORD target_machine = target_is_wow64 ? IMAGE_FILE_MACHINE_I386 : IMAGE_FILE_MACHINE_AMD64;
        if (target_machine != expected_machine)
            return std::unexpected(std::format("Target process machine 0x{:04x} does not match PE machine 0x{:04x}",
                                               target_machine, expected_machine));
#else
        if (expected_machine != IMAGE_FILE_MACHINE_I386 || target_is_wow64 != self_is_wow64)
            return std::unexpected("Target process architecture does not match the x86 injector");
#endif

        return {};
    }

#ifdef _WIN64
    struct Wow64RemoteLoaderData final
    {
        std::uint32_t image_base;
        DWORD nt_headers_rva;
        std::uint32_t fn_load_library_a;
        std::uint32_t fn_get_proc_address;
        std::uint32_t fn_virtual_protect;
        std::uint32_t fn_ldrp_handle_tls_data;
        std::uint32_t fn_rtl_insert_inverted_function_table;
    };
    static_assert(sizeof(Wow64RemoteLoaderData) == 28);

    [[nodiscard]]
    bool relocate_wow64_image_for_base(std::uint8_t* local_image, const std::uint32_t target_base)
    {
        const auto* dos_headers = reinterpret_cast<IMAGE_DOS_HEADER*>(local_image);
        auto* nt_headers = reinterpret_cast<IMAGE_NT_HEADERS32*>(local_image + dos_headers->e_lfanew);

        const auto delta = static_cast<std::int64_t>(target_base) - nt_headers->OptionalHeader.ImageBase;
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
            for (std::size_t i = 0; i < count; i++, info++)
            {
                if (*info >> 0x0C != IMAGE_REL_BASED_HIGHLOW)
                    continue;
                auto* patch = reinterpret_cast<std::uint32_t*>(
                        local_image + block->VirtualAddress + (*info & 0xFFF));
                *patch += static_cast<std::uint32_t>(delta);
            }
            block = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<std::uint8_t*>(block)
                                                              + block->SizeOfBlock);
        }

        nt_headers->OptionalHeader.ImageBase = target_base;
        return true;
    }

    [[nodiscard]]
    std::expected<void, std::string> read_remote_memory(const HANDLE process_handle, const std::uintptr_t address,
                                                        void* destination, const std::size_t size)
    {
        SIZE_T bytes_read = 0;
        if (!ReadProcessMemory(process_handle, reinterpret_cast<const void*>(address), destination, size, &bytes_read)
            || bytes_read != size)
            return std::unexpected(std::format("Failed to read WOW64 process memory at 0x{:x} (error {})",
                                               address, GetLastError()));
        return {};
    }

    struct Wow64RemotePeHeaders final
    {
        IMAGE_DOS_HEADER dos_headers;
        IMAGE_NT_HEADERS32 nt_headers;
    };

    [[nodiscard]]
    std::expected<Wow64RemotePeHeaders, std::string> read_wow64_pe_headers(const HANDLE process_handle,
                                                                          const std::uint32_t module_base)
    {
        Wow64RemotePeHeaders headers{};
        if (const auto read = read_remote_memory(process_handle, module_base, &headers.dos_headers,
                                                 sizeof(headers.dos_headers)); !read)
            return std::unexpected(read.error());

        if (headers.dos_headers.e_magic != IMAGE_DOS_SIGNATURE || headers.dos_headers.e_lfanew < 0)
            return std::unexpected("WOW64 module has invalid DOS headers");

        const auto nt_address = static_cast<std::uintptr_t>(module_base)
                              + static_cast<std::uint32_t>(headers.dos_headers.e_lfanew);
        if (const auto read = read_remote_memory(process_handle, nt_address, &headers.nt_headers,
                                                 sizeof(headers.nt_headers)); !read)
            return std::unexpected(read.error());

        if (headers.nt_headers.Signature != IMAGE_NT_SIGNATURE
            || headers.nt_headers.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
            return std::unexpected("WOW64 module has invalid NT headers");

        return headers;
    }

    [[nodiscard]]
    std::expected<std::uint32_t, std::string> find_wow64_module_base(const DWORD process_id,
                                                                    const std::string_view module_name)
    {
        UniqueHandle snapshot;
        while (true)
        {
            const HANDLE handle = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_id);
            if (handle != INVALID_HANDLE_VALUE)
            {
                snapshot.reset(handle);
                break;
            }
            if (GetLastError() != ERROR_BAD_LENGTH)
                return std::unexpected(std::format("Failed to enumerate WOW64 modules (error {})", GetLastError()));
        }

        MODULEENTRY32 module_entry{};
        module_entry.dwSize = sizeof(module_entry);
        if (Module32First(snapshot.get(), &module_entry))
        {
            const std::string expected_name{module_name};
            do
            {
                if (_stricmp(module_entry.szModule, expected_name.c_str()) != 0)
                    continue;

                const auto base = reinterpret_cast<std::uintptr_t>(module_entry.modBaseAddr);
                if (base > std::numeric_limits<std::uint32_t>::max())
                    continue;
                return static_cast<std::uint32_t>(base);
            }
            while (Module32Next(snapshot.get(), &module_entry));
        }

        return std::unexpected(std::format("Failed to find {} in WOW64 target", module_name));
    }

    template <typename T>
    [[nodiscard]]
    std::expected<std::span<const T>, std::string> get_export_table(const std::vector<std::uint8_t>& export_data,
                                                                   const DWORD export_rva, const DWORD table_rva,
                                                                   const std::size_t count)
    {
        if (table_rva < export_rva)
            return std::unexpected("WOW64 module has an invalid export table RVA");
        const std::size_t offset = table_rva - export_rva;
        if (offset > export_data.size() || count > (export_data.size() - offset) / sizeof(T))
            return std::unexpected("WOW64 module has an export table outside its export directory");
        return std::span<const T>{reinterpret_cast<const T*>(export_data.data() + offset), count};
    }

    [[nodiscard]]
    std::expected<std::string_view, std::string> get_export_string(const std::vector<std::uint8_t>& export_data,
                                                                  const DWORD export_rva, const DWORD string_rva)
    {
        if (string_rva < export_rva)
            return std::unexpected("WOW64 module has an invalid export string RVA");
        const std::size_t offset = string_rva - export_rva;
        if (offset >= export_data.size())
            return std::unexpected("WOW64 module has an export string outside its export directory");

        const auto* first = reinterpret_cast<const char*>(export_data.data() + offset);
        const auto* last = reinterpret_cast<const char*>(export_data.data() + export_data.size());
        const auto* end = std::find(first, last, '\0');
        if (end == last)
            return std::unexpected("WOW64 module has an unterminated export string");
        return std::string_view{first, end};
    }

    [[nodiscard]]
    std::expected<std::uint32_t, std::string> resolve_wow64_export(const HANDLE process_handle,
                                                                  const DWORD process_id,
                                                                  const std::string_view module_name,
                                                                  const std::string_view export_name,
                                                                  const std::optional<DWORD> export_ordinal = std::nullopt,
                                                                  const std::size_t recursion_depth = 0)
    {
        if (recursion_depth > 8)
            return std::unexpected("WOW64 forwarded export recursion limit exceeded");

        const auto module_base = find_wow64_module_base(process_id, module_name);
        if (!module_base)
            return std::unexpected(module_base.error());
        const auto headers = read_wow64_pe_headers(process_handle, *module_base);
        if (!headers)
            return std::unexpected(headers.error());

        const auto& export_directory_data =
                headers->nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (!export_directory_data.Size)
            return std::unexpected(std::format("{} has no WOW64 export directory", module_name));

        std::vector<std::uint8_t> export_data(export_directory_data.Size);
        if (const auto read = read_remote_memory(process_handle, *module_base + export_directory_data.VirtualAddress,
                                                 export_data.data(), export_data.size()); !read)
            return std::unexpected(read.error());
        if (export_data.size() < sizeof(IMAGE_EXPORT_DIRECTORY))
            return std::unexpected(std::format("{} has an invalid WOW64 export directory", module_name));

        const auto& export_directory = *reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(export_data.data());
        std::optional<DWORD> function_index;
        if (export_ordinal)
        {
            if (*export_ordinal < export_directory.Base
                || *export_ordinal - export_directory.Base >= export_directory.NumberOfFunctions)
                return std::unexpected(std::format("{} does not export ordinal {}", module_name, *export_ordinal));
            function_index = *export_ordinal - export_directory.Base;
        }
        else
        {
            const auto names = get_export_table<DWORD>(export_data, export_directory_data.VirtualAddress,
                                                       export_directory.AddressOfNames,
                                                       export_directory.NumberOfNames);
            if (!names)
                return std::unexpected(names.error());
            const auto ordinals = get_export_table<WORD>(export_data, export_directory_data.VirtualAddress,
                                                         export_directory.AddressOfNameOrdinals,
                                                         export_directory.NumberOfNames);
            if (!ordinals)
                return std::unexpected(ordinals.error());

            for (std::size_t i = 0; i < names->size(); i++)
            {
                const auto name = get_export_string(export_data, export_directory_data.VirtualAddress, (*names)[i]);
                if (!name)
                    return std::unexpected(name.error());
                if (*name == export_name)
                {
                    function_index = (*ordinals)[i];
                    break;
                }
            }
        }

        if (!function_index || *function_index >= export_directory.NumberOfFunctions)
            return std::unexpected(std::format("{} does not export {}", module_name, export_name));

        const auto functions = get_export_table<DWORD>(export_data, export_directory_data.VirtualAddress,
                                                       export_directory.AddressOfFunctions,
                                                       export_directory.NumberOfFunctions);
        if (!functions)
            return std::unexpected(functions.error());
        const DWORD function_rva = (*functions)[*function_index];
        if (function_rva >= export_directory_data.VirtualAddress
            && function_rva - export_directory_data.VirtualAddress < export_directory_data.Size)
        {
            const auto forwarder = get_export_string(export_data, export_directory_data.VirtualAddress, function_rva);
            if (!forwarder)
                return std::unexpected(forwarder.error());
            const auto separator = forwarder->find('.');
            if (separator == std::string_view::npos)
                return std::unexpected(std::format("Invalid WOW64 forwarded export {}", *forwarder));

            std::string forwarded_module{forwarder->substr(0, separator)};
            forwarded_module += ".dll";
            const auto forwarded_symbol = forwarder->substr(separator + 1);
            if (forwarded_symbol.starts_with('#'))
            {
                DWORD forwarded_ordinal = 0;
                const auto [ptr, error] = std::from_chars(forwarded_symbol.data() + 1,
                                                          forwarded_symbol.data() + forwarded_symbol.size(),
                                                          forwarded_ordinal);
                if (error != std::errc{} || ptr != forwarded_symbol.data() + forwarded_symbol.size())
                    return std::unexpected(std::format("Invalid WOW64 forwarded export {}", *forwarder));
                return resolve_wow64_export(process_handle, process_id, forwarded_module, {}, forwarded_ordinal,
                                            recursion_depth + 1);
            }
            return resolve_wow64_export(process_handle, process_id, forwarded_module, forwarded_symbol, std::nullopt,
                                        recursion_depth + 1);
        }

        if (function_rva > std::numeric_limits<std::uint32_t>::max() - *module_base)
            return std::unexpected(std::format("{} export {} is outside the WOW64 address range",
                                               module_name, export_name));
        return *module_base + function_rva;
    }

    [[nodiscard]]
    std::expected<std::vector<std::optional<std::uint8_t>>, std::string> parse_pattern(
            const std::string_view pattern)
    {
        std::vector<std::optional<std::uint8_t>> bytes;
        std::size_t position = 0;
        while (position < pattern.size())
        {
            while (position < pattern.size() && std::isspace(static_cast<unsigned char>(pattern[position])))
                position++;
            if (position == pattern.size())
                break;

            std::size_t end = position;
            while (end < pattern.size() && !std::isspace(static_cast<unsigned char>(pattern[end])))
                end++;
            const auto token = pattern.substr(position, end - position);
            if (token == "?" || token == "??")
                bytes.emplace_back(std::nullopt);
            else
            {
                unsigned int byte = 0;
                const auto [ptr, error] = std::from_chars(token.data(), token.data() + token.size(), byte, 16);
                if (error != std::errc{} || ptr != token.data() + token.size() || token.size() != 2 || byte > 0xFF)
                    return std::unexpected(std::format("Invalid byte pattern token {}", token));
                bytes.emplace_back(static_cast<std::uint8_t>(byte));
            }
            position = end;
        }
        return bytes;
    }

    [[nodiscard]]
    std::expected<std::uint32_t, std::string> find_wow64_internal_function(
            const HANDLE process_handle, const DWORD process_id, const std::string_view function_name,
            const std::span<const std::string_view> signatures)
    {
        const auto module_base = find_wow64_module_base(process_id, "ntdll.dll");
        if (!module_base)
            return std::unexpected(module_base.error());
        const auto headers = read_wow64_pe_headers(process_handle, *module_base);
        if (!headers)
            return std::unexpected(headers.error());

        std::vector<IMAGE_SECTION_HEADER> sections(headers->nt_headers.FileHeader.NumberOfSections);
        const auto section_headers_address = static_cast<std::uintptr_t>(*module_base)
                                           + static_cast<std::uint32_t>(headers->dos_headers.e_lfanew)
                                           + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER)
                                           + headers->nt_headers.FileHeader.SizeOfOptionalHeader;
        if (const auto read = read_remote_memory(process_handle, section_headers_address, sections.data(),
                                                 sections.size() * sizeof(IMAGE_SECTION_HEADER)); !read)
            return std::unexpected(read.error());

        constexpr std::array<std::uint8_t, 5> text_name{'.', 't', 'e', 'x', 't'};
        const auto section = std::find_if(sections.begin(), sections.end(), [&](const IMAGE_SECTION_HEADER& candidate)
        {
            return std::equal(text_name.begin(), text_name.end(), candidate.Name);
        });
        if (section == sections.end() || !section->Misc.VirtualSize)
            return std::unexpected("Failed to find .text in WOW64 ntdll.dll");

        std::vector<std::uint8_t> section_data(section->Misc.VirtualSize);
        if (const auto read = read_remote_memory(process_handle, *module_base + section->VirtualAddress,
                                                 section_data.data(), section_data.size()); !read)
            return std::unexpected(read.error());

        for (const auto signature : signatures)
        {
            const auto pattern = parse_pattern(signature);
            if (!pattern)
                return std::unexpected(pattern.error());
            if (pattern->empty() || pattern->size() > section_data.size())
                continue;

            for (std::size_t offset = 0; offset <= section_data.size() - pattern->size(); offset++)
            {
                bool matches = true;
                for (std::size_t i = 0; i < pattern->size(); i++)
                {
                    if ((*pattern)[i] && *(*pattern)[i] != section_data[offset + i])
                    {
                        matches = false;
                        break;
                    }
                }
                if (matches)
                    return *module_base + section->VirtualAddress + static_cast<std::uint32_t>(offset);
            }
        }

        return std::unexpected(std::format("Failed to find {} in WOW64 ntdll.dll", function_name));
    }

    [[nodiscard]]
    std::expected<std::uintptr_t, std::string> manual_map_injection_into_wow64_process(
            const std::span<std::uint8_t>& raw_pe, const std::uintptr_t process_id)
    {
        if (const auto architecture = validate_target_machine(process_id, IMAGE_FILE_MACHINE_I386); !architecture)
            return std::unexpected(architecture.error());

        const UniqueHandle process_handle{OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ
                                                              | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION,
                                                      FALSE, static_cast<DWORD>(process_id))};
        if (!process_handle)
            return std::unexpected(std::format("Failed to open target process (error {})", GetLastError()));

        const auto* dos_headers = reinterpret_cast<const IMAGE_DOS_HEADER*>(raw_pe.data());
        const auto* nt_headers = reinterpret_cast<const IMAGE_NT_HEADERS32*>(raw_pe.data() + dos_headers->e_lfanew);
        const std::size_t image_size = nt_headers->OptionalHeader.SizeOfImage;
        auto* remote_image = static_cast<std::uint8_t*>(
                VirtualAllocEx(process_handle.get(), nullptr, image_size, MEM_COMMIT | MEM_RESERVE,
                               PAGE_EXECUTE_READWRITE));
        if (!remote_image)
            return std::unexpected(std::format("VirtualAllocEx failed for WOW64 image (error {})", GetLastError()));

        const auto fail_image = [&](std::string error) -> std::expected<std::uintptr_t, std::string>
        {
            VirtualFreeEx(process_handle.get(), remote_image, 0, MEM_RELEASE);
            return std::unexpected(std::move(error));
        };

        const auto remote_image_address = reinterpret_cast<std::uintptr_t>(remote_image);
        if (remote_image_address > std::numeric_limits<std::uint32_t>::max())
            return fail_image("WOW64 image allocation is above the 32-bit address range");

        std::vector<std::uint8_t> local_image(image_size, 0);
        std::copy_n(raw_pe.data(), nt_headers->OptionalHeader.SizeOfHeaders, local_image.data());
        auto* section_header = IMAGE_FIRST_SECTION(nt_headers);
        for (WORD i = 0; i < nt_headers->FileHeader.NumberOfSections; i++, section_header++)
        {
            if (!section_header->SizeOfRawData)
                continue;
            std::copy_n(raw_pe.data() + section_header->PointerToRawData, section_header->SizeOfRawData,
                        local_image.data() + section_header->VirtualAddress);
        }

        if (!relocate_wow64_image_for_base(local_image.data(), static_cast<std::uint32_t>(remote_image_address)))
            return fail_image("WOW64 image requires relocation but has no relocation directory");
        if (!WriteProcessMemory(process_handle.get(), remote_image, local_image.data(), image_size, nullptr))
            return fail_image(std::format("WriteProcessMemory failed for WOW64 image (error {})", GetLastError()));

        Wow64RemoteLoaderData loader_data{};
        loader_data.image_base = static_cast<std::uint32_t>(remote_image_address);
        loader_data.nt_headers_rva = static_cast<DWORD>(dos_headers->e_lfanew);

        const auto load_library_a = resolve_wow64_export(process_handle.get(), static_cast<DWORD>(process_id),
                                                         "kernel32.dll", "LoadLibraryA");
        if (!load_library_a)
            return fail_image(load_library_a.error());
        loader_data.fn_load_library_a = *load_library_a;

        const auto get_proc_address = resolve_wow64_export(process_handle.get(), static_cast<DWORD>(process_id),
                                                           "kernel32.dll", "GetProcAddress");
        if (!get_proc_address)
            return fail_image(get_proc_address.error());
        loader_data.fn_get_proc_address = *get_proc_address;

        const auto virtual_protect = resolve_wow64_export(process_handle.get(), static_cast<DWORD>(process_id),
                                                          "kernel32.dll", "VirtualProtect");
        if (!virtual_protect)
            return fail_image(virtual_protect.error());
        loader_data.fn_virtual_protect = *virtual_protect;

        constexpr std::array<std::string_view, 3> ldrp_handle_tls_data_signatures{
                "8B FF 55 8B EC 83 EC ? 53 56 57 8B 7D ? 89 4D",
                "8B FF 55 8B EC 51 51 53 56 57 8B F1 89 75",
                "6A ? 68 ? ? ? ? E8 ? ? ? ? 8B C1 89 45 ? 89 45",
        };
        const auto tls_fn = find_wow64_internal_function(process_handle.get(), static_cast<DWORD>(process_id),
                                                         "LdrpHandleTlsData", ldrp_handle_tls_data_signatures);
        if (!tls_fn)
            return fail_image(tls_fn.error());
        loader_data.fn_ldrp_handle_tls_data = *tls_fn;

        constexpr std::array<std::string_view, 3> rtl_insert_inverted_function_table_signatures{
                "8B FF 55 8B EC 83 EC ? 53 56 57 8D 45 ? 8B FA 50 8D 55",
                "8B FF 55 8B EC 51 51 53 56 57 8B 7D ? 8D 45",
                "8B FF 55 8B EC 53 56 57 8B 7D ? 8D 45",
        };
        if (const auto inverted_fn = find_wow64_internal_function(
                    process_handle.get(), static_cast<DWORD>(process_id), "RtlInsertInvertedFunctionTable",
                    rtl_insert_inverted_function_table_signatures))
            loader_data.fn_rtl_insert_inverted_function_table = *inverted_fn;

        constexpr std::size_t data_aligned = (sizeof(Wow64RemoteLoaderData) + 0xF) & ~0xF;
        constexpr std::size_t total_shellcode = data_aligned + yail::detail::x86_remote_shellcode.size();
        auto* remote_shellcode = static_cast<std::uint8_t*>(
                VirtualAllocEx(process_handle.get(), nullptr, total_shellcode, MEM_COMMIT | MEM_RESERVE,
                               PAGE_EXECUTE_READWRITE));
        if (!remote_shellcode)
            return fail_image(std::format("VirtualAllocEx failed for WOW64 shellcode (error {})", GetLastError()));

        const auto fail_shellcode = [&](std::string error) -> std::expected<std::uintptr_t, std::string>
        {
            VirtualFreeEx(process_handle.get(), remote_shellcode, 0, MEM_RELEASE);
            return fail_image(std::move(error));
        };

        if (reinterpret_cast<std::uintptr_t>(remote_shellcode) > std::numeric_limits<std::uint32_t>::max())
            return fail_shellcode("WOW64 shellcode allocation is above the 32-bit address range");

        std::array<std::uint8_t, total_shellcode> shellcode_page{};
        std::copy_n(reinterpret_cast<const std::uint8_t*>(&loader_data), sizeof(loader_data), shellcode_page.data());
        std::copy(yail::detail::x86_remote_shellcode.begin(), yail::detail::x86_remote_shellcode.end(),
                  shellcode_page.data() + data_aligned);
        if (!WriteProcessMemory(process_handle.get(), remote_shellcode, shellcode_page.data(), shellcode_page.size(),
                                nullptr))
            return fail_shellcode(std::format("WriteProcessMemory failed for WOW64 shellcode (error {})",
                                              GetLastError()));

        const UniqueHandle thread_handle{CreateRemoteThread(
                process_handle.get(), nullptr, 0,
                reinterpret_cast<LPTHREAD_START_ROUTINE>(remote_shellcode + data_aligned),
                remote_shellcode, 0, nullptr)};
        if (!thread_handle)
            return fail_shellcode(std::format("CreateRemoteThread failed for WOW64 shellcode (error {})",
                                              GetLastError()));

        if (WaitForSingleObject(thread_handle.get(), INFINITE) == WAIT_FAILED)
            return fail_shellcode(std::format("Failed to wait for WOW64 shellcode (error {})", GetLastError()));
        DWORD exit_code = 0;
        if (!GetExitCodeThread(thread_handle.get(), &exit_code))
            return fail_shellcode(std::format("Failed to query WOW64 shellcode exit code (error {})", GetLastError()));

        VirtualFreeEx(process_handle.get(), remote_shellcode, 0, MEM_RELEASE);
        if (exit_code != 0)
            return fail_image(std::format("WOW64 remote shellcode failed (exit code {})", exit_code));
        return remote_image_address;
    }
#endif
} // namespace

namespace yail
{
    std::expected<std::uintptr_t, std::string> manual_map_injection_from_raw(const std::span<std::uint8_t>& raw_dll,
                                                                        const std::uintptr_t process_id)
    {
        const auto pe_machine = get_pe_machine(raw_dll);
        if (!pe_machine)
            return std::unexpected("File is not in a Portable Executable format");

#ifdef _WIN64
        if (*pe_machine == IMAGE_FILE_MACHINE_I386)
            return manual_map_injection_into_wow64_process(raw_dll, process_id);
        constexpr WORD expected_machine = IMAGE_FILE_MACHINE_AMD64;
#else
        constexpr WORD expected_machine = IMAGE_FILE_MACHINE_I386;
#endif

        if (*pe_machine != expected_machine)
            return std::unexpected(std::format("Unsupported PE machine 0x{:04x} for this injector", *pe_machine));

        if (const auto architecture = validate_target_machine(process_id, expected_machine); !architecture)
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
        const std::size_t image_size = nt->OptionalHeader.SizeOfImage;

        // Allocate image memory in target process
        auto* remote_image = static_cast<std::uint8_t*>(
                VirtualAllocEx(process_handle, nullptr, image_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

        if (!remote_image)
        {
            CloseHandle(process_handle);
            return std::unexpected(std::format("VirtualAllocEx failed for image (error {})", GetLastError()));
        }

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
        if (!relocate_for_base(local_image.data(), reinterpret_cast<std::uintptr_t>(remote_image)))
        {
            VirtualFreeEx(process_handle, remote_image, 0, MEM_RELEASE);
            CloseHandle(process_handle);
            return std::unexpected("Image requires relocation but has no relocation directory");
        }

        // Write image to target
        if (!WriteProcessMemory(process_handle, remote_image, local_image.data(), image_size, nullptr))
        {
            VirtualFreeEx(process_handle, remote_image, 0, MEM_RELEASE);
            CloseHandle(process_handle);
            return std::unexpected("WriteProcessMemory failed for image");
        }

        // Prepare shellcode page: [RemoteLoaderData | padding | shellcode bytes]
#ifdef _WIN64
        constexpr const auto& native_remote_shellcode = yail::detail::x64_remote_shellcode;
#else
        constexpr const auto& native_remote_shellcode = yail::detail::x86_remote_shellcode;
#endif
        constexpr std::size_t data_aligned = (sizeof(RemoteLoaderData) + 0xF) & ~0xF;
        constexpr std::size_t total_shellcode = data_aligned + native_remote_shellcode.size();

        auto* remote_shellcode = static_cast<std::uint8_t*>(
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
#ifdef _WIN64
        loader_data.fn_rtl_add_function_table = RtlAddFunctionTable;
#endif
        loader_data.fn_virtual_protect = VirtualProtect;
        const auto tls_fn = find_ldrp_handle_tls_data();
        if (!tls_fn)
        {
            VirtualFreeEx(process_handle, remote_image, 0, MEM_RELEASE);
            CloseHandle(process_handle);
            return std::unexpected(tls_fn.error());
        }
        loader_data.fn_ldrp_handle_tls_data = reinterpret_cast<void*>(tls_fn.value());
        // RtlInsertInvertedFunctionTable is required on x64 (unwind tables) but optional on
        // x86 — without it, manually-mapped DLLs that throw will crash on dispatch, but DLLs
        // that don't throw load fine. Treat lookup failure as fatal only on x64.
        if (const auto inv_fn = find_rtl_insert_inverted_function_table())
            loader_data.fn_rtl_insert_inverted_function_table = reinterpret_cast<void*>(inv_fn.value());
#ifdef _WIN64
        else
        {
            VirtualFreeEx(process_handle, remote_image, 0, MEM_RELEASE);
            CloseHandle(process_handle);
            return std::unexpected(inv_fn.error());
        }
#endif

        // Build local shellcode page
        std::vector<std::uint8_t> shell_code_page(total_shellcode, 0);
        std::copy_n(reinterpret_cast<const std::uint8_t*>(&loader_data), sizeof(loader_data), shell_code_page.data());
        std::copy(native_remote_shellcode.begin(), native_remote_shellcode.end(), shell_code_page.data() + data_aligned);

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
            return std::unexpected(std::format("CreateRemoteThread failed (error {})", GetLastError()));
        }

        WaitForSingleObject(thread_handle, INFINITE);

        DWORD exit_code = 0;
        GetExitCodeThread(thread_handle, &exit_code);
        CloseHandle(thread_handle);

        // Free shellcode page — no longer needed after init
        VirtualFreeEx(process_handle, remote_shellcode, 0, MEM_RELEASE);
        CloseHandle(process_handle);

        if (exit_code != 0)
            return std::unexpected(std::format("Remote shellcode failed (exit code {})", exit_code));

        return reinterpret_cast<std::uintptr_t>(remote_image);
    }
    std::expected<std::uintptr_t, std::string> manual_map_injection_from_raw(const std::span<std::uint8_t>& raw_dll,
                                                                        const std::string_view& process_name)
    {
        const auto pid = get_process_id_by_name(process_name);

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

        return manual_map_injection_from_raw({data.data(), data.size()}, process_id);
    }
    std::expected<std::uintptr_t, std::string> manual_map_injection_from_file(const std::string_view& dll_path,
                                                                         const std::string_view& process_name)
    {
        std::vector<std::uint8_t> data(static_cast<std::size_t>(std::filesystem::file_size(dll_path)), 0);
        std::ifstream file(std::filesystem::path{dll_path}, std::ios::binary);
        if (!file.is_open())
            return std::unexpected("Failed to open DLL file");

        file.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));

        return manual_map_injection_from_raw({data.data(), data.size()}, process_name);
    }
} // namespace yail
