#include <Windows.h>
#include <Zydis/Zydis.h>
#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>
#include <winternl.h>

#ifndef YAIL_SOURCE_DIR
#define YAIL_SOURCE_DIR "."
#endif

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

struct FunctionSizeResult
{
    std::size_t size = 0;
    std::size_t instruction_count = 0;
    bool success = false;
};

static bool is_function_terminator(ZydisMnemonic mnemonic)
{
    switch (mnemonic)
    {
    case ZYDIS_MNEMONIC_RET:
    case ZYDIS_MNEMONIC_IRET:
    case ZYDIS_MNEMONIC_IRETD:
    case ZYDIS_MNEMONIC_IRETQ:
        return true;

    default:
        return false;
    }
}

FunctionSizeResult get_function_size_zydis(const void* function, std::size_t max_scan = 0x1000)
{
    FunctionSizeResult result{};

    if (!function || max_scan == 0)
        return result;

    ZydisDecoder decoder{};

#if defined(_M_X64) || defined(__x86_64__)
    if (!ZYAN_SUCCESS(ZydisDecoderInit(
        &decoder,
        ZYDIS_MACHINE_MODE_LONG_64,
        ZYDIS_STACK_WIDTH_64)))
    {
        return result;
    }
#else
    if (!ZYAN_SUCCESS(ZydisDecoderInit(
        &decoder,
        ZYDIS_MACHINE_MODE_LEGACY_32,
        ZYDIS_STACK_WIDTH_32)))
    {
        return result;
    }
#endif

    const auto* code = static_cast<const std::uint8_t*>(function);

    while (result.size < max_scan)
    {
        ZydisDecodedInstruction instr{};

        const ZyanStatus status = ZydisDecoderDecodeInstruction(
            &decoder,
            nullptr,
            code + result.size,
            max_scan - result.size,
            &instr
        );

        if (!ZYAN_SUCCESS(status))
            return result;

        result.size += instr.length;
        result.instruction_count++;

        if (is_function_terminator(instr.mnemonic))
        {
            result.success = true;
            return result;
        }
    }

    return result;
}

bool validate_instructions_zydis(const std::span<const std::uint8_t> code)
{
    if (code.empty())
        return false;

    ZydisDecoder decoder{};

#if defined(_M_X64) || defined(__x86_64__)
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64)))
    {
        return false;
    }
#elif defined(_M_IX86) || defined(__i386__)
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32)))
    {
        return false;
    }
#else
#error generate_shellcode only supports x86 and x64
#endif

    std::size_t offset = 0;
    while (offset < code.size())
    {
        ZydisDecodedInstruction instr{};

        const ZyanStatus status =
                ZydisDecoderDecodeInstruction(&decoder, nullptr, code.data() + offset, code.size() - offset, &instr);

        if (!ZYAN_SUCCESS(status))
            return false;

        offset += instr.length;
    }

    return true;
}

std::string read_text_file(const std::filesystem::path& path)
{
    std::ifstream file(path, std::ios::binary);
    if (!file)
        return {};

    return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
}

bool write_text_file(const std::filesystem::path& path, const std::string_view text)
{
    std::error_code error;
    if (path.has_parent_path())
        std::filesystem::create_directories(path.parent_path(), error);
    if (error)
    {
        std::fprintf(stderr, "failed to create output directory: %s\n", error.message().c_str());
        return false;
    }

    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    if (!file)
        return false;

    file.write(text.data(), static_cast<std::streamsize>(text.size()));
    return file.good();
}

std::vector<std::uint8_t> parse_array_bytes(const std::string_view source, const std::string_view name)
{
    const auto name_pos = source.find(name);
    if (name_pos == std::string_view::npos)
        return {};

    const auto array_begin = source.find('{', name_pos);
    if (array_begin == std::string_view::npos)
        return {};

    const auto array_end = source.find("};", array_begin);
    if (array_end == std::string_view::npos)
        return {};

    const auto body = source.substr(array_begin + 1, array_end - array_begin - 1);
    std::vector<std::uint8_t> bytes;
    std::size_t offset = 0;
    while ((offset = body.find("0x", offset)) != std::string_view::npos)
    {
        unsigned value = 0;
        const auto* first = body.data() + offset + 2;
        const auto* last = body.data() + body.size();
        const auto [ptr, error] = std::from_chars(first, last, value, 16);
        if (error == std::errc{} && ptr != first && value <= 0xFF)
            bytes.push_back(static_cast<std::uint8_t>(value));
        offset += 2;
    }

    return bytes;
}

std::vector<std::uint8_t> parse_shellcode_array(const std::string_view source, const std::string_view generated_name,
                                              const std::string_view legacy_name)
{
    auto bytes = parse_array_bytes(source, generated_name);
    if (!bytes.empty())
        return bytes;
    return parse_array_bytes(source, legacy_name);
}

std::string format_byte(const std::uint8_t byte)
{
    char buffer[5]{};
    std::snprintf(buffer, sizeof(buffer), "0x%02X", byte);
    return buffer;
}

std::string format_array(const std::string_view name, const std::span<const std::uint8_t> shellcode)
{
    std::string output;
    output += "        constexpr std::array<std::uint8_t, ";
    output += std::to_string(shellcode.size());
    output += "> ";
    output += name;
    if (shellcode.empty())
    {
        output += "{};\n";
        return output;
    }

    output += "{\n";
    for (std::size_t index = 0; index < shellcode.size(); index += 16)
    {
        output += "                ";
        const auto end = (index + 16 < shellcode.size()) ? index + 16 : shellcode.size();
        for (std::size_t byte_index = index; byte_index < end; ++byte_index)
        {
            if (byte_index != index)
                output += ", ";
            output += format_byte(shellcode[byte_index]);
        }
        if (end != shellcode.size())
            output += ',';
        output += '\n';
    }
    output += "        };\n";
    return output;
}

std::string format_shellcode_source(const std::span<const std::uint8_t> x64_shellcode,
                                  const std::span<const std::uint8_t> x86_shellcode)
{
    std::string output;
    output += "// Generated by tools/generate_shellcode.cpp. Do not edit manually.\n";
    output += "#include <yail/detail/shellcode.hpp>\n\n";
    output += "#include <array>\n\n";
    output += "namespace yail::detail\n";
    output += "{\n";
    output += "    namespace\n";
    output += "    {\n";
    output += format_array("x64_remote_shellcode_bytes", x64_shellcode);
    output += '\n';
    output += format_array("x86_remote_shellcode_bytes", x86_shellcode);
    output += "    }\n\n";
    output += "    std::span<const std::uint8_t> x64_remote_shellcode()\n";
    output += "    {\n";
    output += "        return x64_remote_shellcode_bytes;\n";
    output += "    }\n\n";
    output += "    std::span<const std::uint8_t> x86_remote_shellcode()\n";
    output += "    {\n";
    output += "        return x86_remote_shellcode_bytes;\n";
    output += "    }\n";
    output += "}\n";
    return output;
}

#ifdef _MSC_VER
#pragma runtime_checks("", off)
#pragma optimize("s", on)
#pragma strict_gs_check(push, off)
#endif
DWORD WINAPI remote_shellcode(const RemoteLoaderData* data)

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
        while (desc->Name)
        {
            const HMODULE module_handle = data->fn_load_library_a(reinterpret_cast<LPCSTR>(base + desc->Name));
            if (!module_handle)
                return 1;

            const DWORD lookup_table_rva =
                    desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
            const auto* original_trunk = reinterpret_cast<IMAGE_THUNK_DATA*>(base + lookup_table_rva);
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

    // Delay imports are resolved by the image's delay-load helper on first use.
    // Resolving them before entry breaks protectors that relocate their original
    // image during startup, because they relocate the already-resolved addresses.

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
            data->fn_rtl_add_function_table(reinterpret_cast<IMAGE_RUNTIME_FUNCTION_ENTRY*>(base + VirtualAddress),
                                            Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY),
                                            reinterpret_cast<std::uintptr_t>(base));
        }
    }
#else
    // Register the private x86 image while its headers expose the mapper's temporary
    // SafeSEH metadata. Modern x86 ntdll passes args in ECX/EDX (__fastcall).
    const DWORD registered_image_size = nt_headers->OptionalHeader.SizeOfImage;
    if (data->fn_rtl_insert_inverted_function_table)
    {
        reinterpret_cast<void(__fastcall*)(PVOID, ULONG)>(data->fn_rtl_insert_inverted_function_table)(
                base, nt_headers->OptionalHeader.SizeOfImage);
    }

    // The inverted function table retained the SafeSEH values. Hide the synthetic
    // metadata from TLS callbacks, protectors, and DllMain.
    nt_headers->OptionalHeader.SizeOfImage = data->original_size_of_image;
    nt_headers->OptionalHeader.NumberOfRvaAndSizes = data->original_number_of_rva_and_sizes;
    nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG] = data->original_load_config;

    if (registered_image_size > data->original_size_of_image)
    {
        DWORD old_protect;
        data->fn_virtual_protect(base + data->original_size_of_image,
                                 registered_image_size - data->original_size_of_image, PAGE_READONLY, &old_protect);
    }
#endif

    // --- Handle static TLS ---
    // ReSharper disable once CppUseStructuredBinding
    const auto& tls_directory = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (tls_directory.Size && data->fn_ldrp_handle_tls_data)
    {
        // Build fake LDR_DATA_TABLE_ENTRY on the stack - zero without memset.
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

    // --- Apply per-section memory protections ---
    {
        auto* section =
                reinterpret_cast<IMAGE_SECTION_HEADER*>(reinterpret_cast<std::uint8_t*>(&nt_headers->OptionalHeader)
                                                        + nt_headers->FileHeader.SizeOfOptionalHeader);

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

    // --- TLS callbacks ---
    if (tls_directory.Size)
    {
        const auto* tls = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(base + tls_directory.VirtualAddress);
        // ReSharper disable once CppTooWideScopeInitStatement
        const auto* call_backs_addr = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(tls->AddressOfCallBacks);
        for (; call_backs_addr && *call_backs_addr; call_backs_addr++)
            (*call_backs_addr)(base, DLL_PROCESS_ATTACH, nullptr);
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
            // EXE entry (mainCRTStartup / WinMainCRTStartup) - __cdecl, no args.
            // When the entry returns the CRT calls exit() -> ExitProcess, terminating
            // the host process. GetModuleHandle(NULL) still resolves to the host EXE.
            const auto entry_point =
                    reinterpret_cast<int(__cdecl*)()>(base + nt_headers->OptionalHeader.AddressOfEntryPoint);
            entry_point();
        }
    }

    return 0;
}
#ifdef _MSC_VER
#pragma strict_gs_check(pop)
#pragma runtime_checks("", restore)
#pragma optimize("", on)
#endif
std::vector<std::uint8_t> extract_remote_shellcode()
{
    const auto shellcode_info = get_function_size_zydis(&remote_shellcode, 0x1000);
    auto begin = reinterpret_cast<const std::uint8_t*>(&remote_shellcode);
    auto end = begin + shellcode_info.size;
    return {begin, end};
}

int main(const int argc, char* argv[])
{
    if (argc > 2)
    {
        std::fprintf(stderr, "usage: generate_shellcode [output-cpp]\n");
        return 2;
    }

    const auto output_path = argc == 2 ? std::filesystem::path(argv[1])
                                       : std::filesystem::path(YAIL_SOURCE_DIR) / "source" / "shellcode.cpp";

    const auto current_shellcode = extract_remote_shellcode();
    if (current_shellcode.empty())
    {
        std::fprintf(stderr, "failed to find remote_shellcode end marker\n");
        return 1;
    }
    if (!validate_instructions_zydis(current_shellcode))
    {
        std::fprintf(stderr, "failed to validate remote_shellcode instructions\n");
        return 1;
    }

    const auto existing_source = read_text_file(output_path);
    auto x64_shellcode =
            parse_shellcode_array(existing_source, "x64_remote_shellcode_bytes", "x64_remote_shellcode");
    auto x86_shellcode =
            parse_shellcode_array(existing_source, "x86_remote_shellcode_bytes", "x86_remote_shellcode");

#if defined(_M_X64) || defined(__x86_64__)
    constexpr const char* current_arch = "x64";
    x64_shellcode = current_shellcode;
#elif defined(_M_IX86) || defined(__i386__)
    constexpr const char* current_arch = "x86";
    x86_shellcode = current_shellcode;
#else
#error generate_shellcode only supports x86 and x64
#endif

    if (x64_shellcode.empty() || x86_shellcode.empty())
    {
        std::fprintf(stderr,
                     "warning: one architecture is empty; run the generator for both x64 and x86 before shipping\n");
    }

    const auto generated_source = format_shellcode_source(x64_shellcode, x86_shellcode);
    if (!write_text_file(output_path, generated_source))
    {
        std::fprintf(stderr, "failed to write %s\n", output_path.string().c_str());
        return 1;
    }

    std::printf("wrote %s (%s: %zu bytes, x64: %zu bytes, x86: %zu bytes)\n", output_path.string().c_str(),
                current_arch, current_shellcode.size(), x64_shellcode.size(), x86_shellcode.size());
    return 0;
}
