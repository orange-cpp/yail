#pragma once
#include <cstdint>
#include <string_view>

namespace yail
{
    enum class Error : std::uint8_t
    {
        process_not_found,
        process_id_out_of_range,
        process_open_failed,
        architecture_query_failed,
        architecture_mismatch,
        file_not_found,
        file_open_failed,
        invalid_pe,
        unsupported_pe_machine,
        truncated_pe_headers,
        truncated_pe_section_table,
        invalid_pe_layout,
        no_executable_sections,
        safe_seh_table_too_large,
        image_too_large,
        image_allocation_failed,
        image_address_out_of_range,
        relocation_missing,
        image_write_failed,
        shellcode_allocation_failed,
        shellcode_address_out_of_range,
        shellcode_write_failed,
        remote_thread_creation_failed,
        remote_thread_wait_failed,
        remote_thread_query_failed,
        remote_shellcode_failed,
        remote_memory_read_failed,
        module_enumeration_failed,
        module_not_found,
        invalid_remote_module,
        export_directory_missing,
        invalid_export_table,
        invalid_export_string,
        export_not_found,
        invalid_forwarded_export,
        forwarded_export_recursion_limit,
        export_address_out_of_range,
        text_section_not_found,
        ldrp_handle_tls_data_not_found,
        rtl_insert_inverted_function_table_not_found,
        ntdll_not_found,
        ntdll_debug_directory_missing,
        ntdll_codeview_record_missing,
        invalid_pdb_identity,
        pdb_download_failed,
        invalid_pdb,
        pdb_stream_missing,
        invalid_pdb_symbol_stream,
        pdb_symbols_not_found,
        pdb_symbol_address_out_of_range,
    };

    [[nodiscard]] constexpr std::string_view to_string(const Error error) noexcept
    {
        switch (error)
        {
        case Error::process_not_found: return "process not found";
        case Error::process_id_out_of_range: return "process id is out of range";
        case Error::process_open_failed: return "failed to open target process";
        case Error::architecture_query_failed: return "failed to query target architecture";
        case Error::architecture_mismatch: return "target architecture does not match the PE image";
        case Error::file_not_found: return "file not found";
        case Error::file_open_failed: return "failed to open file";
        case Error::invalid_pe: return "invalid Portable Executable image";
        case Error::unsupported_pe_machine: return "unsupported PE machine for this injector";
        case Error::truncated_pe_headers: return "PE headers are truncated";
        case Error::truncated_pe_section_table: return "PE section table is truncated";
        case Error::invalid_pe_layout: return "PE image layout is invalid";
        case Error::no_executable_sections: return "PE image has no executable section bytes";
        case Error::safe_seh_table_too_large: return "SafeSEH handler table is too large";
        case Error::image_too_large: return "PE image is too large";
        case Error::image_allocation_failed: return "failed to allocate the remote image";
        case Error::image_address_out_of_range: return "remote image address is out of range";
        case Error::relocation_missing: return "image requires relocation but has no relocation directory";
        case Error::image_write_failed: return "failed to write the remote image";
        case Error::shellcode_allocation_failed: return "failed to allocate remote shellcode";
        case Error::shellcode_address_out_of_range: return "remote shellcode address is out of range";
        case Error::shellcode_write_failed: return "failed to write remote shellcode";
        case Error::remote_thread_creation_failed: return "failed to create the remote thread";
        case Error::remote_thread_wait_failed: return "failed to wait for the remote thread";
        case Error::remote_thread_query_failed: return "failed to query the remote thread";
        case Error::remote_shellcode_failed: return "remote shellcode reported failure";
        case Error::remote_memory_read_failed: return "failed to read remote process memory";
        case Error::module_enumeration_failed: return "failed to enumerate remote modules";
        case Error::module_not_found: return "required remote module was not found";
        case Error::invalid_remote_module: return "remote module has invalid PE headers";
        case Error::export_directory_missing: return "remote module has no export directory";
        case Error::invalid_export_table: return "remote module has an invalid export table";
        case Error::invalid_export_string: return "remote module has an invalid export string";
        case Error::export_not_found: return "required remote export was not found";
        case Error::invalid_forwarded_export: return "remote module has an invalid forwarded export";
        case Error::forwarded_export_recursion_limit: return "forwarded export recursion limit was exceeded";
        case Error::export_address_out_of_range: return "remote export address is out of range";
        case Error::text_section_not_found: return "ntdll .text section was not found";
        case Error::ldrp_handle_tls_data_not_found: return "LdrpHandleTlsData was not found";
        case Error::rtl_insert_inverted_function_table_not_found:
            return "RtlInsertInvertedFunctionTable was not found";
        case Error::ntdll_not_found: return "loaded ntdll.dll was not found";
        case Error::ntdll_debug_directory_missing: return "ntdll.dll has no valid debug directory";
        case Error::ntdll_codeview_record_missing: return "ntdll.dll has no valid CodeView debug record";
        case Error::invalid_pdb_identity: return "ntdll.dll has an invalid PDB identity";
        case Error::pdb_download_failed: return "failed to download the matching ntdll PDB";
        case Error::invalid_pdb: return "downloaded PDB is invalid or truncated";
        case Error::pdb_stream_missing: return "required PDB stream is missing";
        case Error::invalid_pdb_symbol_stream: return "PDB symbol stream is invalid or truncated";
        case Error::pdb_symbols_not_found: return "required ntdll symbols were not found in the PDB";
        case Error::pdb_symbol_address_out_of_range: return "PDB symbol address is out of range";
        }
        return "unknown YAIL error";
    }
}
