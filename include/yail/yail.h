//
// C bindings for the yail public API.
//
#ifndef YAIL_YAIL_H
#define YAIL_YAIL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

    // Status code returned by every yail_* function. YAIL_ERROR_SUCCESS (0) means
    // the call succeeded and the base address was written to the out-parameter.
    // YAIL_ERROR_PROCESS_NOT_FOUND .. YAIL_ERROR_PDB_SYMBOL_ADDRESS_OUT_OF_RANGE
    // mirror yail::Error one-to-one.
    typedef enum yail_error
    {
        YAIL_ERROR_SUCCESS = 0,
        YAIL_ERROR_PROCESS_NOT_FOUND,
        YAIL_ERROR_PROCESS_ID_OUT_OF_RANGE,
        YAIL_ERROR_PROCESS_OPEN_FAILED,
        YAIL_ERROR_ARCHITECTURE_QUERY_FAILED,
        YAIL_ERROR_ARCHITECTURE_MISMATCH,
        YAIL_ERROR_FILE_NOT_FOUND,
        YAIL_ERROR_FILE_OPEN_FAILED,
        YAIL_ERROR_INVALID_PE,
        YAIL_ERROR_UNSUPPORTED_PE_MACHINE,
        YAIL_ERROR_TRUNCATED_PE_HEADERS,
        YAIL_ERROR_TRUNCATED_PE_SECTION_TABLE,
        YAIL_ERROR_INVALID_PE_LAYOUT,
        YAIL_ERROR_NO_EXECUTABLE_SECTIONS,
        YAIL_ERROR_SAFE_SEH_TABLE_TOO_LARGE,
        YAIL_ERROR_IMAGE_TOO_LARGE,
        YAIL_ERROR_IMAGE_ALLOCATION_FAILED,
        YAIL_ERROR_IMAGE_ADDRESS_OUT_OF_RANGE,
        YAIL_ERROR_RELOCATION_MISSING,
        YAIL_ERROR_IMAGE_WRITE_FAILED,
        YAIL_ERROR_SHELLCODE_ALLOCATION_FAILED,
        YAIL_ERROR_SHELLCODE_ADDRESS_OUT_OF_RANGE,
        YAIL_ERROR_SHELLCODE_WRITE_FAILED,
        YAIL_ERROR_REMOTE_THREAD_CREATION_FAILED,
        YAIL_ERROR_REMOTE_THREAD_WAIT_FAILED,
        YAIL_ERROR_REMOTE_THREAD_QUERY_FAILED,
        YAIL_ERROR_REMOTE_SHELLCODE_FAILED,
        YAIL_ERROR_REMOTE_MEMORY_READ_FAILED,
        YAIL_ERROR_MODULE_ENUMERATION_FAILED,
        YAIL_ERROR_MODULE_NOT_FOUND,
        YAIL_ERROR_INVALID_REMOTE_MODULE,
        YAIL_ERROR_EXPORT_DIRECTORY_MISSING,
        YAIL_ERROR_INVALID_EXPORT_TABLE,
        YAIL_ERROR_INVALID_EXPORT_STRING,
        YAIL_ERROR_EXPORT_NOT_FOUND,
        YAIL_ERROR_INVALID_FORWARDED_EXPORT,
        YAIL_ERROR_FORWARDED_EXPORT_RECURSION_LIMIT,
        YAIL_ERROR_EXPORT_ADDRESS_OUT_OF_RANGE,
        YAIL_ERROR_NTDLL_NOT_FOUND,
        YAIL_ERROR_NTDLL_DEBUG_DIRECTORY_MISSING,
        YAIL_ERROR_NTDLL_CODEVIEW_RECORD_MISSING,
        YAIL_ERROR_INVALID_PDB_IDENTITY,
        YAIL_ERROR_PDB_DOWNLOAD_FAILED,
        YAIL_ERROR_INVALID_PDB,
        YAIL_ERROR_PDB_STREAM_MISSING,
        YAIL_ERROR_INVALID_PDB_SYMBOL_STREAM,
        YAIL_ERROR_PDB_SYMBOLS_NOT_FOUND,
        YAIL_ERROR_PDB_SYMBOL_ADDRESS_OUT_OF_RANGE,
        // C-only status for a null or otherwise unusable argument.
        YAIL_ERROR_INVALID_ARGUMENT
    } yail_error;

    // Returns a static, null-terminated description of a status code. The returned
    // pointer must not be freed.
    const char* yail_error_to_string(yail_error error);

    // Manual post-load hardening flags, combined with `|`. Pass 0 for no hardening.
    enum yail_manual_map_option
    {
        YAIL_MANUAL_MAP_ERASE_HEADERS = 1u << 0,
        YAIL_MANUAL_MAP_WIPE_IMPORTS = 1u << 1
    };

    // Manual-maps a PE from disk. Accepts both DLLs and EXEs. The target is
    // selected by process ID; options is a yail_manual_map_option bitmask.
    // On success the mapped image base is written to out_base_address, when non-null.
    yail_error yail_manual_map_injection_from_file(const char* pe_path, uintptr_t process_id, uint32_t options,
                                                    uintptr_t* out_base_address);

    // Manual-maps a PE from disk into the first process matching process_name.
    yail_error yail_manual_map_injection_from_file_by_name(const char* pe_path, const char* process_name,
                                                           uint32_t options, uintptr_t* out_base_address);

    // Manual-maps a PE from raw bytes. raw_pe must point to at least raw_pe_size readable bytes.
    yail_error yail_manual_map_injection_from_raw(const uint8_t* raw_pe, size_t raw_pe_size, uintptr_t process_id,
                                                  uint32_t options, uintptr_t* out_base_address);

    // Manual-maps a PE from raw bytes into the first process matching process_name.
    yail_error yail_manual_map_injection_from_raw_by_name(const uint8_t* raw_pe, size_t raw_pe_size,
                                                          const char* process_name, uint32_t options,
                                                          uintptr_t* out_base_address);

#ifdef __cplusplus
}
#endif

#endif
