//
// C bindings for the yail public API.
//
#include <cstdint>
#include <expected>
#include <span>
#include <string_view>
#include <yail/yail.h>
#include <yail/yail.hpp>

namespace
{
    // The mirrored portion of yail_error is offset by the success code and must
    // stay in lockstep with yail::Error. Checking first and last is sufficient
    // because both enums are sequential.
    static_assert(static_cast<int>(yail::Error::process_not_found) + 1 == YAIL_ERROR_PROCESS_NOT_FOUND);
    static_assert(static_cast<int>(yail::Error::pdb_symbol_address_out_of_range) + 1
                  == YAIL_ERROR_PDB_SYMBOL_ADDRESS_OUT_OF_RANGE);

    yail_error store_result(const std::expected<std::uintptr_t, yail::Error>& result,
                            std::uintptr_t* const out_base_address) noexcept
    {
        if (!result)
            return static_cast<yail_error>(static_cast<int>(result.error()) + 1);

        if (out_base_address != nullptr)
            *out_base_address = result.value();

        return YAIL_ERROR_SUCCESS;
    }
} // namespace

extern "C"
{
    const char* yail_error_to_string(const yail_error error)
    {
        if (error == YAIL_ERROR_SUCCESS)
            return "success";
        if (error == YAIL_ERROR_INVALID_ARGUMENT)
            return "invalid argument";

        return yail::to_string(static_cast<yail::Error>(static_cast<int>(error) - 1)).data();
    }

    yail_error yail_manual_map_injection_from_file(const char* pe_path, const std::uintptr_t process_id,
                                                   const std::uint32_t options, std::uintptr_t* const out_base_address)
    {
        if (pe_path == nullptr)
            return YAIL_ERROR_INVALID_ARGUMENT;

        return store_result(yail::manual_map_injection_from_file(pe_path, process_id, options), out_base_address);
    }

    yail_error yail_manual_map_injection_from_file_by_name(const char* pe_path, const char* process_name,
                                                           const std::uint32_t options,
                                                           std::uintptr_t* const out_base_address)
    {
        if (pe_path == nullptr || process_name == nullptr)
            return YAIL_ERROR_INVALID_ARGUMENT;

        return store_result(yail::manual_map_injection_from_file(pe_path, std::string_view(process_name), options),
                            out_base_address);
    }

    yail_error yail_manual_map_injection_from_raw(const std::uint8_t* raw_pe, const std::size_t raw_pe_size,
                                                  const std::uintptr_t process_id, const std::uint32_t options,
                                                  std::uintptr_t* const out_base_address)
    {
        if (raw_pe == nullptr && raw_pe_size != 0)
            return YAIL_ERROR_INVALID_ARGUMENT;

        return store_result(
                yail::manual_map_injection_from_raw(std::span<const std::uint8_t>(raw_pe, raw_pe_size), process_id,
                                                    options),
                out_base_address);
    }

    yail_error yail_manual_map_injection_from_raw_by_name(const std::uint8_t* raw_pe, const std::size_t raw_pe_size,
                                                          const char* process_name, const std::uint32_t options,
                                                          std::uintptr_t* const out_base_address)
    {
        if ((raw_pe == nullptr && raw_pe_size != 0) || process_name == nullptr)
            return YAIL_ERROR_INVALID_ARGUMENT;

        return store_result(yail::manual_map_injection_from_raw(std::span<const std::uint8_t>(raw_pe, raw_pe_size),
                                                                std::string_view(process_name), options),
                            out_base_address);
    }
} // extern "C"
