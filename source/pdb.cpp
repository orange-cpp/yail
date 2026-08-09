#include <yail/detail/pdb.hpp>

#ifdef YAIL_USE_PDB
#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstring>
#include <format>
#include <limits>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include <windows.h>
#include <winhttp.h>

namespace yail::detail
{
    namespace
    {
        constexpr std::string_view msf_magic{"Microsoft C/C++ MSF 7.00\r\n\x1a" "DS\0\0\0", 32};
        constexpr std::uint32_t missing_stream = std::numeric_limits<std::uint32_t>::max();
        constexpr std::uint16_t missing_stream_index = std::numeric_limits<std::uint16_t>::max();
        constexpr std::uint16_t s_pub32 = 0x110E;

        class InternetHandle final
        {
        public:
            explicit InternetHandle(const HINTERNET handle) : handle_{handle}
            {
            }

            ~InternetHandle()
            {
                if (handle_)
                    WinHttpCloseHandle(handle_);
            }

            [[nodiscard]] HINTERNET get() const
            {
                return handle_;
            }

        private:
            HINTERNET handle_;
        };

        template<typename T>
        [[nodiscard]] std::optional<T> read_value(const std::span<const std::uint8_t> data, const std::size_t offset)
        {
            if (offset > data.size() || data.size() - offset < sizeof(T))
                return std::nullopt;

            T value{};
            std::memcpy(&value, data.data() + offset, sizeof(value));
            return value;
        }

        struct MsfStream final
        {
            std::uint32_t size;
            std::vector<std::uint32_t> blocks;
        };

        class MsfFile final
        {
        public:
            [[nodiscard]] static std::expected<MsfFile, Error> parse(const std::span<const std::uint8_t> data)
            {
                if (data.size() < 56 || std::string_view{reinterpret_cast<const char*>(data.data()), msf_magic.size()}
                                                 != msf_magic)
                    return std::unexpected(Error::invalid_pdb);

                const auto block_size = read_value<std::uint32_t>(data, 32);
                const auto block_count = read_value<std::uint32_t>(data, 40);
                const auto directory_size = read_value<std::uint32_t>(data, 44);
                const auto block_map_block = read_value<std::uint32_t>(data, 52);
                if (!block_size || !block_count || !directory_size || !block_map_block || *block_size < 512
                    || *block_size > (1U << 20) || *block_count == 0)
                    return std::unexpected(Error::invalid_pdb);

                const auto file_size = static_cast<std::uint64_t>(*block_size) * *block_count;
                if (file_size > data.size())
                    return std::unexpected(Error::invalid_pdb);

                const std::size_t directory_block_count =
                        (*directory_size + static_cast<std::size_t>(*block_size) - 1) / *block_size;
                if (directory_block_count > std::numeric_limits<std::size_t>::max() / sizeof(std::uint32_t))
                    return std::unexpected(Error::invalid_pdb);

                const std::size_t block_map_offset = static_cast<std::size_t>(*block_map_block) * *block_size;
                const std::size_t block_map_size = directory_block_count * sizeof(std::uint32_t);
                if (block_map_offset > data.size() || block_map_size > data.size() - block_map_offset)
                    return std::unexpected(Error::invalid_pdb);

                std::vector<std::uint8_t> directory;
                directory.reserve(*directory_size);
                for (std::size_t i = 0; i < directory_block_count; i++)
                {
                    const auto directory_block = read_value<std::uint32_t>(data, block_map_offset + i * 4);
                    if (!directory_block || *directory_block >= *block_count)
                        return std::unexpected(Error::invalid_pdb);

                    const std::size_t source_offset = static_cast<std::size_t>(*directory_block) * *block_size;
                    const std::size_t remaining = *directory_size - directory.size();
                    const std::size_t bytes_to_copy = std::min<std::size_t>(*block_size, remaining);
                    directory.insert(directory.end(), data.begin() + source_offset,
                                     data.begin() + source_offset + bytes_to_copy);
                }

                const auto directory_data = std::span<const std::uint8_t>{directory};
                const auto stream_count = read_value<std::uint32_t>(directory_data, 0);
                if (!stream_count || *stream_count > (directory.size() - sizeof(std::uint32_t)) / sizeof(std::uint32_t))
                    return std::unexpected(Error::invalid_pdb);

                std::size_t cursor = sizeof(std::uint32_t);
                std::vector<MsfStream> streams;
                streams.reserve(*stream_count);
                for (std::uint32_t i = 0; i < *stream_count; i++, cursor += sizeof(std::uint32_t))
                {
                    const auto stream_size = read_value<std::uint32_t>(directory_data, cursor);
                    if (!stream_size)
                        return std::unexpected(Error::invalid_pdb);
                    streams.push_back({*stream_size, {}});
                }

                for (auto& stream : streams)
                {
                    if (stream.size == missing_stream)
                        continue;
                    const std::size_t stream_block_count =
                            (stream.size + static_cast<std::size_t>(*block_size) - 1) / *block_size;
                    if (stream_block_count > (directory_data.size() - cursor) / sizeof(std::uint32_t))
                        return std::unexpected(Error::invalid_pdb);

                    stream.blocks.reserve(stream_block_count);
                    for (std::size_t i = 0; i < stream_block_count; i++, cursor += sizeof(std::uint32_t))
                    {
                        const auto block = read_value<std::uint32_t>(directory_data, cursor);
                        if (!block || *block >= *block_count)
                            return std::unexpected(Error::invalid_pdb);
                        stream.blocks.push_back(*block);
                    }
                }

                return MsfFile{data, *block_size, std::move(streams)};
            }

            [[nodiscard]] std::expected<std::vector<std::uint8_t>, Error>
            read_stream(const std::uint32_t index) const
            {
                if (index >= streams_.size() || streams_[index].size == missing_stream)
                    return std::unexpected(Error::pdb_stream_missing);

                const auto& stream = streams_[index];
                std::vector<std::uint8_t> result;
                result.reserve(stream.size);
                for (const std::uint32_t block : stream.blocks)
                {
                    const std::size_t source_offset = static_cast<std::size_t>(block) * block_size_;
                    const std::size_t remaining = stream.size - result.size();
                    const std::size_t bytes_to_copy = std::min<std::size_t>(block_size_, remaining);
                    result.insert(result.end(), data_.begin() + source_offset,
                                  data_.begin() + source_offset + bytes_to_copy);
                }
                return result;
            }

        private:
            MsfFile(const std::span<const std::uint8_t> data, const std::uint32_t block_size,
                    std::vector<MsfStream> streams)
                : data_{data}, block_size_{block_size}, streams_{std::move(streams)}
            {
            }

            std::span<const std::uint8_t> data_;
            std::uint32_t block_size_;
            std::vector<MsfStream> streams_;
        };

        [[nodiscard]] bool is_safe_pdb_file_name(const std::string_view name)
        {
            return !name.empty() && std::ranges::all_of(name, [](const unsigned char character)
                                                        { return std::isalnum(character) || character == '.'
                                                                 || character == '_' || character == '-'; });
        }

        [[nodiscard]] std::string symbol_store_key(const PdbIdentifier& identifier)
        {
            return std::format("{:08X}{:04X}{:04X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:X}",
                               identifier.guid_data1, identifier.guid_data2, identifier.guid_data3,
                               identifier.guid_data4[0], identifier.guid_data4[1], identifier.guid_data4[2],
                               identifier.guid_data4[3], identifier.guid_data4[4], identifier.guid_data4[5],
                               identifier.guid_data4[6], identifier.guid_data4[7], identifier.age);
        }

        [[nodiscard]] std::string_view undecorate_symbol(const std::string_view name)
        {
            std::size_t first = 0;
            if (name.starts_with('_') || name.starts_with('@'))
                first = 1;
            const std::size_t suffix = name.find('@', first);
            return name.substr(first, suffix == std::string_view::npos ? suffix : suffix - first);
        }

        [[nodiscard]] std::optional<std::uint32_t>
        symbol_rva(const std::span<const PdbImageSection> sections, const std::uint16_t segment,
                   const std::uint32_t offset)
        {
            if (segment == 0 || segment > sections.size())
                return std::nullopt;

            const auto& section = sections[segment - 1];
            if (offset >= section.size || offset > std::numeric_limits<std::uint32_t>::max() - section.rva)
                return std::nullopt;
            return section.rva + offset;
        }

        [[nodiscard]] std::expected<NtdllSymbolRvas, Error>
        parse_symbol_rvas(const std::span<const std::uint8_t> pdb_data,
                          const std::span<const PdbImageSection> image_sections)
        {
            const auto msf = MsfFile::parse(pdb_data);
            if (!msf)
                return std::unexpected(msf.error());

            constexpr std::uint32_t dbi_stream_index = 3;
            const auto dbi_stream = msf->read_stream(dbi_stream_index);
            if (!dbi_stream || dbi_stream->size() < 64)
                return std::unexpected(dbi_stream ? Error::invalid_pdb_symbol_stream : dbi_stream.error());

            const auto symbol_stream_index = read_value<std::uint16_t>(*dbi_stream, 20);
            if (!symbol_stream_index || *symbol_stream_index == missing_stream_index)
                return std::unexpected(Error::pdb_stream_missing);

            const auto symbol_stream = msf->read_stream(*symbol_stream_index);
            if (!symbol_stream)
                return std::unexpected(symbol_stream.error());

            NtdllSymbolRvas result{};
            const auto symbols = std::span<const std::uint8_t>{*symbol_stream};
            std::size_t cursor = 0;
            while (cursor + 4 <= symbols.size())
            {
                const auto record_size = read_value<std::uint16_t>(symbols, cursor);
                const auto record_type = read_value<std::uint16_t>(symbols, cursor + 2);
                if (!record_size || !record_type || *record_size < 2)
                    return std::unexpected(Error::invalid_pdb_symbol_stream);

                const std::size_t total_size = sizeof(std::uint16_t) + *record_size;
                if (total_size > symbols.size() - cursor)
                    return std::unexpected(Error::invalid_pdb_symbol_stream);

                if (*record_type == s_pub32 && total_size >= 15)
                {
                    const auto offset = read_value<std::uint32_t>(symbols, cursor + 8);
                    const auto segment = read_value<std::uint16_t>(symbols, cursor + 12);
                    const auto* name_begin = reinterpret_cast<const char*>(symbols.data() + cursor + 14);
                    const auto* record_end = reinterpret_cast<const char*>(symbols.data() + cursor + total_size);
                    const auto* name_end = std::find(name_begin, record_end, '\0');
                    if (offset && segment && name_end != record_end)
                    {
                        const std::string_view name{name_begin, name_end};
                        if (const auto rva = symbol_rva(image_sections, *segment, *offset))
                        {
                            const auto undecorated = undecorate_symbol(name);
                            if (undecorated == "LdrpHandleTlsData")
                                result.ldrp_handle_tls_data = *rva;
                            else if (undecorated == "RtlInsertInvertedFunctionTable")
                                result.rtl_insert_inverted_function_table = *rva;
                        }
                    }
                }

                cursor += total_size;
                if (result.ldrp_handle_tls_data && result.rtl_insert_inverted_function_table)
                    break;
            }

            if (!result.ldrp_handle_tls_data && !result.rtl_insert_inverted_function_table)
                return std::unexpected(Error::pdb_symbols_not_found);
            return result;
        }

        [[nodiscard]] std::expected<std::vector<std::uint8_t>, Error>
        download_pdb(const std::string_view file_name, const std::string_view symbol_key)
        {
            const std::wstring wide_file_name{file_name.begin(), file_name.end()};
            const std::wstring wide_symbol_key{symbol_key.begin(), symbol_key.end()};
            const std::wstring path = L"/download/symbols/" + wide_file_name + L"/" + wide_symbol_key + L"/"
                                      + wide_file_name;
            const InternetHandle session{WinHttpOpen(L"yail", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                                     WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0)};
            if (!session.get())
                return std::unexpected(Error::pdb_download_failed);

            DWORD redirect_policy = WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS;
            if (!WinHttpSetTimeouts(session.get(), 5000, 5000, 30000, 30000)
                || !WinHttpSetOption(session.get(), WINHTTP_OPTION_REDIRECT_POLICY, &redirect_policy,
                                     sizeof(redirect_policy)))
                return std::unexpected(Error::pdb_download_failed);

            const InternetHandle connection{WinHttpConnect(session.get(), L"msdl.microsoft.com", INTERNET_DEFAULT_HTTPS_PORT, 0)};
            if (!connection.get())
                return std::unexpected(Error::pdb_download_failed);

            const InternetHandle request{WinHttpOpenRequest(connection.get(), L"GET", path.c_str(), nullptr,
                                                             WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                                             WINHTTP_FLAG_SECURE)};
            if (!request.get())
                return std::unexpected(Error::pdb_download_failed);

            if (!WinHttpSendRequest(request.get(), WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)
                || !WinHttpReceiveResponse(request.get(), nullptr))
                return std::unexpected(Error::pdb_download_failed);

            DWORD status{};
            DWORD status_size = sizeof(status);
            if (!WinHttpQueryHeaders(request.get(), WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                     WINHTTP_HEADER_NAME_BY_INDEX, &status, &status_size, WINHTTP_NO_HEADER_INDEX)
                || status != HTTP_STATUS_OK)
                return std::unexpected(Error::pdb_download_failed);

            std::vector<std::uint8_t> result;
            for (;;)
            {
                DWORD available{};
                if (!WinHttpQueryDataAvailable(request.get(), &available))
                    return std::unexpected(Error::pdb_download_failed);
                if (available == 0)
                    break;
                if (available > std::numeric_limits<std::size_t>::max() - result.size())
                    return std::unexpected(Error::pdb_download_failed);

                const std::size_t offset = result.size();
                result.resize(offset + available);
                DWORD read{};
                if (!WinHttpReadData(request.get(), result.data() + offset, available, &read) || read == 0)
                    return std::unexpected(Error::pdb_download_failed);
                result.resize(offset + read);
            }
            return result;
        }
    }

    std::expected<PdbIdentifier, Error> parse_pdb_identifier(const std::span<const std::uint8_t> codeview_data)
    {
        constexpr std::array<std::uint8_t, 4> rsds_signature{'R', 'S', 'D', 'S'};
        constexpr std::size_t file_name_offset = 24;
        if (codeview_data.size() <= file_name_offset
            || !std::equal(rsds_signature.begin(), rsds_signature.end(), codeview_data.begin()))
            return std::unexpected(Error::invalid_pdb_identity);

        const auto guid_data1 = read_value<std::uint32_t>(codeview_data, 4);
        const auto guid_data2 = read_value<std::uint16_t>(codeview_data, 8);
        const auto guid_data3 = read_value<std::uint16_t>(codeview_data, 10);
        const auto age = read_value<std::uint32_t>(codeview_data, 20);
        const auto* file_name_begin = reinterpret_cast<const char*>(codeview_data.data() + file_name_offset);
        const auto* record_end = reinterpret_cast<const char*>(codeview_data.data() + codeview_data.size());
        const auto* file_name_end = std::find(file_name_begin, record_end, '\0');
        if (!guid_data1 || !guid_data2 || !guid_data3 || !age || file_name_end == record_end)
            return std::unexpected(Error::invalid_pdb_identity);

        std::string_view file_path{file_name_begin, file_name_end};
        const std::size_t separator = file_path.find_last_of("\\/");
        const std::string file_name{file_path.substr(separator == std::string_view::npos ? 0 : separator + 1)};
        if (!is_safe_pdb_file_name(file_name))
            return std::unexpected(Error::invalid_pdb_identity);

        PdbIdentifier result{*guid_data1, *guid_data2, *guid_data3, {}, *age, file_name};
        std::copy_n(codeview_data.begin() + 12, result.guid_data4.size(), result.guid_data4.begin());
        return result;
    }

    std::expected<NtdllSymbolRvas, Error>
    download_ntdll_symbol_rvas(const PdbIdentifier& identifier,
                               const std::span<const PdbImageSection> image_sections)
    {
        const auto pdb_data = download_pdb(identifier.file_name, symbol_store_key(identifier));
        if (!pdb_data)
            return std::unexpected(pdb_data.error());
        return parse_symbol_rvas(*pdb_data, image_sections);
    }
}
#endif
