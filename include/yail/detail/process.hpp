#pragma once
#include <Windows.h>
#include <cstdint>
#include <expected>
#include <optional>
#include <string_view>
#include <yail/error.hpp>

namespace yail::detail
{
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
    std::optional<std::uintptr_t> get_process_id_by_name(const std::string_view& process_name);

    [[nodiscard]]
    std::expected<void, Error> validate_target_machine(std::uintptr_t process_id, WORD expected_machine);
}
