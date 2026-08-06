#include <yail/detail/process.hpp>
#include <TlHelp32.h>
#include <limits>

namespace yail::detail
{
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

    std::expected<void, Error> validate_target_machine(const std::uintptr_t process_id, const WORD expected_machine)
    {
        if (process_id > std::numeric_limits<DWORD>::max())
            return std::unexpected(Error::process_id_out_of_range);

        const UniqueHandle process{OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(process_id))};
        if (!process)
            return std::unexpected(Error::process_open_failed);

        using IsWow64Process2Fn = BOOL(WINAPI*)(HANDLE, USHORT*, USHORT*);
        const auto kernel32 = GetModuleHandleA("kernel32.dll");
        const auto is_wow64_process_2 = reinterpret_cast<IsWow64Process2Fn>(
                GetProcAddress(kernel32, "IsWow64Process2"));
        if (is_wow64_process_2)
        {
            USHORT process_machine = IMAGE_FILE_MACHINE_UNKNOWN;
            USHORT native_machine = IMAGE_FILE_MACHINE_UNKNOWN;
            if (!is_wow64_process_2(process.get(), &process_machine, &native_machine))
                return std::unexpected(Error::architecture_query_failed);

            const WORD target_machine = process_machine == IMAGE_FILE_MACHINE_UNKNOWN ? native_machine
                                                                                       : process_machine;
            if (target_machine != expected_machine)
                return std::unexpected(Error::architecture_mismatch);
            return {};
        }

        BOOL target_is_wow64 = FALSE;
        BOOL self_is_wow64 = FALSE;
        if (!IsWow64Process(process.get(), &target_is_wow64)
            || !IsWow64Process(GetCurrentProcess(), &self_is_wow64))
            return std::unexpected(Error::architecture_query_failed);

#ifdef _WIN64
        const WORD target_machine = target_is_wow64 ? IMAGE_FILE_MACHINE_I386 : IMAGE_FILE_MACHINE_AMD64;
        if (target_machine != expected_machine)
            return std::unexpected(Error::architecture_mismatch);
#else
       if (expected_machine != IMAGE_FILE_MACHINE_I386 || target_is_wow64 != self_is_wow64)
            return std::unexpected(Error::architecture_mismatch);
#endif

        return {};
    }
}
