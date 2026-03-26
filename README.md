# yail
**Yet Another Injection Library** — a Windows x64 manual-map DLL injection library written in modern C++23.

## Features

- x64 PE manual mapping (no `LoadLibrary` traces)
- Static TLS support
- Exception handling (SEH/VEH compatible)
- Heap validation compatibility with UCRT
- Inject by process ID or process name
- Load from file path or raw bytes in memory
- Returns `std::expected<uintptr_t, std::string>` — no exceptions, clear error messages

## Requirements

- Windows x64
- C++23 compiler (MSVC recommended)
- CMake 3.28+
- vcpkg

## Building

```bash
cmake --preset windows-debug
cmake --build cmake-build/build/windows-debug
```

To also build the examples:

```bash
cmake --preset windows-debug -DYAIL_BUILD_EXAMPLES=ON
cmake --build cmake-build/build/windows-debug
```

## Usage

### Inject into a process by name

```cpp
#include <yail/yail.hpp>

auto result = yail::manual_map_injection_from_file("my.dll", "target.exe");

if (!result)
    std::println("Failed: {}", result.error());
else
    std::println("Loaded at 0x{:x}", result.value());
```

### Inject into a process by PID

```cpp
auto result = yail::manual_map_injection_from_file("my.dll", GetCurrentProcessId());
```

### Inject from raw bytes

```cpp
std::vector<uint8_t> dll_bytes = /* ... */;
auto result = yail::manual_map_injection_from_raw(dll_bytes, "target.exe");
```

## CMake Integration

After installing, consume yail in your project:

```cmake
find_package(yail CONFIG REQUIRED)
target_link_libraries(my_target PRIVATE yail::yail)
```

## API

```cpp
namespace yail
{
    // Inject from a file path
    std::expected<uintptr_t, std::string>
    manual_map_injection_from_file(std::string_view dll_path, std::uintptr_t process_id);

    std::expected<uintptr_t, std::string>
    manual_map_injection_from_file(std::string_view dll_path, std::string_view process_name);

    // Inject from raw bytes
    std::expected<uintptr_t, std::string>
    manual_map_injection_from_raw(const std::span<std::uint8_t>& raw_dll, std::uintptr_t process_id);

    std::expected<uintptr_t, std::string>
    manual_map_injection_from_raw(const std::span<std::uint8_t>& raw_dll, std::string_view process_name);
}
```

On success, returns the base address of the mapped image in the target process. On failure, returns a string describing the error.

## License

[Zlib](LICENSE)
