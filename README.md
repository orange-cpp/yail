# yail
**Yet Another Injection Library** — a Windows manual-map PE injection library written in modern C++23. Supports both **x64** and **x86**, and can map both **DLLs** and **EXEs** into a target process.

## Features

- Manual PE mapping (no `LoadLibrary` traces)
  - **x64** — full unwind table registration via `RtlInsertInvertedFunctionTable` (with `RtlAddFunctionTable` fallback)
  - **x86** — SEH validation via `RtlInsertInvertedFunctionTable` (handles modern Win11 24H2 internal `__fastcall` convention)
- Maps both **DLLs** and **EXEs** — auto-detected via `IMAGE_FILE_DLL`
  - DLLs invoked as `DllMain(HMODULE, DLL_PROCESS_ATTACH, nullptr)`
  - EXEs invoked as `int __cdecl mainCRTStartup(void)` — works with both `main`-style (console subsystem) and `WinMain`-style (GUI subsystem) entries
- Static TLS via signature-scanned `LdrpHandleTlsData`
- TLS callbacks (`.CRT$XLB`)
- Static and delay-loaded imports
- Exception handling (SEH/VEH/C++) compatible with manually-mapped images
- Per-section memory protections (RX, RW, RO, RWX as declared)
- Inject by process ID or process name
- Load from file path or raw bytes in memory
- Returns `std::expected<uintptr_t, std::string>` — no exceptions, clear error messages

## Requirements

- Windows 10 / 11 (signature scans target Windows 11 24H2 ntdll by default; older builds may need pattern updates)
- C++23 compiler (MSVC recommended)
- CMake 3.28+
- vcpkg

## Building

x64:

```bash
cmake --preset windows-debug-vcpkg
cmake --build cmake-build/build/windows-debug-vcpkg
```

x86:

```bash
cmake --preset windows-debug-vcpkg-x86
cmake --build cmake-build/build/windows-debug-vcpkg-x86
```

The injector and the target image must share bitness — an x86 build of yail injects x86 PEs into x86 (Wow64) processes, an x64 build injects x64 PEs into x64 processes.

Examples build by default. Disable with `-DYAIL_BUILD_EXAMPLES=OFF`.

## Usage

### Inject a DLL into a process by name

```cpp
#include <yail/yail.hpp>

auto result = yail::manual_map_injection_from_file("my.dll", "target.exe");

if (!result)
    std::println("Failed: {}", result.error());
else
    std::println("Loaded at 0x{:x}", result.value());
```

### Inject by PID

```cpp
auto result = yail::manual_map_injection_from_file("my.dll", GetCurrentProcessId());
```

### Inject an EXE

Same API — auto-detection picks the right entry-point shape:

```cpp
auto result = yail::manual_map_injection_from_file("my.exe", GetCurrentProcessId());
```

EXE caveats (apply to both `main` and `WinMain` flavors):
- When the EXE's entry returns, the CRT calls `exit()` → `ExitProcess`. That terminates the **host** process. If you need the host to survive, the injected EXE must avoid letting `main`/`WinMain` return — e.g. `ExitThread(0)` from the entry, like the bundled `test_exe`.
- `GetModuleHandle(nullptr)` inside the injected EXE returns the **host** image base, not the mapped one. `WinMain`'s `hInstance` is correct (it comes from `__ImageBase`, which is relocated), but APIs that read `PEB->ImageBaseAddress` are not.

### Inject from raw bytes

```cpp
std::vector<uint8_t> bytes = /* ... */;
auto result = yail::manual_map_injection_from_raw(bytes, "target.exe");
```

## API

```cpp
namespace yail
{
    // Both functions accept DLLs and EXEs (matched by IMAGE_FILE_DLL).
    // PE machine type must match the build (x64 build → AMD64 PE, x86 → I386).

    std::expected<uintptr_t, std::string>
    manual_map_injection_from_file(std::string_view pe_path, std::uintptr_t process_id);

    std::expected<uintptr_t, std::string>
    manual_map_injection_from_file(std::string_view pe_path, std::string_view process_name);

    std::expected<uintptr_t, std::string>
    manual_map_injection_from_raw(const std::span<std::uint8_t>& raw_pe, std::uintptr_t process_id);

    std::expected<uintptr_t, std::string>
    manual_map_injection_from_raw(const std::span<std::uint8_t>& raw_pe, std::string_view process_name);
}
```

On success, returns the base address of the mapped image in the target process. On failure, returns a string describing the error.

## CMake Integration

```cmake
find_package(yail CONFIG REQUIRED)
target_link_libraries(my_target PRIVATE yail::yail)
```

## Examples

The `examples/` directory contains:

| Target          | Purpose                                                                                |
|-----------------|----------------------------------------------------------------------------------------|
| `loader`        | Manual-maps a PE (DLL or EXE) into the current process. `loader.exe <path>`.           |
| `remote_loader` | Manual-maps into a target process by name. `remote_loader.exe <dll> <process.exe>`.    |
| `test_dll`      | Self-test DLL exercising TLS, SEH, C++ exceptions, delay imports, threading, vtables.  |
| `test_exe`      | Same battery of tests, but as a console-subsystem EXE entered via `main()`.            |
| `test_winexe`   | GUI-subsystem EXE entered via `WinMain` — verifies `hInstance`, `lpCmdLine`, `nShowCmd`. |

Quick verification on either bitness:

```bash
loader.exe test_dll.dll       # 22 tests
loader.exe test_exe.exe       # 16 tests + ExitThread keeps the loader alive
loader.exe test_winexe.exe    # WinMain path + GUI subsystem checks
```

## Signature notes

The library locates two non-exported ntdll routines by byte signatures:

- `LdrpHandleTlsData` — used to register static TLS for the mapped image
- `RtlInsertInvertedFunctionTable` — used to make the image's exception/SEH handlers visible to the OS exception dispatcher

Patterns are versioned per architecture and have been verified on **Windows 11 24H2**. Older Windows builds may require updated signatures — locate the function in WinDbg (`x ntdll!LdrpHandleTlsData`, `uf <addr>`), take ~16 unique leading bytes, and add the wildcarded pattern to the corresponding `find_*` array in `source/yail.cpp`.

On modern x86 ntdll, both functions use `__fastcall` (args in `ECX`/`EDX`) despite their legacy `_Name@N` symbol decoration — the typedef and call sites in the source reflect that. If you target an older x86 Windows where these are still `__stdcall`, you'll need to swap the typedef to `NTAPI*`.

## License

[Zlib](LICENSE)
