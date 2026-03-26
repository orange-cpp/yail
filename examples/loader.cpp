#include "yail/yail.hpp"
#include <Windows.h>
#include <cstdio>
#include <string>
#include <print>
int main(int argc, char* argv[])
{
    std::string dllPath = "test_dll.dll";
    if (argc > 1)
        dllPath = argv[1];

    printf("[loader] Manual-mapping: %s\n\n", dllPath.c_str());

    auto result = yail::manual_map_injection_from_file(dllPath, GetCurrentProcessId());

    if (!result)
    {
        std::println("[loader] FAILED: {}",  result.error());
        return 1;
    }

    std::println("\n[loader] Success - image loaded at 0x{:x}\n", result.value());
    return 0;
}
