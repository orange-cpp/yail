#include <cstdio>
#include <string>

#include "yail/yail.h"
#include "yail/yail.hpp"

int main(int argc, char* argv[])
{
    std::string dllPath = R"(C:\Users\orange\CLionProjects\avhook-titanfall2\build\x64-release\Wraith_protected.dll)";
    std::string target  = "Titanfall2.exe";

    if (argc > 1) dllPath = argv[1];
    if (argc > 2) target  = argv[2];

    printf("[remote_loader] Target: %s\n", target.c_str());

    printf("[remote_loader] Injecting: %s\n\n", dllPath.c_str());

    auto result = yail::manual_map_injection_from_file(dllPath, target, YAIL_MANUAL_MAP_ERASE_HEADERS | YAIL_MANUAL_MAP_WIPE_IMPORTS);

    if (!result)
    {
        const auto error = yail::to_string(result.error());
        printf("[remote_loader] FAILED: %.*s\n", static_cast<int>(error.size()), error.data());
        return 1;
    }

    printf("[remote_loader] Success - remote image at 0x%llX\n",
           static_cast<unsigned long long>(result.value()));
    return 0;
}
