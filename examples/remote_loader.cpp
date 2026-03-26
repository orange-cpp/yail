#include <cstdio>
#include <string>
#include "yail/yail.hpp"

int main(int argc, char* argv[])
{
    std::string dllPath = "test_dll.dll";
    std::string target  = "tf_win64.exe";

    if (argc > 1) dllPath = argv[1];
    if (argc > 2) target  = argv[2];

    printf("[remote_loader] Target: %s\n", target.c_str());

    printf("[remote_loader] Injecting: %s\n\n", dllPath.c_str());

    auto result = yail::manual_map_injection_from_file(dllPath, target);

    if (!result)
    {
        printf("[remote_loader] FAILED: %s\n", result.error().c_str());
        return 1;
    }

    printf("[remote_loader] Success - remote image at 0x%llX\n",
           static_cast<unsigned long long>(result.value()));
    return 0;
}
