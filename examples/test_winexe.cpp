#include <Windows.h>
#include <DbgHelp.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <stdexcept>

// __ImageBase is a linker-emitted symbol whose address equals the image base.
// After manual mapping + relocations, taking its address gives the mapped base.
extern "C" IMAGE_DOS_HEADER __ImageBase;

static int g_passed = 0;
static int g_total  = 0;

static void Report(const char* name, bool ok)
{
    g_total++;
    if (ok) g_passed++;
    printf("  [%s] %s\n", ok ? "PASS" : "FAIL", name);
}

// =========================================================================
// TLS callback — must fire before WinMain
// =========================================================================
static volatile bool g_tlsCallbackFired = false;

static void NTAPI TlsCallback(PVOID, DWORD dwReason, PVOID)
{
    if (dwReason == DLL_PROCESS_ATTACH)
    {
        g_tlsCallbackFired = true;
        printf("[test_winexe] TLS callback fired (DLL_PROCESS_ATTACH)\n");
    }
}

#ifdef _MSC_VER
#ifdef _WIN64
#pragma comment(linker, "/INCLUDE:_tls_used")
#else
#pragma comment(linker, "/INCLUDE:__tls_used")
#endif
#pragma section(".CRT$XLB", read)
__declspec(allocate(".CRT$XLB")) PIMAGE_TLS_CALLBACK g_pfnTlsCallback = TlsCallback;
#endif

static __declspec(thread) int g_tlsInt = 1234;

static bool TestStaticTLS()
{
    if (g_tlsInt != 1234) return false;
    g_tlsInt = 5678;
    return g_tlsInt == 5678;
}

static bool TestSEH()
{
    bool caught = false;
    __try
    {
        *reinterpret_cast<volatile int*>(nullptr) = 0xDEAD;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        caught = true;
    }
    return caught;
}

static bool TestCppException()
{
    try { throw std::runtime_error("winmain ex"); }
    catch (const std::exception& e) { return std::string(e.what()) == "winmain ex"; }
    return false;
}

struct StaticInit { int v; StaticInit() : v(0xBADF00D) {} };
static StaticInit g_staticInit;
static bool TestGlobalCtors() { return g_staticInit.v == 0xBADF00D; }

static bool TestImports()
{
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    return si.dwPageSize > 0;
}

static bool TestDelayImportDbgHelp()
{
    const DWORD original = SymGetOptions();
    SymSetOptions(original | SYMOPT_UNDNAME);
    const DWORD updated = SymGetOptions();
    SymSetOptions(original);
    return (updated & SYMOPT_UNDNAME) != 0;
}

// =========================================================================
// WinMain-specific checks
// =========================================================================
static bool TestHInstanceMatchesImageBase(HINSTANCE hInstance)
{
    // The CRT computes hInstance as &__ImageBase. After manual mapping with
    // relocations applied, both should resolve to the mapped image base.
    return reinterpret_cast<void*>(hInstance) == reinterpret_cast<void*>(&__ImageBase);
}

static bool TestLpCmdLine(LPSTR lpCmdLine)
{
    // The CRT pulls the command line from GetCommandLineA(); lpCmdLine is the
    // tail (program name stripped). It must at least be a valid C string.
    return lpCmdLine != nullptr;
}

static bool TestNShowCmd(int nShowCmd)
{
    // SW_HIDE..SW_MAX is a small range; any sane value falls within.
    return nShowCmd >= 0 && nShowCmd <= 11;
}

// =========================================================================
// WinMain — invoked by WinMainCRTStartup
// =========================================================================
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
    printf("========================================\n");
    printf("[test_winexe] WinMain reached\n");
    printf("  hInstance     = %p\n", static_cast<void*>(hInstance));
    printf("  &__ImageBase  = %p\n", static_cast<void*>(&__ImageBase));
    printf("  hPrevInstance = %p (always null in Win32)\n", static_cast<void*>(hPrevInstance));
    printf("  lpCmdLine     = \"%s\"\n", lpCmdLine ? lpCmdLine : "(null)");
    printf("  nShowCmd      = %d\n", nShowCmd);
    printf("========================================\n\n");

    Report("TLS callback fired",        g_tlsCallbackFired);
    Report("Static TLS",                TestStaticTLS());
    Report("SEH access violation",      TestSEH());
    Report("C++ exception",             TestCppException());
    Report("Global constructors",       TestGlobalCtors());
    Report("Win32 imports",             TestImports());
    Report("Delay import DbgHelp",      TestDelayImportDbgHelp());
    Report("hInstance == &__ImageBase", TestHInstanceMatchesImageBase(hInstance));
    Report("hPrevInstance is nullptr",  hPrevInstance == nullptr);
    Report("lpCmdLine non-null",        TestLpCmdLine(lpCmdLine));
    Report("nShowCmd in valid range",   TestNShowCmd(nShowCmd));

    printf("\n========================================\n");
    printf("[test_winexe] Results: %d/%d passed\n", g_passed, g_total);
    printf("========================================\n");

    MessageBoxA(nullptr, "WinMain EXE tests have completed!", "yail", MB_OK);

    // ExitThread to keep the host loader process alive — see test_exe.cpp.
    ExitThread(0);
}
