#include <Windows.h>
#include <DbgHelp.h>
#include <mmsystem.h>
#include <cstdio>
#include <cmath>
#include <cstring>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <functional>
#include <stdexcept>
#include <memory>
#include <algorithm>

static int g_passed = 0;
static int g_total  = 0;

static void Report(const char* name, bool ok)
{
    g_total++;
    if (ok) g_passed++;
    printf("  [%s] %s\n", ok ? "PASS" : "FAIL", name);
}

// =========================================================================
// TLS callback — must fire before main()
// =========================================================================
static volatile bool g_tlsCallbackFired = false;

static void NTAPI TlsCallback(PVOID, DWORD dwReason, PVOID)
{
    if (dwReason == DLL_PROCESS_ATTACH)
    {
        g_tlsCallbackFired = true;
        printf("[test_exe] TLS callback fired (DLL_PROCESS_ATTACH)\n");
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
#else
__attribute__((section(".CRT$XLB"))) PIMAGE_TLS_CALLBACK g_pfnTlsCallback = TlsCallback;
#endif

// =========================================================================
// Static TLS — __declspec(thread)
// =========================================================================
static __declspec(thread) int         g_tlsInt    = 42;
static __declspec(thread) const char* g_tlsStr    = "hello from TLS";
static __declspec(thread) double      g_tlsDouble = 3.14;

static bool TestStaticTLS()
{
    if (g_tlsInt != 42)                          return false;
    if (g_tlsDouble != 3.14)                     return false;
    if (strcmp(g_tlsStr, "hello from TLS") != 0) return false;

    g_tlsInt    = 100;
    g_tlsDouble = 2.718;
    return g_tlsInt == 100 && g_tlsDouble == 2.718;
}

// =========================================================================
// Static TLS across threads
// =========================================================================
static bool TestTLSPerThread()
{
    std::atomic<bool> ok1{false};
    std::atomic<bool> ok2{false};
    g_tlsInt = 1000;

    std::thread t1([&] { g_tlsInt = 111; ok1 = (g_tlsInt == 111); });
    std::thread t2([&] { g_tlsInt = 222; ok2 = (g_tlsInt == 222); });
    t1.join();
    t2.join();

    return ok1 && ok2 && g_tlsInt == 1000;
}

// =========================================================================
// SEH
// =========================================================================
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

static bool TestSEHDivZero()
{
    bool caught = false;
    __try
    {
        volatile int a = 1, b = 0;
        volatile int c = a / b;
        (void)c;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        caught = true;
    }
    return caught;
}

// =========================================================================
// C++ exceptions
// =========================================================================
static bool TestCppExceptionStd()
{
    try
    {
        throw std::runtime_error("test_exe runtime error");
    }
    catch (const std::exception& e)
    {
        return std::string(e.what()) == "test_exe runtime error";
    }
    return false;
}

static bool g_dtorRan = false;
struct ScopedGuard
{
    bool* flag;
    explicit ScopedGuard(bool* f) : flag(f) { *flag = false; }
    ~ScopedGuard() { *flag = true; }
};

static bool TestCppExceptionUnwind()
{
    g_dtorRan = false;
    try
    {
        ScopedGuard guard(&g_dtorRan);
        throw 42;
    }
    catch (...) {}
    return g_dtorRan;
}

// =========================================================================
// Global constructors
// =========================================================================
struct StaticInit
{
    int magic;
    StaticInit() : magic(0xC0DEC0DE) {}
};
static StaticInit g_staticInit;

static bool TestGlobalCtors() { return g_staticInit.magic == 0xC0DEC0DE; }

// =========================================================================
// Win32 imports
// =========================================================================
static bool TestImports()
{
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    if (si.dwPageSize == 0) return false;

    HANDLE heap = HeapCreate(0, 0, 0);
    if (!heap) return false;
    void* p = HeapAlloc(heap, HEAP_ZERO_MEMORY, 256);
    if (!p) { HeapDestroy(heap); return false; }
    HeapFree(heap, 0, p);
    HeapDestroy(heap);

    LARGE_INTEGER freq{};
    return QueryPerformanceFrequency(&freq) && freq.QuadPart != 0;
}

// =========================================================================
// STL
// =========================================================================
static bool TestSTL()
{
    std::vector<int> v = {5, 3, 1, 4, 2};
    std::sort(v.begin(), v.end());
    if (v != std::vector<int>{1, 2, 3, 4, 5}) return false;

    std::string s = "Hello";
    s += ", EXE!";
    if (s != "Hello, EXE!") return false;

    auto ptr = std::make_unique<int>(42);
    return ptr && *ptr == 42;
}

// =========================================================================
// Floating point
// =========================================================================
static bool TestFloatingPoint()
{
    volatile double a = 2.0;
    if (fabs(sqrt(a) - 1.41421356237) > 1e-6) return false;

    volatile float b = 1.0f;
    return fabsf(sinf(b) - 0.841471f) <= 1e-4f;
}

// =========================================================================
// Threading + mutex
// =========================================================================
static bool TestThreading()
{
    std::atomic<int> counter{0};
    std::mutex mtx;
    constexpr int N = 8;

    std::vector<std::thread> threads;
    threads.reserve(N);
    for (int i = 0; i < N; i++)
    {
        threads.emplace_back([&] {
            std::lock_guard lock(mtx);
            counter++;
        });
    }
    for (auto& t : threads) t.join();
    return counter == N;
}

// =========================================================================
// Vtable dispatch
// =========================================================================
struct IShape
{
    virtual int sides() = 0;
    virtual ~IShape() = default;
};
struct Triangle final : IShape { int sides() override { return 3; } };
struct Hexagon  final : IShape { int sides() override { return 6; } };

static bool TestVTable()
{
    std::unique_ptr<IShape> a = std::make_unique<Triangle>();
    std::unique_ptr<IShape> b = std::make_unique<Hexagon>();
    return a->sides() == 3 && b->sides() == 6;
}

// =========================================================================
// Delay imports
// =========================================================================
static bool TestDelayImportDbgHelp()
{
    const DWORD original = SymGetOptions();
    SymSetOptions(original | SYMOPT_UNDNAME);
    const DWORD updated = SymGetOptions();
    SymSetOptions(original);
    return (updated & SYMOPT_UNDNAME) != 0;
}

static bool TestDelayImportWinmm()
{
    TIMECAPS tc{};
    if (timeGetDevCaps(&tc, sizeof(tc)) != TIMERR_NOERROR) return false;
    return tc.wPeriodMin > 0 && tc.wPeriodMin <= tc.wPeriodMax;
}

// =========================================================================
// CRT-populated argc/argv — EXE-specific.
// The CRT entry pulls these from GetCommandLineA(), so they reflect the
// host process's command line, not anything we passed.
// =========================================================================
static bool TestArgcArgv(int argc, char** argv)
{
    return argc > 0 && argv != nullptr && argv[0] != nullptr;
}

// =========================================================================
// EXE entry — invoked by CRT (mainCRTStartup) after init
// =========================================================================
int main(int argc, char** argv)
{
    printf("========================================\n");
    printf("[test_exe] main() reached (argc=%d)\n", argc);
    if (argv && argc > 0 && argv[0])
        printf("[test_exe] argv[0] = %s\n", argv[0]);
    printf("========================================\n\n");

    Report("TLS callback fired",         g_tlsCallbackFired);
    Report("Static TLS read/write",      TestStaticTLS());
    Report("Static TLS per-thread",      TestTLSPerThread());
    Report("SEH access violation",       TestSEH());
    Report("SEH divide by zero",         TestSEHDivZero());
    Report("C++ exception std::exception", TestCppExceptionStd());
    Report("C++ exception stack unwind", TestCppExceptionUnwind());
    Report("Global constructors",        TestGlobalCtors());
    Report("Win32 API imports",          TestImports());
    Report("STL containers/strings",     TestSTL());
    Report("Floating point / math",      TestFloatingPoint());
    Report("Threading + mutex",          TestThreading());
    Report("Vtable dispatch",            TestVTable());
    Report("Delay import DbgHelp",       TestDelayImportDbgHelp());
    Report("Delay import Winmm",         TestDelayImportWinmm());
    Report("argc/argv populated by CRT", TestArgcArgv(argc, argv));

    printf("\n========================================\n");
    printf("[test_exe] Results: %d/%d passed\n", g_passed, g_total);
    printf("========================================\n");

    MessageBoxA(nullptr, "All EXE tests have completed!", "yail", MB_OK);

    // Returning from main() would invoke the CRT's exit() -> ExitProcess and
    // terminate the host loader process. Exit only this thread instead so the
    // loader's WaitForSingleObject wakes and the process keeps running.
    ExitThread(0);
}
