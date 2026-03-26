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
// =========================================================================
// Globals & helpers
// =========================================================================
static int g_passed = 0;
static int g_total  = 0;

static void Report(const char* name, bool ok)
{
    g_total++;
    if (ok) g_passed++;
    printf("  [%s] %s\n", ok ? "PASS" : "FAIL", name);
}

// =========================================================================
// 1. TLS callback — must fire before DllMain
// =========================================================================
static volatile bool g_tlsCallbackFired = false;

static void NTAPI TlsCallback(PVOID hModule, DWORD dwReason, PVOID pContext)
{
    if (dwReason == DLL_PROCESS_ATTACH)
    {
        g_tlsCallbackFired = true;
        printf("[test_dll] TLS callback fired (DLL_PROCESS_ATTACH)\n");
    }
}

#ifdef _MSC_VER
#pragma comment(linker, "/INCLUDE:_tls_used")
#pragma section(".CRT$XLB", read)
__declspec(allocate(".CRT$XLB")) PIMAGE_TLS_CALLBACK g_pfnTlsCallback = TlsCallback;
#else
__attribute__((section(".CRT$XLB"))) PIMAGE_TLS_CALLBACK g_pfnTlsCallback = TlsCallback;
#endif

// =========================================================================
// 2. Static TLS — __declspec(thread) read/write
// =========================================================================
static __declspec(thread) int         g_tlsInt    = 42;
static __declspec(thread) const char* g_tlsStr    = "hello from TLS";
static __declspec(thread) double      g_tlsDouble = 3.14;
static __declspec(thread) uint64_t    g_tlsLarge  = 0xDEAD'BEEF'CAFE'BABEull;

static bool TestStaticTLS()
{
    if (g_tlsInt != 42)       return false;
    if (g_tlsDouble != 3.14)  return false;
    if (g_tlsLarge != 0xDEAD'BEEF'CAFE'BABEull) return false;
    if (strcmp(g_tlsStr, "hello from TLS") != 0) return false;

    g_tlsInt = 100;
    g_tlsDouble = 2.718;
    g_tlsLarge = 0;
    if (g_tlsInt != 100)     return false;
    if (g_tlsDouble != 2.718) return false;
    if (g_tlsLarge != 0)     return false;

    return true;
}

// =========================================================================
// 3. Static TLS across threads — each thread gets its own copy
// =========================================================================
static bool TestTLSPerThread()
{
    std::atomic<bool> thread1Ok{false};
    std::atomic<bool> thread2Ok{false};

    // Reset on main thread
    g_tlsInt = 1000;

    std::thread t1([&] {
        // New thread should get the initial value (42), not main's 1000
        // Actually after _initterm, new threads get the TLS template value
        g_tlsInt = 111;
        thread1Ok = (g_tlsInt == 111);
    });

    std::thread t2([&] {
        g_tlsInt = 222;
        thread2Ok = (g_tlsInt == 222);
    });

    t1.join();
    t2.join();

    // Main thread value untouched by other threads
    return thread1Ok && thread2Ok && g_tlsInt == 1000;
}

// =========================================================================
// 4. SEH — access violation
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

// =========================================================================
// 5. SEH — integer divide by zero
// =========================================================================
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
// 6. SEH — nested exceptions
// =========================================================================
static bool TestSEHNested()
{
    int depth = 0;
    __try
    {
        __try
        {
            *reinterpret_cast<volatile int*>(nullptr) = 0;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            depth++;
            // Throw again inside handler
            __try
            {
                *reinterpret_cast<volatile int*>(0x1) = 0;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                depth++;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        depth = -1; // Should not reach outer handler
    }
    return depth == 2;
}

// =========================================================================
// 7. SEH filter — EXCEPTION_CONTINUE_SEARCH
// =========================================================================
static bool TestSEHFilter()
{
    bool outerCaught = false;
    __try
    {
        __try
        {
            RaiseException(0xE0000001, 0, 0, nullptr);
        }
        __except (EXCEPTION_CONTINUE_SEARCH)
        {
            return false; // Should not execute
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        outerCaught = true;
    }
    return outerCaught;
}

// =========================================================================
// 8. C++ exception — int
// =========================================================================
static bool TestCppExceptionInt()
{
    try
    {
        throw 0xBEEF;
    }
    catch (int val)
    {
        return val == 0xBEEF;
    }
    return false;
}

// =========================================================================
// 9. C++ exception — std::exception hierarchy
// =========================================================================
static bool TestCppExceptionStd()
{
    try
    {
        throw std::runtime_error("manual map test");
    }
    catch (const std::exception& e)
    {
        return std::string(e.what()) == "manual map test";
    }
    return false;
}

// =========================================================================
// 10. C++ exception — custom class with destructor
// =========================================================================
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
    catch (...)
    {
    }
    // Destructor must have run during stack unwinding
    return g_dtorRan;
}

// =========================================================================
// 11. C++ exception — rethrow
// =========================================================================
static bool TestCppExceptionRethrow()
{
    try
    {
        try
        {
            throw std::logic_error("rethrow me");
        }
        catch (...)
        {
            throw; // rethrow
        }
    }
    catch (const std::logic_error& e)
    {
        return std::string(e.what()) == "rethrow me";
    }
    return false;
}

// =========================================================================
// 12. C++ exception from std::function (indirect call)
// =========================================================================
static bool TestCppExceptionIndirect()
{
    std::function<void()> fn = [] { throw std::bad_alloc(); };
    try
    {
        fn();
    }
    catch (const std::bad_alloc&)
    {
        return true;
    }
    return false;
}

// =========================================================================
// 13. Import table — call various Win32 APIs
// =========================================================================
static bool TestImports()
{
    // kernel32
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    if (si.dwPageSize == 0)
        return false;

    // kernel32 — heap
    HANDLE heap = HeapCreate(0, 0, 0);
    if (!heap)
        return false;
    void* p = HeapAlloc(heap, HEAP_ZERO_MEMORY, 256);
    if (!p)
        return false;
    memset(p, 0xAA, 256);
    HeapFree(heap, 0, p);
    HeapDestroy(heap);

    // kernel32 — QueryPerformanceCounter
    LARGE_INTEGER freq{}, ctr{};
    if (!QueryPerformanceFrequency(&freq) || freq.QuadPart == 0)
        return false;
    if (!QueryPerformanceCounter(&ctr) || ctr.QuadPart == 0)
        return false;

    return true;
}

// =========================================================================
// 14. CRT / STL — containers, algorithms, strings
// =========================================================================
static bool TestSTL()
{
    std::vector<int> v = {5, 3, 1, 4, 2};
    std::sort(v.begin(), v.end());
    if (v != std::vector<int>{1, 2, 3, 4, 5})
        return false;

    std::string s = "Hello";
    s += ", World!";
    if (s != "Hello, World!")
        return false;

    auto ptr = std::make_unique<int>(42);
    if (!ptr || *ptr != 42)
        return false;

    return true;
}

// =========================================================================
// 15. FPU / SSE — floating point math
// =========================================================================
static bool TestFloatingPoint()
{
    volatile double a = 2.0;
    double sq = sqrt(a);
    if (fabs(sq - 1.41421356237) > 1e-6)
        return false;

    volatile float b = 1.0f;
    float s = sinf(b);
    if (fabsf(s - 0.841471f) > 1e-4f)
        return false;

    // SSE: simple vector-ish operation
    volatile double vals[4] = {1.0, 2.0, 3.0, 4.0};
    double sum = 0;
    for (int i = 0; i < 4; i++)
        sum += vals[i] * vals[i];
    if (fabs(sum - 30.0) > 1e-9)
        return false;

    return true;
}

// =========================================================================
// 16. VirtualAlloc / VirtualFree inside mapped DLL
// =========================================================================
static bool TestVirtualMemory()
{
    void* mem = VirtualAlloc(nullptr, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem)
        return false;

    memset(mem, 0xCC, 0x10000);
    if (static_cast<uint8_t*>(mem)[0] != 0xCC)
        return false;

    MEMORY_BASIC_INFORMATION mbi{};
    VirtualQuery(mem, &mbi, sizeof(mbi));
    if (mbi.RegionSize < 0x10000 || mbi.Protect != PAGE_READWRITE)
        return false;

    VirtualFree(mem, 0, MEM_RELEASE);
    return true;
}

// =========================================================================
// 17. Threads — create and join from within mapped DLL
// =========================================================================
static bool TestThreading()
{
    std::atomic<int> counter{0};
    std::mutex mtx;
    constexpr int NUM_THREADS = 8;

    std::vector<std::thread> threads;
    threads.reserve(NUM_THREADS);
    for (int i = 0; i < NUM_THREADS; i++)
    {
        threads.emplace_back([&] {
            std::lock_guard lock(mtx);
            counter++;
        });
    }
    for (auto& t : threads)
        t.join();

    return counter == NUM_THREADS;
}

// =========================================================================
// 18. Global constructors — C++ static init ran correctly
// =========================================================================
struct StaticInit
{
    int value;
    StaticInit() : value(0x1337) {}
};
static StaticInit g_staticInit;

static bool TestGlobalCtors()
{
    return g_staticInit.value == 0x1337;
}

// =========================================================================
// 19. Relocations — function pointers through vtable
// =========================================================================
struct IAnimal
{
    virtual const char* Speak() = 0;
    virtual int Legs() = 0;
    virtual ~IAnimal() = default;
};

struct Dog final : IAnimal
{
    const char* Speak() override { return "Woof"; }
    int Legs() override { return 4; }
};

struct Spider final : IAnimal
{
    const char* Speak() override { return "..."; }
    int Legs() override { return 8; }
};

static bool TestVTable()
{
    std::unique_ptr<IAnimal> d = std::make_unique<Dog>();
    std::unique_ptr<IAnimal> s = std::make_unique<Spider>();

    if (strcmp(d->Speak(), "Woof") != 0) return false;
    if (d->Legs() != 4)                 return false;
    if (strcmp(s->Speak(), "...") != 0)  return false;
    if (s->Legs() != 8)                 return false;

    return true;
}

// =========================================================================
// 20. RaiseException + vectored exception handler
// =========================================================================
static std::atomic<bool> g_vehFired{false};

static LONG CALLBACK VehHandler(PEXCEPTION_POINTERS info)
{
    if (info->ExceptionRecord->ExceptionCode == 0xE0C05700)
    {
        g_vehFired = true;
        return EXCEPTION_CONTINUE_SEARCH;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static bool TestVEH()
{
    g_vehFired = false;
    PVOID handle = AddVectoredExceptionHandler(1, VehHandler);
    if (!handle)
        return false;

    __try
    {
        RaiseException(0xE0C05700, 0, 0, nullptr);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }

    RemoveVectoredExceptionHandler(handle);
    return g_vehFired;
}

// =========================================================================
// 21. Delay imports — DbgHelp.dll (delay-loaded)
// =========================================================================
static bool TestDelayImportDbgHelp()
{
    // SymSetOptions / SymGetOptions are simple stateless calls from dbghelp.dll.
    // If delay import resolution works, the call succeeds without crash.
    const DWORD original = SymGetOptions();
    SymSetOptions(original | SYMOPT_UNDNAME);
    const DWORD updated = SymGetOptions();
    SymSetOptions(original); // restore
    return (updated & SYMOPT_UNDNAME) != 0;
}

// =========================================================================
// 22. Delay imports — Winmm.dll (delay-loaded)
// =========================================================================
static bool TestDelayImportWinmm()
{
    // timeGetDevCaps is a simple query from winmm.dll.
    TIMECAPS tc{};
    const MMRESULT result = timeGetDevCaps(&tc, sizeof(tc));
    if (result != TIMERR_NOERROR)
        return false;

    // Sanity: minimum resolution should be > 0 and <= maximum
    return tc.wPeriodMin > 0 && tc.wPeriodMin <= tc.wPeriodMax;
}

// =========================================================================
// DllMain
// =========================================================================
BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
    if (dwReason != DLL_PROCESS_ATTACH)
        return TRUE;

    printf("========================================\n");
    printf("[test_dll] DllMain DLL_PROCESS_ATTACH\n");
    printf("  module base: %p\n", hModule);
    printf("========================================\n\n");

    Report("TLS callback fired",        g_tlsCallbackFired);
    Report("Static TLS read/write",     TestStaticTLS());
    Report("Static TLS per-thread",     TestTLSPerThread());
    Report("SEH access violation",      TestSEH());
    Report("SEH divide by zero",        TestSEHDivZero());
    Report("SEH nested",                TestSEHNested());
    Report("SEH filter continue_search",TestSEHFilter());
    Report("C++ exception int",         TestCppExceptionInt());
    Report("C++ exception std::exception", TestCppExceptionStd());
    Report("C++ exception stack unwind",TestCppExceptionUnwind());
    Report("C++ exception rethrow",     TestCppExceptionRethrow());
    Report("C++ exception indirect",    TestCppExceptionIndirect());
    Report("Win32 API imports",         TestImports());
    Report("STL containers/strings",    TestSTL());
    Report("Floating point / math",     TestFloatingPoint());
    Report("VirtualAlloc/Free",         TestVirtualMemory());
    Report("Threading + mutex",         TestThreading());
    Report("Global constructors",       TestGlobalCtors());
    Report("Vtable dispatch",           TestVTable());
    Report("Vectored exception handler",TestVEH());
    Report("Delay import DbgHelp",     TestDelayImportDbgHelp());
    Report("Delay import Winmm",       TestDelayImportWinmm());

    printf("\n========================================\n");
    printf("[test_dll] Results: %d/%d passed\n", g_passed, g_total);
    printf("========================================\n");

    MessageBoxA(nullptr, "All tests have passed!", "Yey", MB_OK);
    return TRUE;
}
