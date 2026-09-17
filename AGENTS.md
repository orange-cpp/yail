# AGENTS.md

These instructions apply to the entire repository.

## Project overview

YAIL is a legit Windows-only C++23 static library for manually mapping PE images. It supports native x64 and x86 injection, plus x86 payloads in WOW64 targets from an x64 build. The implementation deals with PE parsing, relocations, imports, TLS, exception tables, SafeSEH, remote shellcode, and private `ntdll` symbols.

Correctness across architecture and Windows loader behavior is more important than broad refactoring.

## Working principles

- State assumptions before implementing. If behavior has multiple materially different interpretations, ask rather than silently choosing one.
- Prefer the smallest change that completely solves the requested problem.
- Touch only lines that trace directly to the task. Do not reformat, modernize, or clean up adjacent code without a request.
- Preserve all unrelated worktree changes. Files may already contain user edits.
- Match the existing naming, formatting, and control-flow style.
- Do not introduce abstractions for a single use or speculative future requirements.
- For multi-step work, define concise, verifiable success criteria and iterate until they pass.

## C++ conventions

- Use C++23 and keep MSVC compatibility. The library builds with warnings as errors (`/W4 /WX`).
- Public and internal fallible operations use `std::expected<T, yail::Error>`. Do not reintroduce allocated string error channels.
- Add a focused `yail::Error` enumerator when a new failure needs to be distinguished, and update `yail::to_string` in the same change.
- Keep the public API under `include/yail/`; implementation details belong under `include/yail/detail/` and `source/`.
- Use RAII for Windows handles and allocations where an existing project wrapper fits. Every failure path must release resources it acquired.
- Avoid complex CRT, allocation, synchronization, or logging work inside `DllMain` and TLS callbacks unless the task specifically requires and validates it.
- Do not assume a target process has a console or valid `stdout`/`stderr`. Prefer explicit logging sinks or `OutputDebugString` for diagnostics.

## Loader-specific invariants

- Preserve both native and WOW64 paths when changing PE mapping or symbol resolution.
- Private `ntdll` symbol RVAs come exclusively from the PDB matching the exact loaded image's RSDS record, downloaded from the Microsoft symbol server. There is no signature-scan fallback; a failed download is a hard error.
- PDB identity must come from the exact loaded image's RSDS record; never use a hard-coded symbol-server identity.
- `RtlInsertInvertedFunctionTable` is required for x64 and optional for x86 as documented by the current call sites.
- Do not change calling conventions for private `ntdll` functions without validating the affected Windows architecture and build.
- Preserve cleanup ordering for remote image memory, shellcode memory, process handles, and thread handles.
- Treat `source/shellcode.cpp` as generated output. Change the reference implementation in `tools/generate_shellcode.cpp`, then regenerate both x64 and x86 output.

## Build and verification

Use the repository presets and build directories; there are no CMake build presets.

```powershell
cmake --preset windows-debug-vcpkg
cmake --build cmake-build/build/windows-debug-vcpkg

cmake --preset windows-debug-vcpkg-x86
cmake --build cmake-build/build/windows-debug-vcpkg-x86
```

Repeat the relevant checks with `windows-debug-vcpkg-x86` for x86-sensitive changes. The presets share `cmake-build/vcpkg_installed`; avoid configuring x64 and x86 concurrently because manifest operations can race over that directory.

For loader changes, run the bundled DLL test from each relevant build directory:

```powershell
cmake-build/build/windows-debug-vcpkg/loader.exe cmake-build/build/windows-debug-vcpkg/test_dll.dll
cmake-build/build/windows-debug-vcpkg-x86/loader.exe cmake-build/build/windows-debug-vcpkg-x86/test_dll.dll
```

The expected DLL result is `23/23 passed`. Also exercise the specific failure path or regression introduced by the task. Documentation-only changes do not require the full build matrix.

After changing shellcode logic, regenerate output with both generator binaries as described in `README.md`, then rebuild and run the relevant loader tests.

## Documentation and delivery

- Update `README.md` when public APIs, build options, supported behavior, or user-visible limitations change.
- Keep examples aligned with the public API, but preserve user-specific example edits that are unrelated to the task.
- Before finishing, run `git diff --check`, inspect `git status --short`, and report verification performed plus any limitation that remains.
