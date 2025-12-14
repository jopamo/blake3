# BLAKE3 C Library

## Project Overview

This is a high-performance fork of the BLAKE3 C implementation, optimized for modern Linux systems. It features a robust Meson build system, aggressive SIMD usage with runtime dispatch (x86-64 and ARM NEON), and a specialized parallel hashing API.

**Key Features:**
*   **Modern Build:** Meson + Ninja
*   **Parallelism:** Dedicated `blake3_parallel` API and multi-threaded `b3sum` CLI tool.
*   **Optimization:** Runtime SIMD dispatch (SSE2, SSE4.1, AVX2, AVX-512, NEON) and Linux-specific I/O optimizations (`preadv2`, `RWF_NOWAIT`).
*   **Portability:** Clean separation of portable and architecture-specific code.

## Building and Running

### Prerequisites
*   **Compiler:** GCC or Clang (Clang required for sanitizers).
*   **Build Tools:** Meson (`>=1.2.0`), Ninja.
*   **Dependencies:** `pkg-config`, `libpthread` (implied on Linux).

### Build Commands

**Standard Release Build:**
```bash
meson setup build -Dbuildtype=release
ninja -C build
```

**Debug Build with Sanitizers (Clang only):**
```bash
CC=clang meson setup build-asan -Ddebug_sanitize=true -Dbuildtype=debugoptimized
ninja -C build-asan
```

**Running the CLI Tool:**
The built executable is located at `build/b3sum`.
```bash
./build/b3sum --help
./build/b3sum test_file
```

## Testing

The project maintains a comprehensive test suite managed by Meson.

**Run All Tests:**
```bash
ninja -C build test
```

**Run Specific Test Suite:**
```bash
# Example: Run the comprehensive parallel API tests
./build/test_b3p_comprehensive
```

**Legacy/Interop Testing:**
The root `test` script benchmarks and verifies output against the reference Rust implementation (requires `b3sum_rust` in path).
```bash
./test
```

## Development Conventions

*   **Language Standard:** C17.
*   **Coding Style:** Chromium-style C formatting. Enforced via `.clang-format`.
    *   Run formatter: `clang-format -i src/filename.c`
*   **Architecture:**
    *   **Public API:** `src/blake3.h` (Standard), `src/blake3_parallel.h` (Parallel Extensions).
    *   **Internals:** `src/blake3_impl.h`.
    *   **Dispatch:** `src/blake3_dispatch.c` handles runtime CPU feature detection.
    *   **SIMD:** Architecture-specific implementations reside in `src/*.S` (assembly) or `src/*.c` (intrinsics).
*   **CI:** GitHub Actions workflow (`.github/workflows/ci.yml`) validates builds on Fedora (containerized) using Clang + ASan/UBSan.

## Directory Structure

*   `src/`: Source code for the library and `b3sum` tool.
*   `tests/`: Unit test sources (C files) and test scripts.
*   `meson.build`: Primary build configuration.
*   `meson_options.txt`: Build options definitions.
