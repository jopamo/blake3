# HACKING / Internal Design

This document provides a high-level overview of the codebase for contributors and curious developers. It covers the directory structure, build system, dynamic dispatch mechanism, and the parallel hashing implementation.

## 📂 Project Structure

| Path | Description |
|---|---|
| `meson.build` | The root build configuration. Defines targets, dependencies, and compiler flags. |
| `src/` | Source code for the library and the `b3sum` CLI. |
| `src/blake3_dispatch.c` | **Runtime SIMD dispatch**. Selects the best implementation for the host CPU at runtime. |
| `src/blake3_parallel.c` | **Parallel API** logic. Manages thread pools and chunk distribution. |
| `src/*_avx*.c`, `*_sse*.c` | Architecture-specific assembly or intrinsic implementations. |
| `tests/` | Test suite, including unit tests, regression tests, and fuzz targets. |

## 🛠️ Build System (Meson)

We use [Meson](https://mesonbuild.com/) for its speed and correctness.

### Build Types
* **Release**: `-Dbuildtype=release` - High optimization (`-O3`), asserts disabled.
* **Debug**: `-Dbuildtype=debug` - Low optimization, debug info, asserts enabled.
* **Debug Optimized**: `-Dbuildtype=debugoptimized` - `-O2` with debug info.

### Feature Flags
Options are defined in `meson_options.txt`.
* `-Dsimd=true/false`: Enable/disable SIMD optimizations.
* `-Ddebug_sanitize=true`: Enable ASan and UBSan (requires Clang).

## ⚡ Dynamic Dispatch (`src/blake3_dispatch.c`)

The library aims to run the fastest possible code for the user's CPU. This is handled by `blake3_dispatch.c`.

1. **Detection**: On the first call, we check CPU features (using `cpuid` on x86 or auxiliary vectors on Linux/ARM).
2. **Selection**: A global function pointer is updated to point to the best available implementation (e.g., AVX-512, AVX2, SSE4.1, or Portable).
3. **Execution**: Subsequent calls go directly to the optimized function.

## 🧵 Parallel Hashing (`src/blake3_parallel.c`)

The `blake3_parallel.h` API implements a divide-and-conquer strategy for large buffers.

* **Chunking**: Input is split into chunks (default 1 MiB).
* **Work Stealing**: We use a lightweight thread pool where threads process chunks independently.
* **Merkle Tree**: The results of chunks are combined into a Merkle tree. The root of this tree is the final hash.

**Key Design Goal**: Avoid global locks where possible. Each thread computes its subtree independently, and the main thread aggregates the final results.

## 🧪 Testing

The `tests/` directory contains:
* **`test_vectors.c`**: Validates output against known official BLAKE3 test vectors.
* **`test_parallel.c`**: Verifies the threaded implementation produces the same output as the serial one.
* **`test_cli.sh`**: Integration tests for the `b3sum` command-line tool.

To run tests:
```bash
ninja -C build test
```

## 📝 Coding Style

* **Standard**: C17.
* **Formatting**: We use `clang-format`. Please run `ninja -C build clang-format` (if configured) or check `.clang-format` before committing.
* **Safety**:
    * Prefer fixed-width integers (`uint8_t`, `size_t`).
    * Use `const` correctness liberally.
    * Check for integer overflows in length calculations.
