# HACKING.md - Developer Guide for BLAKE3 C Library Fork

This document provides guidance for developers working on this fork of the BLAKE3 C library and the homemade `b3sum` implementation. It covers the project structure, build system, architecture, and how to extend the codebase.

## Table of Contents

1. [Project Overview](#project-overview)
2. [Build System](#build-system)
3. [Library Architecture](#library-architecture)
4. [b3sum Tool Architecture](#b3sum-tool-architecture)
5. [Adding New SIMD Implementations](#adding-new-simd-implementations)
6. [Testing and Benchmarking](#testing-and-benchmarking)
7. [Debugging and Sanitizers](#debugging-and-sanitizers)
8. [Contributing Guidelines](#contributing-guidelines)

## Project Overview

This repository is a fork of the official BLAKE3 C implementation with enhancements, particularly in the `b3sum` command-line tool. The library provides high-performance hashing with runtime CPU feature detection and SIMD acceleration.

### Key Components

- **Core Library**: `src/blake3.c`, `src/blake3.h`, `src/blake3_impl.h`
- **SIMD Dispatch**: `src/blake3_dispatch.c` - runtime CPU feature detection
- **Portable Implementation**: `src/blake3_portable.c` - pure C fallback
- **x86 SIMD Implementations**:
  - Assembly: `src/blake3_*_x86-64_unix.S` (SSE2, SSE4.1, AVX2, AVX-512)
  - Intrinsics: `src/blake3_*.c` (SSE2, SSE4.1, AVX2, AVX-512)
- **ARM NEON Implementation**: `src/blake3_neon.c`
- **b3sum Tool**: `src/b3sum.c` - feature-rich parallel hashing utility (serves as the primary example)
- **Build System**: Meson with Ninja backend (replaces CMake from upstream)
- **Test Suite**: `test` - benchmark script comparing C vs Rust implementations

**Note**: The upstream `example.c` mentioned in README.md is not included in this fork. The `b3sum` tool demonstrates comprehensive API usage and can serve as a reference implementation.

## Build System

The project uses Meson as the primary build system. Key features:

- Automatic CPU feature detection and runtime dispatch
- Shared library (`libblake3.so`) and executable (`b3sum`) generation
- Link Time Optimization (LTO) support
- Sanitizer support (Address/Undefined) with Clang
- pkg-config file generation

### Building

```bash
# Configure and build
meson setup build
meson compile -C build

# Install
meson install -C build
```

### Build Options

- `debug_sanitize` (boolean): Enable address and undefined behavior sanitizers (requires Clang)
- See `meson_options.txt` for available options

### Manual Compilation

While Meson is recommended, you can compile manually for integration with other build systems. Note that the original README.md references CMake, but this fork uses Meson as the primary build system.

```bash
# x86_64 Linux with assembly implementations
gcc -shared -O3 -o libblake3.so src/blake3.c src/blake3_dispatch.c src/blake3_portable.c \
    src/blake3_sse2_x86-64_unix.S src/blake3_sse41_x86-64_unix.S \
    src/blake3_avx2_x86-64_unix.S src/blake3_avx512_x86-64_unix.S

# With intrinsics (requires per-file compiler flags)
gcc -c -fPIC -O3 -msse2 src/blake3_sse2.c -o blake3_sse2.o
gcc -c -fPIC -O3 -msse4.1 src/blake3_sse41.c -o blake3_sse41.o
gcc -c -fPIC -O3 -mavx2 src/blake3_avx2.c -o blake3_avx2.o
gcc -c -fPIC -O3 -mavx512f -mavx512vl src/blake3_avx512.c -o blake3_avx512.o
gcc -shared -O3 -o libblake3.so src/blake3.c src/blake3_dispatch.c src/blake3_portable.c \
    blake3_avx2.o blake3_avx512.o blake3_sse41.o blake3_sse2.o
```

## Library Architecture

### Public API (`blake3.h`)

The public API provides incremental hashing with support for keyed hashing and key derivation. Key structures and functions:

- `blake3_hasher`: Opaque struct (1912 bytes on x86-64)
- `blake3_hasher_init()`: Default hashing mode
- `blake3_hasher_update()`: Add input data (single-threaded)
- `blake3_hasher_finalize()`: Produce output of any length
- `blake3_hasher_init_keyed()`: Keyed hashing mode (32-byte key)
- `blake3_hasher_init_derive_key()`: Key derivation mode

### Internal Architecture (`blake3_impl.h`)

- Platform detection macros (`IS_X86`, `IS_AARCH64`)
- SIMD degree configuration (x86: max 16, NEON: max 4, portable: 1)
- Internal flags for chunk/parent/root/keyed/derive modes
- `INLINE` macro for cross-compiler forced inlining

### SIMD Dispatch

`blake3_dispatch.c` implements runtime CPU feature detection using CPUID (x86) or `getauxval` (ARM). It selects the best available implementation:

1. AVX-512 (if supported)
2. AVX2
3. SSE4.1
4. SSE2
5. Portable C fallback

A helper script `src/check_cpu_features.py` is provided for debugging CPU feature detection.

### Implementation Layers

1. **Core Algorithm** (`blake3.c`): Chunk state management, output construction
2. **Compression Functions**: Multiple implementations per SIMD level
3. **Dispatch Layer**: Runtime CPU feature detection
4. **SIMD Backends**: Assembly (preferred) and intrinsics versions

## b3sum Tool Architecture

The homemade `b3sum` tool is a feature-rich parallel file hasher with several optimizations:

### Key Features

- Multi-threaded file hashing with pthreads
- Directory traversal support
- Memory-mapped I/O and asynchronous I/O (Linux-specific)
- Thread-local I/O buffers with alignment optimization
- Task queue system for parallel file processing
- Support for both streaming and tree-based hashing

### Thread Pool and Task Queue

- Fixed-size thread pool based on available CPU cores
- Lock-free task queue with size 32768 (power of two)
- Work-stealing design for load balancing
- Thread-local I/O buffers to avoid contention

### I/O Optimizations

- Memory-mapped files for large files
- Asynchronous I/O with `preadv2` and `RWF_NOWAIT` on Linux
- Buffer alignment optimized for Linux (4096-byte) and other systems (64-byte)
- Configurable buffer sizes (1 MiB default, up to 8 MiB)

### Tree-based Hashing

The tool implements `blake3_hash_region_tree()` for efficient hashing of large memory regions using BLAKE3's tree mode. This is used for memory-mapped files.

### Command-line Options

The tool supports standard `b3sum` options plus extensions for parallelism and I/O tuning.

## Adding New SIMD Implementations

To add a new SIMD implementation (e.g., for a new ISA extension):

### 1. Create Implementation Files

- **Assembly**: Create `src/blake3_<isa>_<arch>_<os>.S` following existing patterns
- **Intrinsics**: Create `src/blake3_<isa>.c` with `BLAKE3_INLINE` functions

### 2. Update Dispatch Logic

Modify `src/blake3_dispatch.c`:

- Add CPU feature detection for the new ISA
- Update `blake3_get_implementation()` to check for the feature
- Define the compression function pointer

### 3. Update Build System

Modify `meson.build`:

- Add new source files to `blake3_sources` list
- Add appropriate compiler flags if needed

### 4. Testing

- Verify correctness against portable implementation
- Benchmark performance improvement

## Testing and Benchmarking

### Test Script

The `test` script performs comprehensive benchmarking:

- **Large file throughput**: Tests from 4 MiB to 8192 MiB
- **Many small files**: Tests syscall/dcache bound performance (5000 files)
- **Cache neutralization**: Alternates run order and drops caches when possible
- **Hash verification**: Ensures C and Rust implementations produce identical results

### Running Tests

```bash
# Ensure Rust b3sum is installed at /usr/bin/b3sum_rust
chmod +x test
./test
```

### Test Requirements

- `/usr/bin/b3sum_rust` (Rust reference implementation)
- GNU time (`/usr/bin/time`)
- Python 3, standard Unix utilities

### Adding Tests

For new features, consider adding:

1. Unit tests for specific functions
2. Integration tests for command-line options
3. Performance regression tests

## Debugging and Sanitizers

### Sanitizer Support

The build system supports AddressSanitizer and UndefinedBehaviorSanitizer when using Clang:

```bash
meson setup build -Ddebug_sanitize=true
meson compile -C build
```

### Debug Builds

For debugging, modify `meson.build` or create a debug build:

```bash
meson setup build --buildtype=debug
meson compile -C build
```

### Common Debugging Techniques

1. **Thread issues**: Use `helgrind` or `tsan` (ThreadSanitizer)
2. **Memory issues**: Use `valgrind` or ASan
3. **Performance profiling**: Use `perf`, `gprof`, or `flamegraph`

## Contributing Guidelines

### Code Style

The project uses Chromium-style C formatting with 4-space indentation. A `.clang-format` file is provided:

```bash
# Format a file
clang-format -i src/filename.c
```

### Commit Messages

Follow the existing commit history style:
- Concise summary line (50-72 characters)
- Detailed description if needed
- Reference issues or PRs when applicable

### Pull Requests

1. **Branch**: Create a feature branch from `master`
2. **Testing**: Ensure all tests pass
3. **Benchmarks**: Check for performance regressions
4. **Documentation**: Update relevant documentation

### Areas for Contribution

1. **New platforms**: Support for additional architectures (RISC-V, POWER, etc.)
2. **Performance optimizations**: Improved SIMD implementations, better scheduling
3. **Features**: Additional command-line options, integration with other tools
4. **Testing**: Expanded test coverage, CI integration

## Additional Resources

- [Official BLAKE3 Specification](https://github.com/BLAKE3-team/BLAKE3-specs)
- [BLAKE3 C Implementation](https://github.com/BLAKE3-team/BLAKE3/tree/master/c)
- [Meson Build System Documentation](https://mesonbuild.com/)

---

*This document was auto-generated based on the project state as of December 2025.*