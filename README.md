# BLAKE3 C Library

![Language](https://img.shields.io/badge/language-C17-blue.svg)
![Build System](https://img.shields.io/badge/build-Meson-green.svg)
![License](https://img.shields.io/badge/license-CC0%20%2F%20Apache--2.0-lightgrey.svg)
![Platform](https://img.shields.io/badge/platform-Linux-linux.svg)

A modern, high-performance fork of the official [BLAKE3](https://github.com/BLAKE3-team/BLAKE3) C implementation, optimized for Linux workstations and servers. This project integrates a robust **Meson** build system, comprehensive **SIMD** dispatch, and a specialized **parallel hashing API**.

---

## 🚀 Key Features

*   **⚡ Modern Build System**: Fully integrated with **Meson** and **Ninja** for fast, reliable, and portable builds.
*   **🏎️ Aggressive Optimization**: Runtime dispatch for **AVX-512**, **AVX2**, **SSE4.1**, **SSE2**, and **ARM NEON**.
*   **🧵 Parallel Hashing**: Includes a dedicated `blake3_parallel` API for multi-threaded performance.
*   **🐧 Linux Optimized**: Utilizes Linux-specific I/O primitives (`preadv2`, `RWF_NOWAIT`) in the `b3sum` tool.
*   **🛡️ Robust Testing**: Integrated test suite including fuzzing, fault injection, and regression testing.

## 🛠️ Building

### Prerequisites

*   **Compiler**: GCC or Clang (Clang required for sanitizers).
*   **Build System**: Meson (`>=1.2.0`) and Ninja.

### Quick Start

```bash
# Setup the build directory
meson setup build -Dbuildtype=release

# Compile
ninja -C build

# Run tests
ninja -C build test
```

### Debugging & Sanitizers

Enable AddressSanitizer (ASan) and UndefinedBehaviorSanitizer (UBSan) easily:

```bash
CC=clang meson setup build-san \
  -Ddebug_sanitize=true \
  -Dbuildtype=debugoptimized

ninja -C build-san test
```

## 📦 Usage

### Command Line Tool (`b3sum`)

The built `b3sum` binary supports multi-threaded hashing of files and stdin.

```bash
./build/b3sum large_file.iso
./build/b3sum --check checksums.txt
```

### C Library API

#### Standard API (`blake3.h`)

```c
#include "blake3.h"

// ... inside your function
blake3_hasher hasher;
blake3_hasher_init(&hasher);
blake3_hasher_update(&hasher, "hello", 5);

uint8_t output[BLAKE3_OUT_LEN];
blake3_hasher_finalize(&hasher, output, BLAKE3_OUT_LEN);
```

#### Parallel API (`blake3_parallel.h`)

Use the specialized API for high-throughput scenarios:

```c
#include "blake3_parallel.h"

b3p_config_t cfg = b3p_config_default();
cfg.nthreads = 8; // Use 8 threads

b3p_ctx_t *ctx = b3p_create(&cfg);

// One-shot parallel hash
b3p_hash_one_shot(ctx, input_buf, len, key, flags, B3P_METHOD_AUTO, out, 32);

b3p_destroy(ctx);
```

## 🧩 Architecture

This repository is structured to separate concerns:

*   **`src/`**: Core logic (`blake3.c`), SIMD backends (`*.S`, `*.c`), and dispatch (`blake3_dispatch.c`).
*   **`tests/`**: Comprehensive unit tests covering determinism, threading, and edge cases.
*   **`meson.build`**: The source of truth for build configuration and feature detection.

See [HACKING.md](HACKING.md) for deep-dive documentation on internals and adding new backends.

## 📄 License

This code is dual-licensed under CC0 1.0 Universal and Apache License 2.0, matching the upstream BLAKE3 repository.
