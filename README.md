# BLAKE3 C Library

<div align="center">

![Language](https://img.shields.io/badge/language-C17-blue.svg)
![Build System](https://img.shields.io/badge/build-Meson-green.svg)
![License](https://img.shields.io/badge/license-CC0%20%2F%20Apache--2.0-lightgrey.svg)
![Platform](https://img.shields.io/badge/platform-Linux-linux.svg)

**A modern, high-performance fork of the official [BLAKE3](https://github.com/BLAKE3-team/BLAKE3) C implementation.**

</div>

Designed for Linux workstations and high-throughput servers, this project integrates a robust **Meson** build system, comprehensive **SIMD** dispatch, and a specialized **parallel hashing API** not found in the standard C implementation.

---

## 🚀 Key Features

* **⚡ Modern Build System**
    Fully integrated with **Meson** and **Ninja** for fast, reliable, and portable builds, replacing the traditional Makefile/autoconf approach.
* **🏎️ Aggressive Optimization**
    Automatic runtime dispatch for **AVX-512**, **AVX2**, **SSE4.1**, **SSE2**, and **ARM NEON** instruction sets.
* **🧵 Parallel Hashing API**
    Includes a dedicated `blake3_parallel` header and logic for multi-threaded performance in C applications.
* **🐧 Linux Optimized**
    The `b3sum` tool utilizes Linux-specific I/O primitives (`preadv2`, `RWF_NOWAIT`) to maximize disk throughput.
* **🛡️ Robust Testing**
    Integrated test suite including fuzzing, fault injection, and regression testing.

---

## 🛠️ Building & Installation

### Prerequisites

* **Compiler**: GCC or Clang (Clang recommended for sanitizers).
* **Build System**: Meson (`>=1.2.0`) and Ninja.

### Quick Start

```bash
# 1. Setup the build directory
meson setup build -Dbuildtype=release

# 2. Compile
ninja -C build

# 3. Run tests
ninja -C build test

# 4. Install (Optional)
sudo ninja -C build install

```

###Debugging & SanitizersEnable AddressSanitizer (ASan) and UndefinedBehaviorSanitizer (UBSan) for development:

```bash
CC=clang meson setup build-san \
  -Ddebug_sanitize=true \
  -Dbuildtype=debugoptimized

ninja -C build-san test

```

---

##📦 Usage###Command Line Tool (`b3sum`)The built `b3sum` binary supports multi-threaded hashing of files and stdin.

```bash
# Hash a large file using available threads
./build/b3sum large_file.iso

# Verify checksums
./build/b3sum --check checksums.txt

```

###C Library API####Standard API (`blake3.h`)This mimics the upstream API for single-threaded hashing.

```c
#include "blake3.h"

// ... inside your function
blake3_hasher hasher;
blake3_hasher_init(&hasher);

// Update with data
blake3_hasher_update(&hasher, "hello", 5);

// Finalize to 32-byte output
uint8_t output[BLAKE3_OUT_LEN];
blake3_hasher_finalize(&hasher, output, BLAKE3_OUT_LEN);

```

####Parallel API (`blake3_parallel.h`)Use the specialized API for high-throughput scenarios (e.g., hashing multi-GB buffers).

```c
#include "blake3_parallel.h"

// Configure parallelism
b3p_config_t cfg = b3p_config_default();
cfg.nthreads = 8; // Force 8 threads

// Create context
b3p_ctx_t *ctx = b3p_create(&cfg);

// One-shot parallel hash
// (ctx, input, length, key, flags, method, output, out_len)
b3p_hash_one_shot(ctx, input_buf, len, NULL, 0, B3P_METHOD_AUTO, out, 32);

// Clean up
b3p_destroy(ctx);

```

---

##🧩 ArchitectureThis repository is structured to separate concerns:

| Directory | Description |
| --- | --- |
| **`src/`** | Core logic (`blake3.c`), SIMD backends (`*.S`, `*.c`), and dispatch (`blake3_dispatch.c`). |
| **`tests/`** | Comprehensive unit tests covering determinism, threading, and edge cases. |
| **`meson.build`** | The source of truth for build configuration, dependency management, and feature detection. |

See [HACKING.md](HACKING.md) for deep-dive documentation on internals and adding new architecture backends.

---

##📄 License & CreditsThis code is dual-licensed under **CC0 1.0 Universal** and **Apache License 2.0**, matching the upstream BLAKE3 repository.

###Credits**Original BLAKE3 Designers:**

* Jack O'Connor
* Jean-Philippe Aumasson
* Samuel Neves
* Zooko Wilcox

**Contributors:**

* *Open to contributions! Please submit a PR.*
