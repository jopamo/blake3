# b3sum / libblake3

`b3sum` and `libblake3` provide high-performance BLAKE3 hashing for Linux users who want:

* A fast CLI checksum tool
* A C library with parallel one-shot APIs

This project focuses strictly on hashing.
It does **not** provide signing, key management, recursive integrity policies, or a full integrity platform.

---

## Why This Exists

This fork targets workloads where hashing cost matters:

* Large files
* Many files
* Repeated verification in CI or artifact pipelines

Example:

* A build farm hashes artifacts with `b3sum -j N`
* CI verifies manifests using strict parsing
* Services call `b3p_hash_unkeyed()` directly instead of shelling out

---

## Quickstart (Fastest Path)

### Build

```bash
meson setup build -Dbuildtype=release
ninja -C build
```

### Hash stdin

```bash
printf abc | ./build/b3sum
```

Example output:

```text
6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85  -
```

Output format:

```
<64-hex-digest><two spaces><filename>
```

`-` indicates stdin.

---

# Common Workflows

---

## 1) Produce a release manifest

**Goal:** generate a checksum file.

```bash
./build/b3sum artifact.tar.zst artifact.sig > BLAKE3SUMS
```

Output format per line:

```
<64-hex-digest>  <filename>
```

**Common mistake:** hashing directories directly
`b3sum` hashes file paths, not trees.

Correct approach:

```bash
find dist -type f -print0 | xargs -0 ./build/b3sum > BLAKE3SUMS
```

---

## 2) Verify in CI (fail-closed)

**Goal:** fail on mismatches *and* malformed manifest lines.

```bash
./build/b3sum --check --strict --warn BLAKE3SUMS
```

Expected:

```
path/to/file: OK
```

Exit code `0` = success.

**Common mistake:** using `--check` without `--strict`

Without `--strict`, malformed lines are ignored and verification may appear successful.

---

## 3) BSD-style tagged format

**Goal:** use `BLAKE3 ...` tagged lines.

Generate:

```bash
./build/b3sum --tag file.bin > file.bin.b3
```

Verify:

```bash
./build/b3sum --check --tag file.bin.b3
```

Manifest format:

```
BLAKE3 <hex>  <filename>
```

**Common mistake:** forgetting `--tag` during verification
Lines may be treated as invalid unless `--strict` or `--warn` is set.

---

## 4) Hash many files faster

**Goal:** increase throughput across many independent files.

```bash
./build/b3sum -j 16 dist/*
```

Output format is unchanged. Wall-clock time drops for sufficiently parallel workloads.

**Common mistake:** setting `-j` higher than storage can sustain
If performance drops, reduce jobs to match actual disk bandwidth.

---

## 5) Hash memory buffers from C

**Goal:** hash in-memory data without invoking the CLI.

```c
#include <b3sum/blake3_parallel.h>

b3p_ctx_t *ctx = b3p_create(NULL);
uint8_t out[BLAKE3_OUT_LEN];

int rc = b3p_hash_unkeyed(
    ctx,
    input,
    input_len,
    B3P_METHOD_AUTO,
    out,
    sizeof(out)
);

b3p_destroy(ctx);
```

Success: return `0`
Failure: return `-1`

**Common mistake:** passing `NULL` with non-zero length
Only `NULL + len=0` is valid.

---

# Core Concepts

---

## Hash Mode vs Check Mode

**Hash mode**
Computes digests from files or stdin.

**Check mode (`--check`)**
Parses a manifest and re-hashes referenced files.

They use different code paths and failure semantics.

Wrong assumption:

> "`--check` fails on bad lines"

Correction:
It fails on malformed lines only when `--strict` is set.

---

## Safe Wrappers vs Raw CV APIs

Safe wrappers:

* `b3p_hash_unkeyed*`
* `b3p_hash_keyed*`
* `b3p_hash_derive*`

Raw APIs (advanced use only):

* `b3p_hash_raw_cv_*`
* legacy `b3p_hash_one_shot*`

Wrong assumption:

> "`b3p_hash_one_shot*` is normal unkeyed hashing"

Correction:
It exposes raw chaining value + flags. Use wrappers unless you intentionally control CV and flags.

---

## Parallelism Is Workload-Dependent

Default mode: `B3P_METHOD_AUTO`

The library chooses method and thread use based on:

* Input size
* Config thresholds
* Available CPUs

Wrong assumption:

> "More threads always means faster"

Correction:
Parallelism benefits large buffers or many files.
Small inputs often run faster in serial paths.

---

# Configuration

---

## CLI Options That Matter Most

Verification controls:

* `--check`
* `--strict`
* `--warn`
* `--quiet`
* `--status`

Hashing controls:

* `--ignore-missing`
* `--tag`
* `--zero`
* `-j, --jobs N`

---

## Library Defaults (`b3p_config_default()`)

* `nthreads = 0` (auto)
* `min_parallel_bytes = 16384`
* `method_a_min_chunks = 4`
* `method_b_min_chunks_per_thread = 16`
* `subtree_chunks = 512`
* `autotune_enable = 1`
* `autotune_sample_mask = 63`

---

### Safe CI Example

```bash
./build/b3sum --check --strict --warn manifest.b3
```

### Risky Example

```bash
./build/b3sum --check manifest.b3
```

This may appear successful while silently skipping malformed lines.

---

# Operational Notes

* Regular files prefer contiguous-buffer paths.
* `mmap` is used when possible.
* Files ≤ 1 MiB use serial one-shot hashing.
* Larger files use the parallel API with work-based thread caps.
* Non-regular files fall back to streaming reads.
* ≥ 64 files (unless `-j 1`) trigger a per-file worker pool.
* Per-thread I/O buffers grow up to 8 MiB.
* No persistent state, cache database, daemon, or metadata storage.

---

## CI-Friendly Output Controls

* `--strict` + `--warn` → manifest quality enforcement
* `--quiet` → suppress `OK`
* `--status` → exit-code-only behavior
