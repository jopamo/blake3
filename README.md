# b3sum / libblake3

`b3sum` and `libblake3` provide fast BLAKE3 hashing for Linux users who need both a CLI checksum tool and a C library with parallel one-shot APIs.
This project does not try to be a full file-integrity platform (no signing, no key management, no recursive policy engine).

## Why This Exists

This fork exists for workloads where hashing overhead matters: large files, many files, and repeated checksum verification in CI or artifact pipelines.

A practical example: a build farm can hash many artifacts with `b3sum -j N` and verify manifests with strict parsing in CI, while services can call `b3p_hash_unkeyed()` directly to avoid shelling out.

## Quickstart (Fastest Path)

Build from source:

```bash
meson setup build -Dbuildtype=release
ninja -C build
```

Hash a payload from stdin:

```bash
printf abc | ./build/b3sum
```

Expected output shape:

```text
6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85  -
```

You just computed a 256-bit BLAKE3 digest and printed it in `hex  <name>` format (`-` means stdin).

## Common Workflows

### 1) Hash files for release artifacts

Goal: produce a checksum manifest.

Command:

```bash
./build/b3sum artifact.tar.zst artifact.sig > SHA256SUMS.b3
```

What to look for: each line is `64-hex-digest`, two spaces, then filename.

Common mistake + fix: passing directories directly. `b3sum` hashes file paths, not directory trees; feed an explicit file list (for example via `find ... -type f`).

### 2) Verify checksums in CI with strict parsing

Goal: fail if any file mismatches or manifest lines are malformed.

Command:

```bash
./build/b3sum --check --strict --warn SHA256SUMS.b3
```

What to look for: `path: OK` per file and process exit code `0`.

Common mistake + fix: using `--check` without `--strict`; malformed lines are otherwise ignored and can make verification look successful. Add `--strict` for fail-closed behavior.

### 3) Use BSD-style tagged checksum format

Goal: produce/verify tagged lines (`BLAKE3 ...`) for tooling that expects BSD-style tags.

Commands:

```bash
./build/b3sum --tag file.bin > file.bin.tag.b3
./build/b3sum --check --tag file.bin.tag.b3
```

What to look for: `BLAKE3 <hex>  <filename>` in the manifest, and `filename: OK` when verifying.

Common mistake + fix: forgetting `--tag` during verification; lines are treated as invalid input and may be silently skipped unless `--strict`/`--warn` is set.

### 4) Hash many files faster

Goal: improve throughput across many independent files.

Command:

```bash
./build/b3sum -j 16 dist/*
```

What to look for: same digest format, lower wall-clock time for many files.

Common mistake + fix: setting `-j` too high for your storage path; if performance drops, reduce jobs to match actual disk bandwidth.

### 5) Use parallel one-shot API from C

Goal: hash in-memory buffers directly from C code.

```c
#include <b3sum/blake3_parallel.h>

b3p_ctx_t *ctx = b3p_create(NULL); // default config
uint8_t out[BLAKE3_OUT_LEN];
int rc = b3p_hash_unkeyed(ctx, input, input_len, B3P_METHOD_AUTO, out, sizeof(out));
b3p_destroy(ctx);
```

What to look for: return code `0` on success, `-1` on invalid inputs or runtime failure.

Common mistake + fix: passing `NULL` pointers with non-zero lengths. Only `NULL + len=0` is valid.

## Concepts You Must Understand

### Hash mode vs check mode

Hash mode computes digests from input files/stdin. Check mode (`--check`) parses a manifest and re-hashes referenced files. These are different code paths and different failure semantics.

Wrong assumption: "`--check` always fails on bad lines."  
Correction: it only fails on malformed lines when `--strict` is set.

### Safe wrappers vs raw CV APIs

`b3p_hash_unkeyed*`, `b3p_hash_keyed*`, and `b3p_hash_derive*` are safe wrappers for the three core BLAKE3 modes. `b3p_hash_raw_cv_*` and legacy `b3p_hash_one_shot*` expose raw chaining value + flags and are easier to misuse.

Wrong assumption: "Legacy `b3p_hash_one_shot*` means normal unkeyed hashing by default."  
Correction: it is a raw API; use safe wrappers unless you intentionally map CV/flags yourself.

### Parallel hashing is workload-dependent

The library auto-selects method/parallelism (`B3P_METHOD_AUTO`) based on input size and config thresholds. Small inputs can be faster in serial paths due to lower overhead.

Wrong assumption: "More threads always means faster."  
Correction: parallelism helps mostly for large buffers or many files, not tiny payloads.

## Configuration

### CLI options that matter most

- `--check`: switch to verification mode.
- `--strict`: in check mode, malformed input lines become hard failures.
- `--warn`: in check mode, print warnings for malformed input lines.
- `--quiet`: in check mode, suppress `OK` lines (failures still matter by exit code).
- `--status`: suppress normal output; rely on exit code.
- `--ignore-missing`: in hash mode, ignore missing input files instead of failing.
- `--tag`: emit/expect BSD-style `BLAKE3 ...` lines.
- `--zero`: terminate output records with NUL.
- `-j, --jobs N`: number of worker threads (default: online CPU count).

### Library config defaults (`b3p_config_default()`)

- `nthreads=0`: auto thread count.
- `min_parallel_bytes=16384`: below this, avoid parallel overhead.
- `method_a_min_chunks=4`: minimum chunks before method A pays off.
- `method_b_min_chunks_per_thread=16`: minimum work per thread for method B.
- `subtree_chunks=512`: subtree partition size.
- `autotune_enable=1`, `autotune_sample_mask=63`.

Safe config example (verification pipeline):

```bash
./build/b3sum --check --strict --warn manifest.b3
```

Dangerous config example (can appear successful while skipping bad lines):

```bash
./build/b3sum --check manifest.b3
```

## Operational Notes

- Regular-file hashing prefers contiguous-buffer paths and uses `mmap` when possible.
- Small regular files (`<= 1 MiB`) use serial one-shot hashing to avoid thread overhead.
- Larger regular files use the parallel API with thread count capped by available coarse work.
- Non-regular files and non-mmapable paths fall back to streaming reads.
- For many files (`>= 64` paths, unless `-j 1`), `b3sum` uses an internal per-file worker pool.
- Per-thread I/O buffers grow up to 8 MiB in streaming paths.
- There is no persistent state: no cache database, no background daemon, no on-disk metadata beyond files you create.

Useful output controls:

- `--warn` and `--strict` for check-mode manifest quality.
- `--quiet` and `--status` for CI-friendly output/exit behavior.
