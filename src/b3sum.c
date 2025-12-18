/* src/b3sum.c
 * Command line utility for calculating BLAKE3 checksums
 */

#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <sys/types.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/uio.h>
#include <unistd.h>

#include "blake3.h"
#include "blake3_parallel.h"
#include "blake3_impl.h"

#if defined(__linux__)
#include <sys/syscall.h>
#ifndef RWF_NOWAIT
#define RWF_NOWAIT 0x00000008
#endif
#endif

#if defined(__linux__) && defined(SYS_preadv2) && defined(RWF_NOWAIT)
#define HAVE_PREADV2_NOWAIT 1
#else
#define HAVE_PREADV2_NOWAIT 0
#endif

/* I/O buffer sizing tuned for throughput on typical NVMe and page cache */
#define DEFAULT_BUF (1 << 20) /* 1 MiB default streaming buffer */
#define MAX_BUF (8 << 20)     /* 8 MiB upper cap for a single buffer */

#if defined(__linux__)
#define IO_BUFFER_ALIGNMENT 4096
#else
#define IO_BUFFER_ALIGNMENT 64
#endif

#define STREAM_BUF_MIN ((size_t)DEFAULT_BUF)
#define STREAM_BUF_MAX ((size_t)MAX_BUF)

/* Per-thread reusable I/O buffer
   Each worker owns a private buffer to avoid malloc/free churn and false sharing */
static __thread uint8_t* tls_io_buf = NULL;
static __thread size_t tls_io_buf_cap = 0;

/* stdout is the only serialized resource
   Keep the lock held only during printing */
static pthread_mutex_t output_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Thread‑local output buffer for batching print calls
   Each thread accumulates formatted lines here and flushes them under the mutex */
static __thread char* tls_out_buf = NULL;
static __thread size_t tls_out_cap = 0;
static __thread size_t tls_out_len = 0;

/* Program options
   Stored as ints for easy zero-init */
typedef struct {
    int check;           // verify hashes instead of printing
    int tag;             // include BLAKE3 tag header
    int zero;            // use null byte terminator
    int ignore_missing;  // skip missing files silently
    int quiet;           // suppress normal output
    int status;          // exit nonzero if mismatch
    int strict;          // reject malformed inputs
    int warn;            // print warnings on parse errors
    int jobs;            // number of worker threads (0 = auto)
} program_opts;

/* Forward declarations */
static int blake3_hash_region_tree(const uint8_t* data, size_t len, uint8_t out_hash[BLAKE3_OUT_LEN]);
static void print_hash_buffered(const uint8_t* hash, const char* filename, int tag, int zero);
static void append_result_to_buffer(const uint8_t* hash, const char* filename, int is_check_mode, const uint8_t* expected, const program_opts* opts, int rc, int saved_errno);
static int process_paths_parallel_tiny(const program_opts* opts, char** files, int fc);

/* Thread-local buffer helpers */

/* ensure_tls_io_buffer
   Ensures the calling thread has a private I/O buffer of at least min_bytes
   Fast path returns the existing buffer when large enough
   Growth rounds up to an alignment boundary suitable for page-cache friendly I/O */
static uint8_t* ensure_tls_io_buffer(size_t min_bytes, size_t* actual_size) {
    if (min_bytes < STREAM_BUF_MIN)
        min_bytes = STREAM_BUF_MIN;

    if (min_bytes <= tls_io_buf_cap) {
        if (actual_size)
            *actual_size = tls_io_buf_cap;
        return tls_io_buf;
    }

    size_t aligned = (min_bytes + (IO_BUFFER_ALIGNMENT - 1)) & ~(IO_BUFFER_ALIGNMENT - 1);

    uint8_t* newbuf;
#if defined(_POSIX_C_SOURCE) && (_POSIX_C_SOURCE >= 200112L)
    if (posix_memalign((void**)&newbuf, IO_BUFFER_ALIGNMENT, aligned))
        return NULL;
#else
    newbuf = malloc(aligned);
    if (!newbuf)
        return NULL;
#endif

    free(tls_io_buf);
    tls_io_buf = newbuf;
    tls_io_buf_cap = aligned;

    if (actual_size)
        *actual_size = aligned;

    return tls_io_buf;
}

/* release_tls_io_buffer
   Frees the calling thread's buffer at thread exit
   Safe to call multiple times */
static void release_tls_io_buffer(void) {
    free(tls_io_buf);
    tls_io_buf = NULL;
    tls_io_buf_cap = 0;
}

/* Thread‑local output buffer helpers */

/* ensure_tls_out_buffer
   Ensures the calling thread has an output buffer of at least min_bytes */
static int ensure_tls_out_buffer(size_t min_bytes) {
    if (min_bytes <= tls_out_cap)
        return 0;

    size_t newcap = (min_bytes + 4095) & ~(size_t)4095; /* round up to 4 KiB */
    char* newbuf = realloc(tls_out_buf, newcap);
    if (!newbuf)
        return -1;

    tls_out_buf = newbuf;
    tls_out_cap = newcap;
    return 0;
}

/* tls_out_append
   Appends formatted data to the thread‑local output buffer.
   Flushes automatically if the buffer would exceed capacity. */
static void tls_out_append(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int needed = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (needed < 0)
        return;

    size_t required = tls_out_len + (size_t)needed + 1; /* +1 for safety */
    if (ensure_tls_out_buffer(required) != 0)
        return; /* out of memory – drop output */

    va_start(ap, fmt);
    int written = vsnprintf(tls_out_buf + tls_out_len, tls_out_cap - tls_out_len, fmt, ap);
    va_end(ap);
    if (written > 0)
        tls_out_len += (size_t)written;
}

/* tls_out_append_raw
   Appends raw bytes to the thread‑local output buffer. */
static void tls_out_append_raw(const char* data, size_t len) {
    if (len == 0)
        return;
    if (ensure_tls_out_buffer(tls_out_len + len) != 0)
        return;
    memcpy(tls_out_buf + tls_out_len, data, len);
    tls_out_len += len;
}

/* tls_out_append_str
   Appends a null‑terminated string. */
static void tls_out_append_str(const char* str) {
    tls_out_append_raw(str, strlen(str));
}

/* tls_out_flush
   Writes the thread‑local buffer to stdout under the output mutex */
static void tls_out_flush(void) {
    if (tls_out_len == 0)
        return;
    pthread_mutex_lock(&output_mutex);
    fwrite(tls_out_buf, 1, tls_out_len, stdout);
    pthread_mutex_unlock(&output_mutex);
    tls_out_len = 0;
}

/* release_tls_out_buffer
   Frees the calling thread's output buffer */
static void release_tls_out_buffer(void) {
    free(tls_out_buf);
    tls_out_buf = NULL;
    tls_out_cap = 0;
    tls_out_len = 0;
}

/* Aggregated results
   Updated by workers, read by main */
static _Atomic int any_failure_global = 0;
static _Atomic int any_format_error_global = 0;

/* Per-file context */
typedef struct {
    int fd;
    off_t size;
    const uint8_t* map;
    size_t map_len;
    size_t total_chunks;
    _Atomic int had_error;
    int io_error_code;
} perfile_ctx;

static int hash_fd_stream_fast(int fd, off_t filesize, uint8_t* output);

/* Hash a regular file with a preference for contiguous-buffer paths
   mmap is used when possible for large files
   small files may be read fully into a TLS buffer and hashed one-shot
   streaming is the fallback for non-mmapable cases */
static int hash_regular_file_parallel(const program_opts* opts, const char* name, int fd, const struct stat* st, uint8_t out_hash[BLAKE3_OUT_LEN]) {
    (void)name;

    perfile_ctx ctx = {0};
    ctx.fd = fd;
    ctx.size = st->st_size;
    atomic_store_explicit(&ctx.had_error, 0, memory_order_release);
    ctx.io_error_code = 0;

    if (ctx.size > 0) {
        void* m = mmap(NULL, (size_t)ctx.size, PROT_READ, MAP_SHARED, fd, 0);
        if (m != MAP_FAILED) {
#if defined(POSIX_MADV_SEQUENTIAL) && !defined(__APPLE__)
            posix_madvise(m, (size_t)ctx.size, POSIX_MADV_SEQUENTIAL);
#endif
            ctx.map = (const uint8_t*)m;
            ctx.map_len = (size_t)ctx.size;
        }
    }

    ctx.total_chunks = (ctx.size + BLAKE3_CHUNK_LEN - 1) / BLAKE3_CHUNK_LEN;
    if (ctx.total_chunks == 0)
        ctx.total_chunks = 1;

    const uint8_t* input_buf = NULL;

    if (ctx.map) {
        input_buf = ctx.map;
    }
    else if (ctx.size <= (8u << 20)) {
        size_t buf_sz = 0;
        uint8_t* buf = ensure_tls_io_buffer((size_t)ctx.size, &buf_sz);
        if (buf && buf_sz >= (size_t)ctx.size) {
            size_t have = 0;
            int read_failed = 0;
            while (have < (size_t)ctx.size) {
                ssize_t r;
#if HAVE_PREADV2_NOWAIT
                struct iovec iov = {.iov_base = buf + have, .iov_len = (size_t)ctx.size - have};
                r = preadv2(fd, &iov, 1, -1, RWF_NOWAIT);
                if (r < 0) {
                    r = read(fd, buf + have, (size_t)ctx.size - have);
                }
#else
                r = read(fd, buf + have, (size_t)ctx.size - have);
#endif
                if (r > 0) {
                    have += (size_t)r;
                    continue;
                }
                if (r == 0) {
                    errno = EIO;
                    read_failed = 1;
                    break;
                }
                if (errno != EINTR) {
                    errno = EIO;
                    read_failed = 1;
                    break;
                }
            }
            if (!read_failed && have == (size_t)ctx.size) {
                input_buf = buf;
            }
        }
    }

    if (input_buf) {
        uint8_t iv_bytes[BLAKE3_KEY_LEN];
        for (size_t i = 0; i < 8; i++) {
            uint32_t w = IV[i];
            iv_bytes[i * 4 + 0] = (uint8_t)(w >> 0);
            iv_bytes[i * 4 + 1] = (uint8_t)(w >> 8);
            iv_bytes[i * 4 + 2] = (uint8_t)(w >> 16);
            iv_bytes[i * 4 + 3] = (uint8_t)(w >> 24);
        }

        /* Small-file fast path
           Avoids parallel engine setup overhead for latency-sensitive sizes */
        if ((size_t)ctx.size <= (1024 * 1024)) {
            int rc = b3p_hash_buffer_serial(input_buf, (size_t)ctx.size, iv_bytes, 0, out_hash, BLAKE3_OUT_LEN);
            if (ctx.map)
                munmap((void*)ctx.map, ctx.map_len);
            if (rc != 0) {
                errno = EIO;
                return -1;
            }
            return 0;
        }

        b3p_config_t cfg = b3p_config_default();
        int nthreads = opts->jobs;
        if (nthreads == 0) {
            nthreads = get_nprocs();
        }

        /* Clamp threads to the number of available coarse work units
           Prevents oversubscription when hashing a single medium file */
        size_t task_size = (size_t)B3P_DEFAULT_SUBTREE_CHUNKS * BLAKE3_CHUNK_LEN;
        size_t num_tasks = ((size_t)ctx.size + task_size - 1) / task_size;
        if (num_tasks < 1)
            num_tasks = 1;
        if ((size_t)nthreads > num_tasks) {
            nthreads = (int)num_tasks;
        }

        cfg.nthreads = nthreads;

        b3p_ctx_t* b3p = b3p_create(&cfg);
        if (!b3p) {
            if (ctx.map)
                munmap((void*)ctx.map, ctx.map_len);
            errno = ENOMEM;
            return -1;
        }

        int rc = b3p_hash_one_shot(b3p, input_buf, (size_t)ctx.size, iv_bytes, 0, B3P_METHOD_AUTO, out_hash, BLAKE3_OUT_LEN);
        b3p_destroy(b3p);

        if (ctx.map)
            munmap((void*)ctx.map, ctx.map_len);

        if (rc != 0) {
            errno = EIO;
            return -1;
        }
        return 0;
    }

    /* Streaming fallback
       Handles special files, non-mmapable inputs, and large sequential reads */
    int rc = hash_fd_stream_fast(fd, ctx.size, out_hash);
    if (ctx.map)
        munmap((void*)ctx.map, ctx.map_len);
    return rc;
}

static void print_help(void) {
    puts(
        "Usage: b3sum [OPTION]... [FILE]...\n"
        "Compute or verify BLAKE3 (256-bit) checksums\n\n"
        "Options:\n"
        "  -c, --check           read checksums from FILEs and verify\n"
        "      --tag             use BSD-style output format\n"
        "  -z, --zero            end lines with NUL, not newline\n"
        "      --ignore-missing  skip missing files without error\n"
        "      --quiet           suppress OK status output\n"
        "      --status          exit code only, no output\n"
        "      --strict          fail on malformed input lines\n"
        "  -w, --warn            warn on malformed input lines\n"
        "  -j, --jobs N          number of worker threads (default: CPUs)\n"
        "      --help            show this help and exit\n"
        "      --version         show version and exit\n");
}

static void print_version(void) {
    puts("b3sum");
}

/* handle_options
   Parses command-line flags into opts
   Returns index of first non-option argument
   Returns 0 when --help or --version was handled
   Returns -1 on error */
static int handle_options(int argc, char** argv, program_opts* opts) {
    memset(opts, 0, sizeof(*opts));
    opts->jobs = 0;

    static const struct option long_opts[] = {{"check", no_argument, NULL, 'c'},          {"tag", no_argument, NULL, 't'},     {"zero", no_argument, NULL, 'z'},
                                              {"ignore-missing", no_argument, NULL, 'i'}, {"quiet", no_argument, NULL, 'q'},   {"status", no_argument, NULL, 's'},
                                              {"strict", no_argument, NULL, 'S'},         {"warn", no_argument, NULL, 'w'},    {"jobs", required_argument, NULL, 'j'},
                                              {"help", no_argument, NULL, 'h'},           {"version", no_argument, NULL, 'v'}, {0, 0, 0, 0}};

    int opt;
    while ((opt = getopt_long(argc, argv, "ctziqsSwj:hv", long_opts, NULL)) != -1) {
        switch (opt) {
            case 'c':
                opts->check = 1;
                break;
            case 't':
                opts->tag = 1;
                break;
            case 'z':
                opts->zero = 1;
                break;
            case 'i':
                opts->ignore_missing = 1;
                break;
            case 'q':
                opts->quiet = 1;
                break;
            case 's':
                opts->status = 1;
                break;
            case 'S':
                opts->strict = 1;
                break;
            case 'w':
                opts->warn = 1;
                break;
            case 'j': {
                long n = strtol(optarg, NULL, 10);
                if (n < 1) {
                    fprintf(stderr, "b3sum: invalid jobs value: %s\n", optarg);
                    return -1;
                }
                opts->jobs = (int)n;
                break;
            }
            case 'h':
                print_help();
                return 0;
            case 'v':
                print_version();
                return 0;
            default:
                fputs("Try 'b3sum --help' for more information\n", stderr);
                return -1;
        }
    }
    return optind;
}

/* unescape_filename
   Converts "\n" to newline and "\\\\" to '\'
   Returns heap-allocated decoded string */
static char* unescape_filename(const char* in) {
    size_t len = strlen(in);
    char* out = malloc(len + 1);
    if (!out)
        return NULL;

    size_t j = 0;
    for (size_t i = 0; i < len;) {
        if (in[i] == '\\' && i + 1 < len) {
            char next = in[i + 1];
            if (next == 'n') {
                out[j++] = '\n';
                i += 2;
                continue;
            }
            else if (next == '\\') {
                out[j++] = '\\';
                i += 2;
                continue;
            }
        }
        out[j++] = in[i++];
    }
    out[j] = '\0';
    return out;
}

/* print_hash
   Prints the digest and filename
   Tag and escaping match common checksum tool behavior */
static void print_hash(const uint8_t* hash, const char* filename, int tag, int zero) {
    if (tag)
        fputs("BLAKE3 ", stdout);

    for (size_t i = 0; i < BLAKE3_OUT_LEN; i++)
        printf("%02x", hash[i]);

    if (zero) {
        printf("  %s%c", *filename ? filename : "-", '\0');
        return;
    }

    int needs_escape = 0;
    for (const char* p = filename; *p; ++p) {
        if (*p == '\n' || *p == '\\') {
            needs_escape = 1;
            break;
        }
    }

    if (needs_escape)
        putchar('\\');

    fputs("  ", stdout);

    for (const char* p = filename; *p; ++p) {
        if (*p == '\\')
            fputs("\\\\", stdout);
        else if (*p == '\n')
            fputs("\\n", stdout);
        else
            putchar(*p);
    }

    putchar('\n');
}

static void print_hash_buffered(const uint8_t* hash, const char* filename, int tag, int zero) {
    if (tag)
        tls_out_append_str("BLAKE3 ");

    char hex[BLAKE3_OUT_LEN * 2 + 1];
    for (size_t i = 0; i < BLAKE3_OUT_LEN; i++)
        snprintf(hex + i * 2, 3, "%02x", hash[i]);
    tls_out_append_str(hex);

    if (zero) {
        tls_out_append_str("  ");
        tls_out_append_str(*filename ? filename : "-");
        tls_out_append_raw("\0", 1);
        return;
    }

    int needs_escape = 0;
    for (const char* p = filename; *p; ++p) {
        if (*p == '\n' || *p == '\\') {
            needs_escape = 1;
            break;
        }
    }

    if (needs_escape)
        tls_out_append_raw("\\", 1);

    tls_out_append_str("  ");

    for (const char* p = filename; *p; ++p) {
        if (*p == '\\')
            tls_out_append_str("\\\\");
        else if (*p == '\n')
            tls_out_append_str("\\n");
        else
            tls_out_append_raw(p, 1);
    }

    tls_out_append_raw("\n", 1);
}

static void append_result_to_buffer(const uint8_t* hash, const char* filename, int is_check_mode, const uint8_t* expected, const program_opts* opts, int rc, int saved_errno) {
    if (is_check_mode) {
        int ok = (rc == 0 && memcmp(expected, hash, BLAKE3_OUT_LEN) == 0);
        if (ok) {
            if (!opts->quiet && !opts->status)
                tls_out_append("%s: OK\n", filename);
        }
        else {
            if (!opts->status)
                tls_out_append("%s: FAILED\n", filename);
        }
    }
    else {
        if (rc == 0 && !opts->status) {
            print_hash_buffered(hash, filename, opts->tag, opts->zero);
        }
        else if (rc != 0 && (!opts->ignore_missing || saved_errno != ENOENT)) {
            /* Error message – we output directly to stderr under the mutex */
            pthread_mutex_lock(&output_mutex);
            fprintf(stderr, "b3sum: %s: %s\n", filename, strerror(saved_errno));
            pthread_mutex_unlock(&output_mutex);
        }
    }
}

/* parse_hex_hash
   Decodes a 64-char hex string into 32 bytes */
static int parse_hex_hash(const char* hex, uint8_t* out) {
    for (size_t i = 0; i < BLAKE3_OUT_LEN; i++) {
        unsigned char a = hex[2 * i], b = hex[2 * i + 1];
        if (!isxdigit(a) || !isxdigit(b))
            return -1;
        char tmp[3] = {(char)a, (char)b, 0};
        unsigned long v = strtoul(tmp, NULL, 16);
        if (v > 0xFF)
            return -1;
        out[i] = (uint8_t)v;
    }
    return 0;
}

/* parse_check_line
   Parses one checksum line into filename and expected digest
   Supports optional BSD-style prefix and escaped filenames */
static int parse_check_line(const char* line_in, const program_opts* opts, char** filename_out, uint8_t* hash_out) {
    char* line = strdup(line_in);
    if (!line)
        return -1;

    char* end = line + strlen(line);
    while (end > line && (end[-1] == '\n' || end[-1] == '\r'))
        *--end = '\0';

    const char* p = line;
    if (opts->tag) {
        static const char prefix[] = "BLAKE3 ";
        size_t plen = sizeof(prefix) - 1;
        if (strncmp(p, prefix, plen) != 0) {
            free(line);
            return -1;
        }
        p += plen;
    }

    int needs_unescape = (!opts->zero && *p == '\\');
    if (needs_unescape)
        p++;

    char* sep = strstr((char*)p, "  ");
    if (!sep)
        sep = strstr((char*)p, " *");
    if (!sep) {
        free(line);
        return -1;
    }

    size_t hex_len = (size_t)(sep - p);
    if (hex_len != BLAKE3_OUT_LEN * 2 || parse_hex_hash(p, hash_out) != 0) {
        free(line);
        return -1;
    }

    const char* fname = sep + 2;
    if (!*fname) {
        free(line);
        return -1;
    }

    char* decoded = needs_unescape ? unescape_filename(fname) : strdup(fname);
    if (!decoded) {
        free(line);
        return -1;
    }

    *filename_out = decoded;
    free(line);
    return 0;
}

/* blake3_hash_region_tree
   Serial reference path for hashing a contiguous region */
static int blake3_hash_region_tree(const uint8_t* data, size_t len, uint8_t out_hash[BLAKE3_OUT_LEN]) {
    blake3_hasher h;
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, data, len);
    blake3_hasher_finalize(&h, out_hash, BLAKE3_OUT_LEN);
    return 0;
}

/* hash_fd_stream_with_buffer
   Streaming hash for non-mmapable or special files
   Uses a caller-provided buffer to avoid allocation */
static int hash_fd_stream_with_buffer(int fd, off_t filesize, uint8_t* output, uint8_t* buf, size_t buf_sz) {
    if (!buf || buf_sz < 1024) {
        errno = ENOMEM;
        return -1;
    }

    blake3_hasher hasher;
    blake3_hasher_init(&hasher);

    if (filesize > 0 && (size_t)filesize <= buf_sz) {
        size_t want = (size_t)filesize;
        size_t have = 0;
        while (have < want) {
            ssize_t r = read(fd, buf + have, want - have);
            if (r > 0) {
                have += (size_t)r;
                continue;
            }
            if (r == 0) {
                errno = EIO;
                return -1;
            }
            if (errno == EINTR)
                continue;
            return -1;
        }
        return blake3_hash_region_tree(buf, want, output);
    }

#if defined(POSIX_FADV_SEQUENTIAL) && !defined(__APPLE__)
    if (filesize > 0)
        posix_fadvise(fd, 0, filesize, POSIX_FADV_SEQUENTIAL);
#endif

    for (;;) {
        ssize_t r;
#if HAVE_PREADV2_NOWAIT
        struct iovec iov = {.iov_base = buf, .iov_len = buf_sz};
        r = preadv2(fd, &iov, 1, -1, RWF_NOWAIT);
        if (r < 0) {
            r = read(fd, buf, buf_sz);
        }
#else
        r = read(fd, buf, buf_sz);
#endif

        if (r > 0) {
            blake3_hasher_update(&hasher, buf, (size_t)r);
            continue;
        }
        if (r == 0)
            break;
        if (errno == EINTR)
            continue;
        return -1;
    }

    blake3_hasher_finalize(&hasher, output, BLAKE3_OUT_LEN);
    return 0;
}

/* hash_fd_stream_fast
   Selects an appropriate TLS buffer size and streams */
static int hash_fd_stream_fast(int fd, off_t filesize, uint8_t* output) {
    size_t request = STREAM_BUF_MAX;

    if (filesize > 0 && (size_t)filesize < request)
        request = (size_t)filesize;

    size_t buf_sz = 0;
    uint8_t* buf = ensure_tls_io_buffer(request, &buf_sz);
    if (!buf) {
        errno = ENOMEM;
        return -1;
    }

    return hash_fd_stream_with_buffer(fd, filesize, output, buf, buf_sz);
}
static int process_one_path(const program_opts* opts, const char* path, int is_check_mode, const uint8_t expected[BLAKE3_OUT_LEN], int buffered) {
    uint8_t out[BLAKE3_OUT_LEN];
    const char* name = path ? path : "-";

    int rc = 0;
    int saved_errno = 0;

    if (strcmp(name, "-") == 0) {
        struct stat stin;
        if (fstat(STDIN_FILENO, &stin) != 0) {
            rc = -1;
            saved_errno = errno;
        }
        else {
            rc = hash_fd_stream_fast(STDIN_FILENO, stin.st_size, out);
            if (rc != 0)
                saved_errno = errno;
        }
    }
    else {
        int oflags = O_RDONLY | O_CLOEXEC;
#ifdef O_NOATIME
        struct stat st0;
        if (lstat(name, &st0) == 0 && (st0.st_uid == geteuid() || geteuid() == 0))
            oflags |= O_NOATIME;
#endif
        int fd = open(name, oflags);
        if (fd < 0) {
            rc = -1;
            saved_errno = errno;
        }
        else {
            struct stat st;
            if (fstat(fd, &st) != 0) {
                rc = -1;
                saved_errno = errno;
            }
            else {
                if (S_ISREG(st.st_mode)) {
                    rc = hash_regular_file_parallel(opts, name, fd, &st, out);
                }
                else {
                    rc = hash_fd_stream_fast(fd, st.st_size, out);
                }
                if (rc != 0)
                    saved_errno = errno;
            }
            close(fd);
        }
    }

    if (buffered) {
        /* Buffered output – append to thread‑local buffer, no mutex */
        if (is_check_mode) {
            int ok = (rc == 0 && memcmp(expected, out, BLAKE3_OUT_LEN) == 0);
            if (!ok)
                atomic_store_explicit(&any_failure_global, 1, memory_order_relaxed);
            append_result_to_buffer(out, name, is_check_mode, expected, opts, rc, saved_errno);
        }
        else {
            if (rc == 0 && !opts->status) {
                print_hash_buffered(out, name, opts->tag, opts->zero);
            }
            else if (rc != 0 && (!opts->ignore_missing || saved_errno != ENOENT)) {
                atomic_store_explicit(&any_failure_global, 1, memory_order_relaxed);
                /* Error message – we output directly to stderr under the mutex */
                pthread_mutex_lock(&output_mutex);
                fprintf(stderr, "b3sum: %s: %s\n", name, strerror(saved_errno));
                pthread_mutex_unlock(&output_mutex);
            }
        }
    }
    else {
        /* Original synchronized output */
        pthread_mutex_lock(&output_mutex);
        if (is_check_mode) {
            int ok = (rc == 0 && memcmp(expected, out, BLAKE3_OUT_LEN) == 0);
            if (ok) {
                if (!opts->quiet && !opts->status)
                    printf("%s: OK\n", name);
            }
            else {
                atomic_store_explicit(&any_failure_global, 1, memory_order_relaxed);
                if (!opts->status)
                    printf("%s: FAILED\n", name);
            }
        }
        else {
            if (rc == 0 && !opts->status) {
                print_hash(out, name, opts->tag, opts->zero);
            }
            else if (rc != 0 && (!opts->ignore_missing || saved_errno != ENOENT)) {
                fprintf(stderr, "b3sum: %s: %s\n", name, strerror(saved_errno));
                atomic_store_explicit(&any_failure_global, 1, memory_order_relaxed);
            }
        }
        pthread_mutex_unlock(&output_mutex);
    }

    return rc;
}
static int process_check_files_serial(int fc, char** files, const program_opts* opts) {
    char* line = NULL;
    size_t len = 0;

    if (fc == 0) {
        while (getline(&line, &len, stdin) != -1) {
            char* fname = NULL;
            uint8_t expected[BLAKE3_OUT_LEN];
            if (parse_check_line(line, opts, &fname, expected) != 0) {
                if (opts->warn)
                    fputs("b3sum: warning: invalid line in checksum input\n", stderr);
                if (opts->strict)
                    atomic_store_explicit(&any_format_error_global, 1, memory_order_relaxed);
                continue;
            }
            process_one_path(opts, fname, 1, expected, 0);
            free(fname);
        }
    }
    else {
        for (int i = 0; i < fc; i++) {
            FILE* f = (strcmp(files[i], "-") == 0) ? stdin : fopen(files[i], "r");
            if (!f) {
                fprintf(stderr, "b3sum: %s: %s\n", files[i], strerror(errno));
                atomic_store_explicit(&any_failure_global, 1, memory_order_relaxed);
                continue;
            }
            while (getline(&line, &len, f) != -1) {
                char* fname = NULL;
                uint8_t expected[BLAKE3_OUT_LEN];
                if (parse_check_line(line, opts, &fname, expected) != 0) {
                    if (opts->warn)
                        fputs("b3sum: warning: invalid line in checksum input\n", stderr);
                    if (opts->strict)
                        atomic_store_explicit(&any_format_error_global, 1, memory_order_relaxed);
                    continue;
                }
                process_one_path(opts, fname, 1, expected, 0);
                free(fname);
            }
            if (f != stdin)
                fclose(f);
        }
    }

    free(line);

    return (atomic_load_explicit(&any_failure_global, memory_order_relaxed) || (atomic_load_explicit(&any_format_error_global, memory_order_relaxed) && opts->strict)) ? 1 : 0;
}

typedef struct {
    const program_opts* opts;
    char** files;
    size_t nfiles;
    _Atomic size_t* next_index;
} worker_ctx_t;

static void* tiny_worker(void* arg) {
    worker_ctx_t* ctx = (worker_ctx_t*)arg;
    size_t i;
    while (1) {
        i = atomic_fetch_add(ctx->next_index, 1);
        if (i >= ctx->nfiles)
            break;
        process_one_path(ctx->opts, ctx->files[i], 0, NULL, 1);
        /* Flush thread‑local output buffer if it's large enough */
        if (tls_out_len >= 65536)
            tls_out_flush();
    }
    tls_out_flush();
    release_tls_out_buffer();
    return NULL;
}

static int process_paths_parallel_tiny(const program_opts* opts, char** files, int fc) {
    size_t nfiles = (size_t)fc;
    static _Atomic size_t next_index = 0;
    int nthreads = opts->jobs;
    if (nthreads == 0) {
        int avail = get_nprocs();
        nthreads = (fc < avail) ? fc : avail;
    }
    if (nthreads < 1)
        nthreads = 1;
    if ((size_t)nthreads > nfiles)
        nthreads = (int)nfiles;

    worker_ctx_t ctx = {
        .opts = opts,
        .files = files,
        .nfiles = nfiles,
        .next_index = &next_index,
    };

    pthread_t* threads = malloc((size_t)nthreads * sizeof(pthread_t));
    if (!threads)
        return -1;

    atomic_store_explicit(&next_index, 0, memory_order_relaxed);

    int t;
    for (t = 0; t < nthreads; t++) {
        if (pthread_create(&threads[t], NULL, tiny_worker, &ctx) != 0)
            break;
    }

    if (t < nthreads) {
        /* Some thread creation failed – stop all workers */
        atomic_store_explicit(&next_index, nfiles, memory_order_relaxed);
        for (int j = 0; j < t; j++)
            pthread_join(threads[j], NULL);
        free(threads);
        return -1;
    }

    for (int j = 0; j < nthreads; j++) {
        pthread_join(threads[j], NULL);
    }

    free(threads);
    return 0;
}

int main(int argc, char** argv) {
    program_opts opts;
    int argi = handle_options(argc, argv, &opts);
    if (argi < 0)
        return EXIT_FAILURE;
    if (argi == 0)
        return EXIT_SUCCESS;

    int fc = argc - argi;
    char** files = &argv[argi];

    if (opts.check) {
        int r = process_check_files_serial(fc, files, &opts);
        release_tls_io_buffer();
        b3p_free_tls_resources();
        return r ? EXIT_FAILURE : EXIT_SUCCESS;
    }

    if (fc == 0) {
        static char* stdin_only[] = {"-"};
        files = stdin_only;
        fc = 1;
    }

    if (fc >= 64 && opts.jobs != 1) {
        if (process_paths_parallel_tiny(&opts, files, fc) != 0) {
            /* fall back to serial processing */
            for (int i = 0; i < fc; i++) {
                process_one_path(&opts, files[i], 0, NULL, 0);
            }
        }
    }
    else {
        for (int i = 0; i < fc; i++) {
            process_one_path(&opts, files[i], 0, NULL, 0);
        }
    }

    release_tls_out_buffer();
    release_tls_io_buffer();
    b3p_free_tls_resources();

    return atomic_load_explicit(&any_failure_global, memory_order_relaxed) ? EXIT_FAILURE : EXIT_SUCCESS;
}
