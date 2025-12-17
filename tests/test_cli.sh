#!/bin/sh
set -e

# Setup paths
BUILD_DIR=${MESON_BUILD_ROOT:-build-test}
B3SUM="$BUILD_DIR/b3sum"
export LD_LIBRARY_PATH="$BUILD_DIR:$LD_LIBRARY_PATH"

if [ ! -x "$B3SUM" ]; then
    echo "b3sum not found at $B3SUM"
    exit 77 # Skip
fi

# 1. Basic hash check
echo -n "abc" > test_input.txt
EXPECTED="6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85  test_input.txt"
ACTUAL=$($B3SUM test_input.txt)

if [ "$ACTUAL" != "$EXPECTED" ]; then
    echo "Basic hash check failed"
    echo "Expected: '$EXPECTED'"
    echo "Actual:   '$ACTUAL'"
    exit 1
fi

# 2. Check functionality
echo "$EXPECTED" > test_checksums.txt
$B3SUM --check test_checksums.txt

# 3. Check failure
echo "0000000000000000000000000000000000000000000000000000000000000000  test_input.txt" > test_bad.txt
if $B3SUM --check test_bad.txt 2>/dev/null; then
    echo "Check should have failed for bad checksum"
    exit 1
fi

# 4. Standard input
ACTUAL_STDIN=$(echo -n "abc" | $B3SUM -)
EXPECTED_STDIN="6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85  -"
if [ "$ACTUAL_STDIN" != "$EXPECTED_STDIN" ]; then
    echo "Stdin check failed"
    echo "Expected: '$EXPECTED_STDIN'"
    echo "Actual:   '$ACTUAL_STDIN'"
    exit 1
fi

# 5. Large file / Parallelism consistency check
# The benchmark failure involved a 4MB file with mixed zero/data regions.
# We create a similar file and verify that multi-threaded hashing matches single-threaded.

# 4MB file: 2MB zero, 1MB random, 1MB zero
# Note: we construct it carefully to ensure specific regions
dd if=/dev/zero of=test_4mb.bin bs=1M count=4 status=none
# Overwrite 3rd MB with random
dd if=/dev/urandom of=test_4mb.bin bs=1M count=1 seek=2 conv=notrunc status=none

HASH_MT=$($B3SUM test_4mb.bin | cut -d' ' -f1)
HASH_ST=$($B3SUM --jobs 1 test_4mb.bin | cut -d' ' -f1)

if [ "$HASH_MT" != "$HASH_ST" ]; then
    echo "Parallel consistency failed on 4MB mixed file"
    echo "Multi-threaded: $HASH_MT"
    echo "Single-threaded: $HASH_ST"
    exit 1
fi
rm test_4mb.bin

# 6. Sparse file check
# Create a sparse file using seek (if supported by FS)
# 4MB hole, then 4KB data
dd if=/dev/urandom of=test_sparse.bin bs=4k count=1 seek=1024 status=none 
HASH_SPARSE_MT=$($B3SUM test_sparse.bin | cut -d' ' -f1)
HASH_SPARSE_ST=$($B3SUM --jobs 1 test_sparse.bin | cut -d' ' -f1)

if [ "$HASH_SPARSE_MT" != "$HASH_SPARSE_ST" ]; then
    echo "Parallel consistency failed on sparse file"
    echo "Multi-threaded: $HASH_SPARSE_MT"
    echo "Single-threaded: $HASH_SPARSE_ST"
    exit 1
fi
rm test_sparse.bin

echo "CLI tests passed"
rm test_input.txt test_checksums.txt test_bad.txt
exit 0
