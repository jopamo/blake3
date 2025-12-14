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

echo "CLI tests passed"
rm test_input.txt test_checksums.txt test_bad.txt
exit 0
