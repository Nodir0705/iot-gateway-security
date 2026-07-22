#!/bin/bash
# Build libnpu_infer.so on Orange Pi (aarch64)
# Requires: gcc, librknnrt.so, rknn_api.h
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RKNN_INC="$HOME/rknn-toolkit2/rknpu2/runtime/Linux/librknn_api/include"

if [ ! -f "$RKNN_INC/rknn_api.h" ]; then
    echo "ERROR: rknn_api.h not found at $RKNN_INC"
    echo "Set RKNN_INC to the correct include path"
    exit 1
fi

echo "Building libnpu_infer.so ..."
gcc -O2 -shared -fPIC \
    -o "$SCRIPT_DIR/libnpu_infer.so" \
    "$SCRIPT_DIR/npu_infer.c" \
    -I"$RKNN_INC" \
    -lrknnrt -lm

echo "Built: $SCRIPT_DIR/libnpu_infer.so ($(stat -c%s "$SCRIPT_DIR/libnpu_infer.so") bytes)"

echo ""
echo "Test with:"
echo "  python3 $SCRIPT_DIR/npu_infer_wrapper.py"
