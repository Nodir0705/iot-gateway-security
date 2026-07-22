#!/usr/bin/env python3
"""Python ctypes wrapper for libnpu_infer.so (rknpu2 C API)"""

import ctypes
import numpy as np
import os

NUM_FEATURES = 13
RKNN_NPU_CORE_0 = 1

class NPUInferC:
    """Drop-in replacement for NPUDetector using the native C rknpu2 API."""

    def __init__(self, model_path=None, core_mask=RKNN_NPU_CORE_0):
        if model_path is None:
            model_path = os.path.expanduser("~/iot-gateway/models/classifier.rknn")

        lib_dir = os.path.dirname(os.path.abspath(__file__))
        lib_path = os.path.join(lib_dir, "libnpu_infer.so")
        if not os.path.exists(lib_path):
            # Try same dir as model
            lib_path = os.path.join(os.path.dirname(model_path), "libnpu_infer.so")

        self.lib = ctypes.CDLL(lib_path)

        # npu_init(const char *model_path, int core_mask) -> int
        self.lib.npu_init.argtypes = [ctypes.c_char_p, ctypes.c_int]
        self.lib.npu_init.restype = ctypes.c_int

        # npu_infer(const float *input, float *output, int n) -> int
        self.lib.npu_infer.argtypes = [
            ctypes.POINTER(ctypes.c_float),
            ctypes.POINTER(ctypes.c_float),
            ctypes.c_int,
        ]
        self.lib.npu_infer.restype = ctypes.c_int

        # npu_scale_features(const float *raw, float *scaled, int n) -> void
        self.lib.npu_scale_features.argtypes = [
            ctypes.POINTER(ctypes.c_float),
            ctypes.POINTER(ctypes.c_float),
            ctypes.c_int,
        ]
        self.lib.npu_scale_features.restype = None

        # npu_infer_classify(const float *raw, int *results, float *scores, int n) -> int
        self.lib.npu_infer_classify.argtypes = [
            ctypes.POINTER(ctypes.c_float),
            ctypes.POINTER(ctypes.c_int),
            ctypes.POINTER(ctypes.c_float),
            ctypes.c_int,
        ]
        self.lib.npu_infer_classify.restype = ctypes.c_int

        # npu_get_output_elems() -> int
        self.lib.npu_get_output_elems.argtypes = []
        self.lib.npu_get_output_elems.restype = ctypes.c_int

        # npu_destroy() -> void
        self.lib.npu_destroy.argtypes = []
        self.lib.npu_destroy.restype = None

        # Initialize
        ret = self.lib.npu_init(model_path.encode(), core_mask)
        if ret != 0:
            raise RuntimeError(f"npu_init failed: {ret}")

        self.backend = "rknn_c"
        self.model_type = "classifier"

    def predict(self, features):
        """
        Classify raw (unscaled) flow features.

        Args:
            features: numpy array, shape [n, 13] or [13], float32
        Returns:
            list of (is_attack: bool, score: float) tuples
        """
        if features.ndim == 1:
            features = features.reshape(1, -1)
        n = len(features)
        features = np.ascontiguousarray(features, dtype=np.float32)

        results = (ctypes.c_int * n)()
        scores = (ctypes.c_float * n)()
        raw_ptr = features.ctypes.data_as(ctypes.POINTER(ctypes.c_float))

        ret = self.lib.npu_infer_classify(raw_ptr, results, scores, n)
        if ret != 0:
            raise RuntimeError(f"npu_infer_classify failed: {ret}")

        return [(bool(results[i]), float(scores[i])) for i in range(n)]

    def destroy(self):
        self.lib.npu_destroy()

    def __del__(self):
        try:
            self.destroy()
        except:
            pass


def benchmark():
    """Quick benchmark comparing C API vs Python rknnlite."""
    import time

    print("=== NPU C API Benchmark ===\n")
    det = NPUInferC()

    # Warmup
    dummy = np.random.rand(10, NUM_FEATURES).astype(np.float32)
    for _ in range(10):
        det.predict(dummy)

    for bs in [1, 10, 100, 1000]:
        batch = np.random.rand(bs, NUM_FEATURES).astype(np.float32)
        iters = max(1, 1000 // bs)
        t0 = time.time()
        for _ in range(iters):
            det.predict(batch)
        elapsed = time.time() - t0
        rate = (bs * iters) / elapsed
        lat = elapsed / (bs * iters) * 1e6
        print(f"  Batch {bs:5d}: {rate:>10,.0f} flows/sec  latency={lat:.0f} μs")

    det.destroy()


if __name__ == "__main__":
    benchmark()
