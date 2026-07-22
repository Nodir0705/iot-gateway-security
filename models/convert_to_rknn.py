#!/usr/bin/env python3
"""
Convert ONNX autoencoder to RKNN format for NPU deployment.
Requires rknn-toolkit2 (try ARM64 version first).
"""
import os
import sys
import numpy as np

model_dir = os.path.expanduser("~/iot-gateway/models")
onnx_path = f"{model_dir}/autoencoder.onnx"
rknn_path = f"{model_dir}/autoencoder.rknn"

# Try importing RKNN toolkit
try:
    from rknn.api import RKNN
    print("rknn-toolkit2 loaded")
except ImportError:
    try:
        from rknnlite.api import RKNNLite
        print("Only rknn-toolkit-lite2 available (inference only)")
        print("Cannot convert ONNX→RKNN on this device.")
        print("")
        print("Options:")
        print("  1. Install rknn-toolkit2: pip3 install rknn-toolkit2")
        print("  2. Convert on x86 machine and copy .rknn file here")
        print("  3. Use ONNX Runtime on CPU instead (see Step 5)")
        sys.exit(1)
    except ImportError:
        print("No RKNN toolkit found. Installing rknn-toolkit2...")
        os.system("pip3 install rknn-toolkit2")
        try:
            from rknn.api import RKNN
        except ImportError:
            print("Failed to install rknn-toolkit2.")
            print("Falling back to ONNX Runtime (see Step 5)")
            sys.exit(1)

# Load calibration data (normal traffic for INT8 quantization)
calib_data = os.path.expanduser("~/iot-gateway/models/training_data.csv")
import pandas as pd
df = pd.read_csv(calib_data)
X_normal = df[df['label'] == 0].drop('label', axis=1).values.astype(np.float32)

# Normalize (same as training)
from sklearn.preprocessing import MinMaxScaler
scaler = MinMaxScaler()
X_scaled = scaler.fit_transform(df.drop('label', axis=1).values.astype(np.float32))
X_normal_scaled = X_scaled[df['label'].values == 0]

# Save calibration dataset for RKNN
calib_file = f"{model_dir}/calibration_data.npy"
np.save(calib_file, X_normal_scaled[:100])

# Create text file listing calibration data paths
calib_list = f"{model_dir}/calibration_list.txt"
with open(calib_list, "w") as f:
    f.write(calib_file + "\n")

# Convert
rknn = RKNN()

print("Configuring RKNN...")
rknn.config(
    mean_values=[[0] * 13],
    std_values=[[1] * 13],
    target_platform='rk3588',
    quantized_dtype='w8a8',          # INT8 quantization
    quantized_algorithm='normal',
)

print(f"Loading ONNX: {onnx_path}")
ret = rknn.load_onnx(model=onnx_path)
if ret != 0:
    print(f"ONNX load failed: {ret}")
    sys.exit(1)

print("Building RKNN model (INT8 quantization)...")
ret = rknn.build(do_quantization=True, dataset=calib_list)
if ret != 0:
    print(f"Build failed: {ret}")
    print("Trying without quantization (FP16)...")
    ret = rknn.build(do_quantization=False)
    if ret != 0:
        print(f"Build still failed: {ret}")
        sys.exit(1)

print(f"Exporting: {rknn_path}")
ret = rknn.export_rknn(rknn_path)
if ret != 0:
    print(f"Export failed: {ret}")
    sys.exit(1)

print(f"RKNN model saved: {rknn_path}")
print(f"Size: {os.path.getsize(rknn_path)} bytes")

rknn.release()
