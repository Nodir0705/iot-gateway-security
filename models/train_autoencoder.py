#!/usr/bin/env python3
"""
Train Autoencoder for anomaly detection.
Learns to reconstruct normal traffic — high reconstruction error = attack.
Exports to ONNX for RKNN conversion.
"""
import numpy as np
import pandas as pd
from sklearn.preprocessing import MinMaxScaler
import os
import time
import json

# Try PyTorch first, fall back to numpy-only implementation
try:
    import torch
    import torch.nn as nn
    HAS_TORCH = True
    print("Using PyTorch backend")
except ImportError:
    HAS_TORCH = False
    print("PyTorch not available — using NumPy autoencoder")

# Load dataset
data_path = os.path.expanduser("~/iot-gateway/models/training_data.csv")
df = pd.read_csv(data_path)

X = df.drop('label', axis=1).values.astype(np.float32)
y = df['label'].values

# Normalize
scaler = MinMaxScaler()
X_scaled = scaler.fit_transform(X)

# Split: train on NORMAL only (unsupervised anomaly detection)
X_normal = X_scaled[y == 0]
X_attack = X_scaled[y == 1]
print(f"Normal samples for training: {len(X_normal)}")
print(f"Attack samples for testing: {len(X_attack)}")

n_features = X_scaled.shape[1]  # 13

if HAS_TORCH:
    # === PyTorch Autoencoder ===
    class Autoencoder(nn.Module):
        def __init__(self, input_dim=13):
            super().__init__()
            self.encoder = nn.Sequential(
                nn.Linear(input_dim, 8),
                nn.ReLU(),
                nn.Linear(8, 4),
                nn.ReLU(),
            )
            self.decoder = nn.Sequential(
                nn.Linear(4, 8),
                nn.ReLU(),
                nn.Linear(8, input_dim),
                nn.Sigmoid(),
            )

        def forward(self, x):
            encoded = self.encoder(x)
            decoded = self.decoder(encoded)
            return decoded

    model = Autoencoder(n_features)
    criterion = nn.MSELoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=0.001)

    # Train on normal data only
    X_train_t = torch.FloatTensor(X_normal)
    print(f"\nTraining Autoencoder ({n_features}→8→4→8→{n_features})...")

    epochs = 200
    batch_size = 32
    t0 = time.time()

    for epoch in range(epochs):
        # Shuffle
        perm = torch.randperm(len(X_train_t))
        X_shuffled = X_train_t[perm]

        epoch_loss = 0
        n_batches = 0
        for i in range(0, len(X_shuffled), batch_size):
            batch = X_shuffled[i:i+batch_size]
            output = model(batch)
            loss = criterion(output, batch)

            optimizer.zero_grad()
            loss.backward()
            optimizer.step()

            epoch_loss += loss.item()
            n_batches += 1

        if (epoch + 1) % 50 == 0:
            avg_loss = epoch_loss / n_batches
            print(f"  Epoch {epoch+1}/{epochs} — Loss: {avg_loss:.6f}")

    train_time = time.time() - t0
    print(f"Training time: {train_time:.2f}s")

    # Compute reconstruction errors
    model.eval()
    with torch.no_grad():
        normal_recon = model(torch.FloatTensor(X_normal))
        normal_errors = torch.mean((normal_recon - torch.FloatTensor(X_normal))**2, dim=1).numpy()

        attack_recon = model(torch.FloatTensor(X_attack))
        attack_errors = torch.mean((attack_recon - torch.FloatTensor(X_attack))**2, dim=1).numpy()

    # Set threshold at 95th percentile of normal errors
    threshold = np.percentile(normal_errors, 95)

    print(f"\n=== Reconstruction Error Analysis ===")
    print(f"Normal — mean: {normal_errors.mean():.6f}, std: {normal_errors.std():.6f}, max: {normal_errors.max():.6f}")
    print(f"Attack — mean: {attack_errors.mean():.6f}, std: {attack_errors.std():.6f}, max: {attack_errors.max():.6f}")
    print(f"Threshold (95th pctl normal): {threshold:.6f}")

    # Classification performance
    normal_pred = (normal_errors > threshold).astype(int)  # Should be 0
    attack_pred = (attack_errors > threshold).astype(int)  # Should be 1

    tn = np.sum(normal_pred == 0)
    fp = np.sum(normal_pred == 1)
    fn = np.sum(attack_pred == 0)
    tp = np.sum(attack_pred == 1)

    precision = tp / (tp + fp + 1e-9)
    recall = tp / (tp + fn + 1e-9)
    f1 = 2 * precision * recall / (precision + recall + 1e-9)

    print(f"\n=== Autoencoder Detection Performance ===")
    print(f"  TN={tn:4d}  FP={fp:4d}")
    print(f"  FN={fn:4d}  TP={tp:4d}")
    print(f"  Precision: {precision:.4f}")
    print(f"  Recall:    {recall:.4f}")
    print(f"  F1 Score:  {f1:.4f}")

    # Export to ONNX
    model_dir = os.path.expanduser("~/iot-gateway/models")
    onnx_path = f"{model_dir}/autoencoder.onnx"

    dummy_input = torch.randn(1, n_features)
    torch.onnx.export(
        model,
        dummy_input,
        onnx_path,
        input_names=['input'],
        output_names=['output'],
        dynamic_axes={'input': {0: 'batch_size'}, 'output': {0: 'batch_size'}},
        opset_version=12,
    )
    print(f"\nONNX model exported: {onnx_path}")

    # Verify ONNX
    import onnx
    onnx_model = onnx.load(onnx_path)
    onnx.checker.check_model(onnx_model)
    print("ONNX model verified OK")

    # Save PyTorch model too
    torch.save(model.state_dict(), f"{model_dir}/autoencoder.pth")

    # Inference benchmark
    print(f"\n=== Inference Benchmark (CPU) ===")
    model.eval()
    for bs in [1, 10, 100, 1000]:
        batch = torch.randn(bs, n_features)
        t0 = time.time()
        with torch.no_grad():
            for _ in range(100):
                _ = model(batch)
        elapsed = time.time() - t0
        rate = (bs * 100) / elapsed
        print(f"  Batch {bs:5d}: {rate:,.0f} flows/sec")

else:
    # === NumPy-only Autoencoder ===
    print(f"\nTraining NumPy Autoencoder ({n_features}→8→4→8→{n_features})...")

    np.random.seed(42)

    def relu(x): return np.maximum(0, x)
    def relu_deriv(x): return (x > 0).astype(np.float32)
    def sigmoid(x): return 1 / (1 + np.exp(-np.clip(x, -10, 10)))

    # Initialize weights
    W1 = np.random.randn(n_features, 8).astype(np.float32) * 0.1
    b1 = np.zeros(8, dtype=np.float32)
    W2 = np.random.randn(8, 4).astype(np.float32) * 0.1
    b2 = np.zeros(4, dtype=np.float32)
    W3 = np.random.randn(4, 8).astype(np.float32) * 0.1
    b3 = np.zeros(8, dtype=np.float32)
    W4 = np.random.randn(8, n_features).astype(np.float32) * 0.1
    b4 = np.zeros(n_features, dtype=np.float32)

    lr = 0.001
    epochs = 200
    batch_size = 32
    t0 = time.time()

    for epoch in range(epochs):
        perm = np.random.permutation(len(X_normal))
        epoch_loss = 0
        n_batches = 0

        for i in range(0, len(X_normal), batch_size):
            batch = X_normal[perm[i:i+batch_size]]
            bs_actual = len(batch)

            # Forward
            z1 = batch @ W1 + b1; a1 = relu(z1)
            z2 = a1 @ W2 + b2; a2 = relu(z2)
            z3 = a2 @ W3 + b3; a3 = relu(z3)
            z4 = a3 @ W4 + b4; output = sigmoid(z4)

            # Loss
            loss = np.mean((output - batch)**2)
            epoch_loss += loss
            n_batches += 1

            # Backward
            d4 = (output - batch) * output * (1 - output) * 2 / bs_actual
            dW4 = a3.T @ d4; db4 = d4.sum(axis=0)
            d3 = (d4 @ W4.T) * relu_deriv(z3)
            dW3 = a2.T @ d3; db3 = d3.sum(axis=0)
            d2 = (d3 @ W3.T) * relu_deriv(z2)
            dW2 = a1.T @ d2; db2 = d2.sum(axis=0)
            d1 = (d2 @ W2.T) * relu_deriv(z1)
            dW1 = batch.T @ d1; db1 = d1.sum(axis=0)

            W4 -= lr * dW4; b4 -= lr * db4
            W3 -= lr * dW3; b3 -= lr * db3
            W2 -= lr * dW2; b2 -= lr * db2
            W1 -= lr * dW1; b1 -= lr * db1

        if (epoch + 1) % 50 == 0:
            print(f"  Epoch {epoch+1}/{epochs} — Loss: {epoch_loss/n_batches:.6f}")

    train_time = time.time() - t0
    print(f"Training time: {train_time:.2f}s")

    # Inference function
    def predict(X):
        z1 = X @ W1 + b1; a1 = relu(z1)
        z2 = a1 @ W2 + b2; a2 = relu(z2)
        z3 = a2 @ W3 + b3; a3 = relu(z3)
        z4 = a3 @ W4 + b4; output = sigmoid(z4)
        return output

    # Reconstruction errors
    normal_recon = predict(X_normal)
    normal_errors = np.mean((normal_recon - X_normal)**2, axis=1)
    attack_recon = predict(X_attack)
    attack_errors = np.mean((attack_recon - X_attack)**2, axis=1)

    threshold = np.percentile(normal_errors, 95)
    print(f"\nNormal error — mean: {normal_errors.mean():.6f}, max: {normal_errors.max():.6f}")
    print(f"Attack error — mean: {attack_errors.mean():.6f}, max: {attack_errors.max():.6f}")
    print(f"Threshold: {threshold:.6f}")

    tp = np.sum(attack_errors > threshold)
    fn = np.sum(attack_errors <= threshold)
    tn = np.sum(normal_errors <= threshold)
    fp = np.sum(normal_errors > threshold)
    print(f"  TN={tn} FP={fp} FN={fn} TP={tp}")

    # Export ONNX manually
    try:
        import onnx
        from onnx import helper, TensorProto, numpy_helper

        # Build ONNX graph manually
        nodes = []
        initializers = []

        for name, w, b in [("enc1", W1, b1), ("enc2", W2, b2),
                           ("dec1", W3, b3), ("dec2", W4, b4)]:
            initializers.append(numpy_helper.from_array(w, f"{name}_w"))
            initializers.append(numpy_helper.from_array(b, f"{name}_b"))

        # Encoder
        nodes.append(helper.make_node("MatMul", ["input", "enc1_w"], ["enc1_mm"]))
        nodes.append(helper.make_node("Add", ["enc1_mm", "enc1_b"], ["enc1_out"]))
        nodes.append(helper.make_node("Relu", ["enc1_out"], ["enc1_relu"]))

        nodes.append(helper.make_node("MatMul", ["enc1_relu", "enc2_w"], ["enc2_mm"]))
        nodes.append(helper.make_node("Add", ["enc2_mm", "enc2_b"], ["enc2_out"]))
        nodes.append(helper.make_node("Relu", ["enc2_out"], ["enc2_relu"]))

        # Decoder
        nodes.append(helper.make_node("MatMul", ["enc2_relu", "dec1_w"], ["dec1_mm"]))
        nodes.append(helper.make_node("Add", ["dec1_mm", "dec1_b"], ["dec1_out"]))
        nodes.append(helper.make_node("Relu", ["dec1_out"], ["dec1_relu"]))

        nodes.append(helper.make_node("MatMul", ["dec1_relu", "dec2_w"], ["dec2_mm"]))
        nodes.append(helper.make_node("Add", ["dec2_mm", "dec2_b"], ["dec2_out"]))
        nodes.append(helper.make_node("Sigmoid", ["dec2_out"], ["output"]))

        input_tensor = helper.make_tensor_value_info("input", TensorProto.FLOAT, [None, n_features])
        output_tensor = helper.make_tensor_value_info("output", TensorProto.FLOAT, [None, n_features])

        graph = helper.make_graph(nodes, "autoencoder", [input_tensor], [output_tensor], initializers)
        onnx_model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 12)])
        onnx.checker.check_model(onnx_model)

        onnx_path = os.path.expanduser("~/iot-gateway/models/autoencoder.onnx")
        onnx.save(onnx_model, onnx_path)
        print(f"\nONNX model exported: {onnx_path}")
    except Exception as e:
        print(f"ONNX export failed: {e}")
        print("Saving numpy weights instead...")

    # Save weights
    model_dir = os.path.expanduser("~/iot-gateway/models")
    np.savez(f"{model_dir}/autoencoder_weights.npz",
             W1=W1, b1=b1, W2=W2, b2=b2, W3=W3, b3=b3, W4=W4, b4=b4)

# Save threshold and config
config = {
    "threshold": float(threshold),
    "n_features": n_features,
    "architecture": "13-8-4-8-13",
    "normal_error_mean": float(normal_errors.mean()),
    "normal_error_std": float(normal_errors.std()),
    "attack_error_mean": float(attack_errors.mean()),
}
model_dir = os.path.expanduser("~/iot-gateway/models")
with open(f"{model_dir}/autoencoder_config.json", "w") as f:
    json.dump(config, f, indent=2)
print(f"Config saved: autoencoder_config.json")
