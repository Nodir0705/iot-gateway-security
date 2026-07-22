#!/usr/bin/env python3
"""
Train Random Forest classifier on flow features.
This runs on CPU — used as the high-accuracy baseline.
"""
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import MinMaxScaler
import joblib
import os
import time

# Load dataset
data_path = os.path.expanduser("~/iot-gateway/models/training_data.csv")
print(f"Loading: {data_path}")
df = pd.read_csv(data_path)
print(f"Dataset: {len(df)} samples, {df['label'].value_counts().to_dict()}")

# Split features and labels
X = df.drop('label', axis=1).values.astype(np.float32)
y = df['label'].values.astype(np.int32)

# Normalize
scaler = MinMaxScaler()
X_scaled = scaler.fit_transform(X)

# Train/test split
X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y, test_size=0.2, random_state=42, stratify=y
)
print(f"Train: {len(X_train)} | Test: {len(X_test)}")

# Train Random Forest
print("\nTraining Random Forest...")
rf = RandomForestClassifier(
    n_estimators=100,
    max_depth=10,
    min_samples_leaf=5,
    random_state=42,
    n_jobs=-1  # Use all cores
)
t0 = time.time()
rf.fit(X_train, y_train)
train_time = time.time() - t0
print(f"Training time: {train_time:.2f}s")

# Evaluate
y_pred = rf.predict(X_test)
print("\n=== Classification Report ===")
print(classification_report(y_test, y_pred, target_names=["Normal", "Attack"]))

print("=== Confusion Matrix ===")
cm = confusion_matrix(y_test, y_pred)
print(f"  TN={cm[0][0]:4d}  FP={cm[0][1]:4d}")
print(f"  FN={cm[1][0]:4d}  TP={cm[1][1]:4d}")

# Cross-validation
scores = cross_val_score(rf, X_scaled, y, cv=5, scoring='f1')
print(f"\n5-fold CV F1: {scores.mean():.4f} (+/- {scores.std():.4f})")

# Feature importance
feature_names = df.columns[:-1].tolist()
importances = rf.feature_importances_
print("\n=== Feature Importance ===")
for name, imp in sorted(zip(feature_names, importances), key=lambda x: -x[1]):
    bar = "█" * int(imp * 50)
    print(f"  {name:25s} {imp:.4f} {bar}")

# Inference benchmark
print("\n=== Inference Benchmark ===")
batch_sizes = [1, 10, 100, 1000]
for bs in batch_sizes:
    batch = np.tile(X_test[0:1], (bs, 1))
    t0 = time.time()
    for _ in range(100):
        rf.predict(batch)
    elapsed = time.time() - t0
    rate = (bs * 100) / elapsed
    print(f"  Batch {bs:5d}: {rate:,.0f} flows/sec")

# Save model and scaler
model_dir = os.path.expanduser("~/iot-gateway/models")
joblib.dump(rf, f"{model_dir}/rf_model.joblib")
joblib.dump(scaler, f"{model_dir}/scaler.joblib")
print(f"\nSaved: rf_model.joblib, scaler.joblib")
