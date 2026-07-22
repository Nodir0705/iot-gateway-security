#!/usr/bin/env python3
"""NPU Anomaly Detection Engine — classifier (INT8) or autoencoder (fp32) on NPU"""
import numpy as np
import json, time, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from flow_features import FEATURE_NAMES, NUM_FEATURES

MODEL_DIR = os.path.expanduser("~/iot-gateway/models")

class NPUDetector:
    def __init__(self):
        self.backend = None
        self.model = None
        self.model_type = "autoencoder"  # "classifier" or "autoencoder"
        self.threshold = 0.01
        self.scaler = None

        # Detect model type: classifier takes priority over autoencoder
        cls_config = f"{MODEL_DIR}/classifier_config.json"
        ae_config  = f"{MODEL_DIR}/autoencoder_config.json"

        if os.path.exists(cls_config):
            with open(cls_config) as f:
                cfg = json.load(f)
            self.model_type = "classifier"
            self.threshold = cfg.get("threshold", 0.5)
            print(f"Model: classifier  Threshold: {self.threshold}")
        elif os.path.exists(ae_config):
            with open(ae_config) as f:
                cfg = json.load(f)
            self.model_type = "autoencoder"
            self.threshold = cfg.get("threshold", 0.01)
            print(f"Model: autoencoder  Threshold: {self.threshold:.6f}")

        try:
            import joblib
            sp = f"{MODEL_DIR}/scaler.joblib"
            if os.path.exists(sp):
                self.scaler = joblib.load(sp)
        except ImportError:
            pass

        self._try_rknn() or self._try_onnx() or self._try_sklearn()
        if not self.backend:
            print("ERROR: No backend!"); sys.exit(1)

    def _try_rknn(self):
        # Prefer classifier.rknn (INT8), fall back to autoencoder.rknn
        if self.model_type == "classifier":
            rp = f"{MODEL_DIR}/classifier.rknn"
        else:
            rp = f"{MODEL_DIR}/autoencoder.rknn"
        if not os.path.exists(rp):
            rp = f"{MODEL_DIR}/autoencoder.rknn"
        if not os.path.exists(rp):
            return False
        try:
            from rknnlite.api import RKNNLite
            r = RKNNLite()
            if r.load_rknn(rp) != 0: return False
            if r.init_runtime(core_mask=RKNNLite.NPU_CORE_0) != 0: return False
            self.model = r; self.backend = "rknn"
            print(f"Backend: RKNN (NPU) — {os.path.basename(rp)}")
            return True
        except:
            return False

    def _try_onnx(self):
        if self.model_type == "classifier":
            op = f"{MODEL_DIR}/classifier.onnx"
        else:
            op = f"{MODEL_DIR}/autoencoder.onnx"
        if not os.path.exists(op):
            op = f"{MODEL_DIR}/autoencoder.onnx"
        if not os.path.exists(op):
            return False
        try:
            import onnxruntime as ort
            self.model = ort.InferenceSession(op, providers=['CPUExecutionProvider'])
            self.backend = "onnx"
            print(f"Backend: ONNX Runtime (CPU) — {os.path.basename(op)}")
            return True
        except:
            return False

    def _try_sklearn(self):
        rp = f"{MODEL_DIR}/rf_model.joblib"
        if not os.path.exists(rp): return False
        try:
            import joblib
            self.model = joblib.load(rp)
            self.backend = "sklearn"; print(f"Backend: sklearn RF (CPU)"); return True
        except: return False

    def predict(self, features):
        if features.ndim == 1: features = features.reshape(1, -1)
        if self.scaler:
            features = self.scaler.transform(features)
        else:
            from flow_features import normalize_features
            features = np.array([normalize_features(f) for f in features])
        features = np.clip(features, -5.0, 5.0)
        results = []

        if self.model_type == "classifier":
            results = self._predict_classifier(features)
        else:
            results = self._predict_autoencoder(features)
        return results

    def _predict_classifier(self, features):
        """Classifier output: [normal_logit, attack_logit] → argmax + softmax score"""
        results = []
        if self.backend == "rknn":
            for i in range(len(features)):
                inp = features[i:i+1].astype(np.float32)
                out = self.model.inference(inputs=[inp])[0].flatten()
                # Softmax
                exp_out = np.exp(out - np.max(out))
                probs = exp_out / exp_out.sum()
                is_attack = bool(np.argmax(probs) == 1)
                score = float(probs[1])  # attack probability
                results.append((is_attack, score))
        elif self.backend == "onnx":
            inp_name = self.model.get_inputs()[0].name
            out = self.model.run(None, {inp_name: features.astype(np.float32)})[0]
            for row in out:
                exp_out = np.exp(row - np.max(row))
                probs = exp_out / exp_out.sum()
                is_attack = bool(np.argmax(probs) == 1)
                score = float(probs[1])
                results.append((is_attack, score))
        elif self.backend == "sklearn":
            preds = self.model.predict(features)
            probas = self.model.predict_proba(features)
            for p, pr in zip(preds, probas):
                results.append((bool(p == 1), float(pr[1])))
        return results

    def _predict_autoencoder(self, features):
        """Autoencoder output: reconstruction → MSE > threshold"""
        results = []
        if self.backend == "rknn":
            for i in range(len(features)):
                inp = features[i:i+1].astype(np.float32)
                out = self.model.inference(inputs=[inp])[0]
                err = float(np.mean((out - inp)**2))
                results.append((err > self.threshold, err))
        elif self.backend == "onnx":
            inp_name = self.model.get_inputs()[0].name
            out = self.model.run(None, {inp_name: features.astype(np.float32)})[0]
            for err in np.mean((out - features)**2, axis=1):
                results.append((float(err) > self.threshold, float(err)))
        elif self.backend == "sklearn":
            preds = self.model.predict(features)
            probas = self.model.predict_proba(features)
            for p, pr in zip(preds, probas):
                results.append((bool(p == 1), float(pr[1])))
        return results

    def benchmark(self):
        print(f"\n=== Inference Benchmark ({self.backend}, {self.model_type}) ===")
        dummy = np.random.rand(10, NUM_FEATURES).astype(np.float32)
        for _ in range(10): self.predict(dummy)
        for bs in [1, 10, 100, 1000]:
            batch = np.random.rand(bs, NUM_FEATURES).astype(np.float32)
            iters = max(1, 1000 // bs)
            t0 = time.time()
            for _ in range(iters): self.predict(batch)
            elapsed = time.time() - t0
            rate = (bs * iters) / elapsed
            print(f"  Batch {bs:5d}: {rate:>10,.0f} flows/sec")

def run_demo():
    import pandas as pd
    detector = NPUDetector()
    df = pd.read_csv(f"{MODEL_DIR}/training_data.csv")
    X = df.drop('label', axis=1).values.astype(np.float32)
    y = df['label'].values

    print(f"\nRunning detection on {len(X)} samples...")
    t0 = time.time()
    results = detector.predict(X)
    elapsed = time.time() - t0

    tp=fp=tn=fn=0
    for (anom, sc), lab in zip(results, y):
        if lab==1 and anom: tp+=1
        elif lab==0 and anom: fp+=1
        elif lab==0 and not anom: tn+=1
        else: fn+=1

    prec = tp/(tp+fp+1e-9); rec = tp/(tp+fn+1e-9)
    f1 = 2*prec*rec/(prec+rec+1e-9)
    print(f"\nResults ({elapsed:.3f}s, {len(X)/elapsed:.0f} samples/sec):")
    print(f"  TN={tn:4d}  FP={fp:4d}")
    print(f"  FN={fn:4d}  TP={tp:4d}")
    print(f"  Precision: {prec:.4f}  Recall: {rec:.4f}  F1: {f1:.4f}")

    detector.benchmark()

if __name__ == '__main__':
    run_demo()
