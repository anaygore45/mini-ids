"""Model Training Pipeline for Mini-IDS.

Trains Random Forest, Logistic Regression, and Isolation Forest models on preprocessed
CIC-IDS2017 flow data using scikit-learn estimators. Saves models and metadata to
`models/` and registers them into the Mini-IDS model registry.
"""

import argparse
import json
import logging
from pathlib import Path
import sys
import time
from typing import Any, Dict, List, Optional

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, f1_score, precision_score, recall_score

# Ensure project root in python path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from detection.feature_schema import CANONICAL_FLOW_FEATURES
from ml.model_registry import ModelRegistry

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def train_and_register_models(
    task_type: str = "multiclass",
    models_to_train: Optional[List[str]] = None,
    data_dir: Path = Path("data/datasets/cicids2017/processed"),
    output_dir: Path = Path("models"),
    random_seed: int = 42,
) -> Dict[str, Dict[str, Any]]:
    """Train estimators on processed splits and save artifacts."""
    if models_to_train is None:
        models_to_train = ["random_forest", "logistic_regression", "isolation_forest"]

    # 1. Load data
    logger.info("Loading processed dataset splits for task: %s from %s", task_type, data_dir)
    X_train = np.load(data_dir / f"X_train_{task_type}.npy")
    y_train = np.load(data_dir / f"y_train_{task_type}.npy")
    X_val = np.load(data_dir / f"X_val_{task_type}.npy")
    y_val = np.load(data_dir / f"y_val_{task_type}.npy")
    scaler = joblib.load(data_dir / f"scaler_{task_type}.joblib")

    with open(data_dir / f"metadata_{task_type}.json", "r", encoding="utf-8") as f:
        meta_data = json.load(f)

    label_map = meta_data["label_mapping"]
    inv_map = {int(k): v for k, v in meta_data["inverse_label_mapping"].items()}
    benign_idx = label_map.get("BENIGN", 0)

    output_dir.mkdir(parents=True, exist_ok=True)
    registry = ModelRegistry(models_dir=output_dir)
    results: Dict[str, Dict[str, Any]] = {}

    timestamp_str = str(int(time.time()))

    # 2. Random Forest
    if "random_forest" in models_to_train or "all" in models_to_train:
        logger.info("--- Training Random Forest (%s) ---", task_type)
        rf = RandomForestClassifier(
            n_estimators=100,
            max_depth=15,
            min_samples_split=2,
            class_weight="balanced",
            random_state=random_seed,
            n_jobs=-1,
        )
        t0 = time.time()
        rf.fit(X_train, y_train)
        duration = time.time() - t0

        y_pred = rf.predict(X_val)
        acc = float(accuracy_score(y_val, y_pred))
        f1_macro = float(f1_score(y_val, y_pred, average="macro", zero_division=0))
        prec_macro = float(precision_score(y_val, y_pred, average="macro", zero_division=0))
        rec_macro = float(recall_score(y_val, y_pred, average="macro", zero_division=0))

        version = f"random_forest_{task_type}_{timestamp_str}"
        metrics = {
            "accuracy": round(acc, 4),
            "f1_macro": round(f1_macro, 4),
            "precision_macro": round(prec_macro, 4),
            "recall_macro": round(rec_macro, 4),
            "training_duration_s": round(duration, 3),
            "train_samples": len(X_train),
            "val_samples": len(X_val),
        }
        logger.info("Random Forest Val Acc: %.4f, F1: %.4f (trained in %.2fs)", acc, f1_macro, duration)

        meta = registry.save_model_bundle(
            name="Random Forest Classifier",
            version=version,
            model=rf,
            preprocessor=scaler,
            model_type=f"supervised_{task_type}",
            algorithm="RandomForestClassifier",
            dataset_name="CIC-IDS2017",
            task_type=task_type,
            feature_schema=CANONICAL_FLOW_FEATURES,
            metrics=metrics,
            set_active=True,
        )
        results["random_forest"] = meta.to_dict()

    # 3. Logistic Regression
    if "logistic_regression" in models_to_train or "all" in models_to_train:
        logger.info("--- Training Logistic Regression (%s) ---", task_type)
        lr = LogisticRegression(
            max_iter=1000,
            C=1.0,
            class_weight="balanced",
            random_state=random_seed,
        )
        t0 = time.time()
        lr.fit(X_train, y_train)
        duration = time.time() - t0

        y_pred = lr.predict(X_val)
        acc = float(accuracy_score(y_val, y_pred))
        f1_macro = float(f1_score(y_val, y_pred, average="macro", zero_division=0))
        prec_macro = float(precision_score(y_val, y_pred, average="macro", zero_division=0))
        rec_macro = float(recall_score(y_val, y_pred, average="macro", zero_division=0))

        version = f"logistic_regression_{task_type}_{timestamp_str}"
        metrics = {
            "accuracy": round(acc, 4),
            "f1_macro": round(f1_macro, 4),
            "precision_macro": round(prec_macro, 4),
            "recall_macro": round(rec_macro, 4),
            "training_duration_s": round(duration, 3),
            "train_samples": len(X_train),
            "val_samples": len(X_val),
        }
        logger.info("Logistic Regression Val Acc: %.4f, F1: %.4f (trained in %.2fs)", acc, f1_macro, duration)

        meta = registry.save_model_bundle(
            name="Logistic Regression Classifier",
            version=version,
            model=lr,
            preprocessor=scaler,
            model_type=f"supervised_{task_type}",
            algorithm="LogisticRegression",
            dataset_name="CIC-IDS2017",
            task_type=task_type,
            feature_schema=CANONICAL_FLOW_FEATURES,
            metrics=metrics,
            set_active=False,
        )
        results["logistic_regression"] = meta.to_dict()

    # 4. Isolation Forest (Unsupervised baseline on BENIGN traffic)
    if "isolation_forest" in models_to_train or "all" in models_to_train:
        logger.info("--- Training Isolation Forest Anomaly Detector ---")
        benign_mask = (y_train == benign_idx)
        X_train_benign = X_train[benign_mask]

        iso = IsolationForest(
            n_estimators=100,
            contamination=0.05,
            random_state=random_seed,
            n_jobs=-1,
        )
        t0 = time.time()
        iso.fit(X_train_benign)
        duration = time.time() - t0

        # Evaluate anomaly predictions on validation set: 1 = inlier (benign), -1 = outlier (attack/anomaly)
        iso_preds = iso.predict(X_val)
        y_val_binary = np.where(y_val == benign_idx, 1, -1)  # inlier vs outlier
        anomaly_acc = float(accuracy_score(y_val_binary, iso_preds))
        # Anomaly detection rate (recall on actual attacks)
        attack_mask = (y_val_binary == -1)
        anomaly_recall = float((iso_preds[attack_mask] == -1).mean()) if attack_mask.any() else 0.0

        version = f"isolation_forest_anomaly_{timestamp_str}"
        metrics = {
            "inlier_accuracy": round(anomaly_acc, 4),
            "attack_detection_rate": round(anomaly_recall, 4),
            "contamination": 0.05,
            "training_duration_s": round(duration, 3),
            "benign_train_samples": len(X_train_benign),
            "val_samples": len(X_val),
        }
        logger.info("Isolation Forest Attack Detection Rate: %.4f (trained on %d benign flows in %.2fs)",
                    anomaly_recall, len(X_train_benign), duration)

        meta = registry.save_model_bundle(
            name="Isolation Forest Anomaly Detector",
            version=version,
            model=iso,
            preprocessor=scaler,
            model_type="anomaly_isolation_forest",
            algorithm="IsolationForest",
            dataset_name="CIC-IDS2017",
            task_type="anomaly",
            feature_schema=CANONICAL_FLOW_FEATURES,
            metrics=metrics,
            set_active=True,
        )
        results["isolation_forest"] = meta.to_dict()

    logger.info("Model training pipeline finished successfully. Artifacts registered in: %s", output_dir)
    return results


def main():
    parser = argparse.ArgumentParser(description="Train Mini-IDS detection and anomaly models.")
    parser.add_argument(
        "--task-type",
        type=str,
        choices=["multiclass", "binary"],
        default="multiclass",
        help="Task type to train on",
    )
    parser.add_argument(
        "--models",
        type=str,
        nargs="+",
        default=["random_forest", "logistic_regression", "isolation_forest"],
        help="Models to train: random_forest logistic_regression isolation_forest",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="models",
        help="Directory to save model artifacts",
    )
    args = parser.parse_args()

    train_and_register_models(
        task_type=args.task_type,
        models_to_train=args.models,
        output_dir=Path(args.output_dir),
    )


if __name__ == "__main__":
    main()
