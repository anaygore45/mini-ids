"""Model Evaluation Pipeline for Mini-IDS.

Evaluates trained Random Forest, Logistic Regression, and Isolation Forest models
on held-out test splits. Generates rigorous scientific metrics: Accuracy, Precision,
Recall, F1-Score, Confusion Matrix, and saves evaluation reports.
"""

import argparse
import json
import logging
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional

import joblib
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

# Ensure project root in python path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def evaluate_models_on_test_set(
    task_type: str = "multiclass",
    models_dir: Path = Path("models"),
    data_dir: Path = Path("data/datasets/cicids2017/processed"),
    output_report_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Load held-out test split, evaluate all models found in models_dir, and output report."""
    logger.info("Loading test data for task: %s from %s", task_type, data_dir)
    X_test = np.load(data_dir / f"X_test_{task_type}.npy")
    y_test = np.load(data_dir / f"y_test_{task_type}.npy")

    with open(data_dir / f"metadata_{task_type}.json", "r", encoding="utf-8") as f:
        meta_data = json.load(f)

    label_map = meta_data["label_mapping"]
    inv_map = {int(k): v for k, v in meta_data["inverse_label_mapping"].items()}
    class_names = [inv_map[i] for i in range(len(inv_map))]
    benign_idx = label_map.get("BENIGN", 0)

    report_summary: Dict[str, Any] = {
        "task_type": task_type,
        "test_samples": int(len(X_test)),
        "class_distribution": {name: int((y_test == idx).sum()) for idx, name in inv_map.items()},
        "models": {},
    }

    print("\n" + "=" * 70)
    print(f"MINI-IDS MODEL EVALUATION REPORT (HELD-OUT TEST SET, N={len(X_test)})")
    print(f"Task: {task_type.upper()} | Classes: {class_names}")
    print("=" * 70)

    # Search for model bundle directories
    model_dirs = sorted([d for d in models_dir.iterdir() if d.is_dir() and (task_type in d.name or "isolation_forest" in d.name)])
    if not model_dirs:
        logger.warning("No model directories found in %s matching task %s", models_dir, task_type)

    for mdir in model_dirs:
        model_file = mdir / "model.joblib"
        meta_file = mdir / "metadata.json"
        if not model_file.exists():
            continue

        model = joblib.load(model_file)
        model_name = mdir.name

        with open(meta_file, "r", encoding="utf-8") as mf:
            saved_meta = json.load(mf)

        algo = saved_meta.get("algorithm", model_name)
        model_type = saved_meta.get("model_type", "")

        if "isolation_forest" in model_name:
            # Unsupervised Anomaly Model
            preds = model.predict(X_test)  # 1 = inlier (benign), -1 = outlier (attack)
            y_test_binary = np.where(y_test == benign_idx, 1, -1)
            inlier_acc = float(accuracy_score(y_test_binary, preds))

            attack_mask = (y_test_binary == -1)
            benign_mask = (y_test_binary == 1)

            attack_recall = float((preds[attack_mask] == -1).mean()) if attack_mask.any() else 0.0
            false_alarm_rate = float((preds[benign_mask] == -1).mean()) if benign_mask.any() else 0.0

            cm = confusion_matrix(y_test_binary, preds, labels=[1, -1])

            print(f"\nModel: {algo} ({mdir.name})")
            print("-" * 50)
            print(f"  Attack Detection Rate (Recall): {attack_recall * 100:.2f}%")
            print(f"  False Alarm Rate on Benign:     {false_alarm_rate * 100:.2f}%")
            print(f"  Overall Inlier/Outlier Acc:     {inlier_acc * 100:.2f}%")
            print(f"  Confusion Matrix [Benign, Attack] x [Inlier, Outlier]:")
            print(f"    {cm.tolist()}")

            report_summary["models"][model_name] = {
                "algorithm": algo,
                "model_type": model_type,
                "attack_detection_rate": round(attack_recall, 4),
                "false_alarm_rate": round(false_alarm_rate, 4),
                "overall_accuracy": round(inlier_acc, 4),
                "confusion_matrix": cm.tolist(),
            }

        else:
            # Supervised Classifier
            preds = model.predict(X_test)
            acc = float(accuracy_score(y_test, preds))
            f1_macro = float(f1_score(y_test, preds, average="macro", zero_division=0))
            f1_weighted = float(f1_score(y_test, preds, average="weighted", zero_division=0))
            prec_macro = float(precision_score(y_test, preds, average="macro", zero_division=0))
            rec_macro = float(recall_score(y_test, preds, average="macro", zero_division=0))
            cm = confusion_matrix(y_test, preds)
            clf_rep = classification_report(y_test, preds, target_names=class_names, output_dict=True, zero_division=0)

            print(f"\nModel: {algo} ({mdir.name})")
            print("-" * 50)
            print(f"  Test Accuracy:     {acc * 100:.2f}%")
            print(f"  Macro F1-Score:    {f1_macro * 100:.2f}%")
            print(f"  Weighted F1-Score: {f1_weighted * 100:.2f}%")
            print(f"  Macro Precision:   {prec_macro * 100:.2f}%")
            print(f"  Macro Recall:      {rec_macro * 100:.2f}%")
            print(f"  Per-class metrics:")
            for cname in class_names:
                cstats = clf_rep.get(cname, {})
                print(f"    - {cname:12s} Prec: {cstats.get('precision', 0)*100:5.1f}% | Rec: {cstats.get('recall', 0)*100:5.1f}% | F1: {cstats.get('f1-score', 0)*100:5.1f}% | N={cstats.get('support', 0)}")

            report_summary["models"][model_name] = {
                "algorithm": algo,
                "model_type": model_type,
                "accuracy": round(acc, 4),
                "macro_f1": round(f1_macro, 4),
                "weighted_f1": round(f1_weighted, 4),
                "macro_precision": round(prec_macro, 4),
                "macro_recall": round(rec_macro, 4),
                "confusion_matrix": cm.tolist(),
                "classification_report": clf_rep,
            }

    print("\n" + "=" * 70 + "\n")

    if output_report_path is None:
        output_report_path = models_dir / f"evaluation_report_{task_type}.json"
    with open(output_report_path, "w", encoding="utf-8") as rf:
        json.dump(report_summary, rf, indent=2)
    logger.info("Saved evaluation report to: %s", output_report_path)

    return report_summary


def main():
    parser = argparse.ArgumentParser(description="Evaluate Mini-IDS models on test split.")
    parser.add_argument(
        "--task-type",
        type=str,
        choices=["multiclass", "binary"],
        default="multiclass",
        help="Task type to evaluate",
    )
    parser.add_argument(
        "--models-dir",
        type=str,
        default="models",
        help="Directory containing saved model artifacts",
    )
    parser.add_argument(
        "--output-report",
        type=str,
        default=None,
        help="Path to output JSON evaluation report",
    )
    args = parser.parse_args()

    out_path = Path(args.output_report) if args.output_report else None
    evaluate_models_on_test_set(
        task_type=args.task_type,
        models_dir=Path(args.models_dir),
        output_report_path=out_path,
    )


if __name__ == "__main__":
    main()
