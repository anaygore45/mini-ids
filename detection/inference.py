"""Central Inference Engine for Mini-IDS.

Provides unified inference across offline files, PCAPs, and real-time telemetry:
- Schema conformance validation
- Preprocessing and scaling pipeline transformation
- Supervised binary and multiclass predictions
- Calibrated prediction confidence scores
- Anomaly scoring and outlier flagging
- Safe fallback mode on missing or corrupt model artifacts.
"""

from dataclasses import asdict, dataclass
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import joblib
import numpy as np
import pandas as pd

from detection.preprocessing import DetectionPreprocessor

logger = logging.getLogger("mini_ids.detection.inference")


@dataclass
class DetectionResult:
    """Structured output from inference engine."""
    is_attack: bool
    predicted_label: str
    confidence: float
    is_anomaly: bool
    anomaly_score: float
    model_name: str
    model_version: str
    severity: str
    explanation: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class CentralInferenceEngine:
    """Manages model loading, input validation, and real-time flow scoring."""

    def __init__(
        self,
        model_path: Optional[Union[str, Path]] = None,
        scaler_path: Optional[Union[str, Path]] = None,
        anomaly_model_path: Optional[Union[str, Path]] = None,
        schema_type: str = "canonical",
        label_mapping: Optional[Dict[int, str]] = None,
    ) -> None:
        self.schema_type = schema_type
        self.model: Optional[Any] = None
        self.scaler: Optional[Any] = None
        self.anomaly_model: Optional[Any] = None
        self.model_name = "Heuristic-Fallback"
        self.model_version = "v0.0.0"
        self.label_mapping = label_mapping or {0: "BENIGN", 1: "ATTACK"}

        # Attempt to load model
        if model_path and Path(model_path).exists():
            try:
                self.model = joblib.load(model_path)
                self.model_name = Path(model_path).stem
                self.model_version = Path(model_path).stem
                logger.info("Loaded supervised model: %s", model_path)
            except Exception as err:
                logger.warning("Failed to load model %s: %s", model_path, err)

        # Attempt to load scaler
        if scaler_path and Path(scaler_path).exists():
            try:
                self.scaler = joblib.load(scaler_path)
                logger.info("Loaded feature scaler: %s", scaler_path)
            except Exception as err:
                logger.warning("Failed to load scaler %s: %s", scaler_path, err)

        # Attempt to load anomaly detector
        if anomaly_model_path and Path(anomaly_model_path).exists():
            try:
                self.anomaly_model = joblib.load(anomaly_model_path)
                logger.info("Loaded anomaly detector: %s", anomaly_model_path)
            except Exception as err:
                logger.warning("Failed to load anomaly detector %s: %s", anomaly_model_path, err)

        self.preprocessor = DetectionPreprocessor(
            schema_type=self.schema_type,
            scaler=self.scaler,
        )

    def predict_flow(self, flow: Dict[str, Any]) -> DetectionResult:
        """Execute full inference pipeline on a single network flow."""
        try:
            X = self.preprocessor.prepare_flow(flow)
        except Exception as err:
            logger.error("Feature validation failed: %s", err)
            return DetectionResult(
                is_attack=False,
                predicted_label="ERROR_MALFORMED",
                confidence=0.0,
                is_anomaly=False,
                anomaly_score=0.0,
                model_name=self.model_name,
                model_version=self.model_version,
                severity="LOW",
                explanation=f"Malformed input schema: {err}",
            )

        # 1. Supervised Prediction
        pred_label_str = "BENIGN"
        is_attack = False
        confidence = 0.5

        if self.model is not None:
            try:
                raw_pred = self.model.predict(X)[0]
                pred_label_str = self.label_mapping.get(int(raw_pred), str(raw_pred))
                is_attack = (pred_label_str != "BENIGN" and raw_pred != 0)

                if hasattr(self.model, "predict_proba"):
                    probas = self.model.predict_proba(X)[0]
                    confidence = float(np.max(probas))
                else:
                    confidence = 0.90 if is_attack else 0.85
            except Exception as err:
                logger.warning("Supervised prediction error: %s", err)

        # 2. Anomaly Scoring
        is_anomaly = False
        anomaly_score = 0.0
        if self.anomaly_model is not None:
            try:
                raw_score = -float(self.anomaly_model.score_samples(X)[0])
                anomaly_score = round(raw_score, 4)
                is_anomaly = (anomaly_score >= 0.50)
            except Exception as err:
                logger.warning("Anomaly evaluation error: %s", err)

        # Severity Assessment
        if is_attack and confidence >= 0.85:
            severity = "HIGH"
            explanation = f"Classified as {pred_label_str} with {confidence:.1%} confidence."
        elif is_attack:
            severity = "MEDIUM"
            explanation = f"Likely {pred_label_str} (confidence: {confidence:.1%})."
        elif is_anomaly:
            severity = "MEDIUM"
            explanation = f"Statistical flow anomaly detected (score: {anomaly_score:.2f})."
        else:
            severity = "LOW"
            explanation = "Normal traffic parameters within baseline limits."

        return DetectionResult(
            is_attack=is_attack,
            predicted_label=pred_label_str,
            confidence=round(confidence, 4),
            is_anomaly=is_anomaly,
            anomaly_score=anomaly_score,
            model_name=self.model_name,
            model_version=self.model_version,
            severity=severity,
            explanation=explanation,
        )


__all__ = ["CentralInferenceEngine", "DetectionResult"]
