"""
train_and_compare.py - Scientific ML Model Training, Evaluation, and Serialization.
Author: Computer Science & Machine Learning Lab
Description: Trains multi-class Random Forest & XGBoost classifiers, 
             computes precise evaluation matrices, and dumps structured JSON.
"""

from __future__ import annotations
import json
import logging
import sys
from pathlib import Path
from typing import Final

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, accuracy_score, matthews_corrcoef, confusion_matrix
from sklearn.ensemble import RandomForestClassifier
import xgboost as xgb

# Ensure project root is on sys.path for config imports
PROJECT_ROOT: Final[Path] = Path(__file__).resolve().parent.parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Configure Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Import the local pipeline module
from pipeline import CICIDS2017Pipeline

def execute_academic_pipeline(dataset_path: str, artifacts_dir: str | None = None) -> None:
    if artifacts_dir is None:
        from config.settings import get_settings
        settings = get_settings()
        artifacts_path = settings.models_dir
    else:
        artifacts_path = Path(artifacts_dir)
    artifacts_path.mkdir(parents=True, exist_ok=True)
    
    # -------------------------------------------------------------------------
    # STEP 1: Data Preparation Pipeline
    # -------------------------------------------------------------------------
    logging.info("=== STEP 1: Running Data Pipeline ===")
    pipeline = CICIDS2017Pipeline(directory_path=dataset_path, artifacts_dir=artifacts_dir)
    
    raw_data = pipeline.load_and_merge_data()
    cleaned_data = pipeline.clean_data(raw_data)
    X_train, X_test, y_train, y_test = pipeline.process_split_and_save_artifacts(cleaned_data, test_size=0.20)
    
    class_names = [str(cls) for cls in pipeline.label_encoder.classes_]
    logging.info(f"System registered {len(class_names)} unique security classes: {class_names}")

    # -------------------------------------------------------------------------
    # STEP 2: Random Forest Multi-class Training
    # -------------------------------------------------------------------------
    logging.info("\n=== STEP 2: Training Random Forest Classifier ===")
    rf_model = RandomForestClassifier(
        n_estimators=150,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )
    logging.info("Training Random Forest model (this might take a few minutes)...")
    rf_model.fit(X_train, y_train)
    
    rf_model_path = artifacts_path / "random_forest_v3.joblib"
    joblib.dump(rf_model, rf_model_path, compress=3)
    logging.info(f"Successfully saved Random Forest artifact: {rf_model_path}")

    # -------------------------------------------------------------------------
    # STEP 3: XGBoost Multi-class Training
    # -------------------------------------------------------------------------
    logging.info("\n=== STEP 3: Training XGBoost Classifier ===")
    xgb_model = xgb.XGBClassifier(
        n_estimators=150,
        max_depth=6,
        learning_rate=0.1,
        objective="multi:softprob",
        num_class=len(class_names),
        eval_metric="mlogloss",
        n_jobs=-1,
        random_state=42
    )
    logging.info("Training XGBoost model...")
    xgb_model.fit(X_train, y_train)
    
    xgb_model_path = artifacts_path / "xgboost_pipeline_v2.joblib"
    joblib.dump(xgb_model, xgb_model_path, compress=3)
    logging.info(f"Successfully saved XGBoost artifact: {xgb_model_path}")

    # -------------------------------------------------------------------------
    # STEP 4: Evaluation, Comparative Analysis & JSON Metric Generation
    # -------------------------------------------------------------------------
    logging.info("\n=== STEP 4: Academic Performance Evaluation ===")
    
    rf_preds = rf_model.predict(X_test)
    xgb_preds = xgb_model.predict(X_test)
    
    # Calculate global metrics
    rf_acc = float(accuracy_score(y_test, rf_preds))
    xgb_acc = float(accuracy_score(y_test, xgb_preds))
    
    rf_mcc = float(matthews_corrcoef(y_test, rf_preds))
    xgb_mcc = float(matthews_corrcoef(y_test, xgb_preds))
    
    # Compute confusion matrices
    rf_cm = confusion_matrix(y_test, rf_preds).tolist()
    xgb_cm = confusion_matrix(y_test, xgb_preds).tolist()
    
    # Generate structured classification reports as dictionaries
    rf_report = classification_report(y_test, rf_preds, target_names=class_names, output_dict=True, zero_division=0)
    xgb_report = classification_report(y_test, xgb_preds, target_names=class_names, output_dict=True, zero_division=0)
    
    # Build complete JSON-serializable evaluation structure
    evaluation_results = {
        "classes": class_names,
        "random_forest": {
            "accuracy": rf_acc,
            "mcc": rf_mcc,
            "report": rf_report,
            "confusion_matrix": rf_cm
        },
        "xgboost": {
            "accuracy": xgb_acc,
            "mcc": xgb_mcc,
            "report": xgb_report,
            "confusion_matrix": xgb_cm
        }
    }
    
    # Export metrics file for Streamlit ingestion
    json_path = artifacts_path / "models_evaluation_results.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(evaluation_results, f, indent=4, ensure_ascii=False)
        
    logging.info(f"Successfully exported structured JSON metrics: {json_path}")
    logging.info("🎉 Multi-class Academic Pipeline Execution Completed Successfully!")

if __name__ == "__main__":
    from config.settings import Settings, get_settings
    settings = get_settings()
    DATASET_PATH = settings.base_dir / "ml" / "training" / "MachineLearningCVE" / "data"
    if not DATASET_PATH.exists():
        print(f"[WARN] Default dataset path not found: {DATASET_PATH}")
        print("[WARN] Please provide the correct path via --dataset argument or update DATASET_PATH below.")
        DATASET_PATH = input("Enter dataset directory path: ").strip() or str(DATASET_PATH)
    execute_academic_pipeline(dataset_path=str(DATASET_PATH))