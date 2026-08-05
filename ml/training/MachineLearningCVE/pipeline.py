"""
pipeline.py - Production-Ready Data Pipeline for CIC-IDS2017 dataset.
Author: Computer Science & Machine Learning Lab
Description: Handles memory-efficient CSV reading, advanced cleaning, 
             stratified splitting, feature scaling, and exports artifacts.
"""

from __future__ import annotations
import os
import glob
import logging
import joblib
import numpy as np
import pandas as pd
from pathlib import Path
from typing import Tuple, List
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

# Configure Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class CICIDS2017Pipeline:
    """
    Highly optimized data preparation pipeline for multi-class classification.
    """
    def __init__(self, directory_path: str, artifacts_dir: str = "models"):
        self.directory_path = Path(directory_path)
        self.artifacts_dir = Path(artifacts_dir)
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        
        self.label_encoder = LabelEncoder()
        self.scaler = StandardScaler()
        self.features_columns: List[str] = []

    def _find_csv_files(self) -> List[Path]:
        """Finds all CSV files inside the targeted directory."""
        files = list(self.directory_path.glob("*.csv"))
        if not files:
            raise FileNotFoundError(f"No CSV files found in directory: {self.directory_path}")
        logging.info(f"Found {len(files)} CSV files for processing.")
        return files

    def load_and_merge_data(self) -> pd.DataFrame:
        """Reads CSV files efficiently and merges them into a single pandas DataFrame."""
        files = self._find_csv_files()
        chunks = []
        
        for file in files:
            logging.info(f"Loading file: {file.name}")
            try:
                # skipinitialspace removes leading spaces from column names automatically
                df_chunk = pd.read_csv(file, skipinitialspace=True)
                chunks.append(df_chunk)
            except Exception as e:
                logging.error(f"Failed to read {file.name}. Reason: {e}")
                
        if not chunks:
            raise ValueError("All file reads failed. Data chunk list is empty.")
            
        logging.info("Merging chunks into a unified DataFrame...")
        merged_df = pd.concat(chunks, axis=0, ignore_index=True)
        logging.info(f"Raw Merged Shape: {merged_df.shape}")
        return merged_df

    def clean_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """Cleans the dataframe by handling infs, NaNs, duplicates and zero-variance columns."""
        logging.info("Starting Deep Data Cleansing Phase...")
        
        # 1. Handle Infinity and Missing Values
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        initial_rows = df.shape[0]
        df.dropna(inplace=True)
        
        # Log dropped rows
        dropped_null_inf = initial_rows - df.shape[0]
        if dropped_null_inf > 0:
            logging.info(f"Dropped {dropped_null_inf} rows containing NaN/Inf values.")

        # 2. Drop Zero-Variance (constant) features
        constant_cols = [col for col in df.columns if df[col].nunique() <= 1]
        if constant_cols:
            df.drop(columns=constant_cols, inplace=True)
            logging.info(f"Dropped {len(constant_cols)} zero-variance constant columns: {constant_cols}")

        # 3. Drop duplicate rows to prevent data leakage and overfitting
        initial_rows_before_dup = df.shape[0]
        df.drop_duplicates(inplace=True)
        logging.info(f"Dropped {initial_rows_before_dup - df.shape[0]} duplicate rows.")
        
        logging.info(f"Final Processed Clean Shape: {df.shape}")
        return df

    def process_split_and_save_artifacts(self, df: pd.DataFrame, test_size: float = 0.2) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """Encodes labels, splits data stratifically, scales features, and exports pipeline artifacts."""
        logging.info("Starting Feature Engineering, Splitting, and Artifact Export...")
        
        if 'Label' not in df.columns:
            raise KeyError("Target column 'Label' is missing from the dataset.")
            
        X = df.drop(columns=['Label'])
        y = df['Label']
        self.features_columns = list(X.columns)

        # Encode multi-class labels safely
        y_encoded = self.label_encoder.fit_transform(y)
        
        # Export Label Encoder
        le_path = self.artifacts_dir / "label_encoder.joblib"
        joblib.dump(self.label_encoder, le_path)
        logging.info(f"Exported Label Encoder to: {le_path}")

        # Stratified Split to preserve class representation in rare attacks
        X_train, X_test, y_train, y_test = train_test_split(
            X, y_encoded, test_size=test_size, random_state=42, stratify=y_encoded
        )

        # Standard Scaling of Features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Export StandardScaler
        scaler_path = self.artifacts_dir / "scaler.joblib"
        joblib.dump(self.scaler, scaler_path)
        logging.info(f"Exported StandardScaler to: {scaler_path}")

        return X_train_scaled, X_test_scaled, y_train, y_test