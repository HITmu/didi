"""使用RandomForest的本地二分类器，带有特征工程。"""

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier

from llm_api_analyze.config import RANDOM_SEED, PREDICTION_THRESHOLD


class LocalBinaryClassifier:
    """两阶段二分类器：特征提取 + RandomForest。"""

    def __init__(self, feature_extractor, threshold=PREDICTION_THRESHOLD):
        self.feature_extractor = feature_extractor
        self.threshold = threshold
        self.model = None
        self.scaler = StandardScaler()
        self.feature_names = None

    def prepare_data(self, df, label_column=None):
        """从数据框中提取特征，可选提取标签。"""
        print(f"Preparing data: {len(df)} logs...")
        all_features, labels = [], []
        for idx, row in df.iterrows():
            features = self.feature_extractor.extract_features_from_log(row)
            if features:
                all_features.append(features)
                if label_column is not None and label_column in row:
                    label = str(row[label_column]).strip().lower()
                    labels.append(0 if label == 'normal' else 1)
        features_df = pd.DataFrame(all_features)
        self.feature_names = features_df.columns.tolist()
        print(f"Features extracted: {len(features_df.columns)} dimensions")
        return features_df, np.array(labels) if labels else None

    def train(self, X_train, y_train):
        """训练RandomForest分类器。"""
        print("Training RandomForest model...")
        X_train_scaled = self.scaler.fit_transform(X_train)
        self.model = RandomForestClassifier(
            n_estimators=200, max_depth=15,
            min_samples_split=5, min_samples_leaf=2,
            random_state=RANDOM_SEED, class_weight='balanced', n_jobs=-1
        )
        self.model.fit(X_train_scaled, y_train)

        # 特征重要性
        importance = pd.DataFrame({
            'feature': self.feature_names,
            'importance': self.model.feature_importances_
        }).sort_values('importance', ascending=False)
        print("\nTop 10 important features:")
        for i, (_, r) in enumerate(importance.head(10).iterrows()):
            print(f"  {i+1:2d}. {r['feature']:30s} {r['importance']:.4f}")
        return self.model

    def predict_with_threshold(self, X, threshold, test_df=None):
        """使用概率阈值和硬规则进行预测。"""
        X_scaled = self.scaler.transform(X)
        y_proba = self.model.predict_proba(X_scaled)[:, 1]
        y_pred = (y_proba >= threshold).astype(int)

        # 硬规则
        if test_df is not None:
            for i in range(min(len(y_pred), len(test_df))):
                try:
                    rt = float(str(test_df.iloc[i, 5]).strip()) if len(test_df.iloc[i]) > 5 else 0
                    if rt > 2000:
                        y_pred[i] = 1
                    elif '../' in str(test_df.iloc[i, 2]):
                        y_pred[i] = 1
                except Exception:
                    continue
        return y_pred, y_proba

    def save_model(self, path):
        """保存训练好的模型工件。"""
        import joblib
        joblib.dump({'model': self.model, 'scaler': self.scaler, 'feature_names': self.feature_names}, path)
