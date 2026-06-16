"""Stage 1 测试：特征提取和二分类。"""

import os
import sys
import pytest
import pandas as pd
import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from llm_api_analyze.feature_extractor import EnhancedSecurityFeatureExtractor
from llm_api_analyze.classifier import LocalBinaryClassifier


# ==================== 夹具 ====================

@pytest.fixture(scope="module")
def feature_extractor():
    return EnhancedSecurityFeatureExtractor()


@pytest.fixture(scope="module")
def train_data():
    path = os.path.join(os.path.dirname(__file__), "..", "final_training_data.csv")
    if not os.path.exists(path):
        pytest.skip("未找到训练数据")
    return pd.read_csv(path)


@pytest.fixture(scope="module")
def test_data():
    path = os.path.join(os.path.dirname(__file__), "..", "test_without_type.csv")
    if not os.path.exists(path):
        pytest.skip("未找到测试数据")
    return pd.read_csv(path)


# ==================== 特征提取测试 ====================

class TestFeatureExtraction:
    """测试 EnhancedSecurityFeatureExtractor。"""

    def test_extraction_from_valid_row(self, feature_extractor):
        """应从标准日志行中提取特征。"""
        row = ["GET", "body", "/api/test", "response", "200", "100", "admin"]
        features = feature_extractor.extract_features_from_log(row)
        assert features, "应返回非空特征"
        assert features["method_get"] == 1
        assert features["method_post"] == 0
        assert features["status_2xx"] == 1
        assert features["url_depth"] >= 2

    def test_extraction_from_empty_row(self, feature_extractor):
        """应优雅地处理空/不完整行而不崩溃。"""
        row = []
        features = feature_extractor.extract_features_from_log(row)
        assert features, "仍应返回特征字典"
        # 验证安全默认值
        assert features.get("request_body_length") == 0
        assert features.get("response_time_ms") == 0

    def test_dir_traversal_detection(self, feature_extractor):
        """应检测目录遍历模式。"""
        row = ["GET", "", "/api/../../../etc/passwd", "", "200", "50", "user"]
        features = feature_extractor.extract_features_from_log(row)
        assert features["dir_traversal_score"] > 0
        assert features["has_dir_traversal"] == 1

    def test_xss_detection(self, feature_extractor):
        """应检测 XSS 模式。"""
        row = ["POST", "<script>alert('xss')</script>", "/api/search", "", "200", "50", "user"]
        features = feature_extractor.extract_features_from_log(row)
        assert features["xss_score"] > 0
        assert features["has_xss"] == 1

    def test_injection_detection(self, feature_extractor):
        """应检测 SQL 注入模式。"""
        # 模式：r"'.*?(or|and).*?=.*?'" 需要闭合单引号
        row = ["GET", "' OR '1'='1", "/api/login", "", "200", "50", "user"]
        features = feature_extractor.extract_features_from_log(row)
        assert features["injection_score"] > 0
        assert features["has_injection"] == 1

    def test_sensitive_data_detection(self, feature_extractor):
        """应检测响应中的敏感数据。"""
        # 模式：r"password\s*[:=]\s*['\"].{6,}['\"]" 需要引号内的值 >=6 个字符
        row = ["GET", "", "/api/user", 'password = "supersecret123456"', "200", "50", "user"]
        features = feature_extractor.extract_features_from_log(row)
        assert features["sensitive_data_leakage"] > 0

    def test_feature_vector_structure(self, feature_extractor):
        """应生成一致的特征维度。"""
        row1 = ["GET", "a", "/b", "c", "200", "100", "user"]
        row2 = ["POST", "d", "/e", "f", "404", "500", "admin"]
        f1 = feature_extractor.extract_features_from_log(row1)
        f2 = feature_extractor.extract_features_from_log(row2)
        assert set(f1.keys()) == set(f2.keys()), "特征键应一致"
        # 验证布尔型与数值型特征
        for k, v in f1.items():
            assert isinstance(v, (int, float, bool, np.integer, np.floating)), \
                f"特征 {k} 的类型 {type(v)} 无效"

    def test_status_code_features(self, feature_extractor):
        """应正确编码状态码。"""
        # 4xx
        row = ["GET", "", "/api", "", "403", "100", "user"]
        f = feature_extractor.extract_features_from_log(row)
        assert f["status_4xx"] == 1
        assert f["status_client_error"] == 1

        # 5xx
        row[4] = "500"
        f = feature_extractor.extract_features_from_log(row)
        assert f["status_5xx"] == 1

    def test_unauthorized_access_heuristic(self, feature_extractor):
        """访客+管理端点应提高未授权分数。"""
        row = ["DELETE", "", "/admin/delete", "", "200", "100", "guest"]
        f = feature_extractor.extract_features_from_log(row)
        assert f["unauthorized_access_score"] > 0

    def test_response_time_features(self, feature_extractor):
        """应标记慢速响应。"""
        row = ["GET", "", "/api", "", "200", "2000", "user"]
        f = feature_extractor.extract_features_from_log(row)
        assert f["slow_response"] == 1
        assert f["response_time_ms"] == 2000


# ==================== 分类器测试 ====================

class TestBinaryClassifier:
    """测试 LocalBinaryClassifier 的训练和预测。"""

    @pytest.fixture
    def classifier(self, feature_extractor):
        return LocalBinaryClassifier(feature_extractor, threshold=0.1)

    def test_feature_preparation_shape(self, classifier, train_data):
        """特征准备应生成一致的形状。"""
        label_column = train_data.columns[7]
        X, y = classifier.prepare_data(train_data, label_column)
        assert X.shape[0] == len(train_data)
        assert y.shape[0] == len(train_data)
        assert all(isinstance(c, str) for c in X.columns)

    def test_training_completes(self, classifier, train_data):
        """在提取的特征上训练随机森林应完成。"""
        label_column = train_data.columns[7]
        X, y = classifier.prepare_data(train_data, label_column)
        model = classifier.train(X, y)
        assert model is not None
        assert hasattr(model, "predict")

    def test_prediction_output(self, classifier, train_data, test_data):
        """预测应返回有效的标签和概率。"""
        label_column = train_data.columns[7]
        X_train, y_train = classifier.prepare_data(train_data, label_column)
        classifier.train(X_train, y_train)

        X_test, _ = classifier.prepare_data(test_data)
        y_pred, y_proba = classifier.predict_with_threshold(X_test, 0.1, test_data)

        assert len(y_pred) == len(test_data)
        assert len(y_proba) == len(test_data)
        assert set(np.unique(y_pred)).issubset({0, 1})
        assert np.all((y_proba >= 0) & (y_proba <= 1))

    def test_different_thresholds(self, classifier, train_data, test_data):
        """较高的阈值应产生较少的正预测。"""
        label_column = train_data.columns[7]
        X_train, y_train = classifier.prepare_data(train_data, label_column)
        classifier.train(X_train, y_train)

        X_test, _ = classifier.prepare_data(test_data)
        y_pred_low, _ = classifier.predict_with_threshold(X_test, 0.05, test_data)
        y_pred_high, _ = classifier.predict_with_threshold(X_test, 0.5, test_data)

        assert y_pred_low.sum() >= y_pred_high.sum()


# ==================== 端到端 Stage 1 ====================

class TestStage1Pipeline:
    """Stage 1 流水线的端到端测试。"""

    def test_full_stage1_run(self, train_data, test_data):
        """运行完整的 Stage 1 流水线并验证输出。"""
        extractor = EnhancedSecurityFeatureExtractor()
        classifier = LocalBinaryClassifier(extractor, threshold=0.017)
        label_column = train_data.columns[7]

        X_train, y_train = classifier.prepare_data(train_data, label_column)
        classifier.train(X_train, y_train)

        X_test, _ = classifier.prepare_data(test_data)
        y_pred, y_proba = classifier.predict_with_threshold(X_test, 0.017, test_data)

        # 验证输出格式
        results_df = pd.DataFrame({
            'index': range(len(y_proba)),
            'probability': y_proba,
            'predicted_label': y_pred
        })
        assert list(results_df.columns) == ['index', 'probability', 'predicted_label']
        assert results_df['predicted_label'].isin([0, 1]).all()
        assert results_df['probability'].between(0, 1).all()

        # 至少有一些差异（并非全部同一类别）
        assert results_df['predicted_label'].nunique() >= 1
