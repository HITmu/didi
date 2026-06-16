"""使用模拟 LLM API 服务器的端到端流水线测试。"""

import os
import sys
import json
import time
import asyncio
import pytest
import pandas as pd
import requests
import uvicorn
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


@pytest.fixture(scope="module")
def mock_server():
    """在端口 18002 上启动模拟 LLM 服务器。"""
    from tests.mock_llm_server import app

    port = 18002
    url = f"http://127.0.0.1:{port}"

    config = uvicorn.Config(app, host="0.0.0.0", port=port, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run)
    thread.daemon = True
    thread.start()

    for _ in range(20):
        try:
            requests.get(f"{url}/health", timeout=2)
            break
        except requests.ConnectionError:
            time.sleep(0.3)

    yield {"url": url, "api_url": f"{url}/v1/chat/completions", "port": port}
    server.should_exit = True
    thread.join(timeout=5)


@pytest.fixture(scope="module")
def test_data():
    """加载测试数据夹具。"""
    root = os.path.dirname(os.path.dirname(__file__))
    train = pd.read_csv(os.path.join(root, "final_training_data.csv"))
    test = pd.read_csv(os.path.join(root, "test_without_type.csv"))
    gt = pd.read_csv(os.path.join(root, "cleaned_test.csv"))
    return {"train": train, "test": test, "ground_truth": gt}


@pytest.fixture(scope="module")
def stage1_results(test_data):
    """运行一次 Stage 1 并在测试间复用结果。"""
    from llm_api_analyze.feature_extractor import EnhancedSecurityFeatureExtractor
    from llm_api_analyze.classifier import LocalBinaryClassifier

    train_df = test_data["train"]
    test_df = test_data["test"]
    label_column = train_df.columns[7]

    extractor = EnhancedSecurityFeatureExtractor()
    classifier = LocalBinaryClassifier(extractor, threshold=0.017)
    X_train, y_train = classifier.prepare_data(train_df, label_column)
    classifier.train(X_train, y_train)
    X_test, _ = classifier.prepare_data(test_df)
    y_pred, y_proba = classifier.predict_with_threshold(X_test, 0.017, test_df)

    results = pd.DataFrame({
        'index': range(len(y_proba)),
        'probability': y_proba,
        'predicted_label': y_pred
    })
    return results, test_df


# ==================== 测试 ====================

class TestStage2WithMockAPI:
    """使用模拟 API 测试 Stage 2 RAG-LLM 集成。"""

    def test_stage2_with_mock_api(self, mock_server, stage1_results, test_data):
        """通过检测器直接使用模拟 API 运行完整的 Stage 2 分析。"""
        results_df, test_df = stage1_results
        suspicious = results_df[results_df['predicted_label'] == 1]['index'].tolist()
        if len(suspicious) == 0:
            pytest.skip("Stage 1 未产生可疑样本")

        from llm_api_analyze.rag.prompt_builder import RAGPromptBuilder
        from llm_api_analyze.rag.detector import SerialAttackDetector

        prompt_dir = os.path.join(os.path.dirname(__file__), "..", "prompts")
        prompt_builder = RAGPromptBuilder(prompt_dir=prompt_dir)
        detector = SerialAttackDetector(prompt_builder, api_url=mock_server["api_url"])

        # 加载测试日志
        test_logs = test_data["test"].values.tolist()
        test_indices = suspicious[:5]

        async def run():
            all_results = []
            for idx in test_indices:
                if idx < len(test_logs):
                    result = await detector.detect_serial(test_logs[idx], idx, {})
                    if result:
                        all_results.append(result)
            return all_results

        results = asyncio.run(run())

        assert len(results) > 0
        for r in results:
            assert len(r) >= 5
            assert r[1] in ("normal", "anomaly", "error")

    def test_serial_detection_lifecycle(self, mock_server):
        """测试串行检测的完整生命周期。"""
        from llm_api_analyze.rag.prompt_builder import RAGPromptBuilder
        from llm_api_analyze.rag.detector import SerialAttackDetector

        prompt_builder = RAGPromptBuilder(
            prompt_dir=os.path.join(os.path.dirname(__file__), "..", "prompts")
        )
        detector = SerialAttackDetector(prompt_builder, api_url=mock_server["api_url"])

        log_data = ["GET", "", "/api/test", "", "200", "100", "user"]
        similar_map = {0: []}

        async def run():
            result = await detector.detect_serial(log_data, 0, similar_map)
            return result

        result = asyncio.run(run())
        assert result is not None
        assert result[0] == 0
        assert result[1] in ("normal", "anomaly")


class TestReportGeneration:
    """使用真实数据进行 RAG 报告生成测试。"""

    def test_generate_report(self, stage1_results, test_data):
        """生成完整的 RAG 报告并验证其结构。"""
        from llm_api_analyze.report.rag_reporter import RAGReportGenerator

        results_df, test_df = stage1_results

        reporter = RAGReportGenerator(
            ground_truth_csv=os.path.join(os.path.dirname(__file__), "..", "cleaned_test.csv")
        )

        report = reporter.generate_report(
            stage1_results=results_df,
            full_test_df=test_df,
            stage2_results=[],
            train_csv_path=os.path.join(os.path.dirname(__file__), "..", "sampled_dataset.csv")
        )

        # 检查报告结构
        assert "report_metadata" in report
        assert "classification_grading" in report
        assert "internal_knowledge" in report
        assert "bad_case_analysis" in report

        # 检查分级
        grading = report["classification_grading"]
        assert "severity_summary" in grading
        assert "threat_level" in grading

        # 检查知识
        knowledge = report["internal_knowledge"]
        assert "attack_type_distribution" in knowledge
        assert "total_samples" in knowledge

        # 检查错误案例
        bad_cases = report["bad_case_analysis"]
        if "error" not in bad_cases:
            assert "summary" in bad_cases

    def test_report_markdown_format(self, stage1_results, test_data):
        """报告应格式化为有效的 Markdown。"""
        from llm_api_analyze.report.rag_reporter import RAGReportGenerator

        reporter = RAGReportGenerator()
        report = reporter.generate_report(
            stage1_results=stage1_results[0],
            full_test_df=test_data["test"],
            stage2_results=[]
        )
        md = reporter.format_report_markdown(report)

        assert md is not None
        assert len(md) > 100  # 有实质内容
        assert "# Security Analysis Report" in md
        assert "## Overall Performance Metrics" in md
        assert "## Classification & Severity Grading" in md
        assert "## Error Case Analysis" in md or "## Internal Knowledge" in md

    def test_report_save_load(self, stage1_results, test_data, tmp_path):
        """报告应能正确保存和加载。"""
        from llm_api_analyze.report.rag_reporter import RAGReportGenerator

        reporter = RAGReportGenerator()
        report = reporter.generate_report(
            stage1_results=stage1_results[0],
            full_test_df=test_data["test"],
            stage2_results=[]
        )

        # 保存为 Markdown
        md_path = os.path.join(tmp_path, "test_report.md")
        reporter.save_report(report, md_path)
        assert os.path.exists(md_path)
        with open(md_path) as f:
            content = f.read()
        assert len(content) > 100

        # 保存为 JSON
        json_path = os.path.join(tmp_path, "test_report.json")
        reporter.save_report(report, json_path, as_json=True)
        assert os.path.exists(json_path)
        with open(json_path) as f:
            loaded = json.load(f)
        assert "report_metadata" in loaded


class TestCascadeIntegration:
    """测试完整的级联系统集成。"""

    def test_cascade_metrics_calculation(self):
        """测试级联指标计算正确性。"""
        from shared.metrics import (
            calculate_cascade_metrics,
            calculate_llm_cost_metrics
        )

        # 模拟 100 个样本
        y_true = [0] * 80 + [1] * 20
        y_pred = [0] * 75 + [1] * 5 + [0] * 5 + [1] * 15
        y_score = [0.1] * 80 + [0.8] * 20

        metrics = calculate_cascade_metrics(y_true, y_pred, y_score)
        assert metrics["total_samples"] == 100
        assert "accuracy" in metrics
        assert "precision" in metrics
        assert "recall" in metrics
        assert "f1_score" in metrics
        assert "auc_score" in metrics
        assert "confusion_matrix" in metrics

        # LLM 成本
        cost = calculate_llm_cost_metrics(
            total_samples=100,
            stage1_normal_count=80,
            actual_llm_calls=50
        )
        assert cost["saved_calls"] > 0
        assert "llm_saved_rate" in cost

    def test_cross_version_config_consistency(self):
        """LLM API 和 SEC 配置应共享相同结构。"""
        import llm_api_analyze.config as dsk_cfg
        import sec.config as sec_cfg

        # 两者应具有相同的必需键
        required = ["ATTACK_TYPES_ORDER", "PREDICTION_THRESHOLD", "BATCH_FILE_SIZE"]
        for key in required:
            assert hasattr(dsk_cfg, key), f"llm_api_analyze 缺少 {key}"
            assert hasattr(sec_cfg, key), f"sec 缺少 {key}"

        # 两者应具有相同顺序的攻击类型
        assert dsk_cfg.ATTACK_TYPES_ORDER == sec_cfg.ATTACK_TYPES_ORDER

        # 阈值应相同
        assert dsk_cfg.PREDICTION_THRESHOLD == sec_cfg.PREDICTION_THRESHOLD

    def test_prompt_templates_loadable(self):
        """所有 7 个提示词模板文件应可加载。"""
        prompt_dir = os.path.join(os.path.dirname(__file__), "..", "prompts")
        required_files = [
            "directory_traversal.txt",
            "cross_site_scripting.txt",
            "injection_attack.txt",
            "performance_issue.txt",
            "invalid_item_value.txt",
            "sensitive_data_leakage.txt",
            "unauthorized_access.txt"
        ]
        for f in required_files:
            path = os.path.join(prompt_dir, f)
            assert os.path.exists(path), f"缺少：{f}"
            with open(path) as fh:
                content = fh.read()
            assert len(content) > 100, f"内容过短：{f}"
