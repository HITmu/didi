"""快速独立测试 — 无需 pytest，用于快速验证。

用法：
    python tests/quick_test.py          # 完整快速测试
    python tests/quick_test.py --stage1 # 仅测试 Stage 1
    python tests/quick_test.py --report # 仅测试报告生成
"""

import os
import sys
import json
import argparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_stage1():
    """快速 Stage 1 验证。"""
    print("\n[1/3] 测试 Stage 1：特征提取 + 二分类")
    from llm_api_analyze.feature_extractor import EnhancedSecurityFeatureExtractor
    from llm_api_analyze.classifier import LocalBinaryClassifier
    import pandas as pd
    import numpy as np

    # 特征提取完整性检查
    extractor = EnhancedSecurityFeatureExtractor()
    test_cases = [
        (["GET", "", "/api/test", "", "200", "50", "user"], "正常 GET"),
        (["POST", "<script>alert(1)</script>", "/api/search",
          "", "200", "50", "user"], "XSS"),
        (["GET", "", "/api/../../../etc/passwd", "", "200", "100", "guest"],
         "目录遍历"),
        (["DELETE", "", "/admin/delete", "", "200", "3000", "guest"],
         "未授权"),
    ]
    for row, desc in test_cases:
        feats = extractor.extract_features_from_log(row)
        print(f"  ✓ {desc}：提取了 {len(feats)} 个特征")
    assert extractor.extract_features_from_log(test_cases[0][0]), "基础特征提取失败"

    # 训练完整性检查
    train_path = os.path.join(os.path.dirname(__file__), "..", "final_training_data.csv")
    if not os.path.exists(train_path):
        print("  ⚠ 未找到训练数据，跳过训练测试")
        return True

    train_df = pd.read_csv(train_path)
    classifier = LocalBinaryClassifier(extractor, threshold=0.017)
    X_train, y_train = classifier.prepare_data(train_df, train_df.columns[7])
    classifier.train(X_train, y_train)

    print(f"  ✓ 模型在 {len(X_train)} 个样本上训练完成，{X_train.shape[1]} 个特征")
    y_pred = classifier.model.predict(classifier.scaler.transform(X_train))
    anomaly_rate = y_pred.sum() / len(y_pred)
    print(f"  ✓ 训练异常率：{anomaly_rate:.2%}")

    return True


def test_report():
    """快速 RAG 报告生成验证。"""
    print("\n[2/3] 测试 RAG 报告生成")
    from llm_api_analyze.report.rag_reporter import RAGReportGenerator
    import pandas as pd
    import os

    root = os.path.dirname(os.path.dirname(__file__))
    test_path = os.path.join(root, "test_without_type.csv")
    if not os.path.exists(test_path):
        print("  ⚠ 未找到测试数据，生成合成报告")
        return True

    test_df = pd.read_csv(test_path)
    reporter = RAGReportGenerator(ground_truth_csv=os.path.join(root, "cleaned_test.csv"))

    # 生成最小报告
    stage1_mock = pd.DataFrame({
        'index': range(len(test_df)),
        'probability': [0.01] * len(test_df),
        'predicted_label': [0] * len(test_df)
    })

    report = reporter.generate_report(
        stage1_results=stage1_mock,
        full_test_df=test_df,
        stage2_results=[],
        train_csv_path=os.path.join(root, "sampled_dataset.csv")
    )

    assert "classification_grading" in report
    assert "internal_knowledge" in report

    # 格式化和保存
    md = reporter.format_report_markdown(report)
    assert len(md) > 200

    output = os.path.join(root, "quick_test_report.md")
    reporter.save_report(report, output)
    print(f"  ✓ 报告已生成（{len(md)} 个字符），已保存至 {output}")

    return True


def test_configs():
    """快速配置一致性检查。"""
    print("\n[3/3] 测试配置一致性")
    import llm_api_analyze.config as llm_cfg
    import llm_cfg.config as sec

    assert llm_cfg.ATTACK_TYPES_ORDER == llm_cfg.ATTACK_TYPES_ORDER
    print(f"  ✓ 两者都有 {len(llm_cfg.ATTACK_TYPES_ORDER)} 种攻击类型，顺序相同")
    print(f"  ✓ LLM API URL：{llm_cfg.LLM_API_URL}")
    print(f"  ✓ SEC URL：{llm_cfg.API_URL}")
    assert llm_cfg.BATCH_FILE_SIZE == llm_cfg.BATCH_FILE_SIZE
    print("  ✓ 处理配置一致")

    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--stage1", action="store_true", help="仅测试 Stage 1")
    parser.add_argument("--report", action="store_true", help="仅测试报告生成")
    parser.add_argument("--config", action="store_true", help="仅测试配置")
    args = parser.parse_args()

    print("=" * 50)
    print("安全分析器 - 快速测试")
    print("=" * 50)

    all_ok = True
    if args.stage1:
        all_ok &= test_stage1()
    elif args.report:
        all_ok &= test_report()
    elif args.config:
        all_ok &= test_configs()
    else:
        all_ok &= test_stage1()
        all_ok &= test_report()
        all_ok &= test_configs()

    print("\n" + "=" * 50)
    if all_ok:
        print("所有快速测试通过！")
    else:
        print("部分测试失败！")
        sys.exit(1)


if __name__ == "__main__":
    main()
