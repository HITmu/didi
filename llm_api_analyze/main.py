"""LLM API 安全分析器 - 主入口（LLM API版本）

用法：
    python -m llm_api_analyze.main

管道流程：
  1. 二分类预过滤（RandomForest）
  2. 对可疑样本进行RAG + LLM串行检测
  3. 指标评估与报告生成（可选RAG报告）
"""

import os
import sys
import asyncio
import pandas as pd
from datetime import datetime

# 确保项目根目录在路径中
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from llm_api_analyze.config import (
    MODEL_TRAIN_CSV, TEST_CSV, RAG_KB_CSV, EMBEDDING_MODEL_PATH,
    PREDICTION_THRESHOLD, GROUND_TRUTH_CSV, PROMPT_DIR
)
from llm_api_analyze.feature_extractor import EnhancedSecurityFeatureExtractor
from llm_api_analyze.classifier import LocalBinaryClassifier
from llm_api_analyze.analyzer import RAGSecurityAnalyzer, CascadeAnalyzer
from llm_api_analyze.report.rag_reporter import RAGReportGenerator


def load_and_preprocess():
    """加载训练集和测试集CSV文件。"""
    print("Loading data...")
    train_df = pd.read_csv(MODEL_TRAIN_CSV)
    print(f"  Train: {train_df.shape}")

    # 自动检测标签列
    label_column = train_df.columns[7] if train_df.shape[1] >= 8 else train_df.columns[-1]
    print(f"  Label column: {label_column}")

    test_df = pd.read_csv(TEST_CSV)
    print(f"  Test: {test_df.shape}")
    return train_df, test_df, label_column


async def main():
    """完整管道：阶段1 -> 阶段2 -> 报告。"""
    print("=" * 60)
    print("LLM API Security Analyzer (LLM API)")
    print("=" * 60)

    # ========== 阶段 1 ==========
    print("\n--- Stage 1: Binary Classification Pre-filter ---")
    train_df, test_df, label_column = load_and_preprocess()
    if label_column is None:
        print("Error: no label column found")
        sys.exit(1)

    feature_extractor = EnhancedSecurityFeatureExtractor()
    classifier = LocalBinaryClassifier(feature_extractor, threshold=PREDICTION_THRESHOLD)
    cascade = CascadeAnalyzer(feature_extractor, classifier)
    stage1_results, _, stage1_output = cascade.run_stage1(train_df, test_df, label_column)

    if stage1_results is None:
        print("Stage 1 failed")
        sys.exit(1)

    # ========== 阶段 2 ==========
    suspicious = stage1_results[stage1_results['predicted_label'] == 1]['index'].tolist()
    print(f"\n--- Stage 2: RAG-LLM Analysis ---")
    print(f"Suspicious logs found: {len(suspicious)}")

    if len(suspicious) == 0:
        print("No suspicious logs to analyze.")

        # 即使没有阶段2也生成报告
        if os.path.exists(GROUND_TRUTH_CSV):
            reporter = RAGReportGenerator()
            report = reporter.generate_report(
                stage1_results=stage1_results,
                full_test_df=test_df,
                stage2_results=[]
            )
            report_path = f"analysis_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
            reporter.save_report(report, report_path)
            print(f"Report saved: {report_path}")
        return

    # 健康检查
    if not await _health_check():
        print("LLM API unavailable; skipping stage 2")
        return

    analyzer = RAGSecurityAnalyzer(RAG_KB_CSV, EMBEDDING_MODEL_PATH, prompt_dir=PROMPT_DIR)
    full_test_df = pd.read_csv(TEST_CSV)
    stage2_results = await analyzer.analyze_with_rag(
        TEST_CSV,
        target_indices=suspicious,
        stage1_results=stage1_results,
        full_test_df=full_test_df
    )

    # ========== 合并与报告 ==========
    print("\n--- Final Merge & Report ---")
    _merge_and_report(stage1_results, stage2_results, test_df, stage1_output)


async def _health_check():
    """检查LLM API是否可访问。"""
    import aiohttp
    from llm_api_analyze.config import LLM_API_URL, HEADERS, LLM_MODEL

    try:
        async with aiohttp.ClientSession() as session:
            payload = {
                "model": LLM_MODEL,
                "messages": [
                    {"role": "system", "content": "You are an assistant."},
                    {"role": "user", "content": "Say 'healthy' only."}
                ],
                "max_tokens": 10, "temperature": 0.1, "stream": False
            }
            async with session.post(LLM_API_URL, json=payload, headers=HEADERS, timeout=30) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    ok = "choices" in data and data["choices"]
                    print(f"{'✅' if ok else '❌'} LLM API health check: {'passed' if ok else 'failed'}")
                    return ok
                print(f"❌ LLM API health check failed: {resp.status}")
                return False
    except Exception as e:
        print(f"❌ LLM API unavailable: {e}")
        return False


def _merge_and_report(stage1_results, stage2_results, test_df, stage1_output):
    """合并阶段1和阶段2的结果，计算指标，生成报告。"""
    from shared.metrics import calculate_cascade_metrics, save_metrics_json

    ground_truth_available = os.path.exists(GROUND_TRUTH_CSV)
    ground_truth_logs = pd.read_csv(GROUND_TRUTH_CSV).values.tolist() if ground_truth_available else []

    final_rows = []
    y_true, y_pred = [], []

    for idx in range(len(test_df)):
        s1_row = stage1_results[stage1_results['index'] == idx]
        if len(s1_row) == 0:
            continue
        s1_pred = s1_row.iloc[0]['predicted_label']
        s1_prob = s1_row.iloc[0]['probability']

        if s1_pred == 0:
            row = {
                'log_id': idx, 'final_type': 'normal', 'anomaly_type': '',
                'reason': 'Stage 1: normal', 'stage1_probability': s1_prob,
                'stage1_prediction': 'normal', 'stage2_analysis': 'Not performed'
            }
            predicted = 0
        else:
            s2 = next((r for r in (stage2_results or []) if r[0] == idx), None)
            if s2 and s2[-1] == "Success":
                row = {
                    'log_id': idx, 'final_type': s2[1], 'anomaly_type': s2[2] or '',
                    'reason': s2[4] if len(s2) > 4 else '',
                    'stage1_probability': s1_prob, 'stage1_prediction': 'suspicious',
                    'stage2_analysis': 'Success'
                }
                predicted = 1 if s2[1] == 'anomaly' else 0
            else:
                row = {
                    'log_id': idx, 'final_type': 'anomaly', 'anomaly_type': 'unknown',
                    'reason': 'Stage 2 failed, using stage 1 result',
                    'stage1_probability': s1_prob, 'stage1_prediction': 'suspicious',
                    'stage2_analysis': 'Failed'
                }
                predicted = 1
        final_rows.append(row)

        if ground_truth_available and idx < len(ground_truth_logs):
            true_label = 1 if str(ground_truth_logs[idx][7]).lower() != "normal" else 0
            y_true.append(true_label)
            y_pred.append(predicted)

    final_df = pd.DataFrame(final_rows)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    final_output = f"final_cascade_results_{timestamp}.csv"
    final_df.to_csv(final_output, index=False, encoding='utf-8-sig')
    print(f"Final results: {final_output}")
    print(f"Stage 1 output: {stage1_output}")

    # 指标
    if y_true:
        metrics = calculate_cascade_metrics(y_true, y_pred)
        print(f"\nMetrics: ACC={metrics['accuracy']}%, P={metrics['precision']}%, "
              f"R={metrics['recall']}%, F1={metrics['f1_score']}, AUC={metrics['auc_score']}")
        metrics_file = f"combined_metrics_{timestamp}.json"
        save_metrics_json(metrics, metrics_file)
        print(f"Metrics saved: {metrics_file}")

    # RAG报告
    reporter = RAGReportGenerator()
    report = reporter.generate_report(
        stage1_results=stage1_results,
        full_test_df=test_df,
        stage2_results=stage2_results or []
    )
    report_path = f"analysis_report_{timestamp}.md"
    reporter.save_report(report, report_path)
    print(f"Analysis report: {report_path}")


if __name__ == "__main__":
    if not os.path.exists(EMBEDDING_MODEL_PATH):
        print(f"Embedding model not found: {EMBEDDING_MODEL_PATH}")
        sys.exit(1)
    if not os.path.exists(PROMPT_DIR):
        print(f"Prompts directory not found: {PROMPT_DIR}")
        sys.exit(1)

    asyncio.run(main())
