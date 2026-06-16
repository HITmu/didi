"""RAG安全分析器 - 协调知识库、向量数据库和串行检测。"""

import os
import time
import json
import shutil
import asyncio
import pandas as pd
from datetime import datetime

from llm_api_analyze.config import (
    RAG_KB_CSV, TEST_CSV, GROUND_TRUTH_CSV, OUTPUT_CSV,
    EMBEDDING_MODEL_PATH, ATTACK_TYPES_ORDER, BATCH_FILE_SIZE,
    REQUEST_INTERVAL, LONG_BREAK_INTERVAL, PROMPT_DIR
)
from llm_api_analyze.rag.knowledge_base import SecurityKnowledgeBase
from llm_api_analyze.rag.vector_db import VectorDatabaseManager
from llm_api_analyze.rag.prompt_builder import RAGPromptBuilder
from llm_api_analyze.rag.detector import SerialAttackDetector
from shared.metrics import calculate_cascade_metrics, calculate_llm_cost_metrics, save_metrics_json


class RAGSecurityAnalyzer:
    """完整的基于RAG的安全分析管道协调器。"""

    def __init__(self, train_csv_path=None, model_path=None, prompt_dir=None):
        print("Initializing RAG analyzer...")
        self.knowledge_manager = SecurityKnowledgeBase()
        self.train_csv_path = train_csv_path or RAG_KB_CSV
        self.model_path = model_path or EMBEDDING_MODEL_PATH
        self.prompt_dir = prompt_dir or PROMPT_DIR

        # 构建向量数据库
        self.vector_db = VectorDatabaseManager("./chroma_db", self.model_path)
        self._build_knowledge_base()

        # 提示词构建器 + 检测器
        self.prompt_builder = RAGPromptBuilder(prompt_dir=self.prompt_dir)

    def _build_knowledge_base(self):
        """从训练数据构建知识库并索引到向量数据库中。"""
        knowledge = self.knowledge_manager.build_knowledge_base(self.train_csv_path)
        self.vector_db.add_to_knowledge_base(knowledge)

    def prepare_test_logs(self, test_csv_path):
        """加载测试日志并为每条日志检索相似事件。"""
        print(f"Reading test data: {test_csv_path}")
        df = pd.read_csv(test_csv_path)
        print(f"Test data shape: {df.shape}")

        test_logs = df.values.tolist()
        similar_events_map = {}
        for idx, log in enumerate(test_logs):
            try:
                features = self._extract_test_features(log)
                similar_events_map[idx] = self.vector_db.retrieve_similar_events(features, top_k=2)
            except Exception:
                similar_events_map[idx] = []
        print(f"Test data ready: {len(test_logs)} logs")
        return test_logs, similar_events_map

    @staticmethod
    def _extract_test_features(log):
        """从单条测试日志行提取查询特征。"""
        return {
            'http_method': str(log[0]) if len(log) > 0 else "",
            'request_body': str(log[1])[:100] if len(log) > 1 else "",
            'endpoint': str(log[2]) if len(log) > 2 else "",
            'response_body': str(log[3])[:100] if len(log) > 3 else "",
            'status_code': str(log[4]) if len(log) > 4 else "",
            'response_time': str(log[5]) if len(log) > 5 else "",
            'user_role': str(log[6]) if len(log) > 6 else "",
        }

    async def analyze_with_rag(self, test_csv_path, target_indices=None,
                                stage1_results=None, full_test_df=None):
        """主分析管道：准备 -> 检测 -> 保存结果。"""
        start_time = time.time()
        test_logs, similar_events_map = self.prepare_test_logs(test_csv_path)
        if not test_logs:
            return []

        # 过滤到目标索引（阶段1中标记为异常的样本）
        if target_indices is not None:
            filtered = [(idx, test_logs[idx]) for idx in target_indices if idx < len(test_logs)]
            filtered_map = {idx: similar_events_map.get(idx, []) for idx, _ in filtered}
            test_logs = [log for _, log in filtered]
            similar_events_map = filtered_map
            print(f"Analyzing {len(test_logs)} targeted logs from stage 1")

        # 创建每次运行的输出目录
        output_dir = f"results_serial_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)
        print(f"Output directory: {output_dir}")

        detector = SerialAttackDetector(self.prompt_builder)
        all_results, batch_buffer = [], []
        batch_counter = 0

        for idx, log in enumerate(test_logs):
            original_idx = idx if target_indices is None else target_indices[idx]
            print(f"\n{'='*50}\nLog {original_idx}\n{'='*50}")

            result = await detector.detect_serial(log, original_idx, similar_events_map)
            if result:
                all_results.append(result)
                batch_buffer.append(result)
                status = result[2] if result[1] == "anomaly" else "normal"
                print(f"Result: {status}")
            else:
                fallback = [original_idx, "error", "unknown", 0.0, "Detection failed", "Failed"]
                all_results.append(fallback)
                batch_buffer.append(fallback)

            # 批量输出
            if len(batch_buffer) >= BATCH_FILE_SIZE:
                batch_counter += 1
                self._save_batch(batch_buffer, batch_counter, output_dir)
                batch_buffer = []

            if idx < len(test_logs) - 1:
                await asyncio.sleep(REQUEST_INTERVAL)
            if (idx + 1) % 50 == 0 and idx < len(test_logs) - 1:
                print(f"Checkpoint: {idx+1} logs, resting...")
                await asyncio.sleep(LONG_BREAK_INTERVAL)

        if batch_buffer:
            batch_counter += 1
            self._save_batch(batch_buffer, batch_counter, output_dir)

        successful = [r for r in all_results if r and r[-1] == "Success"]
        print(f"\nAnalysis complete: {len(successful)}/{len(test_logs)} successful")

        if successful:
            self._save_final(successful, output_dir)

        # 计算并保存指标
        elapsed = time.time() - start_time
        if stage1_results is not None and full_test_df is not None:
            metrics = self._calculate_metrics(successful, full_test_df, stage1_results)
            self._save_detailed_metrics(metrics, elapsed, len(successful), output_dir)
        else:
            print(f"\nTotal time: {elapsed:.2f}s, avg: {elapsed/max(len(successful),1):.2f}s/log")

        return successful

    @staticmethod
    def _save_batch(batch, counter, output_dir):
        """保存一批结果到CSV文件。"""
        df = pd.DataFrame(batch, columns=["Log ID", "Type", "Anomaly Type", "Confidence", "Reason", "Status"])
        path = os.path.join(output_dir, f"batch_{counter:03d}_results.csv")
        df.to_csv(path, index=False, encoding="utf-8-sig")

        # 汇总
        anomaly = sum(1 for r in batch if r[1] == "anomaly")
        normal = sum(1 for r in batch if r[1] == "normal")
        with open(os.path.join(output_dir, "batch_summary.log"), "a", encoding="utf-8") as f:
            f.write(f"Batch {counter}: {len(batch)} total, {anomaly} anomaly, {normal} normal\n")
        print(f"Batch {counter} saved: {anomaly} anomaly, {normal} normal")

    @staticmethod
    def _save_final(results, output_dir):
        """保存合并后的最终结果。"""
        df = pd.DataFrame(results, columns=["Log ID", "Type", "Anomaly Type", "Confidence", "Reason", "Status"])
        path = os.path.join(output_dir, OUTPUT_CSV)
        df.to_csv(path, index=False, encoding="utf-8-sig")
        print(f"Final results saved: {path}")

    @staticmethod
    def _calculate_metrics(successful_results, full_test_df, stage1_results):
        """使用真实标签计算级联系统指标。"""
        if not os.path.exists(GROUND_TRUTH_CSV):
            return {"error": "Ground truth file not found"}

        ground_truth = pd.read_csv(GROUND_TRUTH_CSV).values.tolist()
        stage2_map = {r[0]: r for r in successful_results}

        y_true, y_pred, y_score = [], [], []
        stage1_normal = stage1_anomaly = 0
        stage1_normal_correct = stage1_normal_wrong = 0
        stage2_correct = stage2_wrong = 0
        actual_calls = 0

        for idx in range(len(full_test_df)):
            if idx >= len(ground_truth):
                continue
            true_label = 1 if str(ground_truth[idx][7]).lower() != "normal" else 0

            s1 = stage1_results[stage1_results['index'] == idx]
            if len(s1) == 0:
                continue
            s1_pred, s1_prob = s1.iloc[0]['predicted_label'], s1.iloc[0]['probability']

            if s1_pred == 0:
                y_pred.append(0)
                y_score.append(s1_prob)
                stage1_normal += 1
                if true_label == 0:
                    stage1_normal_correct += 1
                    y_true.append(0)
                else:
                    stage1_normal_wrong += 1
                    y_true.append(1)
            else:
                s2 = stage2_map.get(idx)
                if s2 and s2[1] == "anomaly":
                    y_pred.append(1)
                    confidence = s2[3] if len(s2) >= 5 else 0.9
                    y_score.append(confidence)
                    if s2[2] in ATTACK_TYPES_ORDER:
                        actual_calls += ATTACK_TYPES_ORDER.index(s2[2]) + 1
                    else:
                        actual_calls += 1
                    stage2_correct += (true_label == 1)
                    stage2_wrong += (true_label == 0)
                elif s2 and s2[1] == "normal":
                    y_pred.append(0)
                    y_score.append(0.3)
                    actual_calls += 7
                    stage2_correct += (true_label == 0)
                    stage2_wrong += (true_label == 1)
                else:
                    y_pred.append(1)
                    y_score.append(s1_prob)
                    actual_calls += 1
                    stage2_correct += (true_label == 1)
                    stage2_wrong += (true_label == 0)
                y_true.append(true_label)
                stage1_anomaly += 1

        base_metrics = calculate_cascade_metrics(y_true, y_pred, y_score)
        llm_metrics = calculate_llm_cost_metrics(len(y_true), stage1_normal, actual_calls)

        base_metrics.update(llm_metrics)
        base_metrics.update({
            "stage1_normal": stage1_normal,
            "stage1_normal_correct": stage1_normal_correct,
            "stage1_normal_wrong": stage1_normal_wrong,
            "stage2_analyzed": stage1_anomaly,
            "stage2_correct": stage2_correct,
            "stage2_wrong": stage2_wrong,
        })
        return base_metrics

    @staticmethod
    def _save_detailed_metrics(metrics, elapsed, count, output_dir):
        """保存指标到JSON和CSV文件。"""
        metrics["total_time_seconds"] = round(elapsed, 2)
        metrics["avg_time_per_log"] = round(elapsed / max(count, 1), 2)
        path = os.path.join(output_dir, "detailed_metrics.json")
        save_metrics_json(metrics, path)
        print(f"Metrics saved: {path}")


class CascadeAnalyzer:
    """两阶段级联：二分类器 -> RAG-LLM分析。"""

    def __init__(self, feature_extractor, classifier):
        self.feature_extractor = feature_extractor
        self.classifier = classifier

    def run_stage1(self, train_df, test_df, label_column):
        """阶段1：二分类预过滤。"""
        X_train, y_train = self.classifier.prepare_data(train_df, label_column)
        print(f"Training data: {X_train.shape}")
        self.classifier.train(X_train, y_train)

        X_test, _ = self.classifier.prepare_data(test_df)
        y_pred, y_proba = self.classifier.predict_with_threshold(X_test, self.classifier.threshold, test_df)

        predictions = pd.DataFrame({
            'index': range(len(y_proba)),
            'probability': y_proba,
            'predicted_label': y_pred
        })
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output = f"stage1_predictions_{timestamp}.csv"
        predictions.to_csv(output, index=False)

        print(f"\nStage 1 done: {output}")
        print(f"  Normal: {(y_pred == 0).sum()}, Anomaly: {(y_pred == 1).sum()}")
        return predictions, test_df, output
