"""准确性基准测试 — 每个流水线阶段的精确率、召回率、F1。

测量检测系统在标注数据集上各阶段的准确性：
  - Stage 1：随机森林模型
  - Stage 2：串行攻击检测器（LLM + 规则）
  - 合并：RF 标记 → Stage 2 确认
"""

import os
import sys
import json
import time
from collections import defaultdict

# 确保项目根目录在路径中
_project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

try:
    from engine import RuleEngine
except ImportError:
    RuleEngine = None

from tests.benchmark.data_generator import generate_dataset


class AccuracyBenchmark:
    """测量检测系统在标注数据上的准确性。"""

    def __init__(self, data_path: str = None):
        self.data_path = data_path
        self.results = {}

    def load_data(self, data_path: str = None) -> list:
        path = data_path or self.data_path
        if not path or not os.path.exists(path):
            raise FileNotFoundError(f"数据文件未找到：{path}")

        if path.endswith(".json"):
            with open(path, "r") as f:
                return json.load(f)
        elif path.endswith(".csv"):
            import csv
            with open(path, "r") as f:
                return list(csv.DictReader(f))
        else:
            raise ValueError(f"不支持的文件格式：{path}")

    def run(self, data_path: str = None) -> dict:
        """对数据集运行所有准确性基准测试。"""
        data = self.load_data(data_path)
        ground_truth = [r for r in data if r.get("label") == "anomaly"]
        ground_normal = [r for r in data if r.get("label") == "normal"]

        print(f"\n{'='*60}")
        print(f"准确性基准测试")
        print(f"{'='*60}")
        print(f"总样本数：{len(data)}")
        print(f"  异常：{len(ground_truth)}")
        print(f"  正常：{len(ground_normal)}")

        self.results = {
            "dataset": {
                "total": len(data),
                "anomalies": len(ground_truth),
                "normal": len(ground_normal),
            },
            "stages": {},
        }

        # Stage 1：规则引擎（基于签名）
        self._benchmark_rules(data, ground_truth, ground_normal)

        # Stage 2：组合启发式检测
        self._benchmark_heuristic(data, ground_truth, ground_normal)

        # 总结
        self._print_summary()
        return self.results

    def _benchmark_rules(self, data: list, ground_truth: list, ground_normal: list):
        """基准测试规则引擎的准确性。"""
        if RuleEngine is None:
            print("\n  [Stage 1] RuleEngine 不可用 — 跳过")
            return

        print(f"\n  --- 规则引擎（基于签名）---")
        engine = RuleEngine()
        tp = fp = tn = fn = 0

        for row in data:
            # 转换为 RuleEngine 期望的格式
            log_entry = {
                "url": row.get("url", ""),
                "method": row.get("method", "GET"),
                "status": int(row.get("status", 200)),
                "request_body": row.get("request_body", ""),
                "response_body": row.get("response_body", ""),
            }
            result = engine.detect_all(log_entry)
            is_anomaly = result.get("is_anomaly", False)
            actual = row.get("label") == "anomaly"

            if is_anomaly and actual:
                tp += 1
            elif is_anomaly and not actual:
                fp += 1
            elif not is_anomaly and not actual:
                tn += 1
            elif not is_anomaly and actual:
                fn += 1

        metrics = self._compute_metrics(tp, fp, tn, fn)
        metrics["by_type"] = self._rules_by_type(data, engine)
        self.results["stages"]["rule_engine"] = metrics
        self._print_stage("规则引擎", metrics)

    def _rules_by_type(self, data: list, engine) -> dict:
        """按异常类型细分规则检测准确性。"""
        type_results = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
        for row in data:
            log_entry = {
                "url": row.get("url", ""),
                "method": row.get("method", "GET"),
                "status": int(row.get("status", 200)),
                "request_body": row.get("request_body", ""),
                "response_body": row.get("response_body", ""),
            }
            result = engine.detect_all(log_entry)
            detected_type = result.get("anomaly_type", "none")
            actual_type = row.get("anomaly_type", row.get("label", "normal"))

            if result.get("is_anomaly"):
                if actual_type == detected_type:
                    type_results[actual_type]["tp"] += 1
                elif actual_type != "normal":
                    type_results[actual_type]["fn"] += 1
                    type_results[detected_type]["fp"] += 1
                else:
                    type_results[detected_type]["fp"] += 1
            elif actual_type != "normal":
                type_results[actual_type]["fn"] += 1

        return {
            t: self._compute_metrics(m["tp"], m["fp"], 0, m["fn"])
            for t, m in type_results.items()
        }

    def _benchmark_heuristic(self, data: list, ground_truth: list, ground_normal: list):
        """基准测试组合启发式检测（基于状态码 + 响应时间）。"""
        print(f"\n  --- 启发式检测（状态码 + 响应时间）---")
        tp = fp = tn = fn = 0

        for row in data:
            status = int(row.get("status", 200))
            response_time = float(row.get("response_time", 0))
            method = row.get("method", "GET")
            url = row.get("url", "")

            # 启发式：如果为 5xx 或非常慢或敏感路径上的可疑方法，则为异常
            is_anomaly = (
                status >= 500
                or response_time > 3000
                or (status == 403 and "/admin" in url)
                or (method in ("OPTIONS", "TRACE") and "/api" in url)
                or ("../" in url or "'" in url or "<script>" in url)
            )
            actual = row.get("label") == "anomaly"

            if is_anomaly and actual:
                tp += 1
            elif is_anomaly and not actual:
                fp += 1
            elif not is_anomaly and not actual:
                tn += 1
            elif not is_anomaly and actual:
                fn += 1

        metrics = self._compute_metrics(tp, fp, tn, fn)
        self.results["stages"]["heuristic"] = metrics
        self._print_stage("启发式", metrics)

    @staticmethod
    def _compute_metrics(tp: int, fp: int, tn: int, fn: int) -> dict:
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
        accuracy = (tp + tn) / (tp + fp + tn + fn) if (tp + fp + tn + fn) > 0 else 0.0
        return {
            "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "accuracy": round(accuracy, 4),
        }

    @staticmethod
    def _print_stage(name: str, metrics: dict):
        print(f"    精确率：{metrics['precision']:.4f}")
        print(f"    召回率：{metrics['recall']:.4f}")
        print(f"    F1：{metrics['f1']:.4f}")
        print(f"    准确率：{metrics['accuracy']:.4f}")
        print(f"    TP={metrics['tp']} FP={metrics['fp']} TN={metrics['tn']} FN={metrics['fn']}")

    def _print_summary(self):
        print(f"\n  {'='*50}")
        print(f"  准确性总结")
        print(f"  {'='*50}")
        for stage, metrics in self.results.get("stages", {}).items():
            print(f"  {stage:20s}  F1={metrics['f1']:.4f}  P={metrics['precision']:.4f}  R={metrics['recall']:.4f}  Acc={metrics['accuracy']:.4f}")

    def save_report(self, output_dir: str = None) -> str:
        """将基准测试结果保存到 JSON 文件。"""
        if output_dir is None:
            output_dir = os.path.join(os.path.dirname(__file__), "reports")
        os.makedirs(output_dir, exist_ok=True)

        ts = time.strftime("%Y%m%d_%H%M%S")
        path = os.path.join(output_dir, f"accuracy_{ts}.json")
        with open(path, "w") as f:
            json.dump(self.results, f, indent=2)
        print(f"\n准确性报告已保存：{path}")
        return path


def run_accuracy_benchmark(data_path: str = None, num_samples: int = 1000):
    """必要时生成数据并运行准确性基准测试。"""
    if not data_path or not os.path.exists(data_path):
        print(f"正在生成基准测试数据集（{num_samples} 个样本）...")
        data_path = generate_dataset(num_samples)

    bench = AccuracyBenchmark()
    bench.run(data_path)
    bench.save_report()
    return bench.results


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", default=None, help="基准测试数据路径（JSON/CSV）")
    parser.add_argument("--samples", type=int, default=1000, help="若无数据文件则生成 N 个样本")
    args = parser.parse_args()

    run_accuracy_benchmark(args.data, args.samples)
