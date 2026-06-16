#!/usr/bin/env python3
"""基准测试编排器 — 运行所有基准测试并生成合并报告。

用法：
    python -m tests.benchmark.run_benchmarks [--samples 1000] [--data path/to/data.json]
"""

import os
import sys
import json
import time
import argparse
from datetime import datetime

_project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from tests.benchmark.data_generator import generate_dataset
from tests.benchmark.test_accuracy import AccuracyBenchmark
from tests.benchmark.test_throughput import ThroughputBenchmark


REPORT_DIR = os.path.join(os.path.dirname(__file__), "reports")


class BenchmarkSuite:
    """运行所有基准测试并生成合并报告。"""

    def __init__(self, num_samples: int = 1000, data_path: str = None):
        self.num_samples = num_samples
        self.data_path = data_path
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "config": {"num_samples": num_samples, "data_path": data_path or "（已生成）"},
        }

    def run_all(self):
        """运行所有基准测试。"""
        print(f"\n{'#'*60}")
        print(f"  事件响应系统 — 基准测试套件")
        print(f"  样本数：{self.num_samples}")
        print(f"{'#'*60}")

        # 必要时生成数据
        if not self.data_path or not os.path.exists(self.data_path):
            print(f"\n[*] 正在生成数据集...")
            self.data_path = generate_dataset(self.num_samples)

        # 加载数据以生成摘要
        if self.data_path.endswith(".json"):
            with open(self.data_path, "r") as f:
                data = json.load(f)
        else:
            import csv
            with open(self.data_path, "r") as f:
                data = list(csv.DictReader(f))

        anomalies = sum(1 for r in data if r.get("label") == "anomaly")
        normal = len(data) - anomalies
        self.results["dataset"] = {
            "path": self.data_path,
            "total": len(data),
            "anomalies": anomalies,
            "normal": normal,
        }

        # 准确性
        print(f"\n{'='*60}")
        print(f"  阶段 1：准确性")
        print(f"{'='*60}")
        acc = AccuracyBenchmark()
        acc.run(self.data_path)
        self.results["accuracy"] = acc.results

        # 吞吐量
        print(f"\n{'='*60}")
        print(f"  阶段 2：吞吐量")
        print(f"{'='*60}")
        tp = ThroughputBenchmark()
        tp_results = tp.run(data_path=self.data_path, num_samples=self.num_samples)
        self.results["throughput"] = tp_results

        # 生成 Markdown 报告
        report_path = self._generate_report()
        return self.results

    def _generate_report(self) -> str:
        """生成合并的 Markdown 报告。"""
        os.makedirs(REPORT_DIR, exist_ok=True)
        ts = time.strftime("%Y%m%d_%H%M%S")
        path = os.path.join(REPORT_DIR, f"benchmark_report_{ts}.md")

        lines = [
            "# Benchmark Report",
            f"**日期：**{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"**样本数：**{self.num_samples}",
            f"**数据：**{self.data_path}",
            "",
            "## 数据集",
            f"- 总样本数：{self.results['dataset']['total']}",
            f"- 异常：{self.results['dataset']['anomalies']}",
            f"- 正常：{self.results['dataset']['normal']}",
            "",
            "## 准确性结果",
            "| 阶段 | 精确率 | 召回率 | F1 | 准确率 |",
            "|------|--------|--------|----|--------|",
        ]

        stages = self.results.get("accuracy", {}).get("stages", {})
        for stage, metrics in stages.items():
            lines.append(
                f"| {stage} | {metrics.get('precision', '-'):.4f} | "
                f"{metrics.get('recall', '-'):.4f} | {metrics.get('f1', '-'):.4f} | "
                f"{metrics.get('accuracy', '-'):.4f} |"
            )

        lines.extend([
            "",
            "## 吞吐量结果",
            "| 阶段 | 吞吐量（请求/秒） | 耗时（秒） |",
            "|------|--------------------|------------|",
        ])

        tp_stages = self.results.get("throughput", {}).get("stages", {})
        for stage, metrics in tp_stages.items():
            rps = metrics.get("throughput_rps", "-")
            el = metrics.get("elapsed_s", 0)
            lines.append(f"| {stage} | {rps} | {el:.3f} |")

        lines.extend([
            "",
            "## 分析",
            self._analysis_text(),
            "",
            "---",
            "*由 IR 系统基准测试套件生成*",
        ])

        with open(path, "w") as f:
            f.write("\n".join(lines) + "\n")

        print(f"\n{'='*60}")
        print(f"基准测试报告已写入：{path}")
        print(f"{'='*60}")
        return path

    def _analysis_text(self) -> str:
        """根据结果生成分析文本。"""
        lines = []
        acc = self.results.get("accuracy", {}).get("stages", {})

        if acc:
            best_stage = max(acc, key=lambda s: acc[s].get("f1", 0))
            best_f1 = acc[best_stage].get("f1", 0)
            lines.append(f"- 表现最佳阶段：**{best_stage}**（F1={best_f1:.4f}）")

            for stage, m in acc.items():
                if m.get("precision", 1) < 0.5:
                    lines.append(f"- ⚠ {stage} 精确率较低（{m['precision']:.2f}）— 误报较多")
                if m.get("recall", 1) < 0.5:
                    lines.append(f"- ⚠ {stage} 召回率较低（{m['recall']:.2f}）— 漏报较多")

        tp = self.results.get("throughput", {}).get("stages", {})
        if tp:
            rps_values = [(s, m.get("throughput_rps", 0)) for s, m in tp.items()
                          if m.get("throughput_rps", 0) > 0]
            if rps_values:
                fastest = max(rps_values, key=lambda x: x[1])
                lines.append(f"- 最快阶段：**{fastest[0]}**（{fastest[1]:.0f} 请求/秒）")
                slowest = min(rps_values, key=lambda x: x[1])
                lines.append(f"- 最慢阶段：**{slowest[0]}**（{slowest[1]:.0f} 请求/秒）")

        return "\n".join(lines) if lines else "- 无显著发现。"


def main():
    parser = argparse.ArgumentParser(description="运行完整的 IR 系统基准测试")
    parser.add_argument("--samples", type=int, default=1000, help="测试样本数")
    parser.add_argument("--data", default=None, help="现有数据文件路径")
    args = parser.parse_args()

    suite = BenchmarkSuite(num_samples=args.samples, data_path=args.data)
    suite.run_all()


if __name__ == "__main__":
    main()
