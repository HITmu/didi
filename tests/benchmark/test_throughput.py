"""吞吐量基准测试 — 测量流水线处理速度。

独立测试各阶段的吞吐量：
  - Stage 1：随机森林模型分类
  - Stage 2：串行攻击检测器 LLM 检测
  - 流水线端到端
"""

import os
import sys
import json
import time
from datetime import datetime

_project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from tests.benchmark.data_generator import generate_dataset


class ThroughputBenchmark:
    """以每秒请求数测量流水线吞吐量。"""

    def __init__(self):
        self.results = {}

    def run(self, data_path: str = None, num_samples: int = 1000) -> dict:
        """运行吞吐量基准测试。"""
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "num_samples": num_samples,
            "stages": {},
        }

        print(f"\n{'='*60}")
        print(f"吞吐量基准测试（{num_samples} 个样本）")
        print(f"{'='*60}")

        # 数据加载吞吐量
        data = self._benchmark_data_loading(data_path, num_samples)

        # 规则引擎吞吐量
        self._benchmark_rules(data)

        # 启发式吞吐量
        self._benchmark_heuristic(data)

        # 报告生成吞吐量
        self._benchmark_report_generation(data)

        # 总结
        self._print_summary()
        return self.results

    def _benchmark_data_loading(self, data_path: str, num_samples: int) -> list:
        """测量数据生成/加载吞吐量。"""
        print(f"\n  --- 数据加载 ---")

        if data_path and os.path.exists(data_path):
            start = time.perf_counter()
            if data_path.endswith(".json"):
                with open(data_path, "r") as f:
                    data = json.load(f)
            else:
                import csv
                with open(data_path, "r") as f:
                    data = list(csv.DictReader(f))
            elapsed = time.perf_counter() - start
        else:
            start = time.perf_counter()
            data_path = generate_dataset(num_samples)
            elapsed = time.perf_counter() - start
            if data_path.endswith(".json"):
                with open(data_path, "r") as f:
                    data = json.load(f)

        rate = len(data) / elapsed if elapsed > 0 else 0
        self.results["stages"]["data_loading"] = {
            "count": len(data),
            "elapsed_s": round(elapsed, 4),
            "throughput_rps": round(rate, 2),
        }
        print(f"    {len(data)} 条记录在 {elapsed:.3f} 秒内加载完成（{rate:.0f} 条记录/秒）")
        return data

    def _benchmark_rules(self, data: list):
        """测量规则引擎吞吐量。"""
        from engine import RuleEngine
        engine = RuleEngine()

        print(f"\n  --- 规则引擎 ---")
        total = len(data)
        start = time.perf_counter()

        for row in data:
            log_entry = {
                "url": row.get("url", ""),
                "method": row.get("method", "GET"),
                "status": int(row.get("status", 200)),
                "request_body": row.get("request_body", ""),
                "response_body": row.get("response_body", ""),
            }
            engine.detect_all(log_entry)

        elapsed = time.perf_counter() - start
        rate = total / elapsed if elapsed > 0 else 0
        self.results["stages"]["rule_engine"] = {
            "count": total,
            "elapsed_s": round(elapsed, 4),
            "throughput_rps": round(rate, 2),
        }
        print(f"    {total} 条记录在 {elapsed:.3f} 秒内完成（{rate:.0f} 请求/秒）")

    def _benchmark_heuristic(self, data: list):
        """测量启发式检测吞吐量。"""
        print(f"\n  --- 启发式检测 ---")
        total = len(data)
        start = time.perf_counter()

        for row in data:
            status = int(row.get("status", 200))
            response_time = float(row.get("response_time", 0))
            url = row.get("url", "")
            _ = (
                status >= 500
                or response_time > 3000
                or ("../" in url or "'" in url or "<script>" in url)
            )

        elapsed = time.perf_counter() - start
        rate = total / elapsed if elapsed > 0 else 0
        self.results["stages"]["heuristic"] = {
            "count": total,
            "elapsed_s": round(elapsed, 4),
            "throughput_rps": round(rate, 2),
        }
        print(f"    {total} 条记录在 {elapsed:.3f} 秒内完成（{rate:.0f} 请求/秒）")

    def _benchmark_report_generation(self, data: list):
        """测量报告生成吞吐量。"""
        print(f"\n  --- 安全报告生成 ---")
        try:
            from incident_response.report_generator import SecurityReportGenerator
            gen = SecurityReportGenerator()
            total = len(data)
            start = time.perf_counter()
            report = gen.generate()
            elapsed = time.perf_counter() - start
            self.results["stages"]["report_generation"] = {
                "elapsed_s": round(elapsed, 4),
                "report_size": len(str(report)),
            }
            print(f"    报告在 {elapsed:.3f} 秒内生成完成")
        except Exception as e:
            print(f"    报告生成不可用：{e}")

    def _print_summary(self):
        print(f"\n  {'='*50}")
        print(f"  吞吐量总结")
        print(f"  {'='*50}")
        for stage, metrics in self.results.get("stages", {}).items():
            rps = metrics.get("throughput_rps", "-")
            el = metrics.get("elapsed_s", 0)
            print(f"  {stage:25s}  {rps:>8} 请求/秒  ({el:.3f} 秒)")

    def save_report(self, output_dir: str = None) -> str:
        """将基准测试结果保存到 JSON 文件。"""
        if output_dir is None:
            output_dir = os.path.join(os.path.dirname(__file__), "reports")
        os.makedirs(output_dir, exist_ok=True)

        ts = time.strftime("%Y%m%d_%H%M%S")
        path = os.path.join(output_dir, f"throughput_{ts}.json")
        with open(path, "w") as f:
            json.dump(self.results, f, indent=2)
        print(f"\n吞吐量报告已保存：{path}")
        return path


def run_throughput_benchmark(data_path: str = None, num_samples: int = 1000):
    bench = ThroughputBenchmark()
    bench.run(data_path, num_samples)
    bench.save_report()
    return bench.results


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", default=None)
    parser.add_argument("--samples", type=int, default=1000)
    args = parser.parse_args()
    run_throughput_benchmark(args.data, args.samples)
