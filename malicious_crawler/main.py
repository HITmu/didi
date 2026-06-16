#!/usr/bin/env python3
"""恶意爬虫识别 — 完整实验入口。

用法：
    python main.py                          # 默认参数运行
    python main.py --sessions 200 80 120    # 自定义会话数
    python main.py --data path              # 使用已生成的数据
"""

import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, ROOT)

from malicious_crawler.traffic_simulator import TrafficSimulator
from malicious_crawler.experiment_runner import run_experiment


def main():
    parser = argparse.ArgumentParser(description="恶意爬虫识别实验")
    parser.add_argument("--normal", type=int, default=100, help="正常用户会话数")
    parser.add_argument("--legit", type=int, default=40, help="合法爬虫会话数")
    parser.add_argument("--malicious", type=int, default=60, help="恶意爬虫会话数")
    parser.add_argument("--data", type=str, default=None, help="使用已有数据集路径")
    parser.add_argument("--seed", type=int, default=42, help="随机种子")
    args = parser.parse_args()

    print("=" * 60)
    print("  恶意爬虫识别实验")
    print("=" * 60)

    # 步骤 1: 生成流量数据
    if args.data:
        data_path = args.data
        print(f"\n[1/3] 使用已有数据集: {data_path}")
    else:
        print(f"\n[1/3] 生成流量数据...")
        sim = TrafficSimulator(seed=args.seed)
        data_path = sim.generate_mixed_dataset(
            n_normal=args.normal,
            n_legit=args.legit,
            n_malicious=args.malicious,
        )

    # 步骤 2: 运行实验
    print(f"\n[2/3] 运行检测实验...")
    results = run_experiment(data_path)

    # 步骤 3: 输出汇总
    print(f"\n[3/3] 实验结果汇总")
    print("=" * 60)
    print(f"\n数据集: {os.path.basename(data_path)}")
    print(f"会话总数: {results['total_sessions']}")
    print(f"恶意比例: {results['malicious_ratio']:.1%}")
    print()

    print(f"{'方法':<20} {'准确率':>8} {'精确率':>8} {'召回率':>8} {'F1':>8} {'AUC':>8} {'FPR':>8}")
    print("-" * 68)
    for s in results["summary"]:
        print(f"{s['method']:<20} {s['accuracy']:>8.4f} {s['precision']:>8.4f} "
              f"{s['recall']:>8.4f} {s['f1']:>8.4f} {s['auc']:>8.4f} {s['fpr']:>8.4f}")

    # 特征重要性
    fi = results.get("random_forest", {}).get("feature_importance", [])
    if fi:
        fi_sorted = sorted(fi, key=lambda x: -x[1])[:10]
        print(f"\n[RandomForest] Top-10 特征重要性:")
        for name, imp in fi_sorted:
            print(f"  {name:<30} {imp:.4f}")


if __name__ == "__main__":
    main()
