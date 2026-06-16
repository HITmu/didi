#!/usr/bin/env python3
"""分布式爬虫与众包爬虫检测实验。

生成包含分布式爬虫、众包爬虫的模拟流量数据，
运行三层融合检测引擎，输出评估结果。

用法:
    python distributed_experiment.py
    python distributed_experiment.py --normal 100 --distributed 30 --crowdsourced 30
"""

import argparse
import json
import os
import statistics
import sys
from collections import Counter, defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from malicious_crawler.traffic_simulator import TrafficSimulator
from malicious_crawler.distributed_detector import DistributedCrawlerFusionEngine


def compute_detection_metrics(session_results: dict, records: list[dict]) -> dict:
    """评估融合引擎的检测效果。"""
    # 获取真实标签
    true_labels: dict[str, str] = {}
    for r in records:
        sid = r.get("session_id", "")
        cat = r.get("category", "normal")
        if sid not in true_labels:
            # distributed_crawler 和 crowdsourced_crawler 都是恶意
            if cat == "distributed_crawler":
                true_labels[sid] = "distributed_crawler"
            elif cat == "crowdsourced_crawler":
                true_labels[sid] = "crowdsourced_crawler"
            elif cat == "malicious_crawler":
                true_labels[sid] = "malicious_crawler"
            elif cat == "legit_crawler":
                true_labels[sid] = "legit_crawler"
            else:
                true_labels[sid] = "normal"

    tp_dist = fp_dist = fn_dist = 0
    tp_crowd = fp_crowd = fn_crowd = 0
    tp_mal = fp_mal = fn_mal = 0  # 任意恶意
    fp_any = 0  # 正常/合法被误判为恶意

    for sid, result in session_results.items():
        det = result["determination"]
        true = true_labels.get(sid, "normal")

        is_malicious_pred = det in ("distributed_crawler", "crowdsourced_crawler", "suspicious")
        is_malicious_true = true in ("distributed_crawler", "crowdsourced_crawler", "malicious_crawler")

        if is_malicious_pred and is_malicious_true:
            tp_mal += 1
        elif not is_malicious_pred and is_malicious_true:
            fn_mal += 1
        elif is_malicious_pred and not is_malicious_true:
            fp_mal += 1

        # 分布式爬虫判定
        if det == "distributed_crawler":
            if true == "distributed_crawler":
                tp_dist += 1
            else:
                fp_dist += 1
        elif true == "distributed_crawler":
            fn_dist += 1

        # 众包爬虫判定
        if det == "crowdsourced_crawler":
            if true == "crowdsourced_crawler":
                tp_crowd += 1
            else:
                fp_crowd += 1
        elif true == "crowdsourced_crawler":
            fn_crowd += 1

        # 正常/合法被误判
        if is_malicious_pred and true in ("normal", "legit_crawler"):
            fp_any += 1

    def _safe_metrics(tp, fp, fn):
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        return precision, recall, f1

    total = len(session_results)
    n_true_mal = sum(1 for t in true_labels.values() if t in ("distributed_crawler", "crowdsourced_crawler", "malicious_crawler"))
    n_true_normal = sum(1 for t in true_labels.values() if t in ("normal", "legit_crawler"))

    dist_p, dist_r, dist_f1 = _safe_metrics(tp_dist, fp_dist, fn_dist)
    crowd_p, crowd_r, crowd_f1 = _safe_metrics(tp_crowd, fp_crowd, fn_crowd)
    mal_p, mal_r, mal_f1 = _safe_metrics(tp_mal, fp_mal, fn_mal)

    return {
        "total_sessions": total,
        "malicious_ground_truth": n_true_mal,
        "normal_ground_truth": n_true_normal,
        "distributed_crawler": {
            "tp": tp_dist, "fp": fp_dist, "fn": fn_dist,
            "precision": round(dist_p, 4),
            "recall": round(dist_r, 4),
            "f1": round(dist_f1, 4),
        },
        "crowdsourced_crawler": {
            "tp": tp_crowd, "fp": fp_crowd, "fn": fn_crowd,
            "precision": round(crowd_p, 4),
            "recall": round(crowd_r, 4),
            "f1": round(crowd_f1, 4),
        },
        "any_malicious": {
            "tp": tp_mal, "fp": fp_mal, "fn": fn_mal,
            "precision": round(mal_p, 4),
            "recall": round(mal_r, 4),
            "f1": round(mal_f1, 4),
        },
        "false_positive_normal": fp_any,
        "true_labels": true_labels,
        "determinations": {sid: session_results[sid]["determination"]
                           for sid in session_results},
    }


def print_results(metrics: dict, fusion_result: dict):
    """打印评估结果。"""
    print("\n" + "=" * 60)
    print("  分布式爬虫 & 众包爬虫检测 — 实验结果")
    print("=" * 60)

    print(f"\n总会话数: {metrics['total_sessions']}")
    print(f"真实恶意会话: {metrics['malicious_ground_truth']}")
    print(f"真实正常会话: {metrics['normal_ground_truth']}")
    print(f"正常/合法误报: {metrics['false_positive_normal']}")

    print(f"\n{'检测目标':<20} {'精确率':>10} {'召回率':>10} {'F1':>10}")
    print("-" * 50)
    for target in ["distributed_crawler", "crowdsourced_crawler", "any_malicious"]:
        m = metrics[target]
        print(f"{target:<20} {m['precision']:>10.4f} {m['recall']:>10.4f} {m['f1']:>10.4f}")

    # 集群信息
    clusters = fusion_result.get("clusters", [])
    print(f"\n时序关联簇: {len(clusters)} 个")
    for ci, cl in enumerate(clusters):
        print(f"  簇 #{ci}: size={cl['size']}, "
              f"avg_fusion={cl['avg_fusion_score']:.4f}, "
              f"判定={cl['determination']}")

    # 覆盖分析
    cov = fusion_result.get("coverage", {})
    global_cov = cov.get("global", {})
    per_pat = cov.get("per_pattern", {})
    print(f"\n覆盖分析（全局）:")
    print(f"  覆盖熵: {global_cov.get('coverage_entropy', 'N/A')}")
    print(f"  覆盖完整度: {global_cov.get('coverage_completeness', 'N/A')}")
    print(f"  顺序性评分: {global_cov.get('sequential_score', 'N/A')}")
    print(f"  空闲会话比: {global_cov.get('idle_session_ratio', 'N/A')}")
    print(f"  疑似覆盖: {global_cov.get('suspicious_coverage', 'N/A')}")
    print(f"\n覆盖分析（按模式分组）:")
    for pat, pc in sorted(per_pat.items()):
        print(f"  {pat}: entropy={pc['entropy']}, idle={pc['idle_ratio']}, "
              f"completeness={pc['completeness']}, suspicious={pc['suspicious']}")

    # 网络分析
    net = fusion_result.get("network", {})
    print(f"\n网络拓扑分析:")
    print(f"  众包比例: {net.get('crowdsourced_ratio', 'N/A')}")
    print(f"  众包标记: {net.get('crowdsourced_flag', 'N/A')}")
    print(f"  模式内路径相似度: {net.get('intra_pattern_similarities', {})}")

    # 全局判定
    ga = fusion_result.get("global_assessment", {})
    print(f"\n全局判定:")
    print(f"  存在分布式爬虫: {ga.get('has_distributed_crawler', False)}")
    print(f"  存在众包爬虫: {ga.get('has_crowdsourced_crawler', False)}")
    print(f"  分布式爬虫会话数: {ga.get('distributed_session_count', 0)}")
    print(f"  众包爬虫会话数: {ga.get('crowdsourced_session_count', 0)}")
    print(f"  疑似会话数: {ga.get('suspicious_session_count', 0)}")


def main():
    parser = argparse.ArgumentParser(description="分布式爬虫检测实验")
    parser.add_argument("--normal", type=int, default=50, help="正常用户会话数")
    parser.add_argument("--legit", type=int, default=10, help="合法爬虫会话数")
    parser.add_argument("--distributed", type=int, default=30, help="分布式爬虫会话数")
    parser.add_argument("--crowdsourced", type=int, default=30, help="众包爬虫会话数")
    parser.add_argument("--seed", type=int, default=42, help="随机种子")
    args = parser.parse_args()

    print("=" * 60)
    print("  分布式爬虫 & 众包爬虫检测实验")
    print("=" * 60)

    # 1. 生成流量
    print(f"\n[1/3] 生成分布式/众包爬虫流量...")
    sim = TrafficSimulator(seed=args.seed)
    data_path = sim.generate_distributed_mixed_dataset(
        n_normal=args.normal,
        n_legit=args.legit,
        n_distributed=args.distributed,
        n_crowdsourced=args.crowdsourced,
    )

    # 2. 加载数据
    print(f"\n[2/3] 加载并运行检测...")
    import pandas as pd
    df = pd.read_csv(data_path)
    records = df.to_dict("records")
    print(f"  加载 {len(records)} 条流量记录")

    # 3. 运行融合检测引擎
    engine = DistributedCrawlerFusionEngine()
    fusion_result = engine.analyze(records)
    session_results = fusion_result["session_results"]

    # 4. 评估
    metrics = compute_detection_metrics(session_results, records)

    # 5. 打印结果
    print_results(metrics, fusion_result)

    # 6. 保存结果
    output = {
        "config": vars(args),
        "metrics": metrics,
        "global_assessment": fusion_result["global_assessment"],
        "coverage": fusion_result["coverage"],
        "network": fusion_result["network"],
        "clusters": fusion_result["clusters"],
    }

    results_dir = os.path.join(os.path.dirname(__file__), "results")
    os.makedirs(results_dir, exist_ok=True)
    out_path = os.path.join(results_dir, "distributed_experiment_results.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)
    print(f"\n[Experiment] 结果已保存至 {out_path}")


if __name__ == "__main__":
    main()
