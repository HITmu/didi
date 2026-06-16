"""实验编排：运行检测实验、评估指标、生成报告。"""

import csv
import json
import os
import statistics
from collections import Counter

from .detector import RuleDetector, RFDetector, IForestDetector, EnsembleDetector
from .feature_engineering import extract_all_features

RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results")


def compute_metrics(y_true: list, y_pred: list, y_prob: list = None) -> dict:
    """计算二分类评估指标。"""
    n = len(y_true)
    tp = sum(1 for i in range(n) if y_pred[i] == 1 and y_true[i] == 1)
    fp = sum(1 for i in range(n) if y_pred[i] == 1 and y_true[i] == 0)
    fn = sum(1 for i in range(n) if y_pred[i] == 0 and y_true[i] == 1)
    tn = sum(1 for i in range(n) if y_pred[i] == 0 and y_true[i] == 0)

    accuracy = (tp + tn) / n if n > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0

    # AUC
    auc = 0.0
    if y_prob:
        from sklearn.metrics import roc_auc_score
        try:
            auc = roc_auc_score(y_true, y_prob)
        except Exception:
            pass

    return {
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "fpr": round(fpr, 4),
        "auc": round(auc, 4),
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "total": n,
    }


def per_class_metrics(results: list[dict]) -> dict:
    """按类别计算各类检测器的召回率。"""
    classes = {}
    for r in results:
        cat = r.get("true_category", "unknown")
        if cat not in classes:
            classes[cat] = {"total": 0, "correct": 0}
        classes[cat]["total"] += 1
        if r.get("pred_label") == r.get("true_label"):
            classes[cat]["correct"] += 1

    return {
        cls: {
            "total": info["total"],
            "correct": info["correct"],
            "recall": round(info["correct"] / info["total"], 4) if info["total"] > 0 else 0,
        }
        for cls, info in classes.items()
    }


def run_experiment(data_path: str) -> dict:
    """在给定数据集上运行全部检测方法，返回结果字典。"""
    import pandas as pd

    # 1. 加载数据
    df = pd.read_csv(data_path)
    records = df.to_dict("records")
    print(f"[Experiment] 加载 {len(records)} 条流量记录")

    # 2. 提取特征
    features = extract_all_features(records)
    print(f"[Experiment] 提取 {len(features)} 个会话特征")

    # 3. 构建 session 映射（用于规则检测器）
    from collections import defaultdict
    records_by_session = defaultdict(list)
    for r in records:
        records_by_session[r["session_id"]].append(r)

    # 4. 数据拆分（训练:测试 = 7:3）
    from sklearn.model_selection import train_test_split
    train_feats, test_feats = train_test_split(
        features, test_size=0.3, random_state=42, stratify=[f["true_category"] for f in features]
    )
    print(f"[Experiment] 训练: {len(train_feats)} 会话, 测试: {len(test_feats)} 会话")

    overall = {}

    # ── 方法 1: 规则检测 ──
    print("\n[RuleDetector] 规则基线...")
    rule_detector = RuleDetector()
    rule_results = []
    for f in test_feats:
        sid = f["session_id"]
        recs = records_by_session.get(sid, [])
        pred, conf, info = rule_detector.predict_session(recs)
        true_label = 1 if f["true_category"] == "malicious_crawler" else 0
        rule_results.append({
            "session_id": sid,
            "true_label": true_label,
            "true_category": f["true_category"],
            "pred_label": 1 if pred == "malicious_crawler" else 0,
            "confidence": round(conf, 4),
            "rule_info": info,
        })
    overall["rule"] = {
        "metrics": compute_metrics(
            [r["true_label"] for r in rule_results],
            [r["pred_label"] for r in rule_results],
            [r["confidence"] for r in rule_results],
        ),
        "per_class": per_class_metrics(rule_results),
        "confusion_matrix": {
            "tp": sum(1 for r in rule_results if r["pred_label"] == 1 and r["true_label"] == 1),
            "fp": sum(1 for r in rule_results if r["pred_label"] == 1 and r["true_label"] == 0),
            "fn": sum(1 for r in rule_results if r["pred_label"] == 0 and r["true_label"] == 1),
            "tn": sum(1 for r in rule_results if r["pred_label"] == 0 and r["true_label"] == 0),
        },
    }
    print(f"  Accuracy={overall['rule']['metrics']['accuracy']:.4f}  "
          f"Precision={overall['rule']['metrics']['precision']:.4f}  "
          f"Recall={overall['rule']['metrics']['recall']:.4f}  "
          f"F1={overall['rule']['metrics']['f1']:.4f}")

    # ── 方法 2: 随机森林 ──
    print("\n[RFDetector] 随机森林...")
    rf_detector = RFDetector()
    rf_detector.train(train_feats)
    rf_results = rf_detector.predict(test_feats)
    rf_y_true = [r["true_label"] for r in rf_results]
    rf_y_pred = [r["pred_label"] for r in rf_results]
    rf_y_prob = [r["confidence"] for r in rf_results]
    overall["random_forest"] = {
        "metrics": compute_metrics(rf_y_true, rf_y_pred, rf_y_prob),
        "per_class": per_class_metrics(rf_results),
        "feature_importance": (
            list(zip(rf_detector.feature_names, rf_detector.model.feature_importances_.tolist()))
            if rf_detector.model else []
        ),
        "confusion_matrix": {
            "tp": sum(1 for r in rf_results if r["pred_label"] == 1 and r["true_label"] == 1),
            "fp": sum(1 for r in rf_results if r["pred_label"] == 1 and r["true_label"] == 0),
            "fn": sum(1 for r in rf_results if r["pred_label"] == 0 and r["true_label"] == 1),
            "tn": sum(1 for r in rf_results if r["pred_label"] == 0 and r["true_label"] == 0),
        },
    }
    print(f"  Accuracy={overall['random_forest']['metrics']['accuracy']:.4f}  "
          f"Precision={overall['random_forest']['metrics']['precision']:.4f}  "
          f"Recall={overall['random_forest']['metrics']['recall']:.4f}  "
          f"F1={overall['random_forest']['metrics']['f1']:.4f}")

    # ── 方法 3: 孤立森林 ──
    print("\n[IForestDetector] 孤立森林（无监督）...")
    if_detector = IForestDetector(contamination=0.25)
    if_detector.train(train_feats)
    if_results = if_detector.predict(test_feats)
    if_y_true = [r["true_label"] for r in if_results]
    if_y_pred = [r["pred_label"] for r in if_results]
    if_y_prob = [r["confidence"] for r in if_results]
    overall["isolation_forest"] = {
        "metrics": compute_metrics(if_y_true, if_y_pred, if_y_prob),
        "per_class": per_class_metrics(if_results),
        "confusion_matrix": {
            "tp": sum(1 for r in if_results if r["pred_label"] == 1 and r["true_label"] == 1),
            "fp": sum(1 for r in if_results if r["pred_label"] == 1 and r["true_label"] == 0),
            "fn": sum(1 for r in if_results if r["pred_label"] == 0 and r["true_label"] == 1),
            "tn": sum(1 for r in if_results if r["pred_label"] == 0 and r["true_label"] == 0),
        },
    }
    print(f"  Accuracy={overall['isolation_forest']['metrics']['accuracy']:.4f}  "
          f"Precision={overall['isolation_forest']['metrics']['precision']:.4f}  "
          f"Recall={overall['isolation_forest']['metrics']['recall']:.4f}  "
          f"F1={overall['isolation_forest']['metrics']['f1']:.4f}")

    # ── 方法 4: 集成检测 ──
    print("\n[EnsembleDetector] 集成投票...")
    ensemble = EnsembleDetector()
    ensemble.train(train_feats)
    ens_results = ensemble.predict(test_feats, records_by_session)
    ens_y_true = [r["true_label"] for r in ens_results]
    ens_y_pred = [r["pred_label"] for r in ens_results]
    ens_y_prob = [r["confidence"] for r in ens_results]
    overall["ensemble"] = {
        "metrics": compute_metrics(ens_y_true, ens_y_pred, ens_y_prob),
        "per_class": per_class_metrics(ens_results),
        "confusion_matrix": {
            "tp": sum(1 for r in ens_results if r["pred_label"] == 1 and r["true_label"] == 1),
            "fp": sum(1 for r in ens_results if r["pred_label"] == 1 and r["true_label"] == 0),
            "fn": sum(1 for r in ens_results if r["pred_label"] == 0 and r["true_label"] == 1),
            "tn": sum(1 for r in ens_results if r["pred_label"] == 0 and r["true_label"] == 0),
        },
    }
    print(f"  Accuracy={overall['ensemble']['metrics']['accuracy']:.4f}  "
          f"Precision={overall['ensemble']['metrics']['precision']:.4f}  "
          f"Recall={overall['ensemble']['metrics']['recall']:.4f}  "
          f"F1={overall['ensemble']['metrics']['f1']:.4f}")

    # ── 汇总表 ──
    summary = []
    for method in ["rule", "random_forest", "isolation_forest", "ensemble"]:
        m = overall[method]["metrics"]
        summary.append({
            "method": method,
            "accuracy": m["accuracy"],
            "precision": m["precision"],
            "recall": m["recall"],
            "f1": m["f1"],
            "auc": m["auc"],
            "fpr": m["fpr"],
        })

    overall["summary"] = summary
    overall["total_sessions"] = len(features)
    overall["data_source"] = data_path
    overall["malicious_ratio"] = round(
        sum(1 for f in features if f.get("true_category") == "malicious_crawler") / len(features), 4
    )

    # ── 保存结果 ──
    os.makedirs(RESULTS_DIR, exist_ok=True)
    out_path = os.path.join(RESULTS_DIR, "experiment_results.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(overall, f, ensure_ascii=False, indent=2)
    print(f"\n[Experiment] 结果已保存至 {out_path}")

    return overall
