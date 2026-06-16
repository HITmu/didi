"""级联检测系统的共享指标计算工具。"""

import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score, precision_recall_fscore_support


def calculate_cascade_metrics(y_true, y_pred, y_score=None):
    """计算二分类的综合指标。

    Args:
        y_true: 真实标签（0=正常，1=异常）
        y_pred: 预测标签
        y_score: 预测分数/概率（可选）

    Returns:
        包含 accuracy、precision、recall、f1、auc、confusion_matrix 的字典
    """
    y_true = np.array(y_true)
    y_pred = np.array(y_pred)
    total = len(y_true)

    if total == 0:
        return {"error": "没有样本"}

    tp = int(np.sum((y_true == 1) & (y_pred == 1)))
    fp = int(np.sum((y_true == 0) & (y_pred == 1)))
    fn = int(np.sum((y_true == 1) & (y_pred == 0)))
    tn = int(np.sum((y_true == 0) & (y_pred == 0)))

    accuracy = (tp + tn) / total if total > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    auc = 0.0
    if y_score is not None and len(set(y_true)) > 1:
        auc = roc_auc_score(y_true, y_score)

    return {
        "total_samples": total,
        "accuracy": round(accuracy * 100, 2),
        "precision": round(precision * 100, 2),
        "recall": round(recall * 100, 2),
        "f1_score": round(f1, 4),
        "auc_score": round(auc, 4),
        "confusion_matrix": {"TP": tp, "FP": fp, "FN": fn, "TN": tn},
    }


def calculate_llm_cost_metrics(total_samples, stage1_normal_count, actual_llm_calls):
    """计算 LLM 调用成本指标。

    Args:
        total_samples: 总样本数
        stage1_normal_count: 被 Stage 1 判定为正常的样本数（无需 LLM）
        actual_llm_calls: 实际的 LLM 调用次数

    Returns:
        包含 saved_rate、avg_calls、call_distribution 信息的字典
    """
    potential_full_calls = total_samples * 7
    denominator = actual_llm_calls + (7 * stage1_normal_count)
    llm_call_rate = (actual_llm_calls / denominator * 100) if denominator > 0 else 0

    return {
        "potential_full_calls": potential_full_calls,
        "actual_llm_calls": actual_llm_calls,
        "saved_calls": potential_full_calls - actual_llm_calls,
        "llm_call_rate": round(llm_call_rate, 2),
        "llm_saved_rate": round(100 - llm_call_rate, 2),
        "avg_calls_per_sample": round(actual_llm_calls / total_samples, 2) if total_samples > 0 else 0,
    }


def save_metrics_json(metrics_dict, output_path):
    """将指标字典保存到 JSON 文件。"""
    import json
    from datetime import datetime

    metrics_dict["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(metrics_dict, f, ensure_ascii=False, indent=2)
    return output_path
