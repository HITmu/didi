"""基于RAG的报告生成器：误例分析、内部知识提取和严重程度分级。

生成结构化的分析报告，涵盖：
  1. 误例分析 — 假阳性/假阴性及其根因
  2. 内部知识提取 — 从训练数据和RAG上下文中提取攻击模式
  3. 分类与分级 — 威胁严重级别及置信度评分
"""

import os
import json
import numpy as np
import pandas as pd
from datetime import datetime
from collections import Counter, defaultdict

from shared.metrics import calculate_cascade_metrics


class RAGReportGenerator:
    """生成全面的RAG分析报告。

    报告包括三大支柱：
      - 误例分析：分析误判，提取错误模式
      - 内部知识：从训练数据挖掘攻击签名
      - 分类与分级：严重级别、置信度等级、类型分布
    """

    def __init__(self, ground_truth_csv=None):
        self.ground_truth_csv = ground_truth_csv

    # ----------------------------------------------------------------
    # 1. 误例分析
    # ----------------------------------------------------------------
    def analyze_bad_cases(self, stage1_results, full_test_df, stage2_results):
        """识别和分析假阳性与假阴性。

        返回结构化的误例信息，包含根因分类。
        """
        if not os.path.exists(self.ground_truth_csv or "cleaned_test.csv"):
            return {"error": "Ground truth file not found for bad case analysis"}

        gt_path = self.ground_truth_csv or "cleaned_test.csv"
        ground_truth = pd.read_csv(gt_path).values.tolist()
        stage2_map = {r[0]: r for r in stage2_results} if stage2_results else {}

        bad_cases = {
            "false_positives": [],   # 预测为异常，实际为正常
            "false_negatives": [],   # 预测为正常，实际为异常
            "stage1_false_negatives": [],  # 完全被阶段1遗漏
            "summary": {},
        }

        fp_scores, fn_scores = [], []

        for idx in range(len(full_test_df)):
            if idx >= len(ground_truth):
                continue
            true_label = 1 if str(ground_truth[idx][7]).lower() != "normal" else 0

            s1 = stage1_results[stage1_results['index'] == idx]
            if len(s1) == 0:
                continue
            s1_pred = s1.iloc[0]['predicted_label']
            s1_prob = s1.iloc[0]['probability']

            # 确定最终预测
            if s1_pred == 0:
                final_pred = 0
                stage = "stage1"
            else:
                s2 = stage2_map.get(idx)
                if s2 and s2[1] == "anomaly":
                    final_pred = 1
                    stage = f"stage2_anomaly_{s2[2]}"
                elif s2 and s2[1] == "normal":
                    final_pred = 0
                    stage = "stage2_normal"
                else:
                    final_pred = 1
                    stage = "stage1_fallback"

            if final_pred == 1 and true_label == 0:
                # 假阳性
                log = ground_truth[idx]
                fp_scores.append(s1_prob)
                bad_cases["false_positives"].append({
                    "log_id": int(idx),
                    "stage1_probability": round(s1_prob, 4),
                    "stage": stage,
                    "http_method": str(log[0]) if len(log) > 0 else "",
                    "endpoint": str(log[2]) if len(log) > 2 else "",
                    "status_code": str(log[4]) if len(log) > 4 else "",
                    "user_role": str(log[6]) if len(log) > 6 else "",
                    "request_body": str(log[1])[:100] if len(log) > 1 else "",
                    "response_body": str(log[3])[:100] if len(log) > 3 else "",
                })
            elif final_pred == 0 and true_label == 1:
                # 假阴性
                log = ground_truth[idx]
                fn_scores.append(s1_prob)
                true_type = str(log[7]) if len(log) > 7 else "unknown"
                bad_cases["false_negatives"].append({
                    "log_id": int(idx),
                    "stage1_probability": round(s1_prob, 4),
                    "stage": stage,
                    "true_anomaly_type": true_type,
                    "http_method": str(log[0]) if len(log) > 0 else "",
                    "endpoint": str(log[2]) if len(log) > 2 else "",
                    "status_code": str(log[4]) if len(log) > 4 else "",
                    "user_role": str(log[6]) if len(log) > 6 else "",
                    "request_body": str(log[1])[:100] if len(log) > 1 else "",
                    "response_body": str(log[3])[:100] if len(log) > 3 else "",
                })
                if s1_pred == 0 and stage == "stage1":
                    bad_cases["stage1_false_negatives"].append(int(idx))

        # 汇总统计
        total_fp = len(bad_cases["false_positives"])
        total_fn = len(bad_cases["false_negatives"])
        bad_cases["summary"] = {
            "total_false_positives": total_fp,
            "total_false_negatives": total_fn,
            "stage1_false_negatives": len(bad_cases["stage1_false_negatives"]),
            "fp_avg_probability": round(np.mean(fp_scores), 4) if fp_scores else 0,
            "fn_avg_probability": round(np.mean(fn_scores), 4) if fn_scores else 0,
            "fp_rate": round(total_fp / max(len(full_test_df), 1) * 100, 2),
            "fn_rate": round(total_fn / max(len(full_test_df), 1) * 100, 2),
        }

        # 按异常类型分类FN
        fn_by_type = Counter(bc["true_anomaly_type"] for bc in bad_cases["false_negatives"])
        bad_cases["fn_by_anomaly_type"] = dict(fn_by_type)

        # 按端点分类FP
        fp_by_endpoint = Counter(bc["endpoint"] for bc in bad_cases["false_positives"])
        bad_cases["fp_by_endpoint"] = dict(fp_by_endpoint.most_common(10))

        return bad_cases

    # ----------------------------------------------------------------
    # 2. 内部知识提取
    # ----------------------------------------------------------------
    def extract_internal_knowledge(self, train_csv_path=None):
        """从训练数据提取攻击模式和签名。

        挖掘内容：
          - 按攻击类型统计（HTTP方法、端点、状态码）
          - 常见请求/响应体模式
          - 特征重要性指标
        """
        csv_path = train_csv_path or "sampled_dataset.csv"
        if not os.path.exists(csv_path):
            return {"error": f"Training data not found: {csv_path}"}

        df = pd.read_csv(csv_path)
        knowledge = {
            "total_samples": len(df),
            "attack_type_distribution": {},
            "http_method_distribution": {},
            "status_code_distribution": {},
            "common_endpoints": {},
            "response_time_stats": {},
            "signatures": {},
        }

        # 确定攻击类型列（假设为最后一列）
        type_col = df.columns[-1]

        # 按攻击类型统计
        for attack_type in df[type_col].unique():
            subset = df[df[type_col] == attack_type]
            type_name = str(attack_type).strip().lower()

            methods = Counter(str(row[0]) for _, row in subset.iterrows() if len(row) > 0)
            statuses = Counter(str(row[4]) for _, row in subset.iterrows() if len(row) > 4)
            endpoints = [str(row[2]) for _, row in subset.iterrows() if len(row) > 2]

            knowledge["attack_type_distribution"][type_name] = len(subset)
            knowledge["http_method_distribution"][type_name] = dict(methods.most_common())
            knowledge["status_code_distribution"][type_name] = dict(statuses.most_common())

            # 热门端点
            common_eps = Counter(endpoints).most_common(5)
            knowledge["common_endpoints"][type_name] = [
                {"endpoint": ep, "count": c} for ep, c in common_eps
            ]

            # 响应时间统计
            rt_values = []
            for _, row in subset.iterrows():
                try:
                    rt_values.append(float(row[5]))
                except (ValueError, IndexError):
                    pass
            if rt_values:
                knowledge["response_time_stats"][type_name] = {
                    "mean_ms": round(np.mean(rt_values), 2),
                    "median_ms": round(np.median(rt_values), 2),
                    "max_ms": round(max(rt_values), 2),
                    "min_ms": round(min(rt_values), 2),
                }

        return knowledge

    # ----------------------------------------------------------------
    # 3. 分类与分级
    # ----------------------------------------------------------------
    def grade_results(self, stage1_results, full_test_df, stage2_results):
        """对每个检测结果进行严重级别和置信度等级评定。

        严重级别：
          - CRITICAL: 阶段2检测到，置信度 >= 0.9
          - HIGH: 阶段2检测到，置信度 >= 0.7
          - MEDIUM: 仅阶段2检测到（较低置信度）
          - LOW: 仅阶段1检测到（无阶段2确认）
          - INFO: 被分类为正常

        返回带聚合统计的分级结果。
        """
        stage2_map = {r[0]: r for r in stage2_results} if stage2_results else {}
        graded = []
        severity_counts = Counter()
        type_severity = defaultdict(list)

        for idx in range(len(full_test_df)):
            s1 = stage1_results[stage1_results['index'] == idx]
            if len(s1) == 0:
                continue
            s1_pred = s1.iloc[0]['predicted_label']
            s1_prob = s1.iloc[0]['probability']

            if s1_pred == 0:
                grade = {
                    "log_id": int(idx),
                    "final_verdict": "normal",
                    "severity": "INFO",
                    "confidence": round(float(s1_prob), 4),
                    "anomaly_type": "",
                    "source": "stage1",
                }
            else:
                s2 = stage2_map.get(idx)
                if s2 and s2[1] == "anomaly":
                    conf = s2[3] if len(s2) >= 5 else 0.9
                    if conf >= 0.9:
                        sev = "CRITICAL"
                    elif conf >= 0.7:
                        sev = "HIGH"
                    else:
                        sev = "MEDIUM"
                    grade = {
                        "log_id": int(idx),
                        "final_verdict": "anomaly",
                        "severity": sev,
                        "confidence": round(float(conf), 4),
                        "anomaly_type": s2[2],
                        "reason": s2[4] if len(s2) > 4 else "",
                        "source": "stage2",
                    }
                    type_severity[s2[2]].append(sev)
                elif s2 and s2[1] == "normal":
                    grade = {
                        "log_id": int(idx),
                        "final_verdict": "normal",
                        "severity": "INFO",
                        "confidence": 0.0,
                        "anomaly_type": "",
                        "source": "stage2_cleared",
                    }
                else:
                    grade = {
                        "log_id": int(idx),
                        "final_verdict": "anomaly",
                        "severity": "LOW",
                        "confidence": round(float(s1_prob), 4),
                        "anomaly_type": "unconfirmed",
                        "source": "stage1_only",
                    }
            graded.append(grade)
            severity_counts[grade["severity"]] += 1

        return {
            "per_log": graded,
            "severity_summary": dict(severity_counts),
            "total_critical": severity_counts.get("CRITICAL", 0),
            "total_high": severity_counts.get("HIGH", 0),
            "total_medium": severity_counts.get("MEDIUM", 0),
            "total_low": severity_counts.get("LOW", 0),
            "total_info": severity_counts.get("INFO", 0),
            "threat_level": self._compute_threat_level(severity_counts),
        }

    @staticmethod
    def _compute_threat_level(severity_counts):
        """基于严重级别分布计算整体威胁等级。"""
        critical = severity_counts.get("CRITICAL", 0)
        high = severity_counts.get("HIGH", 0)
        total = sum(severity_counts.values()) or 1

        threat_score = (critical * 10 + high * 5) / total
        if threat_score >= 2:
            return "CRITICAL"
        elif threat_score >= 1:
            return "HIGH"
        elif threat_score >= 0.5:
            return "MEDIUM"
        elif threat_score > 0:
            return "LOW"
        return "NORMAL"

    # ----------------------------------------------------------------
    # 报告组装
    # ----------------------------------------------------------------
    def generate_report(self, stage1_results, full_test_df, stage2_results,
                        train_csv_path=None, ground_truth_csv=None):
        """生成完整的RAG分析报告，包含三大支柱内容。"""
        self.ground_truth_csv = ground_truth_csv or "cleaned_test.csv"

        report = {
            "report_metadata": {
                "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "total_logs": len(full_test_df),
                "stage2_analyzed": len(stage2_results),
            },
            "classification_grading": self.grade_results(stage1_results, full_test_df, stage2_results),
            "internal_knowledge": self.extract_internal_knowledge(train_csv_path),
            "bad_case_analysis": self.analyze_bad_cases(stage1_results, full_test_df, stage2_results),
        }

        # 如果真实标签可用，计算总体指标
        if os.path.exists(self.ground_truth_csv):
            gt = pd.read_csv(self.ground_truth_csv).values.tolist()
            y_true, y_pred = [], []
            stage2_map = {r[0]: r for r in stage2_results}

            for idx in range(len(full_test_df)):
                if idx >= len(gt):
                    continue
                true_label = 1 if str(gt[idx][7]).lower() != "normal" else 0
                s1 = stage1_results[stage1_results['index'] == idx]
                if len(s1) == 0:
                    continue
                s1_pred = s1.iloc[0]['predicted_label']

                if s1_pred == 0:
                    pred = 0
                else:
                    s2 = stage2_map.get(idx)
                    pred = 1 if (s2 and s2[1] == "anomaly") else (0 if (s2 and s2[1] == "normal") else 1)
                y_true.append(true_label)
                y_pred.append(pred)

            if y_true:
                metrics = calculate_cascade_metrics(y_true, y_pred)
                report["overall_metrics"] = metrics

        return report

    @staticmethod
    def format_report_markdown(report):
        """将结构化的报告字典格式化为人类可读的Markdown。"""
        lines = []
        meta = report.get("report_metadata", {})
        lines.append("# Security Analysis Report\n")
        lines.append(f"- **Generated:** {meta.get('generated_at', 'N/A')}")
        lines.append(f"- **Total Logs Analyzed:** {meta.get('total_logs', 'N/A')}")
        lines.append(f"- **Stage 2 (LLM) Analyzed:** {meta.get('stage2_analyzed', 'N/A')}\n")

        # === 总体指标 ===
        if "overall_metrics" in report:
            m = report["overall_metrics"]
            lines.append("## Overall Performance Metrics\n")
            lines.append(f"| Metric | Value |")
            lines.append(f"|--------|-------|")
            lines.append(f"| Accuracy | {m.get('accuracy', 'N/A')}% |")
            lines.append(f"| Precision | {m.get('precision', 'N/A')}% |")
            lines.append(f"| Recall | {m.get('recall', 'N/A')}% |")
            lines.append(f"| F1 Score | {m.get('f1_score', 'N/A')} |")
            lines.append(f"| AUC | {m.get('auc_score', 'N/A')} |")
            cm = m.get('confusion_matrix', {})
            lines.append(f"| TP/FP/FN/TN | {cm.get('TP',0)}/{cm.get('FP',0)}/{cm.get('FN',0)}/{cm.get('TN',0)} |\n")

        # === 分类与严重程度分级 ===
        cg = report.get("classification_grading", {})
        lines.append("## Classification & Severity Grading\n")
        lines.append(f"**Overall Threat Level:** {cg.get('threat_level', 'NORMAL')}\n")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            lines.append(f"| {sev} | {cg.get(f'total_{sev.lower()}', 0)} |")
        lines.append("")

        # 高风险发现
        per_log = cg.get("per_log", [])
        severe = [g for g in per_log if g.get("severity") in ("CRITICAL", "HIGH")]
        if severe:
            lines.append("### Critical & High Severity Findings\n")
            lines.append("| Log ID | Severity | Type | Confidence | Reason |")
            lines.append("|--------|----------|------|------------|--------|")
            for g in severe[:20]:
                lines.append(f"| {g['log_id']} | {g['severity']} | {g['anomaly_type']} | {g['confidence']} | {g.get('reason', '')[:60]} |")
            lines.append("")

        # === 误例分析 ===
        bc = report.get("bad_case_analysis", {})
        if "error" not in bc:
            lines.append("## Error Case Analysis (Bad Cases)\n")
            summary = bc.get("summary", {})
            lines.append(f"- **False Positives:** {summary.get('total_false_positives', 0)} "
                        f"(rate: {summary.get('fp_rate', 0)}%)")
            lines.append(f"- **False Negatives:** {summary.get('total_false_negatives', 0)} "
                        f"(rate: {summary.get('fn_rate', 0)}%)")
            lines.append(f"- **Stage 1 Missed (FN):** {summary.get('stage1_false_negatives', 0)}\n")

            fn_by_type = bc.get("fn_by_anomaly_type", {})
            if fn_by_type:
                lines.append("### False Negatives by Anomaly Type\n")
                lines.append("| Anomaly Type | Count |")
                lines.append("|--------------|-------|")
                for t, c in sorted(fn_by_type.items(), key=lambda x: -x[1]):
                    lines.append(f"| {t} | {c} |")
                lines.append("")

            fp_by_ep = bc.get("fp_by_endpoint", {})
            if fp_by_ep:
                lines.append("### False Positives by Endpoint (Top 10)\n")
                lines.append("| Endpoint | Count |")
                lines.append("|----------|-------|")
                for ep, c in fp_by_ep.items():
                    lines.append(f"| {ep} | {c} |")
                lines.append("")

            # 误例样本
            for label, key in [("False Positive Examples", "false_positives"),
                               ("False Negative Examples", "false_negatives")]:
                samples = bc.get(key, [])[:5]
                if samples:
                    lines.append(f"### {label} (First 5)\n")
                    for s in samples:
                        lines.append(f"- **Log {s['log_id']}**: {s.get('http_method','')} {s.get('endpoint','')} "
                                    f"[{s.get('status_code','')}] prob={s['stage1_probability']}")
                    lines.append("")

        # === 内部知识 ===
        ik = report.get("internal_knowledge", {})
        if "error" not in ik:
            lines.append("## Internal Knowledge Extraction\n")
            lines.append(f"**Training samples:** {ik.get('total_samples', 'N/A')}\n")

            attack_dist = ik.get("attack_type_distribution", {})
            if attack_dist:
                lines.append("### Attack Type Distribution\n")
                lines.append("| Attack Type | Count |")
                lines.append("|-------------|-------|")
                for t, c in sorted(attack_dist.items(), key=lambda x: -x[1]):
                    lines.append(f"| {t} | {c} |")
                lines.append("")

            # 最常见攻击类型的响应时间统计
            rt_stats = ik.get("response_time_stats", {})
            if rt_stats:
                lines.append("### Response Time by Attack Type\n")
                lines.append("| Attack Type | Mean (ms) | Median (ms) | Max (ms) |")
                lines.append("|-------------|-----------|-------------|----------|")
                for t, s in rt_stats.items():
                    lines.append(f"| {t} | {s.get('mean_ms', 'N/A')} | {s.get('median_ms', 'N/A')} | {s.get('max_ms', 'N/A')} |")
                lines.append("")

            common_eps = ik.get("common_endpoints", {})
            if common_eps:
                lines.append("### Common Endpoints per Attack Type\n")
                for t, eps in common_eps.items():
                    if eps:
                        ep_list = ", ".join(f"{e['endpoint']}({e['count']})" for e in eps[:3])
                        lines.append(f"- **{t}**: {ep_list}")
                lines.append("")

        return "\n".join(lines)

    @staticmethod
    def save_report(report, output_path, as_json=False):
        """保存报告到文件（Markdown或JSON格式）。"""
        if as_json or output_path.endswith(".json"):
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(report, f, ensure_ascii=False, indent=2)
        else:
            md = RAGReportGenerator.format_report_markdown(report)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(md)
        print(f"Report saved: {output_path}")
        return output_path
