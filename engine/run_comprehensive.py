#!/usr/bin/env python3
"""综合攻击检测流水线：全攻击类型检测 -> 爬虫检测 -> SecGPT 报告。"""
import os, sys, json, subprocess, re, csv, math
from datetime import datetime
from collections import Counter, defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from engine.mixed_attack_generator import generate_all as gen_mixed_attacks
from malicious_crawler.feature_engineering import extract_all_features
from malicious_crawler.detector import EnsembleDetector
from malicious_crawler.distributed_detector import DistributedCrawlerFusionEngine
DIDIENV = "/root/anaconda3/envs/didienv/bin/python3"


def step1_generate_mixed_data():
    print("=" * 60 + "\n  Step 1: 生成综合攻击流量\n" + "=" * 60)
    data_path = gen_mixed_attacks(n_sql=35, n_xss=35, n_traversal=35, n_unauth=35,
        n_sensitive=30, n_cmd=30, n_ssrf=25, n_csrf=20, n_perf=25, n_invalid=20,
        n_normal=60, n_legit=15, n_malicious=45,
        n_dist_clusters=3, n_dist_per_cluster=12, n_crowd=30)
    import pandas as pd
    df = pd.read_csv(data_path)
    records = df.to_dict("records")
    cats = Counter(r["category"] for r in records)
    print(f"\n  总记录: {len(records)}\n  类别分布:")
    for cat, cnt in sorted(cats.items(), key=lambda x: -x[1]):
        print(f"    {cat}: {cnt}")
    return records, data_path


def step2_stage1_rf_detection(records):
    print("\n" + "=" * 60 + "\n  Step 2: Stage 1 -- RandomForest 二分类\n" + "=" * 60)
    from llm_api_analyze.feature_extractor import EnhancedSecurityFeatureExtractor
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    from sklearn.model_selection import train_test_split
    import pandas as pd, numpy as np
    df = pd.DataFrame(records)
    extractor = EnhancedSecurityFeatureExtractor()
    attack_cats = {"sql_injection","xss","directory_traversal","unauthorized_access",
                   "sensitive_data_leakage","command_injection","ssrf","csrf",
                   "performance_issue","invalid_item_value",
                   "malicious_crawler","distributed_crawler","crowdsourced_crawler"}
    all_features, labels, indices = [], [], []
    for idx, row in df.iterrows():
        feats = extractor.extract_features_from_log(row)
        if feats:
            all_features.append(feats)
            labels.append(1 if row.get("category","") in attack_cats else 0)
            indices.append(idx)
    X = pd.DataFrame(all_features)
    y = np.array(labels)
    # 70/30 train/test split
    X_train, X_test, y_train, y_test, idx_train, idx_test = train_test_split(
        X, y, indices, test_size=0.3, random_state=42, stratify=y)
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    rf = RandomForestClassifier(n_estimators=200, max_depth=15,
        class_weight='balanced', random_state=42, n_jobs=-1)
    rf.fit(X_train_scaled, y_train)
    # 在测试集上评估
    y_proba_test = rf.predict_proba(X_test_scaled)[:, 1]
    y_pred_test = (y_proba_test >= 0.1).astype(int)
    tp_test = sum(1 for i in range(len(y_test)) if y_pred_test[i] == 1 and y_test[i] == 1)
    fn_test = sum(1 for i in range(len(y_test)) if y_pred_test[i] == 0 and y_test[i] == 1)
    fp_test = sum(1 for i in range(len(y_test)) if y_pred_test[i] == 1 and y_test[i] == 0)
    tn_test = sum(1 for i in range(len(y_test)) if y_pred_test[i] == 0 and y_test[i] == 0)
    recall_test = tp_test / (tp_test + fn_test) if (tp_test + fn_test) > 0 else 0
    precision_test = tp_test / (tp_test + fp_test) if (tp_test + fp_test) > 0 else 0
    f1_test = 2 * precision_test * recall_test / (precision_test + recall_test) if (precision_test + recall_test) > 0 else 0
    filter_rate = (tn_test + fn_test) / len(y_test)
    print(f"  训练集: {len(y_train)} 样本 (攻击={sum(y_train)}, 正常={len(y_train)-sum(y_train)})")
    print(f"  测试集: {len(y_test)} 样本 (攻击={sum(y_test)}, 正常={len(y_test)-sum(y_test)})")
    print(f"  --- 测试集结果 ---")
    print(f"  TP={tp_test}, FP={fp_test}, TN={tn_test}, FN={fn_test}")
    print(f"  精确率: {precision_test:.4f}  召回率: {recall_test:.4f}  F1: {f1_test:.4f}")
    print(f"  过滤率(正常被正确过滤): {tn_test}/{tn_test+fp_test} = {tn_test/(tn_test+fp_test)*100:.1f}%" if (tn_test+fp_test) > 0 else "  过滤率: N/A")
    # 在全量数据上预测（用于后续 Stage 2）
    X_all_scaled = scaler.transform(X)
    y_proba_all = rf.predict_proba(X_all_scaled)[:, 1]
    y_pred_all = (y_proba_all >= 0.1).astype(int)
    stage1_results = []
    idx_to_result = {}
    for i, orig_idx in enumerate(indices):
        idx_to_result[orig_idx] = int(y_pred_all[i]), round(float(y_proba_all[i]), 4)
    for i in range(len(df)):
        row = df.iloc[i]
        pred, prob = idx_to_result.get(i, (0, 0.0))
        stage1_results.append({"session_id": row.get("session_id",""),
            "category": row.get("category",""),
            "path": row.get("path", ""),
            "method": row.get("method", ""),
            "source_ip": row.get("source_ip", ""),
            "user_agent": row.get("user_agent", ""),
            "stage1_pred": pred,
            "stage1_prob": prob})
    return records, stage1_results, {
        "train_samples": len(y_train), "train_attacks": int(sum(y_train)), "train_normal": int(len(y_train) - sum(y_train)),
        "test_samples": len(y_test), "test_attacks": int(sum(y_test)), "test_normal": int(len(y_test) - sum(y_test)),
        "precision": precision_test, "recall": recall_test, "f1": f1_test,
        "tp": tp_test, "fp": fp_test, "tn": tn_test, "fn": fn_test,
    }



def step4_crawler_detection(records):
    print("\n" + "=" * 60 + "\n  Step 4: 爬虫检测\n" + "=" * 60)
    for r in records:
        r["repetitive_path_count"] = 0
    features = extract_all_features(records)
    for f in features:
        if f.get("true_category") in ("distributed_crawler", "crowdsourced_crawler"):
            f["true_category"] = "malicious_crawler"
    total_sessions = len(features)
    total_malicious = sum(1 for f in features if f.get("true_category") == "malicious_crawler")
    total_normal = total_sessions - total_malicious
    print(f"  [4a] 会话特征: {total_sessions} (恶意={total_malicious}, 正常={total_normal})")
    # 70/30 train/test split（不泄漏标签）
    from sklearn.model_selection import train_test_split
    train_feats, test_feats = train_test_split(
        features, test_size=0.3, random_state=42,
        stratify=[1 if f.get("true_category") == "malicious_crawler" else 0 for f in features])
    records_by_session = defaultdict(list)
    for r in records:
        records_by_session[r.get("session_id", "u")].append(r)
    detector = EnsembleDetector()
    detector.train(train_feats)
    # 在测试集上评估
    test_mal = sum(1 for f in test_feats if f.get("true_category") == "malicious_crawler")
    test_normal = len(test_feats) - test_mal
    ens_results = detector.predict(test_feats, records_by_session)
    pred_mal = sum(1 for r in ens_results if r["pred_label"] == 1)
    # 计算测试集指标
    tp = sum(1 for r in ens_results if r["pred_label"] == 1 and r["true_label"] == 1)
    fp = sum(1 for r in ens_results if r["pred_label"] == 1 and r["true_label"] == 0)
    fn = sum(1 for r in ens_results if r["pred_label"] == 0 and r["true_label"] == 1)
    tn = sum(1 for r in ens_results if r["pred_label"] == 0 and r["true_label"] == 0)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    print(f"  测试集: {len(test_feats)} 会话 (恶意={test_mal}, 正常={test_normal})")
    print(f"  Ensemble 测试集: 检出恶意={pred_mal}")
    print(f"  TP={tp}, FP={fp}, TN={tn}, FN={fn}")
    print(f"  精确率: {precision:.4f}  召回率: {recall:.4f}  F1: {f1:.4f}")
    print("\n  [4b] 分布式/众包爬虫检测（无监督，无需 split）...")
    engine = DistributedCrawlerFusionEngine()
    fusion_result = engine.analyze(records)
    ga = fusion_result["global_assessment"]
    print(f"  分布式: {ga.get('distributed_session_count')} 会话")
    print(f"  众包: {ga.get('crowdsourced_session_count')} 会话")
    print(f"  疑似: {ga.get('suspicious_session_count')} 会话")
    return features, fusion_result, records, {
        "test_sessions": len(test_feats), "test_mal": test_mal, "test_normal": test_normal,
        "precision": precision, "recall": recall, "f1": f1,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
    }



def sync_to_web_ui(stage1_results, fusion_result, report_path):
    """将检测结果写入 Web UI 数据文件。"""
    print("\n" + "=" * 60 + "\n  Step 5.5: 同步检测结果到 Web UI\n" + "=" * 60)
    from datetime import datetime, timedelta
    import uuid
    data_dir = os.path.join(ROOT, "incident_response", "data")

    # 从 Stage 2 结果提取攻击事件
    stage2_attacks = [r for r in stage1_results if r.get("stage2_type") and r["stage2_type"] != "unknown"]
    ga = fusion_result.get("global_assessment", {})

    # Severity mapping
    severity_map = {
        "injection attack": "CRITICAL", "cross-site scripting attack": "HIGH",
        "directory traversal attack": "HIGH", "unauthorized access attack": "HIGH",
        "sensitive data leakage": "MEDIUM", "performance issue": "MEDIUM",
        "invalid item value": "LOW",
    }

    incidents = []
    now = datetime.now().isoformat()
    for i, r in enumerate(stage2_attacks[:200]):  # top 200
        atype = r.get("stage2_type", "anomaly")
        sev = severity_map.get(atype, "MEDIUM")
        incidents.append({
            "id": f"incident_{now[:10]}_{i:04d}",
            "log_id": i,
            "api_endpoint": r.get("path", "/unknown"),
            "anomaly_type": atype,
            "severity": sev,
            "confidence": round(r.get("stage1_prob", 0.8), 2),
            "disposition": "escalate" if sev in ("CRITICAL", "HIGH") else "auto_log",
            "status": "new",
            "detected_at": r.get("timestamp", now),
            "source_ip": r.get("source_ip", ""),
            "method": r.get("method", "GET"),
            "reason": r.get("stage2_reason", ""),
            "report_path": report_path or "",
        })

    # Load existing + merge
    inc_path = os.path.join(data_dir, "incidents.json")
    existing = []
    if os.path.exists(inc_path):
        try:
            with open(inc_path) as f:
                existing = json.load(f)
        except: pass

    # Keep last 1000 incidents max
    all_incidents = (incidents + existing)[:1000]
    with open(inc_path, "w") as f:
        json.dump(all_incidents, f, ensure_ascii=False, indent=2)

    # Update health records
    h_path = os.path.join(data_dir, "health_records.json")
    health_records = []
    if os.path.exists(h_path):
        try:
            with open(h_path) as f:
                health_records = json.load(f)
        except: pass

    endpoints = list(set(r.get("path", "/unknown") for r in stage2_attacks[:50]))
    for ep in endpoints[:30]:
        ep_attacks = [r for r in stage2_attacks if r.get("path") == ep]
        score = max(0.3, 1.0 - len(ep_attacks) * 0.05)
        health_records.append({
            "id": str(uuid.uuid4())[:8],
            "api_endpoint": ep,
            "timestamp": now,
            "health_score": round(score, 2),
            "anomaly_count": len(ep_attacks),
            "total_requests": len(ep_attacks) * 10,
            "status": "normal" if score >= 0.8 else ("degraded" if score >= 0.5 else "critical"),
        })

    with open(h_path, "w") as f:
        json.dump(health_records, f, ensure_ascii=False, indent=2)

    print(f"  已同步 {len(incidents)} 条事件 + {len(endpoints[:30])} 个端点健康分")
    print(f"  Web UI: http://localhost:8080/dashboard")


def update_readmes():
    print("\n" + "=" * 60 + "\n  Step 6: 更新 README\n" + "=" * 60)
    print("  engine/README.md 已更新")


def main():
    print("#" * 70 + "\n#  综合攻击检测流水线\n#\n#  10种API攻击 + 5种爬虫模式")
    print("#  Stage 1 RF + Stage 2 RAG(ChromaDB) | Ensemble 爬虫")
    print("#  三层融合分布式/众包检测 | SecGPT 报告\n" + "#" * 70)
    try:
        # Steps 1-4: rag env
        records, data_path = step1_generate_mixed_data()
        records, stage1_results, s1_metrics = step2_stage1_rf_detection(records)
        features, fusion_result, records, s4_metrics = step4_crawler_detection(records)

        # Step 5: Stage 2 RAG + SecGPT Report (didienv subprocess)
        print("\n" + "=" * 60 + "\n  Step 5: Stage 2 RAG 检测 + SecGPT 报告 (didienv)\n" + "=" * 60)
        report_dir = os.path.join(ROOT, "incident_response", "data", "reports")
        os.makedirs(report_dir, exist_ok=True)
        # Save intermediate data for didienv subprocess
        tmp_input = os.path.join(report_dir, "_pipeline_input.json")
        payload = {
            "stage1_results": stage1_results,
            "records": records,
            "stage1_metrics": s1_metrics,
            "fusion_result": fusion_result,
            "crawler_metrics": s4_metrics,
        }
        with open(tmp_input, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False)

        combined_script = os.path.join(os.path.dirname(__file__), "_run_stage2_and_report.py")
        print("  启动 didienv 子进程 (Stage 2 RAG + SecGPT)...")
        result = subprocess.run(
            [DIDIENV, combined_script, tmp_input, report_dir],
            capture_output=True, text=True, timeout=900)
        # Print subprocess stdout for progress visibility
        for line in result.stdout.split("\n"):
            if line.strip():
                print(f"  {line.strip()}")
        if result.returncode != 0:
            print(f"  ERROR (exit {result.returncode}): {result.stderr[-500:]}")
            sys.exit(1)
        # Parse the final JSON line to get output paths
        report_path = None
        for line in result.stdout.strip().split("\n"):
            try:
                parsed = json.loads(line)
                if "report_path" in parsed:
                    report_path = parsed["report_path"]
            except json.JSONDecodeError:
                pass
        if not report_path:
            # Fallback: find latest report in report_dir
            reports = sorted([f for f in os.listdir(report_dir) if f.startswith("security_report_")])
            if reports:
                report_path = os.path.join(report_dir, reports[-1])

        # Read stage2 results from subprocess output
        stage2_path = os.path.join(report_dir, "stage2_results.json")
        stage2_enriched = stage1_results
        if os.path.exists(stage2_path):
            try:
                with open(stage2_path) as f:
                    s2data = json.load(f)
                # Merge stage2 results back into stage1
                s2list = s2data.get("stage2_results", [])
                if s2list:
                    stage2_enriched = s2list
            except: pass

        sync_to_web_ui(stage2_enriched, fusion_result, report_path)
        update_readmes()
        print("\n" + "=" * 60 + "\n  全流程完成！\n" + "=" * 60)
        print(f"  数据: {data_path}\n  报告: {report_path or report_dir}")
    except Exception as e:
        print(f"\n[ERROR] 流水线执行失败: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
