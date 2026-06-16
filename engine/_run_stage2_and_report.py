#!/usr/bin/env python3
"""Stage 2 RAG检测 + SecGPT报告生成（在 didienv 中运行，使用 GPU）。

用法:
    didienv/bin/python3 engine/_run_stage2_and_report.py <input.json> <output_dir>
"""
import sys, os, json, re
from collections import Counter, defaultdict
from datetime import datetime

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

INPUT_PATH = sys.argv[1]
OUTPUT_DIR = sys.argv[2]

with open(INPUT_PATH) as f:
    payload = json.load(f)

stage1_results = payload["stage1_results"]
records = payload["records"]
stage1_metrics = payload.get("stage1_metrics", {})
fusion_result = payload.get("fusion_result", {})
crawler_metrics = payload.get("crawler_metrics", {})

# ═══════════════════════════════════════════════════
#  Part 1: Stage 2 RAG 检测
# ═══════════════════════════════════════════════════
print("=" * 50)
print("[Stage 2] RAG-based detection using chroma_db")
print("=" * 50)

import torch
import chromadb
from sentence_transformers import SentenceTransformer

CHROMA_DIR = os.path.join(PROJECT_ROOT, "chroma_db")
MODEL_PATH = "/root/.cache/modelscope/hub/models/BAAI/bge-large-en-v1.5"
PATTERN_THRESHOLD = 0.05   # 精准匹配阈值
FUZZY_THRESHOLD = 0.20     # 模糊匹配阈值
KNOWLEDGE_THRESHOLD = 0.72 # 知识匹配阈值
TOP_K = 3

# 加载模型和向量库
print("[Stage 2] Loading embedding model + pattern DB + knowledge DB...")
model = SentenceTransformer(MODEL_PATH, device="cuda")
client = chromadb.PersistentClient(path=CHROMA_DIR)
pattern_col = client.get_collection("attack_patterns")
knowledge_col = client.get_collection("attack_detection_knowledge")
print(f"[Stage 2] Pattern DB: {pattern_col.count()}, Knowledge DB: {knowledge_col.count()} entries")

# 正则签名（扩充：双重编码、Windows路径、嵌套注入、SSRF、CSRF、URL编码）
ATTACK_SIGNATURES = {
    "directory traversal attack": [
        (r"\.\./", 0.9), (r"%2e%2e", 0.9), (r"/etc/(passwd|shadow|hosts)", 0.95),
        (r"%252f", 0.85), (r"\.\.%5c", 0.85), (r"\.\.\\", 0.85),
        (r"\.\.%2f", 0.85), (r"%2f\.\.%2f", 0.85),
    ],
    "cross-site scripting attack": [
        (r"<script", 0.95), (r"alert\(", 0.9), (r"onerror=", 0.9),
        (r"<svg", 0.85), (r"javascript:", 0.9),
        (r"%3Cscript", 0.85), (r"onload=", 0.85), (r"document\.cookie", 0.85),
    ],
    "unauthorized access attack": [
        (r"/admin/", 0.7), (r"/admin/(users|config|backups|logs|dashboard)", 0.8),
        (r"/transfer", 0.75), (r"/change-password", 0.75),
        (r"/delete-account", 0.8), (r"/api/users/export", 0.75),
    ],
    "injection attack": [
        (r"'.*OR.*=.*", 0.9), (r"UNION.*SELECT", 0.95), (r"DROP\s+TABLE", 0.95),
        (r"1\s*=\s*1", 0.85), (r"'.*--", 0.85), (r"%20OR%201=1", 0.85),
        (r";\s*id\b", 0.9), (r"\$\(", 0.85), (r";\s*cat\s+/etc", 0.9),
        (r";\s*curl\b", 0.8), (r"169\.254\.169\.254", 0.95), (r"file:///", 0.9),
        (r"\|\s*whoami", 0.9), (r"`[^`]+`", 0.8),
        (r"%3B.*SELECT", 0.85), (r"%3B.*%20", 0.8),
    ],
    "sensitive data leakage": [
        (r"/debug/", 0.85), (r"/\.env", 0.9), (r"/actuator", 0.9),
        (r"/metrics", 0.7), (r"/prometheus", 0.75), (r"/phpinfo", 0.8),
        (r"/\.git/", 0.85), (r"/config/", 0.8),
    ],
    "performance issue": [
        (r"page=\d{5,}", 0.85), (r"rows=\d{5,}", 0.85), (r"limit=\d{5,}", 0.8),
    ],
    "invalid item value": [
        (r"id=-1", 0.85), (r"qty=-9", 0.85), (r"score=999", 0.85),
        (r"amount=-", 0.8), (r"/addresses/-", 0.8),
        (r"id=-\d+", 0.75), (r"qty=-\d+", 0.75),
    ],
}
def build_query_text(r):
    """从记录构建查询文本（与 ChromaDB 中存储的格式对齐）。"""
    parts = []
    method = r.get("method", "")
    path = r.get("path", "")
    ua = str(r.get("user_agent", ""))[:80]
    if method: parts.append(f"HTTP Method: {method}")
    if path: parts.append(f"Endpoint: {path}")
    if ua: parts.append(f"User Agent: {ua}")
    return " | ".join(parts)

def classify_by_regex(path, method):
    """用正则确定攻击类型，返回 (type, confidence)。"""
    full = f"{method} {path}"
    best_type, best_conf = "unknown", 0.0
    for atype, patterns in ATTACK_SIGNATURES.items():
        for pat, conf in patterns:
            if re.search(pat, full, re.IGNORECASE):
                if conf > best_conf:
                    best_type, best_conf = atype, conf
    return best_type, best_conf

def semantic_check(path, method, knowledge_col, model):
    """语义检测：查询知识库判断路径是否涉及越权或敏感泄露。

    例如 /admin/users 匹配知识"admin路径应限制管理员访问" → unauthorized
    /api/debug/env 匹配知识"调试端点应在生产环境禁用" → sensitive
    """
    queries = []
    path_lower = path.lower()
    if '/admin' in path_lower:
        queries.append("admin paths access control authorization restricted to administrators")
    if any(k in path_lower for k in ('/debug', '/config', '/.env', '/actuator', '/internal', '/metrics')):
        queries.append("debug endpoints configuration files should be disabled in production")

    if not queries:
        return "unknown", 999

    for q in queries:
        q_emb = model.encode([q], normalize_embeddings=True)[0].tolist()
        res = knowledge_col.query(query_embeddings=[q_emb], n_results=3,
                                  include=["metadatas", "distances"])
        if res['distances'] and res['distances'][0]:
            top_dist = res['distances'][0][0]
            if top_dist < 0.72:
                top_type = res['metadatas'][0][0].get('attack_type', 'unknown') if res['metadatas'][0] else 'unknown'
                if top_type in ('unauthorized access attack', 'sensitive data leakage'):
                    return top_type, top_dist
    return "unknown", 999

print("[Stage 2] Running RAG detection on Stage 1 suspicious items...")
suspicious = [r for r in stage1_results if r["stage1_pred"] == 1]
print(f"  Suspicious items: {len(suspicious)}/{len(stage1_results)}")

# Batch process
BATCH = 256
stage2_results = []
rag_confirmed = 0
rag_rejected = 0
type_from_rag = Counter()
type_from_regex = Counter()

for batch_start in range(0, len(suspicious), BATCH):
    batch = suspicious[batch_start:batch_start + BATCH]
    queries = [build_query_text(r) for r in batch]

    # Batch embed + query (同时查两个库)
    q_embeddings = model.encode(queries, show_progress_bar=False, batch_size=64, normalize_embeddings=True)

    for i, r in enumerate(batch):
        q_emb = q_embeddings[i].tolist()

        # Layer 0: 语义检测（越权 + 敏感泄露——需要理解API语义）
        sem_type, sem_dist = semantic_check(r.get("path", ""), r.get("method", ""), knowledge_col, model)

        # Layer 1: 攻击指纹库精准匹配
        pat_res = pattern_col.query(query_embeddings=[q_emb], n_results=1,
                                    include=["metadatas", "distances"])
        pat_type, pat_dist = "unknown", 999
        if pat_res['distances'] and pat_res['distances'][0]:
            pat_dist = pat_res['distances'][0][0]
            if pat_dist < PATTERN_THRESHOLD:  # exact match
                pat_type = pat_res['metadatas'][0][0].get('attack_type', 'unknown') if pat_res['metadatas'][0] else 'unknown'
            elif pat_dist < FUZZY_THRESHOLD:  # fuzzy match
                pat_type = pat_res['metadatas'][0][0].get('attack_type', 'unknown') if pat_res['metadatas'][0] else 'unknown'

        # Layer 2: 知识库语义匹配
        k_res = knowledge_col.query(query_embeddings=[q_emb], n_results=1,
                                    include=["metadatas", "distances"])
        k_type, k_dist = "unknown", 999
        if k_res['distances'] and k_res['distances'][0]:
            k_dist = k_res['distances'][0][0]
            if k_dist < KNOWLEDGE_THRESHOLD:
                k_type = k_res['metadatas'][0][0].get('attack_type', 'unknown') if k_res['metadatas'][0] else 'unknown'

        # Layer 3: Regex
        path = r.get("path", "")
        method = r.get("method", "")
        regex_type, regex_conf = classify_by_regex(path, method)

        # 综合判定（优先级：语义 > 指纹 > 知识 > regex）
        if sem_type != "unknown":
            final_type = sem_type
            final_reason = f"Semantic({sem_type},dist={sem_dist:.4f})"
        elif pat_type != "unknown":
            final_type = pat_type
            final_reason = f"Pattern({pat_type},dist={pat_dist:.4f})"
        elif k_type != "unknown":
            final_type = k_type
            final_reason = f"Knowledge({k_type},dist={k_dist:.4f})"
        elif regex_type != "unknown" and regex_conf >= 0.85:
            final_type = regex_type
            final_reason = f"Regex({regex_type},conf={regex_conf:.2f})"
        else:
            final_type = "unknown"
            final_reason = f"Semantic(dist={sem_dist:.4f})+Pattern(dist={pat_dist:.4f})+Knowledge(dist={k_dist:.4f})+Regex({regex_type},{regex_conf:.2f})"

        if final_type != "unknown":
            rag_confirmed += 1
        else:
            rag_rejected += 1

        r["stage2_type"] = final_type
        r["stage2_reason"] = final_reason
        r["stage2_pat_distance"] = round(pat_dist, 4)
        r["stage2_knowledge_distance"] = round(k_dist, 4)

        if final_type != "unknown":
            type_from_rag[final_type] += 1

        stage2_results.append(r)

    if (batch_start + BATCH) % 512 == 0 or (batch_start + BATCH) >= len(suspicious):
        print(f"  Processed {min(batch_start + BATCH, len(suspicious))}/{len(suspicious)}")

# Handle filtered (stage1_pred=0) items
for r in stage1_results:
    if r["stage1_pred"] == 0:
        r["stage2_type"] = ""
        r["stage2_reason"] = "filtered"
        r["stage2_pat_distance"] = 999
        r["stage2_knowledge_distance"] = 999
        stage2_results.append(r)

print(f"\n[Stage 2] Results: {rag_confirmed} confirmed, {rag_rejected} rejected")
print(f"  Confirmed attack types:")
stage2_types = Counter(r.get("stage2_type", "") for r in stage2_results
                        if r.get("stage2_type") and r["stage2_type"] != "unknown")
for t, c in sorted(stage2_types.items(), key=lambda x: -x[1]):
    print(f"    {t}: {c}")

# 评估（对比 ground truth，仅用于度量）
category_to_type = {
    "sql_injection": "injection attack", "xss": "cross-site scripting attack",
    "directory_traversal": "directory traversal attack",
    "unauthorized_access": "unauthorized access attack",
    "sensitive_data_leakage": "sensitive data leakage",
    "command_injection": "injection attack", "ssrf": "injection attack",
    "csrf": "unauthorized access attack",
    "performance_issue": "performance issue", "invalid_item_value": "invalid item value",
}
tp_by_type, fn_by_type = Counter(), Counter()
for r in stage2_results:
    true_cat = r.get("category", "")
    expected = category_to_type.get(true_cat)
    if expected:
        fn_by_type[expected] += 1
        if r.get("stage2_type") == expected:
            tp_by_type[expected] += 1

print(f"\n  Per-type recall (RAG+Regex vs ground truth):")
for atype in ["directory traversal attack", "cross-site scripting attack",
              "unauthorized access attack", "injection attack",
              "performance issue", "sensitive data leakage", "invalid item value"]:
    tp = tp_by_type.get(atype, 0)
    fn = fn_by_type.get(atype, 0)
    rec = tp / fn if fn > 0 else 0
    print(f"    {atype:<32s} {rec:>6.1%} ({tp}/{fn})")

stage2_metrics = {
    "confirmed": rag_confirmed, "rejected": rag_rejected,
    "pattern_threshold": PATTERN_THRESHOLD, "fuzzy_threshold": FUZZY_THRESHOLD,
    "knowledge_threshold": KNOWLEDGE_THRESHOLD,
    "total_suspicious": len(suspicious),
    "per_type_recall": {a: tp_by_type.get(a, 0) / max(fn_by_type.get(a, 1), 1)
                        for a in fn_by_type},
    "confirmed_types": dict(stage2_types),
}

# Save Stage 2 results
os.makedirs(OUTPUT_DIR, exist_ok=True)
stage2_path = os.path.join(OUTPUT_DIR, "stage2_results.json")
with open(stage2_path, "w") as f:
    json.dump({"stage2_results": stage2_results, "stage2_metrics": stage2_metrics}, f, ensure_ascii=False, indent=2)

# ═══════════════════════════════════════════════════
#  Part 2: SecGPT Report Generation
# ═══════════════════════════════════════════════════
print("\n" + "=" * 50)
print("[Report] SecGPT-7B+LoRA report generation")
print("=" * 50)

# RAG 检索（精简，仅针对低召回率类型）
from engine.rag_retriever import get_retriever
from prompts.manager import get_prompt_manager

retriever = get_retriever()
pm = get_prompt_manager()

# Build summary for report
ga = fusion_result.get("global_assessment", {})
cov = fusion_result.get("coverage", {})
mal_details = []
session_results = fusion_result.get("session_results", {})
for sid, r in session_results.items():
    if r.get("determination") in ("distributed_crawler", "crowdsourced_crawler", "suspicious"):
        mal_details.append({"session_id": sid, "determination": r["determination"],
                           "fusion_score": r.get("fusion_score", 0)})
mal_details = sorted(mal_details, key=lambda x: -x["fusion_score"])[:15]

s1 = stage1_metrics or {}
s4 = crawler_metrics or {}

# Build prompt variables
prompt_vars = {
    "total_sessions": len(session_results),
    "total_records": len(records),
    "train_samples": s1.get("train_samples", 0),
    "train_attacks": s1.get("train_attacks", 0),
    "train_normal": s1.get("train_normal", 0),
    "test_samples": s1.get("test_samples", 0),
    "test_attacks": s1.get("test_attacks", 0),
    "test_normal": s1.get("test_normal", 0),
    "stage1_precision": f"{s1.get('precision', 0):.4f}",
    "stage1_recall": f"{s1.get('recall', 0):.4f}",
    "stage1_f1": f"{s1.get('f1', 0):.4f}",
    "stage1_filter_rate": f"{s1.get('test_normal', 0) / max(s1.get('test_samples', 1), 1) * 100:.1f}%",
    "stage2_attack_types": json.dumps(dict(stage2_types), ensure_ascii=False),
    "stage2_details": "\n".join(f"- {t}: {c} 条 (RAG确认)" for t, c in sorted(stage2_types.items(), key=lambda x: -x[1])),
    "stage2_recall_table": "\n".join(
        f"  {a:<32s} {tp_by_type.get(a,0)/max(fn_by_type.get(a,1),1):>6.1%} ({tp_by_type.get(a,0)}/{fn_by_type.get(a,0)})"
        for a in ["directory traversal attack", "cross-site scripting attack",
                  "unauthorized access attack", "injection attack",
                  "performance issue", "sensitive data leakage", "invalid item value"]),
    "has_distributed_crawler": ga.get("has_distributed_crawler"),
    "has_crowdsourced_crawler": ga.get("has_crowdsourced_crawler"),
    "distributed_session_count": ga.get("distributed_session_count", 0),
    "crowdsourced_session_count": ga.get("crowdsourced_session_count", 0),
    "ens_test_sessions": s4.get("test_sessions", 0),
    "ens_test_mal": s4.get("test_mal", 0),
    "ens_test_normal": s4.get("test_normal", 0),
    "ens_precision": f"{s4.get('precision', 0):.4f}",
    "ens_recall": f"{s4.get('recall', 0):.4f}",
    "ens_f1": f"{s4.get('f1', 0):.4f}",
    "coverage_entropy": cov.get("global", {}).get("coverage_entropy", "N/A"),
    "coverage_completeness": cov.get("global", {}).get("coverage_completeness", "N/A"),
    "idle_ratio": cov.get("global", {}).get("idle_session_ratio", "N/A"),
    "coverage_per_pattern": "\n".join(
        f"- {p}: entropy={c.get('entropy','?')}, completeness={c.get('completeness','?')}"
        for p, c in sorted(cov.get("per_pattern", {}).items())),
    "cluster_count": len(fusion_result.get("clusters", [])),
    "cluster_details": "\n".join(
        f"- 簇 #{i}: size={c['size']}, avg_fusion={c['avg_fusion_score']}, 判定={c['determination']}"
        for i, c in enumerate(fusion_result.get("clusters", [])[:15])),
    "malicious_details": "\n".join(
        f"- {m['session_id'][:30]}: {m['determination']} (fusion={m['fusion_score']:.3f})"
        for m in mal_details),
}

# 提取实际攻击样本（每种类型取 top 8 个不同的 payload）
attack_samples_by_type = defaultdict(list)
for r in stage2_results:
    if r.get("stage2_type") and r["stage2_type"] != "unknown":
        atype = r["stage2_type"]
        path = r.get("path", "")
        method = r.get("method", "GET")
        if len(attack_samples_by_type[atype]) < 8:
            sample = f"{method} {path}"
            if sample not in attack_samples_by_type[atype]:
                attack_samples_by_type[atype].append(sample)

attack_samples_text = ""
for atype in ["directory traversal attack", "cross-site scripting attack",
              "unauthorized access attack", "injection attack",
              "performance issue", "sensitive data leakage", "invalid item value"]:
    samples = attack_samples_by_type.get(atype, [])
    if samples:
        attack_samples_text += f"\n### {atype} 攻击样本（Top {len(samples)}）\n"
        for i, s in enumerate(samples, 1):
            attack_samples_text += f"  {i}. `{s}`\n"

prompt_vars["attack_samples"] = attack_samples_text

# Render prompt from template
prompt = pm.load("report/comprehensive_user.txt")
for k, v in prompt_vars.items():
    prompt = prompt.replace("{" + k + "}", str(v))
prompt += "\n" + pm.report_schema("comprehensive_report")

# RAG context (精简，仅检索低召回率类型)
rag_context = ""
low_recall_types = [a for a in tp_by_type if fn_by_type.get(a, 1) > 0 and tp_by_type.get(a, 0) / max(fn_by_type.get(a, 1), 1) < 0.9]
if low_recall_types:
    try:
        simplified_summary = {"stage2_attack_types": {t: 1 for t in low_recall_types},
                             "global_assessment": ga}
        rag_context = retriever.build_report_context(simplified_summary, max_chunks=4)
        if rag_context:
            print(f"[RAG] Retrieved knowledge for: {low_recall_types}")
    except Exception as e:
        print(f"[RAG] Retrieval skipped: {e}")

if rag_context:
    prompt = prompt + "\n" + rag_context

SYSTEM_PROMPT = pm.system_prompt("security_analyst")

# SecGPT inference
print("[Report] Loading SecGPT-7B+LoRA...")
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from peft import PeftModel

bnb = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4",
    bnb_4bit_compute_dtype=torch.bfloat16, bnb_4bit_use_double_quant=True)
base = AutoModelForCausalLM.from_pretrained(
    "/root/didi_stest/secgpt_finetune/models/secgpt-7B",
    quantization_config=bnb, device_map="cuda:0",
    trust_remote_code=True, torch_dtype=torch.bfloat16)
tok = AutoTokenizer.from_pretrained(
    "/root/didi_stest/secgpt_finetune/models/secgpt-7B", trust_remote_code=True)
tok.padding_side = "left"
tok.pad_token = tok.eos_token
model = PeftModel.from_pretrained(base, "/root/didi_stest/secgpt_finetune/output/lora_adapter")
model.eval()
print(f"[Report] SecGPT loaded, VRAM: {torch.cuda.memory_allocated()/1024**3:.1f}GB")

msgs = [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": prompt}]
text = tok.apply_chat_template(msgs, tokenize=False, add_generation_prompt=True)
inputs = tok(text, return_tensors="pt").to("cuda")

with torch.no_grad():
    outputs = model.generate(**inputs, max_new_tokens=2048, temperature=0.3,
        top_p=0.9, do_sample=True, repetition_penalty=1.1, pad_token_id=tok.pad_token_id)
resp = tok.decode(outputs[0][inputs.input_ids.shape[1]:], skip_special_tokens=True).strip()

content = resp.removeprefix("```json").removeprefix("```").removesuffix("```").strip()
llm_result = None
try:
    llm_result = json.loads(content)
except json.JSONDecodeError:
    bs, be = content.find("{"), content.rfind("}")
    if bs != -1 and be > bs:
        try:
            llm_result = json.loads(content[bs:be+1])
        except json.JSONDecodeError:
            pass

# Render markdown report
ts = datetime.now().strftime("%Y%m%d_%H%M%S")
report_path = os.path.join(OUTPUT_DIR, f"security_report_{ts}.md")

def build_report_md(s, llm, rag_ctx):
    lines = []
    dt = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines.append("# 安全检测报告\n")
    lines.append(f"**生成时间：**{dt}\n")

    if llm:
        es = llm.get("executive_summary", {})
        lines.append("## 1. 执行摘要\n")
        lines.append(f"**风险等级：**{es.get('overall_risk_level', 'N/A')}  \n")
        lines.append(f"**状态：**{es.get('status', 'N/A')}\n")
        for kf in es.get("key_findings", []):
            lines.append(f"- {kf}")
        lines.append("")

    # 检测结果概览
    lines.append("## 2. 检测结果概览\n")
    st2_total = sum(stage2_types.values())
    lines.append(f"- 总数据：{s['total_records']} 条记录 / {s['total_sessions']} 个会话")
    lines.append(f"- Stage 1 RF 过滤：{prompt_vars['stage1_filter_rate']} 正常流量")
    lines.append(f"- Stage 2 三层RAG确认攻击：{st2_total} 条\n")

    lines.append("| 攻击类型 | RAG确认数 | 召回率 |")
    lines.append("|----------|:------:|:----:|")
    for atype in ["directory traversal attack", "cross-site scripting attack",
                  "unauthorized access attack", "injection attack",
                  "performance issue", "sensitive data leakage", "invalid item value"]:
        count = stage2_types.get(atype, 0)
        rec = tp_by_type.get(atype, 0) / max(fn_by_type.get(atype, 1), 1)
        lines.append(f"| {atype} | {count} | {rec:.1%} |")
    lines.append("")

    # 爬虫检测
    ga = s.get("global_assessment", {})
    lines.append("### 爬虫检测\n")
    lines.append(f"- 分布式爬虫：{ga.get('distributed_session_count', 0)} 会话")
    lines.append(f"- 众包爬虫：{ga.get('crowdsourced_session_count', 0)} 会话")
    lines.append(f"- Ensemble 爬虫 F1：{prompt_vars['ens_f1']}（测试集 {s4.get('test_sessions', 0)} 会话）\n")

    # 攻击样本分析（核心新增）
    lines.append("## 3. 攻击样本分析\n")
    atype_names = {
        "injection attack": "注入攻击", "cross-site scripting attack": "跨站脚本攻击(XSS)",
        "directory traversal attack": "目录遍历攻击", "unauthorized access attack": "越权访问攻击",
        "sensitive data leakage": "敏感数据泄露", "performance issue": "性能问题/DoS",
        "invalid item value": "无效参数攻击",
    }
    for atype in ["injection attack", "cross-site scripting attack", "directory traversal attack",
                  "unauthorized access attack", "sensitive data leakage", "performance issue",
                  "invalid item value"]:
        samples = attack_samples_by_type.get(atype, [])
        if not samples:
            continue
        rec = tp_by_type.get(atype, 0) / max(fn_by_type.get(atype, 1), 1)
        cn_name = atype_names.get(atype, atype)
        lines.append(f"### {cn_name}（召回率 {rec:.1%}）\n")
        lines.append(f"检测到 {len(samples)} 种攻击模式：\n")
        for i, s in enumerate(samples[:6], 1):
            display = s[:120] + "..." if len(s) > 120 else s
            lines.append(f"{i}. `{display}`")
        lines.append("")

    # 安全建议
    if llm:
        aa = llm.get("attack_analysis", {})
        api = aa.get("api_attacks", {})
        if api.get("analysis") or api.get("per_type_analysis"):
            lines.append("## 4. 攻击分析\n")
            if api.get("analysis"):
                lines.append(f"{api['analysis']}\n")
            if api.get("per_type_analysis"):
                lines.append(f"{api['per_type_analysis']}\n")

        lines.append("## 5. 防御建议\n")
        for rec in llm.get("defense_recommendations", []):
            target = rec.get("target", "")
            target_str = f"（目标：{target}）" if target else ""
            lines.append(f"### [{rec.get('priority', 'INFO')}] {rec.get('title', '')}{target_str}")
            lines.append(f"{rec.get('description', '')}\n")

        con = llm.get("conclusion", {})
        if con:
            lines.append("## 6. 结论\n")
            if con.get("overall_assessment"):
                lines.append(f"{con['overall_assessment']}\n")
            if con.get("immediate_actions"):
                lines.append("**立即行动：**\n")
                for a in con["immediate_actions"]:
                    lines.append(f"- [ ] {a}")
                lines.append("")
            if con.get("long_term_improvements"):
                lines.append("**长期改进：**\n")
                for imp in con["long_term_improvements"]:
                    lines.append(f"- {imp}")
                lines.append("")
    else:
        lines.append("## 4. 防御建议（基于实际攻击样本）\n")
        # 针对具体攻击样本生成中文建议
        inj_samples = attack_samples_by_type.get("injection attack", [])
        if inj_samples:
            lines.append("### [高] 注入攻击防御\n")
            lines.append(f"检测到 {len(inj_samples)} 种注入攻击模式，包括SQL注入和命令注入。具体建议：\n")
            lines.append("- **参数化查询**：对所有数据库查询使用 PreparedStatement，禁止拼接用户输入到SQL语句")
            lines.append("- **输入校验**：对 `id`、`host`、`file` 等参数实施白名单校验，拒绝含 `'`、`;`、`|`、`$(` 等特殊字符的输入")
            lines.append("- **WAF规则**：部署针对 `UNION SELECT`、`OR 1=1`、`DROP TABLE`、`;id` 等模式的拦截规则")
            lines.append("")

        unauth_samples = attack_samples_by_type.get("unauthorized access attack", [])
        if unauth_samples:
            lines.append("### [高] 越权访问防御\n")
            lines.append(f"检测到 {len(unauth_samples)} 种越权访问模式，主要涉及 `/admin/` 路径和敏感操作接口。具体建议：\n")
            lines.append("- **API级权限校验**：在每个API端点验证用户角色，`/admin/*` 路径仅允许管理员角色访问")
            lines.append("- **访问控制列表(ACL)**：为 `/api/transfer`、`/api/change-password`、`/api/delete-account` 等敏感操作添加二次认证")
            lines.append("- **会话管理**：检查 JWT token 中的角色声明，确保中间件在所有端点生效")
            lines.append("")

        perf_samples = attack_samples_by_type.get("performance issue", [])
        if perf_samples:
            lines.append("### [中] 性能问题/DoS防御\n")
            lines.append(f"检测到 {len(perf_samples)} 种性能攻击模式（大页码、超长查询等）。具体建议：\n")
            lines.append("- **速率限制**：对 `/api/products`、`/api/search` 等接口实施基于IP的速率限制（如60秒内最多100次请求）")
            lines.append("- **参数限制**：限制 `page` 参数最大值（如1000），拒绝 `page=1000000` 等异常值")
            lines.append("- **查询优化**：对搜索接口限制查询字符串长度（如最大200字符），拒绝超长查询")
            lines.append("")

        sensitive_samples = attack_samples_by_type.get("sensitive data leakage", [])
        if sensitive_samples:
            lines.append("### [中] 敏感数据泄露防御\n")
            lines.append(f"检测到对 `/api/debug/`、`/api/config/`、`/api/.env` 等敏感路径的访问。具体建议：\n")
            lines.append("- **移除调试端点**：生产环境禁用 `/api/debug/`、`/api/metrics`、`/actuator` 等端点")
            lines.append("- **环境变量保护**：确保 `.env` 文件不在Web根目录下，通过Nginx/Apache规则禁止访问隐藏文件")
            lines.append("- **最小化返回数据**：API返回数据仅包含前端需要的字段，不暴露内部配置信息")
            lines.append("")

    # 附录（仅当有 RAG 上下文时显示相关参考）
    if rag_ctx:
        titles = set()
        for line in rag_ctx.split("\n"):
            stripped = line.strip()
            if stripped.startswith("### ") and len(stripped) > 5:
                t = stripped[4:].strip()[:100]
                # 过滤无效标题
                if t and not t.startswith("参考") and t != "##" and "##" not in t[:5] and len(t) > 2:
                    titles.add(t)
        if titles:
            lines.append("---\n")
            lines.append("## 附录：安全知识库参考\n")
            for t in sorted(titles):
                lines.append(f"- {t}")
            lines.append("")

    return "\n".join(lines)

# Additional summary fields needed by build_report_md
summary_for_report = {
    "total_sessions": prompt_vars["total_sessions"],
    "total_records": prompt_vars["total_records"],
    "global_assessment": ga,
}

markdown = build_report_md(summary_for_report, llm_result, rag_context)
with open(report_path, "w", encoding="utf-8") as f:
    f.write(markdown)
print(f"[Report] Saved: {report_path}")

# 输出结果路径
result = {
    "stage2_path": stage2_path,
    "report_path": report_path,
    "rag_confirmed": rag_confirmed,
    "rag_rejected": rag_rejected,
}
print(json.dumps(result))
