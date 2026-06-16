#!/usr/bin/env python3
"""爬虫检测集成流水线：从流量检测到报告输出一条龙。

流程：
  1. 加载/生成流量数据
  2. 运行普通爬虫检测（EnsembleDetector）
  3. 运行分布式/众包爬虫检测（DistributedCrawlerFusionEngine）
  4. 使用本地 SecGPT-7B+LoRA 生成分析报告
  5. 保存报告到 docs/
"""

import argparse
import json
import os
import sys
import re
from collections import Counter, defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from malicious_crawler.traffic_simulator import TrafficSimulator
from malicious_crawler.distributed_detector import DistributedCrawlerFusionEngine
from malicious_crawler.feature_engineering import extract_all_features

# ── secgpt 环境 ─────────────────────────────────────
_SECGPT_PYTHON = "/root/anaconda3/envs/didienv/bin/python3"
REPORTS_DIR = os.path.join(ROOT, "docs")


_CRAWLER_SYSTEM_PROMPT = """你是一个专业的安全态势分析师，专注于爬虫攻击检测。
你收到的数据来自一个多层爬虫检测流水线的输出，包括：
- 普通恶意爬虫检测（Ensemble 投票）
- 分布式爬虫检测（时序关联 + 覆盖分析 + 网络拓扑三层融合）
- 众包爬虫检测（碎片化覆盖分析）

请基于提供的数据生成一份结构化的爬虫安全分析报告。
你的分析应当专业、准确、有针对性。
对于每种检测到的爬虫模式，分析其行为特征、影响范围和防御建议。

严格按照指定的 JSON 格式输出，不要添加额外字段。"""


class CrawlerPipeline:
    """爬虫检测集成流水线。"""

    def __init__(self, data_dir: str = None):
        self.data_dir = data_dir or os.path.join(os.path.dirname(__file__), "data")
        self._model = None
        self._tokenizer = None
        os.makedirs(REPORTS_DIR, exist_ok=True)

    def _ensure_secgpt(self):
        """懒加载 SecGPT-7B+LoRA 模型。"""
        if self._model is not None:
            return
        print("[Pipeline] 加载 SecGPT-7B + LoRA 模型...", flush=True)
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
        from peft import PeftModel

        bnb = BitsAndBytesConfig(
            load_in_4bit=True, bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.bfloat16,
            bnb_4bit_use_double_quant=True,
        )
        base = AutoModelForCausalLM.from_pretrained(
            "/root/didi_stest/secgpt_finetune/models/secgpt-7B",
            quantization_config=bnb, device_map="cuda:0",
            trust_remote_code=True, torch_dtype=torch.bfloat16,
        )
        self._tokenizer = AutoTokenizer.from_pretrained(
            "/root/didi_stest/secgpt_finetune/models/secgpt-7B",
            trust_remote_code=True,
        )
        self._tokenizer.padding_side = "left"
        self._tokenizer.pad_token = self._tokenizer.eos_token
        self._model = PeftModel.from_pretrained(base, "/root/didi_stest/secgpt_finetune/output/lora_adapter")
        self._model.eval()
        import torch
        print(f"[Pipeline] SecGPT 已加载, VRAM: {torch.cuda.memory_allocated()/1024**3:.1f}GB", flush=True)

    def run(self, data_path: str = None, output_name: str = None) -> dict:
        """执行完整流水线。

        Args:
            data_path: CSV 数据路径，None 则生成模拟数据
            output_name: 报告文件名（不含路径）
        """
        # ── 1. 数据加载 ──
        if data_path is None:
            print("[Pipeline] 生成模拟流量数据...")
            sim = TrafficSimulator()
            data_path = sim.generate_distributed_mixed_dataset(
                n_normal=80, n_legit=15,
                n_distributed=30, n_crowdsourced=25,
            )

        import pandas as pd
        df = pd.read_csv(data_path)
        records = df.to_dict("records")
        print(f"[Pipeline] 加载 {len(records)} 条流量记录")

        # ── 2. 普通爬虫检测 ──
        print("\n[Pipeline] 运行 Ensemble 爬虫检测...")
        from malicious_crawler.detector import EnsembleDetector
        from malicious_crawler.feature_engineering import extract_all_features, features_to_matrix

        features = extract_all_features(records)
        # 将分布式/众包类别映射为 malicious_crawler（EnsembleDetector 的正类标签）
        for f in features:
            if f.get("true_category") in ("distributed_crawler", "crowdsourced_crawler"):
                f["true_category"] = "malicious_crawler"

        records_by_session = defaultdict(list)
        for r in records:
            records_by_session[r["session_id"]].append(r)

        detector = EnsembleDetector()
        detector.train(features)
        ens_results = detector.predict(features, records_by_session)
        ens_map = {r["session_id"]: r for r in ens_results}

        # ── 3. 分布式/众包爬虫检测 ──
        print("[Pipeline] 运行分布式/众包爬虫检测...")
        engine = DistributedCrawlerFusionEngine()
        fusion_result = engine.analyze(records)
        session_results = fusion_result["session_results"]
        clusters = fusion_result["clusters"]
        coverage = fusion_result["coverage"]
        network_info = fusion_result["network"]
        global_assessment = fusion_result["global_assessment"]

        # ── 4. 汇总统计 ──
        summary = self._build_summary(
            records, features, ens_map, session_results,
            fusion_result, global_assessment,
        )

        # ── 5. SecGPT 报告生成 ──
        print("\n[Pipeline] 使用 SecGPT-7B+LoRA 生成报告...")
        report_content = self._generate_report(summary)

        # ── 6. 保存 ──
        if output_name is None:
            from datetime import datetime
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_name = f"crawler_security_report_{ts}.md"

        output_path = os.path.join(REPORTS_DIR, output_name)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report_content)

        # 同时保存 JSON 摘要
        summary_path = os.path.join(
            os.path.dirname(__file__), "results", "pipeline_summary.json"
        )
        os.makedirs(os.path.dirname(summary_path), exist_ok=True)
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, ensure_ascii=False, indent=2)

        print(f"\n[Pipeline] 报告已保存: {output_path}")
        print(f"[Pipeline] 摘要已保存: {summary_path}")

        return summary

    def _build_summary(self, records, features, ens_map, session_results,
                        fusion_result, global_assessment) -> dict:
        """构建结构化的检测汇总。"""
        # 真实标签
        true_labels = {}
        category_counts = Counter()
        for r in records:
            sid = r.get("session_id", "")
            cat = r.get("category", "normal")
            true_labels[sid] = cat
            category_counts[cat] += 1

        # 检测结果
        detection_counts = Counter()
        for sid, result in session_results.items():
            detection_counts[result["determination"]] += 1

        # Ensemble 标签
        ensemble_labels = {}
        for sid, r in ens_map.items():
            ensemble_labels[sid] = "malicious" if r["pred_label"] == 1 else "normal"

        # 恶意 session 详细统计
        malicious_sessions = []
        for sid, result in session_results.items():
            if result["determination"] in ("distributed_crawler", "crowdsourced_crawler", "suspicious"):
                malicious_sessions.append({
                    "session_id": sid,
                    "determination": result["determination"],
                    "fusion_score": result["fusion_score"],
                    "temporal_score": result["temporal_score"],
                    "coverage_score": result["coverage_score"],
                    "network_score": result["network_score"],
                    "in_cluster": result["in_temporal_cluster"],
                })

        # 时序簇信息
        cluster_info = []
        for cl in fusion_result.get("clusters", []):
            cluster_info.append({
                "size": cl["size"],
                "avg_fusion": cl["avg_fusion_score"],
                "determination": cl["determination"],
            })

        # 覆盖分析
        cov_global = fusion_result.get("coverage", {}).get("global", {})
        cov_patterns = fusion_result.get("coverage", {}).get("per_pattern", {})
        network_info = fusion_result.get("network", {})

        return {
            "total_sessions": len(session_results),
            "total_records": len(records),
            "true_distribution": dict(category_counts),
            "detection_distribution": dict(detection_counts),
            "global_assessment": global_assessment,
            "clusters": cluster_info,
            "coverage_global": {
                "entropy": cov_global.get("coverage_entropy"),
                "completeness": cov_global.get("coverage_completeness"),
                "sequential_score": cov_global.get("sequential_score"),
                "idle_ratio": cov_global.get("idle_session_ratio"),
                "suspicious": cov_global.get("suspicious_coverage"),
            },
            "coverage_per_pattern": {
                pat: {
                    "entropy": c.get("entropy"),
                    "completeness": c.get("completeness"),
                    "idle_ratio": c.get("idle_ratio"),
                    "suspicious": c.get("suspicious"),
                }
                for pat, c in cov_patterns.items()
            },
            "network": {
                "crowdsourced_ratio": network_info.get("crowdsourced_ratio"),
                "crowdsourced_flag": network_info.get("crowdsourced_flag"),
            },
            "malicious_details": sorted(malicious_sessions,
                                         key=lambda x: -x["fusion_score"])[:30],
        }

    def _generate_report(self, summary: dict) -> str:
        """调用本地 SecGPT 生成分析报告（in-process）。"""
        prompt = self._build_crawler_prompt(summary)

        self._ensure_secgpt()

        import torch
        msgs = [
            {"role": "system", "content": _CRAWLER_SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ]
        text = self._tokenizer.apply_chat_template(
            msgs, tokenize=False, add_generation_prompt=True
        )
        inputs = self._tokenizer(text, return_tensors="pt").to("cuda")

        with torch.no_grad():
            outputs = self._model.generate(
                **inputs, max_new_tokens=2048, temperature=0.3,
                top_p=0.9, do_sample=True, repetition_penalty=1.1,
                pad_token_id=self._tokenizer.pad_token_id,
            )

        resp = self._tokenizer.decode(
            outputs[0][inputs.input_ids.shape[1]:], skip_special_tokens=True
        ).strip()

        content = resp.removeprefix("```json").removeprefix("```").removesuffix("```").strip()
        llm_result = None
        try:
            llm_result = json.loads(content)
        except json.JSONDecodeError:
            brace_start = content.find("{")
            brace_end = content.rfind("}")
            if brace_start != -1 and brace_end > brace_start:
                try:
                    llm_result = json.loads(content[brace_start:brace_end + 1])
                except json.JSONDecodeError:
                    pass

        if llm_result is None or "error" in llm_result:
            print("[Pipeline] SecGPT 输出解析失败，回退到模板报告")
            print(f"[Pipeline] 原始输出: {content[:500]}")
            return self._build_template_report(summary)

        return self._build_markdown(summary, llm_result)

    def _build_crawler_prompt(self, summary: dict) -> str:
        """构建面向爬虫检测的 prompt。"""
        s = summary
        prompt = f"""# 爬虫检测报告上下文

## 总览
- 总会话数：{s['total_sessions']}
- 总请求数：{s['total_records']}
- 真实分布：{json.dumps(s['true_distribution'], ensure_ascii=False)}
- 检测分布：{json.dumps(s['detection_distribution'], ensure_ascii=False)}

## 全局判定
- 存在分布式爬虫：{s['global_assessment'].get('has_distributed_crawler')}
- 存在众包爬虫：{s['global_assessment'].get('has_crowdsourced_crawler')}
- 分布式爬虫会话数：{s['global_assessment'].get('distributed_session_count')}
- 众包爬虫会话数：{s['global_assessment'].get('crowdsourced_session_count')}
- 疑似爬虫会话数：{s['global_assessment'].get('suspicious_session_count')}

## 覆盖分析（全局）
- 覆盖熵：{s['coverage_global']['entropy']}
- 覆盖完整度：{s['coverage_global']['completeness']}
- 顺序性评分：{s['coverage_global']['sequential_score']}
- 空闲会话率：{s['coverage_global']['idle_ratio']}
- 疑似覆盖：{s['coverage_global']['suspicious']}

## 覆盖分析（按模式组）
"""
        for pat, pc in sorted(s.get("coverage_per_pattern", {}).items()):
            prompt += (f"- {pat}: entropy={pc['entropy']}, "
                       f"completeness={pc['completeness']}, "
                       f"idle_ratio={pc['idle_ratio']}\n")

        prompt += f"""
## 时序关联簇（共 {len(s['clusters'])} 个）
"""
        for ci, cl in enumerate(s["clusters"]):
            prompt += f"- 簇 #{ci}: size={cl['size']}, avg_fusion={cl['avg_fusion']}, 判定={cl['determination']}\n"

        prompt += f"""
## 网络拓扑分析
- 众包比例：{s['network']['crowdsourced_ratio']}
- 众包标记：{s['network']['crowdsourced_flag']}

## 任务

基于以上爬虫检测数据，生成 JSON 格式的爬虫安全分析报告。请从以下维度分析：

### 输出 JSON Schema
{{
  "executive_summary": {{
    "status": "active|stable|critical",
    "crawler_activity_level": "HIGH|MEDIUM|LOW",
    "key_findings": ["要点1", "要点2", ...]
  }},
  "crawler_analysis": {{
    "distributed_crawlers": [
      {{
        "cluster_size": "集群规模",
        "detection_evidence": "时序关联 + 网络聚集的检出依据",
        "behavior_pattern": "行为模式描述",
        "impact": "影响分析",
        "remediation": "防御建议"
      }}
    ],
    "crowdsourced_crawlers": {{
      "detected": true|false,
      "session_count": "众包会话数",
      "coverage_characteristics": "覆盖特征描述",
      "difficulty": "检测难度分析",
      "remediation": "防御建议"
    }},
    "patterns_summary": "整体爬虫攻击模式总结"
  }},
  "defense_recommendations": [
    {{
      "priority": "HIGH|MEDIUM|LOW",
      "title": "建议标题",
      "description": "具体描述",
      "expected_effect": "预期效果"
    }}
  ],
  "conclusion": {{
    "overall_assessment": "总体评估",
    "immediate_actions": ["行动1", "行动2"],
    "long_term_improvements": ["改进1", "改进2"]
  }}
}}

### 分析要求
- 基于提供的数据，不要编造数字
- 对分布式爬虫和众包爬虫的区别要说明清楚
- 结合覆盖分析和时序分析给出针对性建议
- 输出严格 JSON，不要包含 ```json 标记或其他文字"""
        return prompt

    def _build_markdown(self, summary: dict, llm_result: dict) -> str:
        """将 LLM 结果渲染为 Markdown 报告。"""
        from datetime import datetime
        lines = []
        lines.append("# 爬虫安全态势报告\n")
        lines.append(f"**生成时间：**{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

        # ===== 1. 执行摘要 =====
        es = llm_result.get("executive_summary", {})
        lines.append("## 1. 执行摘要\n")
        lines.append(f"**爬虫活跃度：**{es.get('crawler_activity_level', 'N/A')}")
        lines.append(f"**状态：**{es.get('status', 'N/A')}\n")
        for finding in es.get("key_findings", []):
            lines.append(f"- {finding}")
        lines.append("")

        # ===== 2. 检测概览（数据驱动）=====
        s = summary
        lines.append("## 2. 检测概览\n")
        lines.append("| 指标 | 数值 |")
        lines.append("|------|------|")
        lines.append(f"| 总会话数 | {s['total_sessions']} |")
        lines.append(f"| 总请求数 | {s['total_records']} |")
        lines.append(f"| 真实分布 | {s['true_distribution']} |")
        lines.append(f"| 检测分布 | {s['detection_distribution']} |")
        lines.append("")

        lines.append("### 全局判定\n")
        ga = s['global_assessment']
        lines.append(f"- 分布式爬虫：{'**检出**' if ga['has_distributed_crawler'] else '未检出'}（{ga['distributed_session_count']} 会话）")
        lines.append(f"- 众包爬虫：{'**检出**' if ga['has_crowdsourced_crawler'] else '未检出'}（{ga['crowdsourced_session_count']} 会话）")
        lines.append(f"- 疑似爬虫：{ga['suspicious_session_count']} 会话")
        lines.append("")

        # ===== 3. 覆盖分析 =====
        lines.append("## 3. 覆盖分析\n")
        lines.append("### 全局覆盖\n")
        cg = s['coverage_global']
        lines.append("| 指标 | 数值 | 说明 |")
        lines.append("|------|------|------|")
        lines.append(f"| 覆盖熵 | {cg['entropy']} | 越低=越系统化 |")
        lines.append(f"| 覆盖完整度 | {cg['completeness']} | 越高=爬取越完整 |")
        lines.append(f"| 顺序性评分 | {cg['sequential_score']} | 越高=访问越有序 |")
        lines.append(f"| 空闲会话率 | {cg['idle_ratio']} | 越高=众包嫌疑越大 |")
        lines.append(f"| 疑似覆盖 | {cg['suspicious']} | 是否触发可疑标记 |")
        lines.append("")

        lines.append("### 按模式分组覆盖\n")
        lines.append("| 模式 | 熵 | 完整度 | 空闲率 | 可疑 |")
        lines.append("|------|:--:|:------:|:------:|:----:|")
        for pat, pc in sorted(s.get("coverage_per_pattern", {}).items()):
            lines.append(f"| {pat} | {pc['entropy']} | {pc['completeness']} | {pc['idle_ratio']} | {pc['suspicious']} |")
        lines.append("")

        # ===== 4. 时序关联簇 =====
        if s['clusters']:
            lines.append("## 4. 时序关联簇\n")
            lines.append("| 簇 ID | 规模 | 平均融合分 | 判定 |")
            lines.append("|-------|:----:|:----------:|:----:|")
            for ci, cl in enumerate(s['clusters']):
                lines.append(f"| #{ci} | {cl['size']} | {cl['avg_fusion']} | {cl['determination']} |")
            lines.append("")

        # ===== 5. 爬虫分析（LLM）=====
        ca = llm_result.get("crawler_analysis", {})
        lines.append("## 5. 爬虫分析\n")

        for dc in ca.get("distributed_crawlers", []):
            lines.append(f"### 分布式爬虫集群（规模 {dc.get('cluster_size', '?')}）")
            lines.append(f"- **检出依据：**{dc.get('detection_evidence', '')}")
            lines.append(f"- **行为模式：**{dc.get('behavior_pattern', '')}")
            lines.append(f"- **影响：**{dc.get('impact', '')}")
            lines.append(f"- **防御：**{dc.get('remediation', '')}")
            lines.append("")

        cc = ca.get("crowdsourced_crawlers", {})
        if cc.get("detected"):
            lines.append("### 众包爬虫\n")
            lines.append(f"- **检出状态：**已检出（{cc.get('session_count', '?')} 会话）")
            lines.append(f"- **覆盖特征：**{cc.get('coverage_characteristics', '')}")
            lines.append(f"- **检测难度：**{cc.get('difficulty', '')}")
            lines.append(f"- **防御：**{cc.get('remediation', '')}")
            lines.append("")

        if ca.get("patterns_summary"):
            lines.append(f"**模式总结：**{ca['patterns_summary']}\n")

        # ===== 6. 防御建议 =====
        lines.append("## 6. 防御建议\n")
        for rec in llm_result.get("defense_recommendations", []):
            lines.append(f"### [{rec.get('priority', 'INFO')}] {rec.get('title', '')}")
            lines.append(f"- **描述：**{rec.get('description', '')}")
            lines.append(f"- **预期效果：**{rec.get('expected_effect', '')}")
            lines.append("")
        if not llm_result.get("defense_recommendations"):
            lines.append("（无防御建议）\n")

        # ===== 7. 结论 =====
        con = llm_result.get("conclusion", {})
        lines.append("## 7. 结论\n")
        if con.get("overall_assessment"):
            lines.append(f"{con['overall_assessment']}\n")
        if con.get("immediate_actions"):
            lines.append("### 立即行动\n")
            for act in con["immediate_actions"]:
                lines.append(f"- [ ] {act}")
            lines.append("")
        if con.get("long_term_improvements"):
            lines.append("### 长期改进\n")
            for imp in con["long_term_improvements"]:
                lines.append(f"- {imp}")
            lines.append("")

        return "\n".join(lines)

    def _build_template_report(self, summary: dict) -> str:
        """LLM 失败时的纯模板回退报告。"""
        from datetime import datetime
        s = summary
        lines = []
        lines.append("# 爬虫安全态势报告（模板回退）\n")
        lines.append(f"**生成时间：**{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

        lines.append("## 1. 检测概览\n")
        lines.append(f"| 指标 | 数值 |")
        lines.append(f"|------|------|")
        lines.append(f"| 总会话数 | {s['total_sessions']} |")
        lines.append(f"| 总请求数 | {s['total_records']} |")
        lines.append(f"| 真实分布 | {s['true_distribution']} |")
        lines.append(f"| 检测分布 | {s['detection_distribution']} |")
        lines.append("")

        ga = s['global_assessment']
        lines.append(f"**全局判定：**分布式爬虫 {ga['distributed_session_count']} 会话 / "
                     f"众包爬虫 {ga['crowdsourced_session_count']} 会话 / "
                     f"疑似 {ga['suspicious_session_count']} 会话\n")

        lines.append("## 2. 覆盖分析\n")
        cg = s['coverage_global']
        lines.append(f"- 覆盖熵：{cg['entropy']}（{'系统化爬取' if cg['entropy'] < 0.75 else '正常随机'}）")
        lines.append(f"- 覆盖完整度：{cg['completeness']}")
        lines.append(f"- 空闲会话率：{cg['idle_ratio']}（{'众包嫌疑' if cg['idle_ratio'] > 0.3 else '正常'}）")
        lines.append("")

        if s['clusters']:
            lines.append("## 3. 时序关联簇\n")
            for ci, cl in enumerate(s['clusters']):
                lines.append(f"- 簇 #{ci}: {cl['size']} 节点, 融合分 {cl['avg_fusion']}, 判定 {cl['determination']}")
            lines.append("")

        lines.append("## 4. 恶意会话详情\n")
        for ms in s.get("malicious_details", [])[:10]:
            lines.append(f"- {ms['session_id']}: {ms['determination']} "
                         f"(fusion={ms['fusion_score']}, "
                         f"temporal={ms['temporal_score']}, "
                         f"coverage={ms['coverage_score']}, "
                         f"network={ms['network_score']})")
        lines.append("")

        lines.append("## 5. 结论\n")
        if ga['has_distributed_crawler']:
            lines.append("检测到分布式爬虫活动，建议检查 API 频率限制和 IP 白名单策略。\n")
        if ga['has_crowdsourced_crawler']:
            lines.append("检测到众包爬虫活动，建议引入行为验证码和客户端指纹识别。\n")
        if not ga['has_distributed_crawler'] and not ga['has_crowdsourced_crawler']:
            lines.append("未检测到显著的分布式/众包爬虫活动。\n")

        return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="爬虫检测集成流水线")
    parser.add_argument("--data", type=str, default=None, help="流量数据 CSV 路径")
    parser.add_argument("--output", type=str, default=None, help="报告文件名")
    parser.add_argument("--normal", type=int, default=80, help="正常用户会话数")
    parser.add_argument("--legit", type=int, default=15, help="合法爬虫会话数")
    parser.add_argument("--distributed", type=int, default=30, help="分布式爬虫会话数")
    parser.add_argument("--crowdsourced", type=int, default=25, help="众包爬虫会话数")
    parser.add_argument("--seed", type=int, default=42, help="随机种子")
    args = parser.parse_args()

    from datetime import datetime
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_name = args.output or f"crawler_security_report_{ts}.md"

    pipeline = CrawlerPipeline()
    data_path = args.data
    pipeline.run(data_path=data_path, output_name=output_name)


if __name__ == "__main__":
    main()
