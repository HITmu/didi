"""安全报告生成器：将事件、健康和知识汇总为结构化的安全态势报告，
支持 Markdown 和 CLI 输出。"""

import os, json
from datetime import datetime

from .disposition import DispositionEngine
from .health_tracker import HealthTracker
from .knowledge_internalizer import KnowledgeInternalizer
from .enterprise_knowledge import EnterpriseKnowledgeBase
from . import person_binding as pb


class SecurityReportGenerator:
    """从所有子系统生成汇总的安全态势报告。"""

    def __init__(self, data_dir: str = None):
        self.data_dir = data_dir or os.path.join(os.path.dirname(__file__), "data")
        self.reports_dir = os.path.join(self.data_dir, "reports")
        self.engine = DispositionEngine(self.data_dir)
        self.health_tracker = HealthTracker(self.data_dir)
        self.knowledge = KnowledgeInternalizer(self.data_dir)
        self.enterprise_kb = EnterpriseKnowledgeBase(self.data_dir)
        os.makedirs(self.reports_dir, exist_ok=True)

    # ==================== 主流程 ====================

    def generate(self) -> dict:
        """生成完整的安全报告（字典格式），含企业知识 RAG 上下文。"""
        report = {
            "generated_at": datetime.now().isoformat(),
            "executive_summary": self._executive_summary(),
            "incident_breakdown": self._incident_breakdown(),
            "health_assessment": self._health_assessment(),
            "effectiveness_analysis": self._effectiveness_analysis(),
            "insights": self._insights_with_enterprise_context(),
            "enterprise_knowledge": self._enterprise_rag_context(),
            "responsible_persons": self._responsible_persons(),
        }
        # 闭环反馈：从本次报告生成中内化新知识
        self._internalize_after_report(report)
        return report

    # ==================== 章节 ====================

    def _executive_summary(self) -> dict:
        incidents = self.engine.get_incident_history()
        stats = self.engine.get_summary_stats()
        if not incidents:
            return {"total_incidents": 0, "status": "no incidents"}

        severity = stats.get("by_severity", {})
        return {
            "total_incidents": len(incidents),
            "critical_count": severity.get("CRITICAL", 0),
            "high_count": severity.get("HIGH", 0),
            "medium_count": severity.get("MEDIUM", 0),
            "low_count": severity.get("LOW", 0),
            "unique_apis_affected": len(stats.get("by_api", {})),
            "disposition_summary": stats.get("by_disposition", {}),
            "status": "active",
        }

    def _incident_breakdown(self) -> dict:
        incidents = self.engine.get_incident_history()
        if not incidents:
            return {}

        by_endpoint = {}
        for i in incidents:
            api = i.get("api_endpoint", "/unknown")
            if api not in by_endpoint:
                by_endpoint[api] = {"count": 0, "severities": {}, "dispositions": {}}
            by_endpoint[api]["count"] += 1
            sev = i.get("severity", "UNKNOWN")
            by_endpoint[api]["severities"][sev] = by_endpoint[api]["severities"].get(sev, 0) + 1
            disp = i.get("disposition", "unknown")
            by_endpoint[api]["dispositions"][disp] = by_endpoint[api]["dispositions"].get(disp, 0) + 1

        return {
            "total": len(incidents),
            "by_endpoint": dict(sorted(by_endpoint.items(), key=lambda x: -x[1]["count"])),
        }

    def _health_assessment(self) -> dict:
        changes = self.health_tracker.get_all_changes()
        if not changes:
            return {"total_changes": 0, "status": "no data"}

        deltas = [c.get("health_delta", 0) for c in changes]
        total_delta = round(sum(deltas), 4)
        avg_delta = round(sum(deltas) / len(deltas), 4) if deltas else 0

        by_api = {}
        for c in changes:
            api = c.get("api_endpoint", "/unknown")
            if api not in by_api:
                by_api[api] = {"changes": 0, "total_delta": 0.0}
            by_api[api]["changes"] += 1
            by_api[api]["total_delta"] += c.get("health_delta", 0)

        for v in by_api.values():
            v["total_delta"] = round(v["total_delta"], 4)

        return {
            "total_changes": len(changes),
            "total_health_delta": total_delta,
            "avg_health_delta": avg_delta,
            "improved_count": sum(1 for d in deltas if d > 0),
            "degraded_count": sum(1 for d in deltas if d < 0),
            "unchanged_count": sum(1 for d in deltas if d == 0),
            "by_api": dict(sorted(by_api.items(), key=lambda x: -abs(x[1]["total_delta"]))),
        }

    def _effectiveness_analysis(self) -> dict:
        entries = self.knowledge.get_all()
        if not entries:
            return {"total_entries": 0, "status": "no data"}

        scores = [e.effectiveness_score for e in entries]
        return {
            "total_entries": len(entries),
            "avg_effectiveness": round(sum(scores) / len(scores), 4),
            "max_effectiveness": max(scores),
            "min_effectiveness": min(scores),
            "by_health_impact": self.knowledge.get_summary().get("by_health_impact", {}),
        }

    def _insights(self) -> dict:
        entries = self.knowledge.get_all()
        if not entries:
            return {"patterns": [], "recommendations": []}

        # Group by type
        by_type = {}
        for e in entries:
            by_type.setdefault(e.incident_type, []).append(e)

        patterns = []
        for itype, group in by_type.items():
            avg_eff = round(sum(e.effectiveness_score for e in group) / len(group), 4)
            top = sorted(group, key=lambda x: x.effectiveness_score, reverse=True)[0]
            patterns.append({
                "type": itype,
                "count": len(group),
                "avg_effectiveness": avg_eff,
                "example_pattern": top.learned_pattern,
            })

        patterns.sort(key=lambda x: -x["count"])

        # Group by (type, api_endpoint) — each payload variant gets its own recommendation
        by_variant = {}
        for e in entries:
            key = (e.incident_type, e.api_endpoint)
            by_variant.setdefault(key, []).append(e)

        recommendations = []
        for (itype, endpoint), group in sorted(by_variant.items(), key=lambda x: -len(x[1])):
            top = sorted(group, key=lambda x: x.effectiveness_score, reverse=True)[0]
            recommendations.append({
                "type": itype,
                "endpoint": endpoint,
                "count": len(group),
                "recommendation": top.recommendation,
            })

        return {"patterns": patterns, "recommendations": recommendations}

    def _responsible_persons(self) -> list:
        incidents = self.engine.get_incident_history()
        if not incidents:
            return []

        affected_apis = set(i.get("api_endpoint") for i in incidents)
        result = []
        seen = set()
        for api in sorted(affected_apis):
            matched = pb.find_responsible_for_api(api)
            for _binding, person in matched:
                if person.id not in seen:
                    seen.add(person.id)
                    result.append({
                        "name": person.name,
                        "email": person.email,
                        "role": person.role,
                        "phone": person.phone,
                    })
        return result

    # ==================== 企业知识 RAG ====================

    def _enterprise_rag_context(self) -> dict:
        """查询企业知识库获取与本次报告相关的 RAG 上下文。"""
        incidents = self.engine.get_incident_history()
        if not incidents:
            return {"status": "no_data", "entries": 0}

        incident_types = list(set(i.get("anomaly_type") for i in incidents if i.get("anomaly_type")))
        endpoints = list(set(i.get("api_endpoint") for i in incidents if i.get("api_endpoint")))
        severities = list(set(i.get("severity") for i in incidents if i.get("severity")))

        return self.enterprise_kb.query_for_report(
            incident_types=incident_types,
            endpoints=endpoints,
            severities=severities,
        )

    def _insights_with_enterprise_context(self) -> dict:
        """增强洞察：在原有洞察基础上融入企业知识上下文。"""
        base = self._insights()
        ek = self._enterprise_rag_context()
        if ek.get("status") == "no_data":
            return base

        if ek.get("policies"):
            base["policy_recommendations"] = [
                {"type": e.get("title", ""), "content": e.get("content", "")[:200],
                 "remediation": e.get("remediation", ""), "severity": e.get("severity", "INFO"),
                 "relevance": e.get("relevance", 0), "source": "enterprise_kb"}
                for e in ek["policies"]
            ]
        if ek.get("patterns"):
            base["enterprise_patterns"] = [
                {"type": e.get("title", ""), "content": e.get("content", "")[:200],
                 "effectiveness": e.get("effectiveness_score", 0), "source": "enterprise_kb"}
                for e in ek["patterns"]
            ]
        return base

    def _internalize_after_report(self, report: dict) -> None:
        """报告生成后的闭环反馈：提取新模式/建议并内化。"""
        try:
            insights = report.get("insights", {})
            new = self.enterprise_kb.internalize_from_report(report, insights)
            if new:
                print(f"[EnterpriseKB] Internalized {len(new)} new knowledge entries from report")
        except Exception as e:
            print(f"[EnterpriseKB] Post-report internalization failed: {e}")

    # ==================== 输出 ====================

    def format_markdown(self, report: dict = None) -> str:
        """将报告渲染为格式化的 Markdown 字符串。"""
        if report is None:
            report = self.generate()

        lines = []
        lines.append("# 安全态势报告\n")
        ts = report.get("generated_at", "")
        if ts:
            lines.append(f"**生成时间：**{ts[:19].replace('T', ' ')}\n")

        es = report.get("executive_summary", {})
        if es.get("status") == "no incidents":
            lines.append("## 执行摘要\n")
            lines.append("尚未处理任何事件，无法生成报告。\n")
            return "\n".join(lines)

        lines.append("## 执行摘要\n")
        lines.append(f"- **事件总数：**{es.get('total_incidents', 0)}")
        lines.append(f"- **严重分布：**严重={es.get('critical_count', 0)} | 高={es.get('high_count', 0)} | 中={es.get('medium_count', 0)} | 低={es.get('low_count', 0)}")
        lines.append(f"- **受影响 API 数：**{es.get('unique_apis_affected', 0)}")
        lines.append(f"- **处置汇总：**{json.dumps(es.get('disposition_summary', {}), ensure_ascii=False)}\n")

        # Incident Breakdown
        ib = report.get("incident_breakdown", {})
        if ib:
            lines.append("## 事件细分\n")
            lines.append(f"**总计：**{ib.get('total', 0)} 个事件\n")
            lines.append("| API 端点 | 事件数 | 严重性 | 处置方式 |")
            lines.append("|----------|--------|--------|----------|")
            for api, info in ib.get("by_endpoint", {}).items():
                sevs = ", ".join(f"{k}={v}" for k, v in info.get("severities", {}).items())
                disps = ", ".join(f"{k}={v}" for k, v in info.get("dispositions", {}).items())
                lines.append(f"| {api} | {info['count']} | {sevs} | {disps} |")
            lines.append("")

        # Health Assessment
        ha = report.get("health_assessment", {})
        if ha.get("status") != "no data":
            lines.append("## 健康影响评估\n")
            lines.append(f"- **总变化数：**{ha.get('total_changes', 0)}")
            lines.append(f"- **总健康 Delta：**{ha.get('total_health_delta', 0):+.4f}")
            lines.append(f"- **平均 Delta：**{ha.get('avg_health_delta', 0):+.4f}")
            lines.append(f"- **改善：**{ha.get('improved_count', 0)} | **恶化：**{ha.get('degraded_count', 0)} | **不变：**{ha.get('unchanged_count', 0)}")
            lines.append("")
            lines.append("| API 端点 | 变化数 | Delta |")
            lines.append("|----------|--------|-------|")
            for api, info in ha.get("by_api", {}).items():
                lines.append(f"| {api} | {info['changes']} | {info['total_delta']:+.4f} |")
            lines.append("")
        else:
            lines.append("## 健康影响评估\n无健康数据可用。\n")

        # Effectiveness Analysis
        ea = report.get("effectiveness_analysis", {})
        if ea.get("status") != "no data":
            lines.append("## 处置有效性\n")
            lines.append(f"- **知识条目数：**{ea.get('total_entries', 0)}")
            lines.append(f"- **平均有效性：**{ea.get('avg_effectiveness', 0):.4f}")
            lines.append(f"- **范围：**{ea.get('min_effectiveness', 0):.4f} – {ea.get('max_effectiveness', 0):.4f}")
            lines.append(f"- **按健康影响：**{json.dumps(ea.get('by_health_impact', {}), ensure_ascii=False)}\n")
        else:
            lines.append("## 处置有效性\n无知识数据可用。\n")

        # Enterprise Knowledge Context
        ek = report.get("enterprise_knowledge", {})
        if ek.get("status") != "no_data":
            lines.append("## 企业知识上下文\n")
            if ek.get("policies"):
                lines.append("### 适用安全策略\n")
                for p in ek["policies"]:
                    lines.append(f"- [{p.get('severity', 'INFO')}] {p.get('title', '')}")
                    lines.append(f"  - {p.get('content', '')[:150]}")
                    if p.get("remediation"):
                        lines.append(f"  - *修复建议：*{p['remediation'][:150]}")
                    lines.append(f"  - 相关度：{p.get('relevance', 0):.2f}")
                    lines.append("")
            if ek.get("cases"):
                lines.append("### 相似历史案例\n")
                for c in ek["cases"]:
                    lines.append(f"- {c.get('title', '')}（有效性：{c.get('effectiveness_score', 0):.2f}）")
                    lines.append(f"  - {c.get('content', '')[:150]}")
                    lines.append("")
            if ek.get("patterns"):
                lines.append("### 已知攻击模式\n")
                for pat in ek["patterns"]:
                    lines.append(f"- {pat.get('title', '')}（置信度：{pat.get('confidence', 0):.2f}）")
                    lines.append(f"  - {pat.get('content', '')[:150]}")
                    lines.append("")
            if ek.get("role_insights"):
                lines.append("### 负责角色与人员\n")
                for r in ek["role_insights"]:
                    lines.append(f"- {r.get('title', '')}")
                    if r.get("content"):
                        lines.append(f"  - {r['content'][:150]}")
                    lines.append("")
            lines.append("")

        # Insights
        ins = report.get("insights", {})
        if ins.get("patterns"):
            lines.append("## 关键洞察\n")
            lines.append("### 模式\n")
            for p in ins["patterns"]:
                lines.append(f"- **{p['type']}**（{p['count']} 次出现，平均有效性：{p['avg_effectiveness']:.4f}）")
                lines.append(f"  - {p['example_pattern']}")
            lines.append("")
            lines.append("### 建议\n")
            for r in ins["recommendations"]:
                ep = r.get("endpoint", "")
                if ep:
                    ep_short = ep.split("/")[-1] if "/" in ep else ep
                    lines.append(f"- **{r['type']}** `{ep_short}`：{r['recommendation']}")
                else:
                    lines.append(f"- **{r['type']}：**{r['recommendation']}")
            lines.append("")
            if ins.get("policy_recommendations"):
                lines.append("### 安全策略建议\n")
                for pr in ins["policy_recommendations"]:
                    lines.append(f"- [{pr.get('severity', 'INFO')}] {pr.get('type', '')}")
                    if pr.get("remediation"):
                        lines.append(f"  - *修复建议：*{pr['remediation'][:200]}")
                    lines.append("")

        # Responsible Persons
        rp = report.get("responsible_persons", [])
        if rp:
            lines.append("## 责任人\n")
            lines.append("| 姓名 | 角色 | 邮箱 | 电话 |")
            lines.append("|------|------|------|------|")
            for p in rp:
                lines.append(f"| {p['name']} | {p['role']} | {p['email']} | {p.get('phone', '')} |")
            lines.append("")

        return "\n".join(lines)

    def save_report(self, output_path: str = None) -> str:
        """生成并保存 Markdown 报告。如果未指定路径则自动生成文件名。"""
        if not output_path:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = os.path.join(self.reports_dir, f"security_report_{ts}.md")

        report = self.generate()
        markdown = self.format_markdown(report)
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(markdown)
        return output_path
