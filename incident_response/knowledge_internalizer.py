"""知识内化器：将分派结果转换为 RAG 知识条目。

通过从分派结果和健康影响中提取模式和建议，
使系统能够从过去的事件中学习。
"""

import os
import json
import uuid
from datetime import datetime
from typing import Optional, List

from .models import (
    Incident, HealthRecord, HealthChange, InternalizedKnowledge
)


class KnowledgeInternalizer:
    """将分派结果内化为结构化知识，供未来的 RAG 使用。"""

    def __init__(self, data_dir: str = None):
        self.data_dir = data_dir or os.path.join(os.path.dirname(__file__), "data")
        self.knowledge_file = os.path.join(self.data_dir, "internalized_knowledge.json")
        os.makedirs(self.data_dir, exist_ok=True)

    # ==================== 内化 ====================

    def internalize(self, incident: Incident,
                    before_health: HealthRecord,
                    after_health: HealthRecord,
                    disposition_result: str) -> InternalizedKnowledge:
        """将分派结果转换为内化的知识条目。

        分析前后的健康影响以确定有效性，
        并提取可复用的模式和建议。
        """
        health_delta = after_health.health_score - before_health.health_score

        if health_delta > 0.05:
            health_impact = "improved"
        elif health_delta < -0.05:
            health_impact = "degraded"
        else:
            health_impact = "unchanged"

        effectiveness = self._compute_effectiveness(
            incident, disposition_result, health_delta
        )

        learned_pattern = self._build_learned_pattern(incident, health_impact)
        recommendation = self._build_recommendation(
            incident, disposition_result, health_impact
        )

        knowledge = InternalizedKnowledge(
            id=str(uuid.uuid4())[:8],
            api_endpoint=incident.api_endpoint,
            incident_type=incident.anomaly_type,
            severity=incident.severity,
            disposition_taken=incident.disposition,
            health_impact=health_impact,
            learned_pattern=learned_pattern,
            recommendation=recommendation,
            effectiveness_score=round(effectiveness, 4),
        )

        self._save(knowledge)
        return knowledge

    def _compute_effectiveness(self, incident: Incident,
                                disposition_result: str,
                                health_delta: float) -> float:
        """评分 0.0~1.0：分派的效果如何。"""
        score = 0.5  # 基线

        # 分派成功完成
        if disposition_result == "completed":
            score += 0.2

        # 分派后健康改善
        if health_delta > 0:
            score += health_delta * 2  # 完全恢复最多 +0.2
        elif health_delta < -0.1:
            score -= 0.2  # 健康状况恶化

        # 对严重事件的自动阻断非常有效
        if incident.severity == "CRITICAL" and incident.disposition == "auto_block":
            score += 0.15

        # 升级表示初始分派不够
        if incident.disposition == "escalate":
            score -= 0.1

        return max(0.0, min(1.0, score))

    @staticmethod
    def _build_learned_pattern(incident: Incident, health_impact: str) -> str:
        """构建学习到的模式的自然语言描述。"""
        impact_desc = {
            "improved": "health improved after action",
            "degraded": "health continued to decline",
            "unchanged": "health remained stable",
        }
        return (
            f"Incident type '{incident.anomaly_type}' on {incident.api_endpoint} "
            f"at severity {incident.severity} — {impact_desc.get(health_impact, 'unknown')}. "
            f"Disposition applied: {incident.disposition}. "
            f"Confidence: {incident.confidence:.0%}."
        )

    @staticmethod
    def _build_recommendation(incident: Incident,
                               disposition_result: str,
                               health_impact: str) -> str:
        """为未来同类事件构建建议，融入payload具体特征。"""
        # 加入payload特征以区分不同变体
        reason = (incident.reason or "")[:100]
        payload_hint = ""
        if "etc/passwd" in reason or "/passwd" in reason:
            payload_hint = "Target: /etc/passwd system file extraction."
        elif "etc/hosts" in reason or "/hosts" in reason:
            payload_hint = "Target: /etc/hosts with encoding bypass."
        elif "%2f" in reason.lower() or "%2e" in reason.lower():
            payload_hint = "Technique: URL-encoded path traversal."
        elif ".sql" in reason or "backup" in reason or "db_dump" in reason:
            payload_hint = "Target: sensitive backup file."
        elif "1=1" in reason or "tautology" in reason or "bypass" in reason.lower():
            payload_hint = "Technique: SQL tautology authentication bypass."

        if health_impact == "improved":
            base = (
                f"Continue using '{incident.disposition}' for "
                f"{incident.severity} {incident.anomaly_type} incidents on "
                f"{incident.api_endpoint} — it was effective. {payload_hint}"
            )
        elif health_impact == "degraded":
            base = (
                f"Consider escalating '{incident.disposition}' for "
                f"{incident.severity} {incident.anomaly_type} incidents on "
                f"{incident.api_endpoint} — health declined after action. {payload_hint}"
            )
        else:
            base = (
                f"Monitor '{incident.disposition}' for "
                f"{incident.severity} {incident.anomaly_type} incidents on "
                f"{incident.api_endpoint} — no significant health change. {payload_hint}"
            )
        return base.strip()

    # ==================== 持久化 ====================

    def _load_all(self) -> list:
        if os.path.exists(self.knowledge_file):
            with open(self.knowledge_file, "r", encoding="utf-8") as f:
                return json.load(f)
        return []

    def _save(self, knowledge: InternalizedKnowledge):
        entries = self._load_all()
        entries.append(knowledge.to_dict())
        with open(self.knowledge_file, "w", encoding="utf-8") as f:
            json.dump(entries, f, ensure_ascii=False, indent=2)

    def get_all(self) -> List[InternalizedKnowledge]:
        return [InternalizedKnowledge.from_dict(d)
                for d in self._load_all()]

    # ==================== 查询 ====================

    def search(self, api_endpoint: str = None,
               incident_type: str = None,
               min_effectiveness: float = 0.0) -> List[InternalizedKnowledge]:
        """使用筛选条件搜索内化的知识。"""
        results = []
        for k in self.get_all():
            if api_endpoint and k.api_endpoint != api_endpoint:
                continue
            if incident_type and k.incident_type != incident_type:
                continue
            if k.effectiveness_score < min_effectiveness:
                continue
            results.append(k)
        return results

    def build_rag_context(self, api_endpoint: str,
                           incident_type: str,
                           max_entries: int = 5) -> str:
        """从相关知识条目构建 RAG 上下文字符串。

        用于将过去的分派经验注入到 LLM 提示中。
        """
        entries = self.search(api_endpoint=api_endpoint,
                              incident_type=incident_type)
        entries.sort(key=lambda x: x.effectiveness_score, reverse=True)
        entries = entries[:max_entries]

        if not entries:
            return "No prior knowledge available for this incident type."

        lines = ["Past incident knowledge (by effectiveness):"]
        for i, e in enumerate(entries, 1):
            lines.append(
                f"\n[{i}] {e.severity} | {e.disposition_taken} | "
                f"health: {e.health_impact} | "
                f"effectiveness: {e.effectiveness_score:.2f}"
            )
            lines.append(f"    Pattern: {e.learned_pattern}")
            lines.append(f"    Recommendation: {e.recommendation}")

        return "\n".join(lines)

    def get_summary(self) -> dict:
        """获取内化知识的汇总统计信息。"""
        entries = self.get_all()
        if not entries:
            return {"total": 0}

        by_type = {}
        by_disposition = {}
        by_health_impact = {}
        total_effectiveness = 0.0

        for e in entries:
            by_type[e.incident_type] = by_type.get(e.incident_type, 0) + 1
            by_disposition[e.disposition_taken] = by_disposition.get(e.disposition_taken, 0) + 1
            by_health_impact[e.health_impact] = by_health_impact.get(e.health_impact, 0) + 1
            total_effectiveness += e.effectiveness_score

        return {
            "total": len(entries),
            "by_incident_type": by_type,
            "by_disposition": by_disposition,
            "by_health_impact": by_health_impact,
            "avg_effectiveness": round(total_effectiveness / len(entries), 4),
        }
