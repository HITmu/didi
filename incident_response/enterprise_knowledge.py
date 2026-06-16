"""企业知识库引擎 — 多源 RAG 知识聚合、查询与内化反馈。"""

import os, json, uuid
from datetime import datetime
from fnmatch import fnmatch
from typing import Optional

from .models import EnterpriseKnowledgeEntry
from . import person_binding as pb
from .traceability import TraceabilityAnalyzer
from .knowledge_internalizer import KnowledgeInternalizer
from .nlg_explainer import NlgExplainer


class EnterpriseKnowledgeBase:
    """企业知识库：聚合策略、案例、模式、角色洞察和最佳实践。

    数据持久化：data/enterprise_knowledge.json
    可通过 rebuild_from_sources() 从现有子系统重建。
    """

    def __init__(self, data_dir: str = None):
        self.data_dir = data_dir or os.path.join(os.path.dirname(__file__), "data")
        self.entries_file = os.path.join(self.data_dir, "enterprise_knowledge.json")
        os.makedirs(self.data_dir, exist_ok=True)

    # ==================== 持久化 ====================

    def _load_all(self) -> list[EnterpriseKnowledgeEntry]:
        if not os.path.exists(self.entries_file):
            return []
        try:
            with open(self.entries_file, "r", encoding="utf-8") as f:
                raw = json.load(f)
            return [EnterpriseKnowledgeEntry.from_dict(d) for d in raw if d]
        except (json.JSONDecodeError, IOError):
            return []

    def _save_all(self, entries: list[EnterpriseKnowledgeEntry]) -> None:
        with open(self.entries_file, "w", encoding="utf-8") as f:
            json.dump([e.to_dict() for e in entries], f, ensure_ascii=False, indent=2)

    # ==================== CRUD ====================

    def add_entry(self, entry: EnterpriseKnowledgeEntry) -> EnterpriseKnowledgeEntry:
        if not entry.id:
            entry.id = uuid.uuid4().hex[:12]
        entry.updated_at = datetime.now().isoformat()
        entries = self._load_all()
        entries.append(entry)
        self._save_all(entries)
        return entry

    def update_entry(self, entry_id: str, **kwargs) -> Optional[EnterpriseKnowledgeEntry]:
        entries = self._load_all()
        for e in entries:
            if e.id == entry_id:
                for k, v in kwargs.items():
                    if hasattr(e, k) and v is not None:
                        setattr(e, k, v)
                e.updated_at = datetime.now().isoformat()
                self._save_all(entries)
                return e
        return None

    def delete_entry(self, entry_id: str) -> bool:
        entries = self._load_all()
        new = [e for e in entries if e.id != entry_id]
        if len(new) == len(entries):
            return False
        self._save_all(new)
        return True

    def get_entry(self, entry_id: str) -> Optional[EnterpriseKnowledgeEntry]:
        for e in self._load_all():
            if e.id == entry_id:
                return e
        return None

    def get_all(self, active_only: bool = True) -> list[EnterpriseKnowledgeEntry]:
        entries = self._load_all()
        if active_only:
            entries = [e for e in entries if e.is_active]
        return entries

    # ==================== 查询 ====================

    def search(self, query: str = None, category: str = None, tags: list = None,
               min_effectiveness: float = 0.0, endpoint: str = None,
               severity: str = None) -> list[EnterpriseKnowledgeEntry]:
        entries = self.get_all(active_only=True)

        if category:
            entries = [e for e in entries if e.category == category]
        if severity:
            entries = [e for e in entries if e.severity == severity]
        if min_effectiveness > 0:
            entries = [e for e in entries if e.effectiveness_score >= min_effectiveness]
        if tags:
            entries = [e for e in entries if any(t in e.tags for t in tags)]
        if endpoint:
            entries = [e for e in entries if any(fnmatch(endpoint, p) for p in e.affected_endpoints)]
        if query:
            q = query.lower()
            entries = [e for e in entries if q in e.title.lower() or q in e.content.lower()]

        entries.sort(key=lambda x: x.effectiveness_score, reverse=True)
        return entries

    # ==================== RAG 上下文构建 ====================

    def _compute_relevance(self, entry: EnterpriseKnowledgeEntry,
                           incident_types: list[str], endpoints: list[str],
                           severities: list[str]) -> float:
        """计算知识条目与给定上下文的关联度分数 (0.0~1.0)。"""
        score = 0.0
        if entry.category == "policy":
            score += 0.3

        for it in incident_types:
            if any(it.lower() in t.lower() for t in entry.tags):
                score += 0.15
                break

        for ep in endpoints:
            if any(fnmatch(ep, ap) for ap in entry.affected_endpoints):
                score += 0.2
                break

        if entry.severity in severities:
            score += 0.15

        score += entry.effectiveness_score * 0.1

        return min(score, 1.0)

    def query_for_report(self, incident_types: list[str] = None, endpoints: list[str] = None,
                         severities: list[str] = None, max_entries: int = 15) -> dict:
        """为报告生成分类的 RAG 上下文。"""
        incident_types = incident_types or []
        endpoints = endpoints or []
        severities = severities or []
        all_entries = self.get_all(active_only=True)

        if not all_entries:
            return {"status": "no_data", "entries": 0,
                    "policies": [], "cases": [], "patterns": [],
                    "role_insights": [], "best_practices": []}

        scored = [(e, self._compute_relevance(e, incident_types, endpoints, severities))
                  for e in all_entries]
        scored.sort(key=lambda x: -x[1])

        result = {"policies": [], "cases": [], "patterns": [],
                  "role_insights": [], "best_practices": []}
        counts = {"policy": "policies", "case": "cases", "pattern": "patterns",
                  "role_insight": "role_insights", "best_practice": "best_practices"}

        for entry, relevance in scored:
            key = counts.get(entry.category)
            if key and len(result[key]) < max_entries // 3:
                d = entry.to_dict()
                d["relevance"] = round(relevance, 4)
                result[key].append(d)
                entry.usage_count += 1
                entry.last_used_at = datetime.now().isoformat()

        # 确保总数不超 max_entries
        flat = []
        for lst in result.values():
            flat.extend(lst)
        if len(flat) > max_entries:
            # 按关联度重新排序截断
            all_items = []
            for key, lst in result.items():
                all_items.extend(lst)
            all_items.sort(key=lambda x: -x["relevance"])
            all_items = all_items[:max_entries]
            result = {"policies": [], "cases": [], "patterns": [],
                      "role_insights": [], "best_practices": []}
            for item in all_items:
                for key, lst_key in counts.items():
                    if item.get("category") == key:
                        result[lst_key].append(item)

        self._save_all(self.get_all(active_only=False))
        result["status"] = "ok"
        result["entries"] = sum(len(v) for k, v in result.items() if isinstance(v, list))
        return result

    def build_rag_context(self, incident_types: list[str] = None,
                          endpoints: list[str] = None,
                          severities: list[str] = None) -> str:
        """生成纯文本 RAG 上下文（适用于 LLM 提示词注入）。"""
        data = self.query_for_report(incident_types, endpoints, severities)
        if data.get("status") == "no_data":
            return ""

        lines = ["=== 企业知识上下文 ===\n"]

        section_titles = {
            "policies": "安全策略",
            "cases": "相似历史案例",
            "patterns": "攻击模式",
            "role_insights": "负责角色与人员",
            "best_practices": "最佳实践",
        }

        for key, title in section_titles.items():
            items = data.get(key, [])
            if not items:
                continue
            lines.append(f"## {title}（{len(items)} 条）")
            for item in items:
                lines.append(f"[{item.get('severity', 'INFO')}] {item.get('title', '')}")
                content = item.get('content', '')
                if content:
                    lines.append(f"   {content[:200]}")
                remediation = item.get('remediation', '')
                if remediation:
                    lines.append(f"   修复建议：{remediation[:200]}")
                rel = item.get('relevance', 0)
                if rel:
                    lines.append(f"   相关度：{rel:.2f}")
                lines.append("")
            lines.append("")

        return "\n".join(lines)

    # ==================== 从现有源重建 ====================

    def rebuild_from_sources(self) -> dict:
        """从所有现有子系统扫描并创建企业知识条目。"""
        created = 0
        updated = 0
        skipped = 0
        existing = self._load_all()

        def exists(title_match: str, source_type_match: str) -> bool:
            return any(e.title == title_match and e.source_type == source_type_match
                       for e in existing)

        # 1. Internalized Knowledge → case 条目
        ki = KnowledgeInternalizer(self.data_dir)
        for k in ki.get_all():
            title = f"案例：{k.incident_type} 在 {k.api_endpoint}"
            if exists(title, "internalized_knowledge"):
                skipped += 1
                continue
            entry = EnterpriseKnowledgeEntry(
                id=uuid.uuid4().hex[:12],
                title=title,
                content=f"模式：{k.learned_pattern}\n建议：{k.recommendation}",
                category="case",
                source_type="internalized_knowledge",
                source_ids=[k.id],
                tags=[k.incident_type, k.api_endpoint.split("/")[-1]] if k.api_endpoint else [k.incident_type],
                severity=k.severity,
                affected_endpoints=[k.api_endpoint] if k.api_endpoint else [],
                remediation=k.recommendation,
                effectiveness_score=k.effectiveness_score,
                confidence=k.effectiveness_score * 0.85,
            )
            existing.append(entry)
            created += 1

        # 2. Persons + Bindings → role_insight 条目
        persons = pb.list_persons()
        bindings = pb.list_bindings()
        person_endpoints: dict[str, list] = {}
        for b in bindings:
            person_endpoints.setdefault(b.person_id, []).append(b.api_pattern)
        for p in persons:
            title = f"角色：{p.name}（{p.role}）"
            if exists(title, "person_binding"):
                skipped += 1
                continue
            eps = person_endpoints.get(p.id, [])
            content_parts = [f"姓名：{p.name}", f"角色：{p.role}", f"邮箱：{p.email}"]
            if p.phone:
                content_parts.append(f"电话：{p.phone}")
            if eps:
                content_parts.append(f"负责 API：{', '.join(eps)}")
            entry = EnterpriseKnowledgeEntry(
                id=uuid.uuid4().hex[:12],
                title=title,
                content=" | ".join(content_parts),
                category="role_insight",
                source_type="person_binding",
                source_ids=[p.id],
                tags=["role", p.role] + [ep.split("/")[1] if ep.startswith("/") else ep for ep in eps[:5]],
                severity="INFO",
                affected_endpoints=eps,
                confidence=0.9,
            )
            existing.append(entry)
            created += 1

        # 3. Traceability → pattern 条目
        try:
            ta = TraceabilityAnalyzer(self.data_dir)
            patterns = ta.analyze_attack_patterns()
            for attack_type, info in patterns.get("by_type", {}).items():
                title = f"模式：{attack_type}"
                if exists(title, "traceability"):
                    skipped += 1
                    continue
                count = info.get("count", 0) if isinstance(info, dict) else info
                eps = info.get("endpoints", []) if isinstance(info, dict) else []
                entry = EnterpriseKnowledgeEntry(
                    id=uuid.uuid4().hex[:12],
                    title=title,
                    content=f"攻击类型 '{attack_type}' 在跟踪事件中出现 {count} 次。",
                    category="pattern",
                    source_type="traceability",
                    tags=[attack_type, "traceability"],
                    severity=patterns.get("severity_escalation", {}).get(attack_type, "HIGH"),
                    affected_endpoints=eps if eps else ["*"],
                    effectiveness_score=0.6,
                    confidence=0.7,
                )
                existing.append(entry)
                created += 1

            # 跨 API 相关性模式
            for attack_type, related_eps in patterns.get("widespread_types", {}).items():
                title = f"跨 API 模式：{attack_type}"
                if exists(title, "traceability"):
                    skipped += 1
                    continue
                entry = EnterpriseKnowledgeEntry(
                    id=uuid.uuid4().hex[:12],
                    title=title,
                    content=f"'{attack_type}' 同时影响多个 API：{', '.join(related_eps)}",
                    category="pattern",
                    source_type="traceability",
                    tags=[attack_type, "cross_api", "correlation"],
                    severity="HIGH",
                    affected_endpoints=related_eps,
                    effectiveness_score=0.65,
                    confidence=0.7,
                )
                existing.append(entry)
                created += 1
        except Exception:
            pass

        # 4. NLG Explainer 模板 → best_practice 条目
        try:
            explainer = NlgExplainer()
            known = ["directory_traversal", "injection", "xss", "unauthorized_access",
                     "sensitive_data_leakage", "performance"]
            for atype in known:
                title = f"最佳实践：{atype}"
                if exists(title, "nlg_explainer"):
                    skipped += 1
                    continue
                entry = EnterpriseKnowledgeEntry(
                    id=uuid.uuid4().hex[:12],
                    title=title,
                    content=f"基于处置经验的'{atype}'事件处理最佳实践指南。",
                    category="best_practice",
                    source_type="nlg_explainer",
                    tags=[atype, "best_practice"],
                    severity="MEDIUM",
                    affected_endpoints=["*"],
                    effectiveness_score=0.5,
                    confidence=0.5,
                )
                existing.append(entry)
                created += 1
        except Exception:
            pass

        self._save_all(existing)
        return {"created": created, "updated": updated, "skipped": skipped}

    # ==================== 种子数据 ====================

    def seed_default_policies(self) -> int:
        """加载种子安全策略（避免重复）。"""
        from .enterprise_seed_data import SEED_POLICIES

        existing = self._load_all()
        existing_titles = {e.title for e in existing}
        created = 0

        for data in SEED_POLICIES:
            if data["title"] in existing_titles:
                continue
            entry = EnterpriseKnowledgeEntry(
                id=uuid.uuid4().hex[:12],
                **{k: v for k, v in data.items() if k in EnterpriseKnowledgeEntry.__dataclass_fields__},
            )
            existing.append(entry)
            created += 1

        if created:
            self._save_all(existing)
        return created

    # ==================== 报告反馈内化 ====================

    def internalize_from_report(self, report: dict, insights: dict = None) -> list[EnterpriseKnowledgeEntry]:
        """从报告洞察中提取新模式并内化为知识条目。"""
        new_entries = []
        existing = self._load_all()
        existing_titles = {e.title for e in existing}

        if insights is None:
            insights = report.get("insights", {})

        # 从 patterns 中提取
        for p in insights.get("patterns", []):
            title = f"模式：{p.get('type', 'unknown')}"
            if title in existing_titles:
                continue
            entry = EnterpriseKnowledgeEntry(
                id=uuid.uuid4().hex[:12],
                title=title,
                content=p.get("example_pattern", f"检测到的模式：{p.get('type', 'unknown')}"),
                category="pattern",
                source_type="report_insight",
                tags=[p.get("type", "unknown"), "report_generated"],
                severity="MEDIUM",
                affected_endpoints=["*"],
                effectiveness_score=p.get("avg_effectiveness", 0.5),
                confidence=0.6,
            )
            existing.append(entry)
            new_entries.append(entry)

        # 从 recommendations 中提取
        for r in insights.get("recommendations", []):
            title = f"建议：{r.get('type', 'unknown')}"
            if title in existing_titles:
                continue
            entry = EnterpriseKnowledgeEntry(
                id=uuid.uuid4().hex[:12],
                title=title,
                content=r.get("recommendation", f"针对 {r.get('type', 'unknown')} 的建议"),
                category="best_practice",
                source_type="report_insight",
                tags=[r.get("type", "unknown"), "recommendation"],
                severity="MEDIUM",
                affected_endpoints=["*"],
                effectiveness_score=0.5,
                confidence=0.5,
            )
            existing.append(entry)
            new_entries.append(entry)

        if new_entries:
            self._save_all(existing)

        return new_entries

    # ==================== 统计 ====================

    def get_stats(self) -> dict:
        entries = self.get_all(active_only=True)
        if not entries:
            return {"total": 0, "status": "no_data"}

        by_category = {}
        by_severity = {}
        scores = []
        total_usage = 0
        for e in entries:
            by_category[e.category] = by_category.get(e.category, 0) + 1
            by_severity[e.severity] = by_severity.get(e.severity, 0) + 1
            scores.append(e.effectiveness_score)
            total_usage += e.usage_count

        return {
            "total": len(entries),
            "by_category": by_category,
            "by_severity": by_severity,
            "avg_effectiveness": round(sum(scores) / len(scores), 4) if scores else 0,
            "max_effectiveness": max(scores) if scores else 0,
            "total_usage_count": total_usage,
            "categories": sorted(by_category.keys()),
            "status": "ok",
        }
