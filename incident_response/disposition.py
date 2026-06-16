"""分派引擎：根据严重程度和置信度将事件路由到适当的处理程序。

流水线：
  1. 接收分级事件（来自分类报告）
  2. 根据规则确定分派类型
  3. 查找该 API 端点的责任人
  4. 执行通知 / 自动操作
  5. 追踪处理前后的健康状态
  6. 内化知识
"""

import os
import json
import uuid
from datetime import datetime
from typing import Optional

from .models import (
    Incident, SEVERITY_LEVELS, DISPOSITION_TYPES,
    determine_disposition, format_severity_display
)
from .person_binding import find_responsible_for_api
from .notifier import notify
from .health_tracker import HealthTracker
from .knowledge_internalizer import KnowledgeInternalizer
from .nlg_explainer import NlgExplainer


class DispositionEngine:
    """端到端处理事件的主要分派引擎。"""

    def __init__(self, data_dir: str = None):
        self.data_dir = data_dir or os.path.join(os.path.dirname(__file__), "data")
        self.incidents_file = os.path.join(self.data_dir, "incidents.json")
        self.health_tracker = HealthTracker(self.data_dir)
        self.knowledge_internalizer = KnowledgeInternalizer(self.data_dir)
        self.explainer = NlgExplainer()
        os.makedirs(self.data_dir, exist_ok=True)

    # ==================== 事件管理 ====================

    def _load_incidents(self) -> list:
        """从存储加载所有事件。"""
        if os.path.exists(self.incidents_file):
            with open(self.incidents_file, "r", encoding="utf-8") as f:
                return json.load(f)
        return []

    def _save_incidents(self, incidents: list):
        """将所有事件保存到存储。"""
        with open(self.incidents_file, "w", encoding="utf-8") as f:
            json.dump(incidents, f, ensure_ascii=False, indent=2)

    def process_incident(self, log_id: int, api_endpoint: str, severity: str,
                          confidence: float, anomaly_type: str = "",
                          reason: str = "") -> Incident:
        """处理单个安全事件，经过完整的分派流水线。

        返回创建的事件及其分派结果。
        """
        # 1. 创建事件记录
        incident = Incident(
            id=str(uuid.uuid4())[:12],
            log_id=log_id,
            api_endpoint=api_endpoint,
            severity=severity,
            confidence=confidence,
            anomaly_type=anomaly_type,
            reason=reason,
            detected_at=datetime.now().isoformat(),
        )

        # 2. 根据严重程度和置信度确定分派类型
        incident.disposition = determine_disposition(severity, confidence)

        # 3. 查找该 API 的责任人
        matched = find_responsible_for_api(api_endpoint)
        person = matched[0][1] if matched else None

        # 4. 记录分派前的健康状态
        before = self.health_tracker.snapshot(api_endpoint, label="before_disposition")

        # 5. 执行通知
        try:
            notify(incident, person)
            incident.disposition_status = "completed"
            if person:
                incident.notified_person = person.name
                incident.notified_at = datetime.now().isoformat()
        except Exception as e:
            incident.disposition_status = "failed"
            incident.disposition_detail = str(e)

        # 6. 记录分派后的健康状态（立即）
        after = self.health_tracker.snapshot(api_endpoint, label="after_disposition")

        # 7. 从本次分派中内化知识
        try:
            self.knowledge_internalizer.internalize(
                incident=incident,
                before_health=before,
                after_health=after,
                disposition_result=incident.disposition_status
            )
        except Exception as e:
            print(f"  [Knowledge] Internalization failed: {e}")

        # 8. 生成 NLG 解释
        try:
            incident.disposition_detail = self.explainer.explain_disposition(
                incident.to_dict(),
                health_delta=after.health_score - before.health_score,
            )
        except Exception:
            pass

        # 9. 持久化事件
        incidents = self._load_incidents()
        incidents.append(incident.to_dict())
        self._save_incidents(incidents)

        return incident

    def process_batch(self, graded_results: list) -> list:
        """Process a batch of graded results from the report generator.

        Args:
            graded_results: List of dicts from RAGReportGenerator.grade_results()["per_log"]
                            Each dict has: log_id, final_verdict, severity, confidence,
                            anomaly_type, etc.
        Returns:
            List of processed Incidents
        """
        incidents = []
        for item in graded_results:
            if item.get("final_verdict") != "anomaly":
                continue  # 跳过正常日志

            endpoint = self._extract_endpoint(item)
            inc = self.process_incident(
                log_id=item.get("log_id", 0),
                api_endpoint=endpoint,
                severity=item.get("severity", "LOW"),
                confidence=item.get("confidence", 0.5),
                anomaly_type=item.get("anomaly_type", "unknown"),
                reason=item.get("reason", ""),
            )
            incidents.append(inc)

        return incidents

    @staticmethod
    def _extract_endpoint(item: dict) -> str:
        """从分级结果项中提取 API 端点。"""
        return item.get("endpoint", item.get("api_endpoint", "/unknown"))

    # ==================== 查询 ====================

    def get_incident_history(self, api_endpoint: str = None,
                             severity: str = None, limit: int = 50) -> list:
        """查询事件历史，支持可选筛选条件。"""
        incidents = self._load_incidents()
        filtered = []

        for item in incidents:
            if api_endpoint and item.get("api_endpoint") != api_endpoint:
                continue
            if severity and item.get("severity") != severity:
                continue
            filtered.append(item)

        return sorted(filtered, key=lambda x: x.get("detected_at", ""), reverse=True)[:limit]

    def get_summary_stats(self) -> dict:
        """获取仪表盘用的汇总统计信息。"""
        incidents = self._load_incidents()
        if not incidents:
            return {"total": 0}

        severity_counts = {}
        disposition_counts = {}
        by_api = {}

        for item in incidents:
            sev = item.get("severity", "UNKNOWN")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

            disp = item.get("disposition", "unknown")
            disposition_counts[disp] = disposition_counts.get(disp, 0) + 1

            api = item.get("api_endpoint", "/unknown")
            if api not in by_api:
                by_api[api] = {"total": 0, "severities": {}}
            by_api[api]["total"] += 1
            by_api[api]["severities"][sev] = by_api[api]["severities"].get(sev, 0) + 1

        return {
            "total": len(incidents),
            "by_severity": severity_counts,
            "by_disposition": disposition_counts,
            "by_api": dict(sorted(by_api.items(), key=lambda x: -x[1]["total"])[:20]),
            "top_apis": sorted(by_api.keys(), key=lambda a: by_api[a]["total"], reverse=True)[:5],
        }

    def print_summary(self):
        """在控制台打印所有已处理事件的汇总信息。"""
        stats = self.get_summary_stats()
        if stats["total"] == 0:
            print("No incidents processed yet.")
            return

        print("\n" + "=" * 60)
        print("Disposition Engine Summary")
        print("=" * 60)
        print(f"Total incidents processed: {stats['total']}")
        print(f"\nBy severity:")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = stats["by_severity"].get(sev, 0)
            if count > 0:
                print(f"  {format_severity_display(sev)}: {count}")

        print(f"\nBy disposition:")
        for disp, count in sorted(stats["by_disposition"].items(), key=lambda x: -x[1]):
            print(f"  {disp}: {count}")

        if stats["top_apis"]:
            print(f"\nTop APIs by incidents:")
            for api in stats["top_apis"][:5]:
                print(f"  {api}: {stats['by_api'][api]['total']}")

        knowledge = self.knowledge_internalizer.get_all()
        if knowledge:
            print(f"\nInternalized knowledge entries: {len(knowledge)}")
