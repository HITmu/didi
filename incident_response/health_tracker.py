"""API 健康追踪器：监控分派前后的健康状态。

记录健康快照并计算随时间变化的健康变化。
支持基于实时指标的多因素动态风险评分。
"""

import os
import json
import uuid
from datetime import datetime, timedelta
from typing import Optional
from collections import defaultdict, deque

from .models import HealthRecord, HealthChange


DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
HEALTH_FILE = os.path.join(DATA_DIR, "health_records.json")
CHANGES_FILE = os.path.join(DATA_DIR, "health_changes.json")

# 动态风险评估的评分权重
DEFAULT_WEIGHTS = {
    "anomaly_rate": 0.35,
    "error_rate": 0.20,
    "response_time": 0.15,
    "incident_frequency": 0.20,
    "recency": 0.10,
}


class HealthTracker:
    """随时间追踪 API 健康指标，关联事件。"""

    def __init__(self, data_dir: str = None, weights: dict = None):
        self.data_dir = data_dir or DATA_DIR
        self.health_file = os.path.join(self.data_dir, "health_records.json")
        self.changes_file = os.path.join(self.data_dir, "health_changes.json")
        self.weights = weights or DEFAULT_WEIGHTS
        os.makedirs(self.data_dir, exist_ok=True)

    # ==================== 快照 ====================

    def snapshot(self, api_endpoint: str, label: str = "",
                 anomaly_count: int = 0, total_requests: int = 0,
                 avg_response_time_ms: float = 0.0,
                 error_4xx_count: int = 0, error_5xx_count: int = 0) -> HealthRecord:
        """获取当前时间 API 端点的健康快照。

        使用多因素评分：异常率、错误率（4xx/5xx）、
        响应时间异常、事件频率和时效性。

        在生产环境中，这些指标将来自监控系统（Prometheus 等）。
        """
        # 加载该端点的最近记录以计算趋势
        records = self._get_records_for_api(api_endpoint)

        # 加载事件以进行频率评分
        incidents = self._load_incidents()

        # 使用多因素评估计算健康评分
        health_score = self._compute_health_score(
            api_endpoint, records, anomaly_count, total_requests,
            avg_response_time_ms, error_4xx_count, error_5xx_count,
            incidents,
        )

        # 确定状态
        if health_score >= 0.8:
            status = "normal"
        elif health_score >= 0.5:
            status = "degraded"
        else:
            status = "critical"

        record = HealthRecord(
            id=str(uuid.uuid4())[:8],
            api_endpoint=api_endpoint,
            timestamp=datetime.now().isoformat(),
            health_score=round(health_score, 4),
            anomaly_count=anomaly_count,
            total_requests=total_requests or max(total_requests, 1),
            avg_response_time_ms=avg_response_time_ms,
            error_4xx_count=error_4xx_count,
            error_5xx_count=error_5xx_count,
            status=status,
        )

        self._save_record(record)
        return record

    def _compute_health_score(self, api_endpoint: str,
                               records: list, anomaly_count: int,
                               total_requests: int,
                               avg_response_time_ms: float = 0.0,
                               error_4xx_count: int = 0,
                               error_5xx_count: int = 0,
                               incidents: list = None) -> float:
        """使用多因素评估计算 0.0 到 1.0 的健康评分。

        因素（可通过 self.weights 配置）：
          - anomaly_rate：近期异常比率
          - error_rate：4xx/5xx 比率
          - response_time：与基线响应时间的偏差
          - incident_frequency：该 API 近期遭受事件的频率
          - recency：如果上一条记录为降级或严重状态则施加惩罚
        """
        score = 1.0
        w = self.weights

        # 因素 1：异常率
        if total_requests > 0:
            rate = anomaly_count / max(total_requests, 1)
            score -= rate * w["anomaly_rate"] * 2

        # 因素 2：错误率（4xx/5xx）
        if total_requests > 0:
            error_rate = (error_4xx_count + error_5xx_count) / max(total_requests, 1)
            score -= error_rate * w["error_rate"] * 2

        # 因素 3：与基线响应时间的偏差
        if avg_response_time_ms > 0 and records:
            baseline_times = [
                r.avg_response_time_ms for r in records[-10:]
                if r.avg_response_time_ms > 0
            ]
            if baseline_times:
                baseline = sum(baseline_times) / len(baseline_times)
                if baseline > 0:
                    ratio = avg_response_time_ms / baseline
                    if ratio > 1.5:  # 减速 50% 以上
                        penalty = min((ratio - 1.5) * w["response_time"], 0.2)
                        score -= penalty

        # 因素 4：事件频率（最近 24 小时）
        if incidents:
            try:
                cutoff = (datetime.now() - timedelta(hours=24)).isoformat()
                recent_incidents = [
                    i for i in incidents
                    if i.get("api_endpoint") == api_endpoint
                    and i.get("detected_at", "") >= cutoff
                ]
                freq_penalty = len(recent_incidents) * w["incident_frequency"] * 0.05
                score -= min(freq_penalty, 0.3)
            except Exception:
                pass

        # 因素 5：时效性惩罚
        if records:
            last = records[-1]
            if last.status in ("degraded", "critical"):
                score -= w["recency"]

        return max(0.0, min(1.0, score))

    def _load_incidents(self) -> list:
        """加载事件以进行频率分析。"""
        path = os.path.join(self.data_dir, "incidents.json")
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        return []

    def recalculate_all_scores(self) -> dict:
        """使用当前权重重新计算所有现有记录的健康评分。

        在调整权重后查看历史评分会如何变化时很有用。
        返回更新摘要。
        """
        all_records = self._load_all()
        if not all_records:
            return {"status": "no_data", "updated": 0}

        incidents = self._load_incidents()
        updated = 0
        changes = []

        # 收集所有 API 端点
        all_apis = list({r.get("api_endpoint", "") for r in all_records})

        # 按顺序重新处理每个 API 的记录
        for api in all_apis:
            api_records = [r for r in all_records if r.get("api_endpoint") == api]
            api_records.sort(key=lambda x: x.get("timestamp", ""))

            for i, rec in enumerate(api_records):
                prev_records = [
                    HealthRecord.from_dict(r) for r in api_records[:i]
                ]
                new_score = self._compute_health_score(
                    api_endpoint=api,
                    records=prev_records,
                    anomaly_count=rec.get("anomaly_count", 0),
                    total_requests=rec.get("total_requests", 0),
                    avg_response_time_ms=rec.get("avg_response_time_ms", 0.0),
                    error_4xx_count=rec.get("error_4xx_count", 0),
                    error_5xx_count=rec.get("error_5xx_count", 0),
                    incidents=incidents,
                )
                old_score = rec.get("health_score", 1.0)
                if abs(new_score - old_score) > 0.001:
                    rec["health_score"] = round(new_score, 4)
                    rec["status"] = (
                        "normal" if new_score >= 0.8 else
                        "degraded" if new_score >= 0.5 else
                        "critical"
                    )
                    updated += 1
                    changes.append({
                        "id": rec.get("id"),
                        "api_endpoint": api,
                        "old_score": old_score,
                        "new_score": round(new_score, 4),
                    })

        # 保存更新后的记录
        if updated:
            with open(self.health_file, "w", encoding="utf-8") as f:
                json.dump(all_records, f, ensure_ascii=False, indent=2)

        return {
            "status": "ok",
            "total_records": len(all_records),
            "updated": updated,
            "changes": changes,
        }

    def _get_records_for_api(self, api_endpoint: str) -> list:
        """加载特定 API 的所有健康记录。"""
        all_records = self._load_all()
        return [
            HealthRecord.from_dict(r) for r in all_records
            if r.get("api_endpoint") == api_endpoint
        ]

    def _load_all(self) -> list:
        if os.path.exists(self.health_file):
            with open(self.health_file, "r", encoding="utf-8") as f:
                return json.load(f)
        return []

    def _save_record(self, record: HealthRecord):
        records = self._load_all()
        records.append(record.to_dict())
        with open(self.health_file, "w", encoding="utf-8") as f:
            json.dump(records, f, ensure_ascii=False, indent=2)

    # ==================== 健康变化 ====================

    def record_change(self, incident_id: str, before: HealthRecord,
                       after: HealthRecord,
                       disposition_taken: str) -> HealthChange:
        """记录分派前后的健康变化。"""
        change = HealthChange(
            api_endpoint=before.api_endpoint,
            before=before,
            after=after,
            incident_id=incident_id,
            disposition_taken=disposition_taken,
        )
        self._save_change(change)
        return change

    def _save_change(self, change: HealthChange):
        changes = []
        if os.path.exists(self.changes_file):
            with open(self.changes_file, "r", encoding="utf-8") as f:
                changes = json.load(f)
        changes.append(change.to_dict())
        with open(self.changes_file, "w", encoding="utf-8") as f:
            json.dump(changes, f, ensure_ascii=False, indent=2)

    def get_health_trend(self, api_endpoint: str, window: int = 10) -> dict:
        """获取 API 端点最近记录的健康趋势。"""
        records = self._get_records_for_api(api_endpoint)
        recent = records[-window:] if len(records) >= window else records

        if not recent:
            return {"api_endpoint": api_endpoint, "status": "unknown"}

        scores = [r.health_score for r in recent]
        return {
            "api_endpoint": api_endpoint,
            "current_score": recent[-1].health_score,
            "avg_score": round(sum(scores) / len(scores), 4),
            "min_score": min(scores),
            "max_score": max(scores),
            "trend": "improving" if scores[-1] > scores[0] else (
                "declining" if scores[-1] < scores[0] else "stable"
            ),
            "records_count": len(recent),
            "current_status": recent[-1].status,
        }

    def get_all_changes(self) -> list:
        if os.path.exists(self.changes_file):
            with open(self.changes_file, "r", encoding="utf-8") as f:
                return json.load(f)
        return []
