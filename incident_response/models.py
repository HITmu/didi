"""应急响应系统的数据模型。"""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional
import json


# ==================== 核心模型 ====================

@dataclass
class ResponsiblePerson:
    """负责特定 API 的人员。"""
    id: str
    name: str
    email: str
    phone: str = ""
    role: str = "developer"
    slack_webhook: str = ""
    created_at: str = ""

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now().isoformat()

    def to_dict(self):
        return asdict(self)

    @staticmethod
    def from_dict(d):
        return ResponsiblePerson(**d)


@dataclass
class ApiBinding:
    """将 API 端点模式映射到责任人。"""
    id: str
    api_pattern: str          # 例如 "/api/users/*" 或正则表达式
    person_id: str            # 关联到 ResponsiblePerson 的外键
    priority: int = 0         # 数字越大表示匹配越精确
    description: str = ""
    created_at: str = ""

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now().isoformat()

    def matches(self, endpoint: str) -> bool:
        """检查此绑定是否匹配给定的端点。"""
        import fnmatch
        return fnmatch.fnmatch(endpoint, self.api_pattern)

    def to_dict(self):
        return asdict(self)

    @staticmethod
    def from_dict(d):
        return ApiBinding(**d)


# ==================== 事件模型 ====================

SEVERITY_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
DISPOSITION_TYPES = ["auto_log", "auto_block", "notify_email", "notify_slack", "escalate", "none"]


@dataclass
class Incident:
    """检测到的安全事件，含分派追踪。"""
    id: str
    log_id: int
    api_endpoint: str
    severity: str               # CRITICAL / HIGH / MEDIUM / LOW / INFO
    confidence: float
    anomaly_type: str
    reason: str = ""
    detected_at: str = ""
    disposition: str = "pending"  # pending（待定）、auto_log（自动记录）、auto_block（自动阻断）、notify_email（邮件通知）等
    disposition_status: str = "pending"  # pending（待定）、completed（已完成）、failed（失败）、skipped（已跳过）
    disposition_detail: str = ""
    resolved_at: str = ""
    notified_person: str = ""
    notified_at: str = ""

    def __post_init__(self):
        if not self.detected_at:
            self.detected_at = datetime.now().isoformat()

    @property
    def requires_immediate_action(self) -> bool:
        return self.severity in ("CRITICAL", "HIGH")

    @property
    def should_notify(self) -> bool:
        return self.severity in ("CRITICAL", "HIGH", "MEDIUM")

    def to_dict(self):
        return asdict(self)

    @staticmethod
    def from_dict(d):
        return Incident(**d)


@dataclass
class HealthRecord:
    """某个时间点的 API 健康指标快照。"""
    id: str
    api_endpoint: str
    timestamp: str
    health_score: float         # 0.0 ~ 1.0
    anomaly_count: int = 0
    total_requests: int = 0
    avg_response_time_ms: float = 0.0
    error_count: int = 0
    error_4xx_count: int = 0
    error_5xx_count: int = 0
    error_rate: float = 0.0
    status: str = "normal"      # normal（正常）、degraded（降级）、critical（严重）

    def __post_init__(self):
        # 向后兼容：如果缺失则从计数计算错误率
        if self.error_rate == 0.0 and (self.error_4xx_count or self.error_5xx_count) and self.total_requests:
            self.error_rate = (self.error_4xx_count + self.error_5xx_count) / self.total_requests

    def to_dict(self):
        return asdict(self)

    @staticmethod
    def from_dict(d):
        valid_fields = set(HealthRecord.__dataclass_fields__)
        valid = {k: v for k, v in d.items() if k in valid_fields}
        return HealthRecord(**valid)


@dataclass
class HealthChange:
    """分派前后健康指标的差异。"""
    api_endpoint: str
    before: HealthRecord
    after: HealthRecord
    incident_id: str
    disposition_taken: str

    @property
    def health_delta(self) -> float:
        return self.after.health_score - self.before.health_score

    @property
    def anomaly_delta(self) -> int:
        return self.after.anomaly_count - self.before.anomaly_count

    @property
    def improvement(self) -> bool:
        return self.health_delta > 0 or self.anomaly_delta < 0

    def to_dict(self):
        return {
            "api_endpoint": self.api_endpoint,
            "incident_id": self.incident_id,
            "disposition_taken": self.disposition_taken,
            "health_delta": round(self.health_delta, 4),
            "anomaly_delta": self.anomaly_delta,
            "improvement": self.improvement,
            "before": self.before.to_dict(),
            "after": self.after.to_dict(),
        }


@dataclass
class InternalizedKnowledge:
    """从分派结果内化的 RAG 知识条目。"""
    id: str
    api_endpoint: str
    incident_type: str
    severity: str
    disposition_taken: str
    health_impact: str           # improved（改善）、unchanged（未变）、degraded（恶化）
    learned_pattern: str         # 模式的自然语言描述
    recommendation: str          # 下次该怎么做
    created_at: str = ""
    effectiveness_score: float = 0.0  # 0.0~1.0 分派效果评分

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now().isoformat()

    def to_dict(self):
        return asdict(self)

    @staticmethod
    def from_dict(d):
        return InternalizedKnowledge(**d)


@dataclass
class EnterpriseKnowledgeEntry:
    """企业知识库条目：用于增强 RAG 上下文的知识单元。

    类别：
      - policy：安全策略/防护规则（如 OWASP 指南）
      - case：历史事件案例（从 internalized_knowledge 重建）
      - pattern：跨事件的攻击模式（从 traceability 重建）
      - role_insight：角色/权限知识（从 person_binding 重建）
      - best_practice：最佳实践（从成功处置中提取）
    """
    id: str
    title: str
    content: str
    category: str                          # policy | case | pattern | role_insight | best_practice
    source_type: str = ""                  # security_policy | internalized_knowledge | incident | traceability | person_binding | report_insight | manual
    source_ids: list = field(default_factory=list)
    tags: list = field(default_factory=list)
    severity: str = "INFO"
    affected_endpoints: list = field(default_factory=list)
    remediation: str = ""
    effectiveness_score: float = 0.0
    confidence: float = 0.0
    usage_count: int = 0
    created_at: str = ""
    updated_at: str = ""
    last_used_at: str = ""
    is_active: bool = True

    def __post_init__(self):
        now = datetime.now().isoformat()
        if not self.created_at:
            self.created_at = now
        if not self.updated_at:
            self.updated_at = now

    def to_dict(self):
        return asdict(self)

    @staticmethod
    def from_dict(d):
        valid_fields = set(EnterpriseKnowledgeEntry.__dataclass_fields__)
        valid = {k: v for k, v in d.items() if k in valid_fields}
        return EnterpriseKnowledgeEntry(**valid)


# ==================== 分派规则 ====================

DISPOSITION_RULES = [
    # （严重程度，最低置信度，分派类型）
    ("CRITICAL", 0.9, "auto_block"),
    ("CRITICAL", 0.7, "notify_email"),
    ("HIGH", 0.8, "notify_email"),
    ("HIGH", 0.0, "notify_email"),
    ("MEDIUM", 0.0, "notify_email"),
    ("LOW", 0.0, "auto_log"),
    ("INFO", 0.0, "none"),
]


def determine_disposition(severity: str, confidence: float) -> str:
    """根据严重程度和置信度确定分派类型。"""
    for sev, min_conf, disp in DISPOSITION_RULES:
        if severity == sev and confidence >= min_conf:
            return disp
    return "auto_log"


def format_severity_display(severity: str) -> str:
    icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "⚪"}
    return f"{icons.get(severity, '⚪')} {severity}"
