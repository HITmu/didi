"""安全事件的通知模块。

支持：
  - 控制台日志输出（始终）
  - 文件日志输出（始终）
  - 邮件通知（通过日志模拟）
  - Slack Webhook 通知（如果已配置）
"""

import os
import logging
from datetime import datetime
from typing import Optional

from .models import Incident, ResponsiblePerson, format_severity_display

# 日志设置
LOG_DIR = os.path.join(os.path.dirname(__file__), "notifications")
os.makedirs(LOG_DIR, exist_ok=True)

logger = logging.getLogger("incident_response")
logger.setLevel(logging.INFO)

# 控制台处理器
console = logging.StreamHandler()
console.setLevel(logging.INFO)
console.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
logger.addHandler(console)

# 文件处理器
file_handler = logging.FileHandler(
    os.path.join(LOG_DIR, f"incidents_{datetime.now().strftime('%Y%m%d')}.log"),
    encoding="utf-8"
)
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(
    logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
)
logger.addHandler(file_handler)


# ==================== 通知函数 ====================

def notify(incident: Incident, person: Optional[ResponsiblePerson] = None):
    """根据事件的严重程度和分派类型路由通知。"""
    severity_display = format_severity_display(incident.severity)

    # 始终记录日志
    logger.info(
        f"[{severity_display}] Incident #{incident.id} | "
        f"API: {incident.api_endpoint} | "
        f"Type: {incident.anomaly_type} | "
        f"Confidence: {incident.confidence:.2%} | "
        f"Disposition: {incident.disposition}"
    )

    # 根据分派类型路由
    if incident.disposition == "auto_block":
        _handle_auto_block(incident, person)
    elif incident.disposition in ("notify_email", "notify_slack"):
        _handle_notify(incident, person)
    elif incident.disposition == "escalate":
        _handle_escalate(incident, person)
    elif incident.disposition == "auto_log":
        _handle_auto_log(incident)


def _handle_auto_block(incident: Incident, person: Optional[ResponsiblePerson]):
    """严重：自动阻断端点并通知。"""
    msg = (
        f"[ACTION REQUIRED] Automatic block triggered\n"
        f"  Endpoint: {incident.api_endpoint}\n"
        f"  Anomaly: {incident.anomaly_type} (confidence: {incident.confidence:.2%})\n"
        f"  Action: Endpoint blocked, traffic rejected\n"
        f"  Reason: {incident.reason}"
    )
    logger.warning(msg)

    if person:
        _send_email(person, f"[CRITICAL] API Blocked: {incident.api_endpoint}", msg)
        logger.info(f"  → Notified {person.name} <{person.email}> via email")


def _handle_notify(incident: Incident, person: Optional[ResponsiblePerson]):
    """高/中：通知责任人。"""
    msg = (
        f"[REQUIRES ATTENTION] Security incident detected\n"
        f"  Endpoint: {incident.api_endpoint}\n"
        f"  Severity: {incident.severity}\n"
        f"  Anomaly: {incident.anomaly_type}\n"
        f"  Confidence: {incident.confidence:.2%}\n"
        f"  Reason: {incident.reason}\n"
        f"  Suggested action: Review and investigate"
    )
    logger.info(msg)

    if person:
        _send_email(person, f"[{incident.severity}] API Incident: {incident.api_endpoint}", msg)
        logger.info(f"  → Notified {person.name} <{person.email}> via email")
    else:
        logger.info(f"  → No responsible person bound to {incident.api_endpoint}, logged only")


def _handle_escalate(incident: Incident, person: Optional[ResponsiblePerson]):
    """升级：同时通知责任人和上报管理员。"""
    msg = (
        f"[ESCALATION] Incident requires immediate escalation\n"
        f"  Endpoint: {incident.api_endpoint}\n"
        f"  Anomaly: {incident.anomaly_type}\n"
        f"  Confidence: {incident.confidence:.2%}\n"
        f"  Previous disposition failed or insufficient"
    )
    logger.error(msg)

    if person:
        _send_email(person, f"[ESCALATION] {incident.api_endpoint}", msg)
        logger.info(f"  → Escalated to {person.name} <{person.email}>")

    # 记录到升级文件供管理员审查
    esc_file = os.path.join(LOG_DIR, "escalations.log")
    with open(esc_file, "a", encoding="utf-8") as f:
        f.write(f"{datetime.now().isoformat()} | {incident.id} | {incident.api_endpoint} | {incident.anomaly_type}\n")


def _handle_auto_log(incident: Incident):
    """低：仅记录日志。"""
    logger.debug(
        f"Auto-logged incident #{incident.id}: "
        f"{incident.api_endpoint} -> {incident.anomaly_type}"
    )


def _send_email(person: ResponsiblePerson, subject: str, body: str):
    """模拟发送邮件。

    在生产环境中，替换为实际的 SMTP/SES/SendGrid 集成。
    """
    email_log = os.path.join(LOG_DIR, "email_log.txt")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(email_log, "a", encoding="utf-8") as f:
        f.write(f"""
{'='*60}
Time: {timestamp}
To: {person.name} <{person.email}>
Subject: {subject}
Body:
{body}
{'='*60}
""")
    # 在生产环境中：在此发送实际邮件
    # 例如 smtplib.sendmail() 或 AWS SES / SendGrid API


def notify_health_change(api_endpoint: str, health_delta: float,
                          person: Optional[ResponsiblePerson] = None):
    """通知 API 健康变化（用于定期健康报告）。"""
    direction = "improved" if health_delta > 0 else "degraded"
    msg = (
        f"[Health Report] API health {direction} for {api_endpoint}\n"
        f"  Health delta: {health_delta:+.2%}"
    )
    logger.info(msg)

    if person and abs(health_delta) > 0.1:  # 仅在变化显著时通知
        _send_email(
            person,
            f"[Health] API {direction}: {api_endpoint}",
            msg
        )
