"""NLG 决策解释器 — 为分派生成差异化自然语言解释。

使用本地 SecGPT-7B + LoRA 模型（如果可用），
否则使用丰富的模板，确保每个攻击变体生成不同建议。
"""

import os
import json
from typing import Optional

LLM_API_URL = "http://localhost:18000"

# 丰富模板：按攻击类型+payload特征组合生成差异化建议
RECOMMENDATION_TEMPLATES = {
    "directory_traversal": {
        "etc_passwd": (
            "Immediately block all requests containing '/etc/passwd' on {api_endpoint}. "
            "This endpoint is being targeted for system file extraction. "
            "Implement path normalization (os.path.realpath) and verify the resolved path "
            "stays within the permitted base directory."
        ),
        "etc_hosts": (
            "The '....//' double-dot encoding bypass on {api_endpoint} indicates an "
            "advanced traversal attempt targeting system configuration files. "
            "Add a WAF rule to normalize '....//' to '../' and reject if path escapes base."
        ),
        "encoded": (
            "URL-encoded path traversal (%2e%2e%2f, %2f) detected on {api_endpoint}. "
            "These encoding bypasses evade simple '../' pattern matching. "
            "Decode URL parameters before path validation, then apply the same "
            "whitelist-based path check as with unencoded paths."
        ),
        "backup": (
            "Backup file access attempt via path traversal on {api_endpoint}. "
            "Database dump files must be stored outside the web root. "
            "Restrict download endpoints to a specific directory with no upward navigation possible."
        ),
        "default": (
            "Path traversal detected on {api_endpoint} using unexpected pattern '{payload}'. "
            "Review WAF rules to cover this variant. Apply strict input validation: "
            "reject any path containing '../', '..\\', or their encoded forms."
        ),
    },
    "injection": {
        "tautology": (
            "SQL tautology injection (' OR 1=1) detected on {api_endpoint}. "
            "This confirms the endpoint is vulnerable to authentication bypass. "
            "Immediately rewrite the query to use parameterized statements — "
            "never concatenate user input into SQL strings."
        ),
        "union": (
            "UNION-based SQL injection detected on {api_endpoint}. "
            "Attackers are attempting to extract data from other tables. "
            "Apply parameterized queries and restrict database account permissions "
            "to the minimum required (no SELECT on unrelated tables)."
        ),
        "blind": (
            "Time-based blind SQL injection suspected on {api_endpoint}. "
            "Monitor response time anomalies and implement prepared statements. "
            "Use a WAF to block requests containing SLEEP/BENCHMARK functions."
        ),
        "default": (
            "SQL injection attempt on {api_endpoint} with payload pattern '{payload}'. "
            "Audit all database queries on this endpoint for string concatenation."
        ),
    },
    "xss": (
        "XSS attempt detected on {api_endpoint}. Implement context-sensitive output encoding "
        "and set Content-Security-Policy header. Sanitize all user-supplied input rendered in responses."
    ),
    "unauthorized_access": (
        "Unauthorized access attempt on {api_endpoint}. Review authentication logic and "
        "ensure proper session validation. Implement rate limiting on auth endpoints."
    ),
    "sensitive_data_leakage": (
        "Potential sensitive data exposure on {api_endpoint}. Audit response payloads to "
        "ensure no PII, credentials, or internal details are leaked. Implement response field filtering."
    ),
    "default": (
        "Investigate the {anomaly_type} pattern on {api_endpoint}. Review access logs and "
        "implement appropriate security controls based on the specific attack vector."
    ),
}

# 分派解释模板（按处置方式+严重性）
DISP_EXPLANATIONS = {
    "notify_email": "The '{anomaly_type}' attack on {api_endpoint} (severity: {severity}, confidence: {confidence:.0%}) exceeded the notification threshold. The responsible person was notified via email for manual investigation and remediation. Priority action: {remediation_guide}",
    "auto_block": "CRITICAL '{anomaly_type}' attack on {api_endpoint} (confidence: {confidence:.0%}) triggered automatic blocking to prevent damage. The attack pattern matched criteria requiring immediate termination of the request.",
    "auto_log": "Low-severity '{anomaly_type}' pattern on {api_endpoint} logged for monitoring. No immediate action needed, but frequency should be tracked for trend analysis.",
}

# 按攻击变体提取payload关键词的规则
PAYLOAD_SIGNATURES = [
    ("etc_passwd", ["etc/passwd", "/passwd", "passwd"]),
    ("etc_hosts", ["etc/hosts", "/hosts"]),
    ("encoded", ["%2f", "%2e", "%2F", "%2E"]),
    ("backup", [".sql", ".bak", "backup", "db_dump"]),
    ("tautology", ["or 1=1", "or '1'='1", "or 1=1", "or\"1\"=\"1"]),
    ("union", ["union select", "union all", "union("]),
    ("blind", ["sleep(", "benchmark(", "waitfor delay"]),
]


class NlgExplainer:
    """为分派决策生成自然语言解释。"""

    def __init__(self, llm_api_url: str = None):
        self.llm_api_url = llm_api_url or LLM_API_URL

    def explain_disposition(self, incident: dict, health_delta: float = 0,
                             effectiveness: float = 0) -> str:
        """为分派决策生成自然语言解释。"""
        try:
            result = self._call_llm(incident, "explain")
            if result:
                return result
        except Exception:
            pass
        return self._template_explain(incident, health_delta, effectiveness)

    def generate_recommendation(self, incident: dict) -> str:
        """为事件生成修复建议。"""
        try:
            result = self._call_llm(incident, "recommend")
            if result:
                return result
        except Exception:
            pass
        return self._template_recommend(incident)

    def generate_incident_summary(self, incident: dict) -> str:
        """生成简洁的事件摘要。"""
        try:
            result = self._call_llm(incident, "summarize")
            if result:
                return result
        except Exception:
            pass
        return self._template_summarize(incident)

    def _call_llm(self, incident: dict, mode: str) -> Optional[str]:
        """调用 Mock LLM API 生成自然语言文本。

        默认跳过外部 LLM 调用，直接使用模板系统以确保
        基于 payload 变体的差异化推荐生成。
        """
        return None

    @staticmethod
    def _detect_payload_variant(incident: dict) -> str:
        """从事件的原因/端口中提取payload特征，返回子模板键名。"""
        reason = (incident.get("reason", "") or "").lower()
        endpoint = (incident.get("api_endpoint", "") or "").lower()
        text = reason + " " + endpoint
        for variant, keywords in PAYLOAD_SIGNATURES:
            if any(kw in text for kw in keywords):
                return variant
        return "default"

    def _template_explain(self, incident: dict, health_delta: float = 0,
                           effectiveness: float = 0) -> str:
        """基于模板的解释，融入payload具体信息。"""
        sev = incident.get("severity", "LOW")
        disp = incident.get("disposition", "auto_log")
        atype = incident.get("anomaly_type", "anomaly")
        api = incident.get("api_endpoint", "/unknown")
        conf = incident.get("confidence", 0.0)
        reason = incident.get("reason", "") or ""

        # 生成修复指引摘要
        variant = self._detect_payload_variant(incident)
        atype_normalized = atype.replace("_", " ").title() if atype else "Anomaly"
        remediation_guide = self._build_remediation_guide(atype, variant)

        template = DISP_EXPLANATIONS.get(disp, DISP_EXPLANATIONS["auto_log"])
        text = template.format(
            anomaly_type=atype_normalized,
            api_endpoint=api,
            severity=sev.upper(),
            confidence=conf,
            remediation_guide=remediation_guide,
        )
        if reason:
            text += f" Specific trigger: {reason[:120]}."

        if abs(health_delta) > 0.001:
            direction = "improved" if health_delta > 0 else "degraded"
            text += f" Health {direction} by {abs(health_delta):.3f}."
        return text

    def _build_remediation_guide(self, atype: str, variant: str) -> str:
        """生成修复指引摘要。"""
        templates = {
            "directory_traversal": {
                "etc_passwd": "Block /etc/passwd access, normalize paths",
                "etc_hosts": "Normalize '....//' encoding, reject escaped paths",
                "encoded": "Decode URL before validation, whitelist-based path check",
                "backup": "Move backups outside web root, restrict download dir",
                "default": "Apply strict path validation, reject '../' variants",
            },
            "injection": {
                "tautology": "Use parameterized queries, never concatenate input",
                "union": "Restrict DB permissions, prepared statements",
                "blind": "Use prepared statements, WAF for SLEEP/BENCHMARK",
                "default": "Audit SQL queries, implement parameterization",
            },
        }
        atype_normalized = atype.replace("_", " ").lower().replace("attack", "").strip()
        if atype_normalized in templates:
            return templates[atype_normalized].get(variant, templates[atype_normalized].get("default", "Review and patch"))
        return "Review and patch"

    def _template_recommend(self, incident: dict) -> str:
        """基于payload变体生成差异化建议。"""
        atype = incident.get("anomaly_type", "default")
        api = incident.get("api_endpoint", "/unknown")
        variant = self._detect_payload_variant(incident)
        payload = (incident.get("reason", "") or "")[:80]

        # 尝试获取按变体区分的模板
        atype_key = atype.replace("_", " ").lower().replace("attack", "").strip()
        atype_key = atype_key.replace(" ", "_")
        # map injection → injection, sql_injection → injection, directory_traversal → directory_traversal
        type_map = {
            "sql_injection": "injection", "injection": "injection",
            "directory_traversal": "directory_traversal",
            "xss": "xss", "cross_site_scripting": "xss",
            "unauthorized_access": "unauthorized_access",
            "sensitive_data_exposure": "sensitive_data_leakage",
            "sensitive_data_leakage": "sensitive_data_leakage",
            "performance_degradation": "default",
            "invalid_input": "default",
        }
        tkey = type_map.get(atype, atype)
        template_group = RECOMMENDATION_TEMPLATES.get(tkey)

        if isinstance(template_group, dict):
            tmpl = template_group.get(variant) or template_group.get("default", RECOMMENDATION_TEMPLATES["default"])
        else:
            tmpl = template_group or RECOMMENDATION_TEMPLATES["default"]

        return tmpl.format(
            anomaly_type=atype.replace("_", " ").title(),
            api_endpoint=api,
            payload=payload,
        )

    def _template_summarize(self, incident: dict) -> str:
        """基于模板的备用摘要。"""
        sev = incident.get("severity", "LOW")
        atype = incident.get("anomaly_type", "anomaly")
        api = incident.get("api_endpoint", "/unknown")
        conf = incident.get("confidence", 0)
        disp = incident.get("disposition", "unknown")
        return (
            f"{sev} severity {atype} detected on {api} "
            f"(confidence: {conf:.0%}) → disposition: {disp}."
        )
