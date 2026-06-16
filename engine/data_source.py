#!/usr/bin/env python3
"""多源安全数据接入适配器。

将 WAF/IDS/API 网关三类数据源统一接入主检测流水线。

设计思路：
  每个数据源实现一个 Connector 子类，负责连接/鉴权/拉取。
  Normalizer 负责将各数据源特有格式映射为统一内部 Schema。
  DataSourceManager 负责任务调度与统一读取接口。
"""

import abc
import csv
import json
import os
import time
from datetime import datetime, timedelta
from typing import Any
from collections import defaultdict


# ═══════════════════════════════════════════════════════
#  统一内部 Schema
# ═══════════════════════════════════════════════════════

INTERNAL_SCHEMA = {
    "timestamp":      "",       # ISO8601 时间戳
    "source_ip":      "",       # 请求来源 IP
    "method":         "",       # GET/POST/PUT/DELETE
    "path":           "",       # URL 路径
    "status":         0,        # HTTP 状态码
    "user_agent":     "",       # User-Agent 头部
    "request_body":   "",       # 请求体（前 1000 字符）
    "response_body":  "",       # 响应体（前 1000 字符）
    "latency_ms":     0,        # 响应延迟(ms)
    "severity":       "",       # 告警级别（WAF/IDS）
    "rule_id":        "",       # 触发的规则 ID（WAF/IDS）
    "alert_type":     "",       # 告警类型
    "session_id":     "",       # 会话标识
    "source_type":    "",       # 数据来源：waf/ids/api_gateway
    "raw":            {},       # 原始记录全文
}


# ═══════════════════════════════════════════════════════
#  数据源连接器基类
# ═══════════════════════════════════════════════════════

class BaseConnector(abc.ABC):
    """数据源连接器抽象基类。"""

    def __init__(self, name: str, config: dict):
        self.name = name
        self.config = config
        self._connected = False

    @abc.abstractmethod
    def connect(self) -> bool:
        """建立与数据源的连接。"""

    @abc.abstractmethod
    def fetch(self, since: datetime = None, limit: int = 1000) -> list[dict]:
        """拉取数据，返回原始记录列表。"""

    @abc.abstractmethod
    def normalize(self, raw: dict) -> dict:
        """将原始记录映射为 INTERNAL_SCHEMA。"""

    def disconnect(self):
        self._connected = False


# ═══════════════════════════════════════════════════════
#  WAF 连接器（Web 应用防火墙）
# ═══════════════════════════════════════════════════════

class WafConnector(BaseConnector):
    """WAF 数据源接入（示例：ModSecurity / AWS WAF / 阿里云WAF 日志）。"""

    def connect(self) -> bool:
        # 真实环境：初始化 SDK 客户端/数据库连接/日志文件监控
        self._connected = True
        return True

    def fetch(self, since=None, limit=1000) -> list[dict]:
        if not self._connected:
            self.connect()
        # 模拟 WAF 日志 — 复用 IP 池使 session 拼接有效
        ip_pool = [f"10.0.{i}.{j}" for i in range(5) for j in range(1, 11)]
        ua_pool = ["Mozilla/5.0 Chrome/120", "Mozilla/5.0 Firefox/118",
                    "curl/7.88.1", "python-requests/2.31.0"]
        logs = []
        base = since or datetime.now() - timedelta(hours=1)
        for i in range(limit):
            ts = base + timedelta(seconds=i * 5)
            ip = ip_pool[i % len(ip_pool)]
            logs.append({
                "timestamp": ts.isoformat(),
                "client_ip": ip,
                "method": "GET" if i % 3 != 0 else "POST",
                "uri": ["/api/products", "/api/login", "/admin/config",
                        "/api/search?q=../etc/passwd", "/api/items/1' OR 1=1--"][i % 5],
                "status": [200, 200, 403, 403, 500][i % 5],
                "action": ["ALLOW", "ALLOW", "BLOCK", "BLOCK", "ALERT"][i % 5],
                "rule_id": ["", "", "942100", "933210", "941100"][i % 5],
                "severity": ["INFO", "INFO", "CRITICAL", "HIGH", "MEDIUM"][i % 5],
                "user_agent": ua_pool[i % len(ua_pool)],
                "request_body": "",
            })
        return logs

    def normalize(self, raw: dict) -> dict:
        return {
            "timestamp": raw.get("timestamp", ""),
            "source_ip": raw.get("client_ip", ""),
            "method": raw.get("method", "GET"),
            "path": raw.get("uri", ""),
            "status": raw.get("status", 0),
            "user_agent": raw.get("user_agent", ""),
            "request_body": raw.get("request_body", ""),
            "response_body": "",
            "latency_ms": 0,
            "severity": raw.get("severity", ""),
            "rule_id": raw.get("rule_id", ""),
            "alert_type": raw.get("action", ""),
            "session_id": f"waf_{hash(raw.get('client_ip', '')) & 0xffffffff:08x}",
            "source_type": "waf",
            "raw": raw,
        }


# ═══════════════════════════════════════════════════════
#  IDS 连接器（入侵检测系统）
# ═══════════════════════════════════════════════════════

class IdsConnector(BaseConnector):
    """IDS 数据源接入（示例：Snort / Suricata / Zeek）。"""

    def connect(self) -> bool:
        self._connected = True
        return True

    def fetch(self, since=None, limit=1000) -> list[dict]:
        logs = []
        base = since or datetime.now() - timedelta(hours=1)
        sig_pool = [
            ("ET WEB_SERVER SQLI", "injection", "HIGH"),
            ("ET XSS Cross-Site Scripting", "xss", "HIGH"),
            ("ET DIR_TRAVERSAL", "directory_traversal", "MEDIUM"),
            ("ET POLICY Sensitive Data", "sensitive_data", "LOW"),
            ("ET WEB_SERVER 403 Forbidden", "unauthorized", "MEDIUM"),
        ]
        ip_pool = [f"10.0.{i}.{j}" for i in range(5) for j in range(1, 11)]
        for i in range(limit):
            ts = base + timedelta(seconds=i * 30)
            sig, atype, sev = sig_pool[i % len(sig_pool)]
            ip = ip_pool[i % len(ip_pool)]
            logs.append({
                "timestamp": ts.isoformat(),
                "src_ip": ip,
                "dst_ip": "10.0.0.1",
                "dst_port": 443,
                "protocol": "TCP",
                "signature": sig,
                "alert_type": atype,
                "severity": sev,
                "uri": f"/api/items/{i % 100}",
                "http_method": "GET",
                "http_user_agent": "curl/7.88.1" if i % 5 == 0 else "Mozilla/5.0",
            })
        return logs

    def normalize(self, raw: dict) -> dict:
        return {
            "timestamp": raw.get("timestamp", ""),
            "source_ip": raw.get("src_ip", ""),
            "method": raw.get("http_method", "GET"),
            "path": raw.get("uri", ""),
            "status": 403 if raw.get("severity") == "HIGH" else 200,
            "user_agent": raw.get("http_user_agent", ""),
            "request_body": "",
            "response_body": "",
            "latency_ms": 0,
            "severity": raw.get("severity", ""),
            "rule_id": raw.get("signature", ""),
            "alert_type": raw.get("alert_type", ""),
            "session_id": f"ids_{hash(raw.get('src_ip', '')) & 0xffffffff:08x}",
            "source_type": "ids",
            "raw": raw,
        }


# ═══════════════════════════════════════════════════════
#  API 网关连接器
# ═══════════════════════════════════════════════════════

class ApiGatewayConnector(BaseConnector):
    """API 网关数据源接入（示例：Kong / APISIX / AWS API Gateway）。"""

    def connect(self) -> bool:
        self._connected = True
        return True

    def fetch(self, since=None, limit=1000) -> list[dict]:
        logs = []
        base = since or datetime.now() - timedelta(hours=1)
        paths = [
            "/api/products", "/api/items/1", "/api/login",
            "/api/comments?page=3", "/api/profile",
            "/admin/users", "/api/payments",
        ]
        ip_pool = [f"10.0.{i}.{j}" for i in range(5) for j in range(1, 11)]
        ua_pool = ["Mozilla/5.0 Chrome/120", "python-requests/2.31.0"]
        for i in range(limit):
            ts = base + timedelta(milliseconds=i * 500)
            path = paths[i % len(paths)]
            latencies = [15, 23, 8, 45, 12, 120, 89, 34, 200, 5]
            ip = ip_pool[i % len(ip_pool)]
            logs.append({
                "request_time": ts.isoformat(),
                "client_ip": ip,
                "request_method": "POST" if "login" in path else "GET",
                "request_uri": path,
                "status_code": 200 if i % 10 != 9 else 500,
                "response_time_ms": latencies[i % len(latencies)],
                "user_agent": ua_pool[i % len(ua_pool)],
                "request_body": "",
                "response_body": "",
                "api_key": f"ak_{i % 5}",
                "upstream_addr": f"10.0.1.{i % 10 + 1}:8080",
            })
        return logs

    def normalize(self, raw: dict) -> dict:
        return {
            "timestamp": raw.get("request_time", ""),
            "source_ip": raw.get("client_ip", ""),
            "method": raw.get("request_method", "GET"),
            "path": raw.get("request_uri", ""),
            "status": raw.get("status_code", 0),
            "user_agent": raw.get("user_agent", ""),
            "request_body": raw.get("request_body", ""),
            "response_body": raw.get("response_body", ""),
            "latency_ms": raw.get("response_time_ms", 0),
            "severity": "",
            "rule_id": "",
            "alert_type": "",
            "session_id": f"gw_{hash(raw.get('client_ip', '')) & 0xffffffff:08x}",
            "source_type": "api_gateway",
            "raw": raw,
        }


# ═══════════════════════════════════════════════════════
#  数据源管理器
# ═══════════════════════════════════════════════════════

class DataSourceManager:
    """多源数据接入管理器。

    用法:
        mgr = DataSourceManager({
            "waf": {"enabled": True, "type": "waf"},
            "ids": {"enabled": True, "type": "ids"},
            "api_gateway": {"enabled": True, "type": "api_gateway"},
        })
        records = mgr.collect(since=datetime.now()-timedelta(minutes=5))
    """

    CONNECTOR_MAP = {
        "waf": WafConnector,
        "ids": IdsConnector,
        "api_gateway": ApiGatewayConnector,
    }

    def __init__(self, sources_config: dict):
        self.connectors: dict[str, BaseConnector] = {}
        for name, cfg in sources_config.items():
            if cfg.get("enabled", True):
                connector_cls = self.CONNECTOR_MAP.get(cfg.get("type", name))
                if connector_cls:
                    self.connectors[name] = connector_cls(name, cfg)

    def collect(self, since: datetime = None, limit_per_source: int = 5000) -> list[dict]:
        """从所有已启用的数据源拉取并归一化数据。"""
        all_records = []
        for name, conn in self.connectors.items():
            try:
                raw_list = conn.fetch(since=since, limit=limit_per_source)
                normalized = [conn.normalize(r) for r in raw_list]
                print(f"[DataSource] {name}: {len(normalized)} 条")
                all_records.extend(normalized)
            except Exception as e:
                print(f"[DataSource] {name} 拉取失败: {e}")
        # 按时间排序
        all_records.sort(key=lambda r: r.get("timestamp", ""))
        return all_records

    def count_by_source(self, records: list[dict]) -> dict:
        counter = defaultdict(int)
        for r in records:
            counter[r.get("source_type", "unknown")] += 1
        return dict(counter)


# ═══════════════════════════════════════════════════════
#  快速演示
# ═══════════════════════════════════════════════════════

def demo():
    print("=" * 60)
    print("  三类安全数据源接入演示")
    print("=" * 60)

    mgr = DataSourceManager({
        "waf": {"enabled": True, "type": "waf"},
        "ids": {"enabled": True, "type": "ids"},
        "api_gateway": {"enabled": True, "type": "api_gateway"},
    })

    records = mgr.collect(limit_per_source=5)
    print(f"\n总记录: {len(records)}")
    print(f"来源分布: {mgr.count_by_source(records)}")

    # 展示各来源的一条示例
    for st in ["waf", "ids", "api_gateway"]:
        sample = next((r for r in records if r["source_type"] == st), None)
        if sample:
            print(f"\n--- {st} 归一化示例 ---")
            for k in ["timestamp", "source_ip", "method", "path", "status",
                       "severity", "rule_id", "alert_type", "session_id"]:
                print(f"  {k}: {sample.get(k, '')}")


if __name__ == "__main__":
    demo()
