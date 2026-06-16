"""特征工程：从原始流量记录中提取用于恶意爬虫分类的行为特征。

为保持与主项目 llm_api_analyze/ 模块的兼容性，特征以 DataFrame 形式组织。"""

import math
import statistics
from collections import Counter, defaultdict
from datetime import datetime


# ── 时间窗口常量 ────────────────────────────────────

WINDOWS_SEC = [1, 5, 30, 60, 300]  # 各时间窗口（秒）


# ── 单会话特征提取 ──────────────────────────────────


def extract_session_features(records: list[dict]) -> dict:
    """从同一个 session 的所有请求中提取行为特征。

    Args:
        records: 同一 session_id 的请求记录（按时间升序）

    Returns:
        特征字典
    """
    if not records:
        return {}

    session_id = records[0].get("session_id", "unknown")
    timestamps = []
    paths = []
    methods = []
    statuses = []
    agents = []

    for r in records:
        # 解析时间戳
        ts_str = r.get("timestamp", "")
        try:
            ts = datetime.fromisoformat(ts_str).timestamp()
        except (ValueError, TypeError):
            continue
        timestamps.append(ts)
        paths.append(r.get("path", ""))
        methods.append(r.get("method", "GET"))
        statuses.append(r.get("status", 200))
        agents.append(r.get("user_agent", ""))

    n = len(timestamps)
    if n < 2:
        return {"session_id": session_id, "request_count": n, "feature_valid": False}

    # ── 基础统计 ──
    duration = timestamps[-1] - timestamps[0]
    intervals = [timestamps[i] - timestamps[i - 1] for i in range(1, n)]
    avg_interval = statistics.mean(intervals) if intervals else 0
    min_interval = min(intervals) if intervals else 0

    # ── 速率特征 ──
    requests_per_second = n / duration if duration > 0 else n

    # ── 路径特征 ──
    path_counter = Counter(paths)
    unique_paths = len(path_counter)
    path_repetition_rate = 1 - (unique_paths / n) if n > 0 else 0
    most_common_path, most_common_count = path_counter.most_common(1)[0] if path_counter else ("", 0)
    path_concentration = most_common_count / n  # 单一路径集中度

    # ── 敏感路径访问 ──
    sensitive_keywords = ["admin", "payment", "export", "backup", "config"]
    sensitive_count = sum(1 for p in paths if any(k in p.lower() for k in sensitive_keywords))
    sensitive_ratio = sensitive_count / n

    # ── 状态码特征 ──
    status_counter = Counter(statuses)
    error_4xx = sum(v for k, v in status_counter.items() if 400 <= k < 500)
    error_5xx = sum(v for k, v in status_counter.items() if 500 <= k < 600)
    error_rate = (error_4xx + error_5xx) / n
    auth_fail_count = status_counter.get(401, 0) + status_counter.get(403, 0)

    # ── 方法特征 ──
    method_counter = Counter(methods)
    post_ratio = method_counter.get("POST", 0) / n

    # ── 时间窗口密度 ──
    def requests_in_window(sec: int) -> float:
        """计算滑动窗口最大请求数，返回窗口内最大密度。"""
        max_count = 0
        left = 0
        for right in range(n):
            while timestamps[right] - timestamps[left] > sec:
                left += 1
            max_count = max(max_count, right - left + 1)
        return max_count / sec if sec > 0 else 0

    peak_rps_1s = requests_in_window(1)
    peak_rps_5s = requests_in_window(5)

    # ── 周期性检测（相邻相同路径的模式） ──
    consecutive_duplicates = 0
    max_consecutive = 0
    for i in range(1, n):
        if paths[i] == paths[i - 1]:
            consecutive_duplicates += 1
            max_consecutive = max(max_consecutive, consecutive_duplicates)
        else:
            consecutive_duplicates = 0

    # ── UA 识别 ──
    known_crawler = 0
    suspicious_ua = 0
    for a in agents:
        a_lower = a.lower()
        if any(kw in a_lower for kw in ["googlebot", "bingbot", "baiduspider", "duckduckbot"]):
            known_crawler += 1
        elif any(kw in a_lower for kw in ["python-requests", "curl/", "scrapy", "go-http",
                                            "okhttp", "apache-httpclient", "mj12bot", "customscraper"]):
            suspicious_ua += 1

    features = {
        "session_id": session_id,
        "request_count": n,
        "duration_sec": round(duration, 2),
        "avg_interval_sec": round(avg_interval, 3),
        "min_interval_ms": round(min_interval * 1000, 1),
        "requests_per_second": round(requests_per_second, 3),
        "unique_paths": unique_paths,
        "path_diversity_ratio": round(unique_paths / n, 4) if n > 0 else 0,
        "path_repetition_rate": round(path_repetition_rate, 4),
        "path_concentration": round(path_concentration, 4),
        "sensitive_path_ratio": round(sensitive_ratio, 4),
        "error_rate": round(error_rate, 4),
        "auth_fail_count": auth_fail_count,
        "post_ratio": round(post_ratio, 4),
        "peak_rps_1s": round(peak_rps_1s, 3),
        "peak_rps_5s": round(peak_rps_5s, 3),
        "max_consecutive_same_path": max_consecutive,
        "known_crawler_ua_ratio": round(known_crawler / n, 4) if n > 0 else 0,
        "suspicious_ua_ratio": round(suspicious_ua / n, 4) if n > 0 else 0,
        "feature_valid": True,
    }
    return features


# ── 批量特征提取 ────────────────────────────────────


def extract_all_features(records: list[dict]) -> list[dict]:
    """按 session_id 分组后，为每个会话提取特征。"""
    sessions: dict[str, list[dict]] = defaultdict(list)
    for r in records:
        sessions[r.get("session_id", "unknown")].append(r)

    # 每组内按时间排序
    features = []
    for sid, recs in sessions.items():
        recs.sort(key=lambda x: x.get("timestamp", ""))
        feats = extract_session_features(recs)
        if feats.get("feature_valid"):
            # 记录真实标签
            labels = set(r.get("category", "") for r in recs)
            feats["true_category"] = labels.pop() if len(labels) == 1 else "mixed"
            features.append(feats)

    return features


def features_to_matrix(features: list[dict]) -> tuple[list, list, list]:
    """将特征列表转为 (X, y, session_ids) 矩阵。

    排除非数值字段，二分类标签：malicious_crawler=1，其他=0。
    """
    exclude = {"session_id", "true_category", "feature_valid"}
    feature_names = [k for k in features[0].keys() if k not in exclude]

    X = []
    y = []
    ids = []
    for f in features:
        row = [f.get(k, 0) for k in feature_names]
        X.append(row)
        y.append(1 if f.get("true_category") == "malicious_crawler" else 0)
        ids.append(f.get("session_id", ""))

    return X, y, feature_names, ids
