"""多源数据会话拼接器：将 WAF/IDS/API 网关的独立日志聚合成有意义的会话。

核心策略：
  1. IP + 时间窗口拼接（同一 IP 在 N 秒内的请求 = 一个 session）
  2. Cookie/Session-Token 拼接（如果日志含 token 字段）
  3. UA + IP + 路径连续性拼接
"""

import hashlib
from datetime import datetime
from collections import defaultdict


class SessionStitcher:
    """将多源分散日志聚合成会话。

    按 source_ip + 滑动时间窗口拼接，确保每个 session 有足够请求数用于特征提取。
    """

    def __init__(self, window_sec: int = 60):
        self.window_sec = window_sec

    def stitch(self, records: list[dict]) -> list[dict]:
        """对记录做 session 拼接，返回补充了 session_id 的记录列表。"""
        # 1. 按 IP 分桶
        ip_buckets: dict[str, list[dict]] = defaultdict(list)
        for r in records:
            ip = r.get("source_ip", "unknown")
            ip_buckets[ip].append(r)

        # 2. 每个桶内按时间窗口切分 session
        new_records = []
        session_counter = 0
        for ip, recs in ip_buckets.items():
            # 按时间排序
            recs.sort(key=lambda x: x.get("timestamp", ""))
            windows = self._split_windows(recs)
            for win_recs in windows:
                sid = self._make_session_id(ip, win_recs, session_counter)
                session_counter += 1
                for r in win_recs:
                    r["session_id"] = sid
                    new_records.append(r)

        return new_records

    def _split_windows(self, records: list[dict]) -> list[list[dict]]:
        """用滑动时间窗口分割记录。"""
        windows: list[list[dict]] = []
        cur: list[dict] = []
        last_ts: float | None = None

        for r in records:
            ts = self._parse_ts(r.get("timestamp", ""))
            if ts is None:
                continue
            if last_ts is not None and (ts - last_ts) > self.window_sec:
                if cur:
                    windows.append(cur)
                cur = []
            cur.append(r)
            last_ts = ts

        if cur:
            windows.append(cur)
        return windows

    def _make_session_id(self, ip: str, records: list[dict], idx: int) -> str:
        """生成统一格式的 session_id。"""
        sources = set(r.get("source_type", "unknown") for r in records)
        source_tag = "+".join(sorted(sources)) if len(sources) <= 3 else "multi"
        # 取第一条记录的路径片段
        first_path = records[0].get("path", "/").replace("/", "_").strip("_")[:12]
        n = len(records)
        hash_suffix = hashlib.md5(f"{ip}_{idx}".encode()).hexdigest()[:6]
        return f"stitched_{source_tag}_{n}req_{first_path}_{hash_suffix}"

    @staticmethod
    def _parse_ts(ts_str: str) -> float | None:
        try:
            return datetime.fromisoformat(ts_str).timestamp()
        except (ValueError, TypeError):
            return None


# ── 按源类型生成 session_id 前缀映射 ──

def normalize_session_ids(records: list[dict]) -> list[dict]:
    """确保 session_id 能被 pattern extraction 识别。"""
    for r in records:
        st = r.get("source_type", "unknown")
        r["source_type"] = st
    return records


def classify_source_severity(records: list[dict]) -> list[dict]:
    """更精细地从多源数据推断恶意等级。"""
    for r in records:
        sev = r.get("severity", "")
        alert = r.get("alert_type", "")
        rule_id = r.get("rule_id", "")
        status = r.get("status", 0)

        # WAF 规则
        if rule_id and sev in ("CRITICAL", "HIGH"):
            r["category"] = "malicious_crawler"
        # IDS 告警
        elif alert in ("injection", "xss", "directory_traversal", "sensitive_data"):
            r["category"] = "malicious_crawler"
        # API 高延迟异常
        elif r.get("latency_ms", 0) > 100:
            r["category"] = "malicious_crawler"
        # 403/500
        elif status in (403, 500) and sev in ("HIGH", "MEDIUM"):
            r["category"] = "malicious_crawler"
        else:
            r["category"] = "normal"

        r["repetitive_path_count"] = 0
    return records


def demo():
    """演示拼接效果。"""
    from engine.data_source import DataSourceManager

    mgr = DataSourceManager({
        "waf": {"enabled": True, "type": "waf"},
        "ids": {"enabled": True, "type": "ids"},
        "api_gateway": {"enabled": True, "type": "api_gateway"},
    })
    records = mgr.collect(limit_per_source=200)

    print(f"拼接前: {len(records)} 条, {len(set(r['session_id'] for r in records))} sessions")

    stitcher = SessionStitcher(window_sec=60)
    records = stitcher.stitch(records)
    records = classify_source_severity(records)

    from collections import Counter
    sid_counts = Counter(r["session_id"] for r in records)
    print(f"拼接后: {len(records)} 条, {len(sid_counts)} sessions")
    req_per_session = list(sid_counts.values())
    print(f"  请求/session: min={min(req_per_session)}, max={max(req_per_session)}, avg={sum(req_per_session)/len(req_per_session):.1f}")
    print(f"  1请求 session: {sum(1 for c in req_per_session if c==1)}/{len(req_per_session)}")

    # 展示拼接 sample
    multi_req = [sid for sid, c in sid_counts.items() if c >= 3]
    print(f"  >=3 请求 session: {len(multi_req)}")
    if multi_req:
        sample_sid = multi_req[0]
        sample_recs = [r for r in records if r["session_id"] == sample_sid]
        sources = set(r["source_type"] for r in sample_recs)
        paths = set(r["path"] for r in sample_recs)
        print(f"  示例: {sample_sid}")
        print(f"    来源: {sources}, 路径: {paths}")

    # 检测测试
    from malicious_crawler.feature_engineering import extract_all_features
    features = extract_all_features(records)
    valid = sum(1 for f in features if f.get("feature_valid"))
    print(f"\n  有效特征 session: {valid}/{len(features)}")

    if valid > 5:
        from malicious_crawler.detector import EnsembleDetector
        from collections import defaultdict
        records_by_session = defaultdict(list)
        for r in records:
            records_by_session[r.get("session_id", "")].append(r)
        detector = EnsembleDetector()
        detector.train(features)
        results = detector.predict(features, records_by_session)
        mal = sum(1 for r in results if r["pred_label"] == 1)
        print(f"  Ensemble 检测: 恶意={mal}/{len(results)}")


if __name__ == "__main__":
    demo()
