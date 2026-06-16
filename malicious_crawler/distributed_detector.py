"""分布式爬虫与众包爬虫检测器。

三层检测：
  Layer 1: 时序关联分析（滑动窗口共现图）
  Layer 2: 资源覆盖分析（覆盖熵 + 系统性评分）
  Layer 3: 网络拓扑聚类（ASN/IP段聚集度）

融合评分 → 判定分布式/众包爬虫。
"""

import math
import statistics
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any


# ── 配置 ────────────────────────────────────────────

CO_ACCESS_WINDOW_SEC = 5       # 时序共现窗口
EDGE_WEIGHT_THRESHOLD = 1      # 共现图边权重阈值（≥1 即算关联）
MIN_CLUSTER_SIZE = 3           # 最小协同簇规模（≥3 个节点）
COVERAGE_ENTROPY_THRESHOLD = 0.75  # 覆盖熵阈值（高于此值 = 可疑的低有序度 → 实际低于此值 = 系统性爬虫）
ASN_CONCENTRATION_THRESHOLD = 0.5  # ASN 集中度阈值

# 融合权重
W_TEMPORAL = 0.35
W_COVERAGE = 0.35
W_NETWORK = 0.30


# ============================================================
#  Layer 1: 时序关联分析
# ============================================================


class TemporalCorrelationAnalyzer:
    """滑动窗口共现图 + Louvain 社区发现。"""

    def analyze(self, records: list[dict]) -> dict:
        """分析所有记录，返回时序关联结果。

        Returns:
            { "clusters": [[sid1, sid2, ...], ...],
              "cluster_map": {sid: cluster_id},
              "co_access_scores": {sid: score},
              "stats": {...} }
        """
        # 1. 时间离散化为窗口
        windows = self._discretize(records, CO_ACCESS_WINDOW_SEC)

        # 2. 构建共现图
        edges: dict[tuple[str, str], int] = defaultdict(int)
        session_paths: dict[str, set] = defaultdict(set)
        session_times: dict[str, list[float]] = defaultdict(list)

        for win_records in windows:
            sids = list({r.get("session_id", "") for r in win_records})
            for i in range(len(sids)):
                for j in range(i + 1, len(sids)):
                    a, b = sids[i], sids[j]
                    if a and b:
                        key = tuple(sorted([a, b]))
                        edges[key] += 1
            for r in win_records:
                sid = r.get("session_id", "")
                session_paths[sid].add(r.get("path", ""))
                ts = self._parse_ts(r.get("timestamp", ""))
                if ts:
                    session_times[sid].append(ts)

        # 3. 社区发现（Connected Components）
        adj: dict[str, set] = defaultdict(set)
        for (a, b), w in edges.items():
            if w >= EDGE_WEIGHT_THRESHOLD:  # 共现至少 N 次才算强关联
                adj[a].add(b)
                adj[b].add(a)

        clusters = self._find_connected_components(adj)

        cluster_map: dict[str, int] = {}
        for cid, members in enumerate(clusters):
            for m in members:
                cluster_map[m] = cid

        # 4. 每个 session 的时序关联度评分
        co_access_scores: dict[str, float] = {}
        for sid, paths in session_paths.items():
            if sid not in cluster_map:
                co_access_scores[sid] = 0.0
                continue
            cid = cluster_map[sid]
            cluster_members = clusters[cid]
            if len(cluster_members) < 2:
                co_access_scores[sid] = 0.0
                continue

            # 与该 session 共现的 peer 数量占比
            peers = [m for m in cluster_members if m != sid]
            peer_edges = sum(1 for p in peers if tuple(sorted([sid, p])) in edges)
            peer_ratio = peer_edges / len(peers) if peers else 0

            # 路径相似度
            peer_path_sim = 0.0
            for p in peers[:10]:
                jaccard = self._jaccard(paths, session_paths.get(p, set()))
                peer_path_sim += jaccard
            peer_path_sim = peer_path_sim / min(len(peers), 10) if peers else 0

            co_access_scores[sid] = round((peer_ratio + peer_path_sim) / 2, 4)

        n_clusters = len(clusters)
        sessions_in_clusters = sum(len(c) for c in clusters)

        return {
            "clusters": [list(c) for c in clusters],
            "cluster_map": cluster_map,
            "co_access_scores": co_access_scores,
            "stats": {
                "total_clusters": n_clusters,
                "sessions_in_clusters": sessions_in_clusters,
                "largest_cluster": max(len(c) for c in clusters) if clusters else 0,
            },
        }

    def _discretize(self, records: list[dict], window_sec: int) -> list[list[dict]]:
        """按滑动窗口切分时间线。"""
        timed = []
        for r in records:
            ts = self._parse_ts(r.get("timestamp", ""))
            if ts:
                timed.append((ts, r))
        timed.sort(key=lambda x: x[0])

        if not timed:
            return []

        windows: list[list[dict]] = []
        start_ts = timed[0][0]
        cur: list[dict] = []
        for ts, r in timed:
            if ts - start_ts > window_sec:
                if cur:
                    windows.append(cur)
                cur = []
                start_ts = ts
            cur.append(r)
        if cur:
            windows.append(cur)

        return windows

    def _parse_ts(self, ts_str: str) -> float | None:
        try:
            return datetime.fromisoformat(ts_str).timestamp()
        except (ValueError, TypeError):
            return None

    def _find_connected_components(self, adj: dict[str, set]) -> list[set]:
        visited: set[str] = set()
        components: list[set] = []
        for node in adj:
            if node not in visited:
                stack = [node]
                comp: set[str] = set()
                while stack:
                    n = stack.pop()
                    if n not in visited:
                        visited.add(n)
                        comp.add(n)
                        stack.extend(adj.get(n, set()) - visited)
                if len(comp) >= MIN_CLUSTER_SIZE:
                    components.append(comp)
        return components

    @staticmethod
    def _jaccard(a: set, b: set) -> float:
        if not a and not b:
            return 0.0
        return len(a & b) / len(a | b)


# ============================================================
#  Layer 2: 资源覆盖分析
# ============================================================


class CoverageAnalyzer:
    """分析多个 session 对目标资源的覆盖系统性。"""

    def analyze(self, records: list[dict],
                session_ids: list[str] | None = None) -> dict:
        """分析资源覆盖的系统性和完整性。

        Returns:
            { "coverage_completeness": float,
              "coverage_entropy": float,
              "sequential_score": float,
              "idle_session_ratio": float,
              "suspicious_coverage": bool }
        """
        # 按 session 分组
        session_paths: dict[str, set] = defaultdict(set)
        session_counts: dict[str, int] = defaultdict(int)
        for r in records:
            sid = r.get("session_id", "")
            session_paths[sid].add(r.get("path", ""))
            session_counts[sid] += 1

        if session_ids:
            target_sessions = [s for s in session_ids if s in session_paths]
        else:
            target_sessions = list(session_paths.keys())

        if len(target_sessions) < 2:
            return {
                "coverage_completeness": 0.0,
                "coverage_entropy": 1.0,
                "sequential_score": 0.0,
                "idle_session_ratio": 0.0,
                "suspicious_coverage": False,
            }

        # 1. 合并所有路径
        all_paths: set[str] = set()
        for sid in target_sessions:
            all_paths |= session_paths[sid]
        total_resources = len(all_paths)

        # 2. 路径频次分布 → 覆盖熵
        path_freq: Counter[str] = Counter()
        for sid in target_sessions:
            for p in session_paths[sid]:
                path_freq[p] += 1

        total_hits = sum(path_freq.values())
        entropy = 0.0
        if total_hits > 0:
            for freq in path_freq.values():
                p = freq / total_hits
                if p > 0:
                    entropy -= p * math.log2(p)
        max_entropy = math.log2(len(path_freq)) if path_freq else 1
        normalized_entropy = entropy / max_entropy if max_entropy > 0 else 1.0

        # 3. 覆盖完整度
        #    推断目标资源空间大小（从 URL 模式推测分页/ID 序列）
        resource_patterns = self._infer_resource_patterns(all_paths)
        estimated_total = 0
        for pattern_name, (matched, sample) in resource_patterns.items():
            estimated_total += sample

        coverage_completeness = 0.0
        if estimated_total > 0:
            coverage_completeness = min(1.0, total_resources / estimated_total)

        # 4. 顺序性评分（访问是否按自然序列）
        sequential_score = self._compute_sequential_score(
            session_paths, target_sessions, resource_patterns
        )

        # 5. 单次会话比例
        idle_count = sum(1 for sid in target_sessions if session_counts.get(sid, 0) <= 2)
        idle_ratio = idle_count / len(target_sessions)

        # 6. 总体判定 — 两种模式
        # 模式 A: 低熵系统性覆盖（分布式爬虫，多个节点访问相同资源）
        # 模式 B: 高完整性覆盖（众包爬虫，每个节点访问少量不同资源，合起来完整覆盖）
        is_systematic_low_entropy = (
            normalized_entropy < COVERAGE_ENTROPY_THRESHOLD
            and idle_ratio > 0.3
        )
        is_fragmented_coverage = (
            total_resources >= 5
            and coverage_completeness > 0.5
            and idle_ratio > 0.3
        )

        return {
            "coverage_completeness": round(coverage_completeness, 4),
            "coverage_entropy": round(normalized_entropy, 4),
            "sequential_score": round(sequential_score, 4),
            "idle_session_ratio": round(idle_ratio, 4),
            "suspicious_coverage": is_systematic_low_entropy or is_fragmented_coverage,
            "suspicious_low_entropy": is_systematic_low_entropy,
            "suspicious_fragmented": is_fragmented_coverage,
            "total_unique_paths": total_resources,
            "estimated_resource_space": estimated_total,
        }

    def _infer_resource_patterns(self, paths: set[str]) -> dict[str, tuple[int, int]]:
        """推断资源模式，返回 {pattern_name: (matched_count, estimated_total)}。

        识别模式如 /api/items/{id}, /api/comments?page={n} 等。
        """
        import re
        patterns: dict[str, tuple[set, set]] = {}

        for p in paths:
            # 数字 ID 模式: /api/items/123
            m = re.match(r"^(/.+?)/(\d+)$", p)
            if m:
                base = m.group(1)
                val = int(m.group(2))
                if base not in patterns:
                    patterns[base] = (set(), set())
                patterns[base][0].add(p)
                patterns[base][1].add(val)
                continue

            # 分页模式: /api/comments?page=3
            m = re.match(r"^(/.+?)\?.*page[=](\d+)", p)
            if m:
                base = m.group(1)
                val = int(m.group(2))
                key = f"{base}?page"
                if key not in patterns:
                    patterns[key] = (set(), set())
                patterns[key][0].add(p)
                patterns[key][1].add(val)

            # /api/product/{slug} 或固定路径
            key = f"static:{p}"
            if key not in patterns:
                patterns[key] = (set(), set())
            patterns[key][0].add(p)

        result: dict[str, tuple[int, int]] = {}
        for name, (matched_paths, values) in patterns.items():
            if values:
                # 有数字序列 → 估计总数 = max(observed) 或 max*1.2
                estimated = max(values) + 2
            else:
                estimated = len(matched_paths)
            result[name] = (len(matched_paths), estimated)

        return result

    def _compute_sequential_score(self, session_paths: dict[str, set],
                                    target_sessions: list[str],
                                    resource_patterns: dict) -> float:
        """评估整体访问的顺序性（高的顺序性 = 爬虫嫌疑）。

        如果大量 session 按照接近 ID 递增顺序访问资源，说明是系统性爬取。
        """
        import re
        sequential_count = 0
        total_check = 0

        for sid in target_sessions[:100]:  # 限制计算量
            paths = session_paths.get(sid, set())
            ids = []
            for p in paths:
                m = re.search(r"/(\d+)$", p)
                if m:
                    ids.append(int(m.group(1)))
            if len(ids) >= 2:
                total_check += 1
                # 检查是否单调递增
                if all(ids[i] < ids[i + 1] for i in range(len(ids) - 1)):
                    sequential_count += 1
                # 检查是否等差（如 page=1,2,3,4）
                elif len(ids) >= 3 and all(
                    ids[i + 1] - ids[i] == ids[1] - ids[0]
                    for i in range(1, len(ids) - 1)
                ):
                    sequential_count += 1

        return sequential_count / total_check if total_check > 0 else 0.0


# ============================================================
#  Layer 3: 网络拓扑聚类（模拟）
# ============================================================


class NetworkTopologyAnalyzer:
    """基于 IP/ASN 的网络拓扑聚集度分析。

    在模拟环境中，session_id 包含了模式信息（normal_xxx, legit_xxx,
    malicious_scraper_xxx 等），用于推断分布式程度。
    """

    def analyze(self, records: list[dict]) -> dict:
        """分析网络拓扑聚集度。

        真实环境应接入 IP → ASN/子网/机房标签 映射服务。
        当前模拟方案依据 session_id 命名规则推断分布式程度。
        """
        # 按 session 分组
        session_info: dict[str, dict] = defaultdict(lambda: {
            "paths": set(), "count": 0, "pattern": "unknown",
        })
        for r in records:
            sid = r.get("session_id", "")
            session_info[sid]["paths"].add(r.get("path", ""))
            session_info[sid]["count"] += 1
            # 从 session_id 推断模式（处理 credential_stuffer 多下划线情况）
            session_info[sid]["pattern"] = self._extract_pattern(sid)

        # 按模式分组
        pattern_groups: dict[str, list[str]] = defaultdict(list)
        for sid, info in session_info.items():
            pattern_groups[info["pattern"]].append(sid)

        # 路径相似度矩阵（同模式内）
        intra_pattern_scores: dict[str, float] = {}
        for pattern, sids in pattern_groups.items():
            if len(sids) < 2:
                intra_pattern_scores[pattern] = 0.0
                continue
            sims = []
            for i in range(min(len(sids), 20)):
                for j in range(i + 1, min(len(sids), 20)):
                    a = session_info[sids[i]]["paths"]
                    b = session_info[sids[j]]["paths"]
                    sims.append(self._jaccard(a, b))
            intra_pattern_scores[pattern] = (
                statistics.mean(sims) if sims else 0.0
            )

        # session 级网络聚集度评分
        network_scores: dict[str, float] = {}
        # 用于众包爬虫检测：单次短 session 的比例
        single_request_sessions = sum(
            1 for sid, info in session_info.items()
            if info["count"] <= 2 and "malicious" in sid
        )
        total_malicious = sum(
            1 for sid in session_info if "malicious" in sid
        )
        crowdsourced_ratio = (
            single_request_sessions / total_malicious
            if total_malicious > 0 else 0.0
        )

        for sid, info in session_info.items():
            pattern = info["pattern"]
            if pattern == "scraper":
                sim = intra_pattern_scores.get(pattern, 0)
                network_scores[sid] = round(min(1.0, sim * 1.5), 4)
            elif pattern == "ddos_tool":
                network_scores[sid] = 0.9
            elif pattern == "credential_stuffer":
                network_scores[sid] = 0.8
            elif pattern == "crowdsourced":
                network_scores[sid] = 0.15  # 众包 IP 分散，网络聚集度低
            elif pattern == "normal":
                network_scores[sid] = 0.1
            elif pattern == "legit":
                network_scores[sid] = 0.2
            else:
                network_scores[sid] = 0.0

        return {
            "network_scores": network_scores,
            "intra_pattern_similarities": dict(intra_pattern_scores),
            "crowdsourced_ratio": round(crowdsourced_ratio, 4),
            "pattern_distribution": {
                pat: len(sids) for pat, sids in pattern_groups.items()
            },
            "stats": {
                "total_sessions": len(session_info),
                "pattern_count": len(pattern_groups),
                "crowdsourced_flag": crowdsourced_ratio > 0.3,
            },
        }

    @staticmethod
    def _extract_pattern(sid: str) -> str:
        """从 session_id 提取模式类型，处理多下划线情形。"""
        if "crowdsourced" in sid:
            return "crowdsourced"
        if "credential_stuffer" in sid:
            return "credential_stuffer"
        if "ddos_tool" in sid:
            return "ddos_tool"
        if "scraper" in sid:
            return "scraper"
        if "normal" in sid:
            return "normal"
        if "legit" in sid:
            return "legit"
        return "unknown"

    @staticmethod
    def _jaccard(a: set, b: set) -> float:
        if not a and not b:
            return 0.0
        return len(a & b) / len(a | b) if a | b else 0.0


# ============================================================
#  融合评分引擎
# ============================================================


class DistributedCrawlerFusionEngine:
    """三层融合评分，判定分布式爬虫与众包爬虫。

    对每个推测的模式组分别做覆盖分析，解决混合全局分析的稀释问题。
    """

    def __init__(self):
        self.temporal = TemporalCorrelationAnalyzer()
        self.coverage = CoverageAnalyzer()
        self.network = NetworkTopologyAnalyzer()

    def analyze(self, records: list[dict]) -> dict:
        """全链路分析。"""
        # Layer 1: 时序关联
        temporal_result = self.temporal.analyze(records)

        # Layer 3: 网络拓扑（提取模式分组）
        network_result = self.network.analyze(records)
        pattern_dist = network_result.get("pattern_distribution", {})

        # ── 分模式组做覆盖分析 ──
        # 按 session_id 模式分组
        pattern_to_sids: dict[str, list[str]] = defaultdict(list)
        for r in records:
            sid = r.get("session_id", "")
            pat = NetworkTopologyAnalyzer._extract_pattern(sid)
            pattern_to_sids[pat].append(sid)
        for pat in pattern_to_sids:
            pattern_to_sids[pat] = list(set(pattern_to_sids[pat]))

        # 对每个显著的模式组单独做覆盖分析
        per_pattern_coverage: dict[str, dict] = {}
        for pat, sids in pattern_to_sids.items():
            if len(sids) >= 2:
                per_pattern_coverage[pat] = self.coverage.analyze(records, sids)

        # 对全部 session 做整体覆盖分析（作为 baseline）
        all_sids = list(set(r.get("session_id", "") for r in records))
        global_coverage = self.coverage.analyze(records, all_sids)

        # ── 融合评分 ──
        cluster_map = temporal_result.get("cluster_map", {})
        co_access_scores = temporal_result.get("co_access_scores", {})
        network_scores = network_result.get("network_scores", {})
        network_pattern_sims = network_result.get("intra_pattern_similarities", {})

        session_results: dict[str, dict] = {}
        for sid in all_sids:
            pat = NetworkTopologyAnalyzer._extract_pattern(sid)

            # Layer 1: 时序关联度
            t_score = co_access_scores.get(sid, 0.0)
            in_cluster = sid in cluster_map
            cluster_size = 0
            if in_cluster:
                cid = cluster_map[sid]
                cluster = temporal_result.get("clusters", [])
                if cid < len(cluster):
                    cluster_size = len(cluster[cid])
            temporal_score = t_score * (1.0 if in_cluster and cluster_size >= 3 else 0.3)

            # Layer 2: 覆盖系统性（使用该模式组的覆盖分析结果，fallback 到全局）
            cov = per_pattern_coverage.get(pat, global_coverage)
            cov_entropy = cov.get("coverage_entropy", 1.0)
            cov_suspicious = cov.get("suspicious_coverage", False)
            cov_fragmented = cov.get("suspicious_fragmented", False)
            cov_low_entropy = cov.get("suspicious_low_entropy", False)
            cov_idle = cov.get("idle_session_ratio", 0.0)
            cov_completeness = cov.get("coverage_completeness", 0.0)
            cov_sequential = cov.get("sequential_score", 0.0)

            coverage_score = max(
                0.0,
                (1 - cov_entropy) * (0.6 if cov_low_entropy else 0.2)
                + cov_completeness * 0.25
                + cov_sequential * 0.15,
            )

            # Layer 3: 网络聚集度
            n_score = network_scores.get(sid, 0.0)

            # 融合
            fusion = (
                W_TEMPORAL * temporal_score
                + W_COVERAGE * coverage_score
                + W_NETWORK * n_score
            )

            # ── 判定逻辑 ──
            # 众包爬虫：模式=crowdsourced + 碎片化覆盖（高完整但高熵）+ 低网络分
            is_crowdsourced_candidate = (
                pat == "crowdsourced"
                and cov_fragmented
                and n_score <= 0.3
            )
            # 分布式爬虫：在时序簇中 + 高网络聚集度 + 低熵覆盖
            is_distributed_candidate = (
                in_cluster and cluster_size >= 3
                and n_score > 0.4
                and (cov_low_entropy or cov_completeness > 0.3)
            )

            if is_crowdsourced_candidate:
                determination = "crowdsourced_crawler"
            elif is_distributed_candidate and fusion >= 0.55:
                determination = "distributed_crawler"
            elif fusion >= 0.5:
                determination = "suspicious"
            else:
                determination = "normal"

            session_results[sid] = {
                "determination": determination,
                "fusion_score": round(fusion, 4),
                "temporal_score": round(temporal_score, 4),
                "coverage_score": round(coverage_score, 4),
                "network_score": round(n_score, 4),
                "in_temporal_cluster": in_cluster,
                "cluster_size": cluster_size,
                "_pattern": pat,
                "_cov_entropy": round(cov_entropy, 3),
                "_cov_idle": round(cov_idle, 3),
                "_cov_completeness": round(cov_completeness, 3),
            }

        # ── 集群级汇总 ──
        cluster_results = []
        for ci, members in enumerate(temporal_result.get("clusters", [])):
            member_list = list(members)
            scores = [
                session_results[m]["fusion_score"]
                for m in member_list if m in session_results
            ]
            avg_score = statistics.mean(scores) if scores else 0
            cluster_results.append({
                "cluster_id": ci,
                "size": len(member_list),
                "avg_fusion_score": round(avg_score, 4),
                "members": member_list[:10],
                "determination": (
                    "distributed_crawler" if avg_score >= 0.55
                    else "suspicious" if avg_score >= 0.45
                    else "normal"
                ),
            })

        return {
            "session_results": session_results,
            "clusters": cluster_results,
            "coverage": {
                "global": global_coverage,
                "per_pattern": {
                    pat: {
                        "entropy": c["coverage_entropy"],
                        "idle_ratio": c["idle_session_ratio"],
                        "completeness": c["coverage_completeness"],
                        "sequential_score": c["sequential_score"],
                        "suspicious": c["suspicious_coverage"],
                    }
                    for pat, c in per_pattern_coverage.items()
                },
            },
            "network": {
                "crowdsourced_ratio": network_result.get("crowdsourced_ratio"),
                "crowdsourced_flag": network_result.get("stats", {}).get("crowdsourced_flag"),
                "intra_pattern_similarities": network_result.get("intra_pattern_similarities"),
            },
            "global_assessment": {
                "has_distributed_crawler": any(
                    r["determination"] == "distributed_crawler"
                    for r in session_results.values()
                ),
                "has_crowdsourced_crawler": any(
                    r["determination"] == "crowdsourced_crawler"
                    for r in session_results.values()
                ),
                "distributed_session_count": sum(
                    1 for r in session_results.values()
                    if r["determination"] == "distributed_crawler"
                ),
                "crowdsourced_session_count": sum(
                    1 for r in session_results.values()
                    if r["determination"] == "crowdsourced_crawler"
                ),
                "suspicious_session_count": sum(
                    1 for r in session_results.values()
                    if r["determination"] == "suspicious"
                ),
            },
        }
