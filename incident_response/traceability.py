"""溯源分析 — 从事件数据中重建攻击路径和时间线。

支持：
  - 按 API 端点重建时间线
  - 攻击进展分析（首次访问 → 探测 → 利用）
  - 跨端点关联（同一模式出现在多个 API 上）
  - 通过日志 ID 和用户身份模式进行来源追踪
"""

import os
import json
from datetime import datetime, timedelta
from collections import defaultdict
from typing import List, Dict, Optional


class TraceabilityAnalyzer:
    """分析事件数据以重建攻击路径和时间线。"""

    def __init__(self, data_dir: str = None):
        self.data_dir = data_dir or os.path.join(os.path.dirname(__file__), "data")

    # ==================== 数据加载 ====================

    def _load_json(self, filename: str) -> list:
        path = os.path.join(self.data_dir, filename)
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        return []

    # ==================== 核心分析 ====================

    def analyze_api_timeline(self, api_endpoint: str = None) -> dict:
        """为特定 API 或所有 API 构建事件时间线。"""
        incidents = self._load_json("incidents.json")
        changes = self._load_json("health_changes.json")
        records = self._load_json("health_records.json")

        # 如果指定了 API 则过滤
        if api_endpoint:
            incidents = [i for i in incidents if i.get('api_endpoint') == api_endpoint]
            changes = [c for c in changes if c.get('api_endpoint') == api_endpoint]
            records = [r for r in records if r.get('api_endpoint') == api_endpoint]

        if not incidents and not records:
            return {"status": "no_data"}

        # 按时间戳排序
        incidents.sort(key=lambda x: x.get('detected_at', ''))
        records.sort(key=lambda x: x.get('timestamp', ''))

        # 构建事件时间线
        timeline = []

        # 健康记录时间线
        for r in records:
            timeline.append({
                'time': r.get('timestamp', ''),
                'type': 'health_snapshot',
                'api': r.get('api_endpoint', ''),
                'health_score': r.get('health_score', 1.0),
                'status': r.get('status', 'normal'),
            })

        # 事件时间线
        for i in incidents:
            timeline.append({
                'time': i.get('detected_at', ''),
                'type': 'incident',
                'api': i.get('api_endpoint', ''),
                'incident_id': i.get('id', ''),
                'severity': i.get('severity', ''),
                'anomaly_type': i.get('anomaly_type', ''),
                'disposition': i.get('disposition', ''),
                'confidence': i.get('confidence', 0),
            })

        # 健康变化时间线
        for c in changes:
            timeline.append({
                'time': c.get('after', {}).get('timestamp', ''),
                'type': 'health_change',
                'api': c.get('api_endpoint', ''),
                'incident_id': c.get('incident_id', ''),
                'health_delta': c.get('health_delta', 0),
                'disposition_taken': c.get('disposition_taken', ''),
            })

        timeline.sort(key=lambda x: x.get('time', ''))

        return {
            'api_endpoint': api_endpoint or '*',
            'total_events': len(timeline),
            'total_incidents': len(incidents),
            'time_span': self._time_span(incidents + records),
            'timeline': timeline,
        }

    def analyze_attack_patterns(self) -> dict:
        """查找所有事件的攻击模式。"""
        incidents = self._load_json("incidents.json")
        if not incidents:
            return {"status": "no_data"}

        # 按异常类型分组
        by_type = defaultdict(list)
        for i in incidents:
            by_type[i.get('anomaly_type', 'unknown')].append(i)

        # 按端点分组
        by_endpoint = defaultdict(list)
        for i in incidents:
            by_endpoint[i.get('api_endpoint', '/unknown')].append(i)

        # 查找多攻击端点（同一端点被多次攻击）
        multi_attack = {ep: hits for ep, hits in by_endpoint.items() if len(hits) > 1}

        # 查找严重程度演进
        progression = {}
        for ep, hits in by_endpoint.items():
            sorted_hits = sorted(hits, key=lambda x: x.get('detected_at', ''))
            sevs = [h.get('severity', 'LOW') for h in sorted_hits]
            sev_rank = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}
            numeric = [sev_rank.get(s, 0) for s in sevs]
            if len(numeric) > 1 and numeric[-1] > numeric[0]:
                progression[ep] = {
                    'start': sevs[0],
                    'end': sevs[-1],
                    'escalated': True,
                    'step_count': len(sevs),
                }

        return {
            'total_incidents': len(incidents),
            'unique_attack_types': list(by_type.keys()),
            'by_type': {t: len(v) for t, v in by_type.items()},
            'most_attacked_endpoints': sorted(
                [(ep, len(hits)) for ep, hits in by_endpoint.items()],
                key=lambda x: -x[1],
            )[:10],
            'multi_hit_endpoints': len(multi_attack),
            'severity_escalations': progression,
        }

    def trace_attack_path(self, incident_id: str = None) -> dict:
        """追踪单个事件的完整攻击路径 — 周边事件、健康影响、知识。"""
        incidents = self._load_json("incidents.json")
        changes = self._load_json("health_changes.json")
        knowledge = self._load_json("internalized_knowledge.json")

        if incident_id:
            incident = next((i for i in incidents if i.get('id') == incident_id), None)
        else:
            incident = incidents[-1] if incidents else None

        if not incident:
            return {"status": "not_found"}

        api = incident.get('api_endpoint', '')
        incident_time = incident.get('detected_at', '')

        # 查找相关的健康变化
        related_changes = [c for c in changes if c.get('incident_id') == incident_id]

        # 查找相关的知识
        related_knowledge = [
            k for k in knowledge
            if k.get('api_endpoint') == api
        ]

        # 查找附近事件（同一 API，时间相近）
        nearby = [
            i for i in incidents
            if i.get('api_endpoint') == api
            and i.get('id') != incident_id
        ]

        return {
            'incident': {
                'id': incident.get('id', ''),
                'api_endpoint': api,
                'severity': incident.get('severity', ''),
                'anomaly_type': incident.get('anomaly_type', ''),
                'confidence': incident.get('confidence', 0),
                'disposition': incident.get('disposition', ''),
                'status': incident.get('disposition_status', ''),
                'detected_at': incident.get('detected_at', ''),
                'reason': incident.get('reason', ''),
            },
            'health_impact': related_changes,
            'knowledge_generated': [
                {
                    'id': k.get('id', ''),
                    'effectiveness': k.get('effectiveness_score', 0),
                    'recommendation': k.get('recommendation', ''),
                }
                for k in related_knowledge
            ],
            'nearby_incidents': [
                {
                    'id': n.get('id', '')[:8],
                    'severity': n.get('severity', ''),
                    'detected_at': n.get('detected_at', ''),
                }
                for n in nearby
            ],
            'attack_path_summary': self._build_path_summary(incident, related_changes, related_knowledge),
        }

    def correlation_analysis(self) -> dict:
        """跨端点关联 — 查找不同 API 之间的共享模式。"""
        incidents = self._load_json("incidents.json")
        if not incidents:
            return {"status": "no_data"}

        # 同一用户攻击多个 API
        # （在此数据集中，所有用户都是 'user' — 因此没有有意义的 IP 关联）
        # 改为按以下方式关联：跨 API 的相同 anomaly_type、相同严重程度、相同时间窗口

        by_time_window = defaultdict(set)
        for i in incidents:
            ts = i.get('detected_at', '')
            if ts:
                # 按分钟分组
                minute_key = ts[:16]
                by_time_window[minute_key].add(i.get('api_endpoint', ''))

        # 查找有多个 API 同时受到攻击的时间窗口
        mass_attacks = {
            k: list(v) for k, v in by_time_window.items()
            if len(v) > 3
        }

        # 同一攻击类型攻击多个 API
        by_type_endpoints = defaultdict(set)
        for i in incidents:
            by_type_endpoints[i.get('anomaly_type', 'unknown')].add(i.get('api_endpoint', ''))

        widespread_types = {
            t: list(eps) for t, eps in by_type_endpoints.items()
            if len(eps) > 1
        }

        return {
            'total_incidents': len(incidents),
            'unique_apis': len(set(i.get('api_endpoint', '') for i in incidents)),
            'mass_attack_windows': len(mass_attacks),
            'widespread_attack_types': widespread_types,
            'simultaneous_attacks': mass_attacks,
        }

    # ==================== 辅助函数 ====================

    @staticmethod
    def _time_span(events: list) -> Optional[dict]:
        """计算事件的时间跨度。"""
        timestamps = [
            e.get('detected_at', e.get('timestamp', ''))
            for e in events if e.get('detected_at', e.get('timestamp', ''))
        ]
        if len(timestamps) < 2:
            return None
        timestamps.sort()
        return {"start": timestamps[0], "end": timestamps[-1]}

    @staticmethod
    def _build_path_summary(incident: dict, changes: list, knowledge: list) -> str:
        """生成人类可读的攻击路径摘要。"""
        sev = incident.get('severity', 'UNKNOWN')
        atype = incident.get('anomaly_type', 'unknown')
        api = incident.get('api_endpoint', '')
        disp = incident.get('disposition', 'unknown')
        conf = incident.get('confidence', 0)

        total_delta = sum(c.get('health_delta', 0) for c in changes)
        delta_str = f"{total_delta:+.3f}" if total_delta != 0 else "no change"

        eff_str = ""
        if knowledge:
            avg_eff = sum(k.get('effectiveness_score', 0) for k in knowledge) / len(knowledge)
            eff_str = f", avg effectiveness: {avg_eff:.2f}"

        return (
            f"{sev} severity {atype} on {api} (confidence: {conf:.0%}) "
            f"→ disposition: {disp} → health impact: {delta_str}{eff_str}"
        )

    # ==================== 显示 ====================

    def print_timeline(self, api_endpoint: str = None):
        """打印人类可读的时间线。"""
        result = self.analyze_api_timeline(api_endpoint)
        if result.get('status') == 'no_data':
            print(f"No timeline data for {api_endpoint or 'all APIs'}.")
            return

        print(f"Timeline for {result['api_endpoint']}: {result['total_events']} events, {result['total_incidents']} incidents")
        if result.get('time_span'):
            print(f"  Period: {result['time_span']['start'][:19]} → {result['time_span']['end'][:19]}")
        print()

        for event in result['timeline'][-20:]:  # 最近 20 个事件
            t = event.get('time', '')[:19]
            etype = event.get('type', '')
            api = event.get('api', '')[:30]

            if etype == 'incident':
                print(f"  [{t}] 🔴 {api} — {event.get('anomaly_type')} ({event.get('severity')}) conf={event.get('confidence', 0):.0%} → {event.get('disposition')}")
            elif etype == 'health_snapshot':
                print(f"  [{t}] 📊 {api} — health={event.get('health_score')} ({event.get('status')})")
            elif etype == 'health_change':
                delta = event.get('health_delta', 0)
                icon = "🟢" if delta >= 0 else "🔴"
                print(f"  [{t}] {icon} {api} — delta={delta:+.3f} ({event.get('disposition_taken')})")

    def print_attack_patterns(self):
        """打印攻击模式分析。"""
        patterns = self.analyze_attack_patterns()
        if patterns.get('status') == 'no_data':
            print("No incident data to analyze.")
            return

        print(f"Attack Pattern Analysis ({patterns['total_incidents']} incidents)")
        print(f"  Unique attack types: {patterns['unique_attack_types']}")
        print(f"  By type: {patterns['by_type']}")
        print(f"  Multi-hit endpoints: {patterns['multi_hit_endpoints']}")
        print(f"  Most attacked:")
        for ep, count in patterns['most_attacked_endpoints'][:5]:
            print(f"    {ep}: {count} times")
        if patterns['severity_escalations']:
            print(f"  Severity escalations detected:")
            for ep, info in patterns['severity_escalations'].items():
                print(f"    {ep}: {info['start']} → {info['end']} ({info['step_count']} steps)")
