"""知识图谱 — 将事件、API、人员、知识和健康记录连接成可查询的图结构，
用于跨实体关联和影响分析。

使用 NetworkX 进行图操作，并导出 JSON 用于 Web 可视化。
"""

import os
import json
import uuid
from datetime import datetime
from typing import List, Dict, Optional, Any

import networkx as nx

_DATA_DIR = os.path.join(os.path.dirname(__file__), "data")


class KnowledgeGraph:
    """基于图的知识库，连接所有应急响应实体。

    节点类型：incident（事件）、api_endpoint（API 端点）、person（人员）、knowledge（知识）、health_record（健康记录）
    边类型：affects（影响）、responsible_for（负责）、produces_knowledge（产生知识）、tracks（追踪）、related_to（关联）
    """

    def __init__(self, data_dir: str = None):
        self.data_dir = data_dir or _DATA_DIR
        self.graph: nx.MultiDiGraph = nx.MultiDiGraph()
        self._built = False

    # ==================== 构建 ====================

    def build(self) -> int:
        """从所有数据源构建图。返回节点总数。"""
        self.graph.clear()

        self._add_incidents()
        self._add_knowledge()
        self._add_health_records()
        self._add_health_changes()
        self._add_persons_and_bindings()

        self._built = True
        return self.graph.number_of_nodes()

    def _load_json(self, filename: str) -> list:
        path = os.path.join(self.data_dir, filename)
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        return []

    def _add_incidents(self):
        for item in self._load_json("incidents.json"):
            nid = f"incident:{item['id']}"
            self.graph.add_node(nid, type="incident", label=item['id'][:8],
                                severity=item.get('severity', 'UNKNOWN'),
                                disposition=item.get('disposition', ''),
                                anomaly_type=item.get('anomaly_type', ''),
                                api_endpoint=item.get('api_endpoint', ''),
                                confidence=item.get('confidence', 0),
                                detected_at=item.get('detected_at', ''))

            api = item.get('api_endpoint', '')
            if api:
                self._ensure_api_node(api)
                self.graph.add_edge(nid, f"api:{api}", type="affects",
                                    label=f"affects {api}",
                                    severity=item.get('severity', ''))

            # 将事件链接到已通知的人员
            person_name = item.get('notified_person', '')
            if person_name:
                pid = f"person:{person_name}"
                self.graph.add_edge(nid, pid, type="notified",
                                    label=f"notified {person_name}")

    def _add_knowledge(self):
        for item in self._load_json("internalized_knowledge.json"):
            nid = f"knowledge:{item['id']}"
            self.graph.add_node(nid, type="knowledge", label=item['id'],
                                api_endpoint=item.get('api_endpoint', ''),
                                incident_type=item.get('incident_type', ''),
                                severity=item.get('severity', ''),
                                disposition_taken=item.get('disposition_taken', ''),
                                health_impact=item.get('health_impact', ''),
                                effectiveness=item.get('effectiveness_score', 0),
                                recommendation=item.get('recommendation', '')[:80])

            api = item.get('api_endpoint', '')
            if api:
                self._ensure_api_node(api)
                self.graph.add_edge(nid, f"api:{api}", type="related_to",
                                    label=f"knowledge about {api}",
                                    effectiveness=item.get('effectiveness_score', 0))

    def _add_health_records(self):
        for item in self._load_json("health_records.json"):
            nid = f"health:{item['id']}"
            self.graph.add_node(nid, type="health_record", label=item['id'],
                                api_endpoint=item.get('api_endpoint', ''),
                                health_score=item.get('health_score', 1.0),
                                status=item.get('status', 'normal'),
                                timestamp=item.get('timestamp', ''))

            api = item.get('api_endpoint', '')
            if api:
                self._ensure_api_node(api)
                self.graph.add_edge(f"api:{api}", nid, type="tracks",
                                    label=f"health {item.get('health_score', 1.0):.2f}",
                                    health_score=item.get('health_score', 1.0))

    def _add_health_changes(self):
        for item in self._load_json("health_changes.json"):
            inc_id = item.get('incident_id', '')
            if inc_id:
                src = f"incident:{inc_id}"
                api = item.get('api_endpoint', '')
                if api:
                    self._ensure_api_node(api)
                    nid = f"change:{inc_id}"
                    self.graph.add_node(nid, type="health_change", label=inc_id[:8],
                                        api_endpoint=api,
                                        health_delta=item.get('health_delta', 0),
                                        disposition_taken=item.get('disposition_taken', ''),
                                        improvement=item.get('improvement', False))
                    self.graph.add_edge(src, nid, type="impacts_health",
                                        label=f"delta={item.get('health_delta', 0):+.3f}",
                                        health_delta=item.get('health_delta', 0))

    def _add_persons_and_bindings(self):
        persons = {}
        for p in self._load_json("persons.json"):
            pid = f"person:{p['name']}"
            persons[p['id']] = p['name']
            self.graph.add_node(pid, type="person", label=p['name'],
                                email=p.get('email', ''),
                                role=p.get('role', ''))

        for b in self._load_json("bindings.json"):
            person_id = b.get('person_id', '')
            if person_id in persons:
                api_pattern = b.get('api_pattern', '')
                if api_pattern:
                    aid = f"api:{api_pattern}"
                    self._ensure_api_node(api_pattern)
                    self.graph.add_edge(f"person:{persons[person_id]}", aid,
                                        type="responsible_for",
                                        label=f"responsible for {api_pattern}",
                                        priority=b.get('priority', 0))

    def _ensure_api_node(self, api_endpoint: str):
        nid = f"api:{api_endpoint}"
        if not self.graph.has_node(nid):
            self.graph.add_node(nid, type="api_endpoint", label=api_endpoint,
                                api_endpoint=api_endpoint)

    # ==================== 查询 ====================

    def get_related(self, entity_id: str, max_hops: int = 2) -> Dict[str, list]:
        """查找与给定节点在 N 跳内相关的所有实体。

        Args:
            entity_id: 节点 ID（例如 'api:/orders'、'incident:f1819b3e'）
            max_hops: 遍历深度

        Returns:
            按类型分组的节点和边字典
        """
        if not self._built:
            self.build()

        if not self.graph.has_node(entity_id):
            # 尝试模糊匹配
            entity_id = self._fuzzy_find(entity_id)

        if not entity_id:
            return {"nodes": [], "edges": [], "error": "Entity not found"}

        # BFS 广度优先遍历
        related_nodes = set([entity_id])
        current = {entity_id}
        for _ in range(max_hops):
            neighbors = set()
            for n in current:
                neighbors.update(self.graph.successors(n))
                neighbors.update(self.graph.predecessors(n))
            current = neighbors - related_nodes
            related_nodes.update(current)

        # 提取子图
        sub = self.graph.subgraph(related_nodes)
        return {
            "nodes": [self._node_data(n, sub) for n in sub.nodes()],
            "edges": [self._edge_data(u, v, k, sub) for u, v, k in sub.edges(keys=True)],
            "center": entity_id,
        }

    def _fuzzy_find(self, fragment: str) -> Optional[str]:
        """通过部分匹配查找节点 ID。"""
        for n in self.graph.nodes():
            if fragment in n or fragment in self.graph.nodes[n].get('api_endpoint', ''):
                return n
        return None

    def find_path(self, src_fragment: str, dst_fragment: str) -> list:
        """查找两个实体之间的最短路径。"""
        if not self._built:
            self.build()

        src = self._fuzzy_find(src_fragment)
        dst = self._fuzzy_find(dst_fragment)

        if not src or not dst:
            return []

        try:
            path = nx.shortest_path(self.graph.to_undirected(), src, dst)
            return [self._node_data(n, self.graph) for n in path]
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return []

    def get_impact_analysis(self, api_endpoint: str) -> dict:
        """分析 API 端点的完整影响。"""
        nid = f"api:{api_endpoint}"
        related = self.get_related(nid, max_hops=2)

        incidents = [n for n in related['nodes'] if n.get('type') == 'incident']
        knowledge = [n for n in related['nodes'] if n.get('type') == 'knowledge']
        health_records = [n for n in related['nodes'] if n.get('type') == 'health_record']
        persons = [n for n in related['nodes'] if n.get('type') == 'person']

        return {
            "api_endpoint": api_endpoint,
            "total_incidents": len(incidents),
            "total_knowledge": len(knowledge),
            "health_records_count": len(health_records),
            "responsible_persons": [p['label'] for p in persons],
            "severities": list(set(i.get('severity') for i in incidents if i.get('severity'))),
            "avg_effectiveness": round(
                sum(k.get('effectiveness', 0) for k in knowledge) / max(len(knowledge), 1), 4
            ),
        }

    def get_statistics(self) -> dict:
        """返回图级别的统计信息。"""
        if not self._built:
            self.build()

        type_counts = {}
        for _, data in self.graph.nodes(data=True):
            t = data.get('type', 'unknown')
            type_counts[t] = type_counts.get(t, 0) + 1

        return {
            "total_nodes": self.graph.number_of_nodes(),
            "total_edges": self.graph.number_of_edges(),
            "by_type": type_counts,
            "density": round(nx.density(self.graph), 6),
        }

    # ==================== 导出 ====================

    def to_cytoscape(self) -> Dict[str, list]:
        """将图导出为 Cytoscape.js JSON 格式，用于 Web 可视化。"""
        if not self._built:
            self.build()

        elements = []

        # 按类型的颜色映射
        colors = {
            'incident': '#ef5350',
            'api_endpoint': '#42a5f5',
            'person': '#66bb6a',
            'knowledge': '#ffa726',
            'health_record': '#ab47bc',
            'health_change': '#26c6da',
        }

        for n, data in self.graph.nodes(data=True):
            dtype = data.get('type', 'unknown')
            elements.append({
                "data": {
                    "id": n,
                    "label": data.get('label', n),
                    "type": dtype,
                    "color": colors.get(dtype, '#9e9e9e'),
                    "severity": data.get('severity', ''),
                    "health_score": data.get('health_score', ''),
                    "effectiveness": data.get('effectiveness', ''),
                }
            })

        for u, v, k, data in self.graph.edges(keys=True, data=True):
            elements.append({
                "data": {
                    "id": f"{u}-{v}-{k}",
                    "source": u,
                    "target": v,
                    "label": data.get('label', ''),
                    "type": data.get('type', ''),
                }
            })

        return {"elements": elements}

    def to_json(self) -> dict:
        """将完整图导出为可序列化的字典。"""
        if not self._built:
            self.build()

        nodes = []
        for n, data in self.graph.nodes(data=True):
            nodes.append({"id": n, **data})

        edges = []
        for u, v, k, data in self.graph.edges(keys=True, data=True):
            edges.append({"source": u, "target": v, "id": f"{u}→{v}", **data})

        return {
            "nodes": nodes,
            "edges": edges,
            "stats": self.get_statistics(),
        }

    @staticmethod
    def _node_data(n, graph) -> dict:
        data = dict(graph.nodes[n])
        data['id'] = n
        return data

    @staticmethod
    def _edge_data(u, v, k, graph) -> dict:
        data = dict(graph.edges[u, v, k])
        data['source'] = u
        data['target'] = v
        return data

    # ==================== CLI 显示 ====================

    def print_summary(self):
        """打印人类可读的图摘要。"""
        stats = self.get_statistics()
        print(f"Knowledge Graph Summary")
        print(f"  Nodes: {stats['total_nodes']}  Edges: {stats['total_edges']}  Density: {stats['density']:.6f}")
        print(f"  By type:")
        for t, c in sorted(stats['by_type'].items(), key=lambda x: -x[1]):
            print(f"    {t}: {c}")

        # 显示连接最多的 API
        if self.graph.number_of_nodes() > 0:
            api_nodes = [(n, d) for n, d in self.graph.nodes(data=True) if d.get('type') == 'api_endpoint']
            if api_nodes:
                print(f"\n  APIs by connectivity:")
                for n, d in sorted(api_nodes,
                                   key=lambda x: self.graph.degree(x[0]), reverse=True)[:5]:
                    print(f"    {d['label']}: degree={self.graph.degree(n)}")
