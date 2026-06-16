# 事件响应系统 (incident_response)

基于安全检测结果的多级事件处置、知识管理与可视化平台。

## 架构概览

```
检测引擎 → DispositionEngine → 通知/封禁/日志
               ↓
          KnowledgeInternalizer → EnterpriseKnowledgeBase
               ↓
          HealthTracker ← 处置前后快照
               ↓
          NLG Explainer → 人类可读的处置解释
               ↓
          TraceabilityAnalyzer → 攻击路径追踪
               ↓
          KnowledgeGraph → 图谱可视化 (Cytoscape)
               ↓
          Web Dashboard → FastAPI + Chart.js (10页面, 30+ API)
```

## 目录结构

| 文件 | 说明 |
|------|------|
| `disposition.py` | DispositionEngine：5 级处置路由（auto_block / notify_email / escalate / auto_log / none） |
| `health_tracker.py` | HealthTracker：5 因子健康评分（异常率 35% / 错误率 20% / 响应时间 15% / 事件频率 20% / 新鲜度 10%） |
| `knowledge_internalizer.py` | KnowledgeInternalizer：处置后自动内化知识条目，含有效性评分和健康改善追踪 |
| `enterprise_knowledge.py` | EnterpriseKnowledgeBase：5 类知识源（policy / case / pattern / role_insight / best_practice），加权相关性排序 |
| `knowledge_graph.py` | KnowledgeGraph：NetworkX 图谱（111 节点 / 120 边），Cytoscape 导出 + BFS 影响分析 |
| `traceability.py` | TraceabilityAnalyzer：API 时间线 + 攻击路径追踪 + 跨事件关联分析 |
| `nlg_explainer.py` | NlgExplainer：6 种 payload 变体差异化模板，按攻击类型生成解释文本 |
| `report_generator.py` | 安全报告生成（模板模式）：聚合各子系统 + 差异化建议 |
| `llm_report_generator.py` | 安全报告生成（LLM 模式）：支持 SecGPT-7B+LoRA 生成结构化报告 |
| `person_binding.py` | 负责人管理：人员 CRUD + API 端点-人员模式匹配绑定 |
| `notifier.py` | 通知模块：控制台 / 文件日志 / 邮件 / Slack |
| `models.py` | 数据模型（Incident, HealthRecord, HealthChange, InternalizedKnowledge, EnterpriseKnowledgeEntry 等） |
| `cli.py` | 命令行管理工具（10+ 子命令） |
| `enterprise_seed_data.py` | 企业知识种子数据（8 条安全策略） |
| `data/` | 数据存储目录（JSON：incidents / health / knowledge / enterprise / bindings / persons） |
| `notifications/` | 通知日志目录 |
| `web/` | Web 仪表盘（FastAPI + Jinja2 + Chart.js 4.4.7） |

## 使用方式

### Web 仪表盘

```bash
# 启动 (端口 8080)
/root/anaconda3/envs/rag/bin/python -m incident_response.web.app

# 使用 uvicorn
uvicorn incident_response.web.app:app --host 0.0.0.0 --port 8080
```

访问 http://localhost:8080

### 10 个页面

| 页面 | 路由 | 功能 |
|------|------|------|
| Dashboard | `/dashboard` | 统计卡片 + 环形图 |
| Health | `/health` | 健康分折线图 |
| Incidents | `/incidents` | 事件筛选表格 |
| Persons | `/persons` | 人员 CRUD |
| Knowledge | `/knowledge` | 知识库搜索 |
| Enterprise KB | `/enterprise-knowledge` | 企业知识库 |
| Report | `/report` | 安全报告 |
| Graph | `/graph` | 知识图谱 (Cytoscape) |
| Traceability | `/traceability` | 溯源分析 |
| Crawler | `/crawler` | 爬虫检测可视化 |

### CLI 管理

```bash
/root/anaconda3/envs/rag/bin/python -m incident_response.cli --help
```

支持人员管理、事件查询、健康检查、知识检索、报告生成等子命令。

## 处置规则

| 严重程度 | 置信度 | 处置动作 |
|----------|:------:|----------|
| CRITICAL | >= 90% | auto_block — 自动封禁 |
| HIGH | >= 80% | notify_email — 邮件通知 |
| MEDIUM | >= 60% | escalate — 升级处理 |
| LOW | >= 40% | auto_log — 仅记录 |
| 全部 | < 40% | none — 不处置 |

## 健康评分公式

5 因子加权评分（0.0~1.0），分数低于 0.5 触发告警：

| 因子 | 权重 | 计算方式 |
|------|:----:|----------|
| 异常率 | 35% | max(0, 1 - anomaly_rate * 2) |
| 错误率 | 20% | max(0, 1 - error_rate * 2) |
| 响应时间 | 15% | max(0, 1 - rt_degradation * penalty) |
| 事件频率 | 20% | min(0.3, incident_count * 0.05) |
| 新鲜度 | 10% | recency_factor |

## 知识图谱

- 节点类型：incident / endpoint / person / knowledge / enterprise_entry
- 边类型：related_to / affects / assigned_to / derived_from / caused_by
- 图谱规模：111 节点 / 120 边
- 查询：BFS 影响范围（max_hops 可配）、最短攻击路径、实体关联

## 闭环反馈

```
检测 → 处置 → 评估有效性 → 内化为知识条目 → RAG 检索 → 改善后续检测
```

知识内化记录 effectiveness_score（0.0~1.0），企业知识库加权查询优先返回高有效性条目。
