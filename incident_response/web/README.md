# Web 可视化仪表盘

该目录包含应急响应系统的 Web 仪表盘，基于 FastAPI + Chart.js 构建，提供9个可视化页面和30+ JSON API。

## 目录结构

- `__init__.py` — 模块入口
- `app.py` — FastAPI 应用：9个页面路由 + 30+ JSON API 端点
- `templates/` — Jinja2 模板文件（含 enterprise_knowledge.html）
- `static/` — 静态资源文件 (js + css)

## 页面

| 路由 | 页面 | 功能 |
|------|------|------|
| `/dashboard` | 仪表盘 | 统计卡片、严重级别/处置方式环形图、最近事件 |
| `/health` | 健康追踪 | 端点选择、健康分折线图、多因子重新计算 |
| `/incidents` | 事件历史 | 可筛选事件表格（API端点 + 严重级别） |
| `/persons` | 人员绑定 | 负责人CRUD + API绑定管理（模态弹窗） |
| `/knowledge` | 知识内化 | 搜索过滤、有效性条形图、RAG上下文构建器 |
| `/enterprise-knowledge` | 企业知识库 | 5类知识管理（策略/案例/模式/角色/最佳实践） |
| `/report` | 安全报告 | 综合安全报告（执行摘要、健康影响、建议） |
| `/graph` | 知识图谱 | Cytoscape.js 交互图谱、影响分析、关联查询 |
| `/traceability` | 溯源分析 | 时间线、攻击模式分类、路径追踪、关联分析 |

## 启动

```bash
python -m incident_response.web.app
# http://localhost:8080/dashboard
```
