# 模板目录

该目录包含 Web 仪表盘的 Jinja2 HTML 模板文件。

## 文件说明

- `base.html` — 基础布局模板：侧边栏导航、页脚、通用脚本加载
- `dashboard.html` — 仪表盘页面：显示统计概览、严重程度图表、最近事件
- `health.html` — 健康追踪页面：显示健康评分趋势和变化记录
- `incidents.html` — 事件列表页面：支持按 API 和严重程度筛选
- `knowledge.html` — 知识内化页面：知识条目搜索、有效性分析、RAG 上下文构建
- `enterprise_knowledge.html` — 企业知识库页面：5类知识管理、搜索、分类环形图
- `persons.html` — 人员与绑定管理页面：责任人和 API 绑定的 CRUD 操作
- `report.html` — 安全报告页面：展示安全态势报告（含企业RAG上下文）
- `graph.html` — 知识图谱页面：基于 Cytoscape.js 的交互式图谱可视化
- `traceability.html` — 溯源分析页面：时间线、攻击模式、路径追踪和关联分析
- `error.html` — 404 错误页面
