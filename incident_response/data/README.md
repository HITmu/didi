# 数据目录

该目录存储应急响应系统的持久化数据，以 JSON 文件格式保存。

## 文件说明

- `incidents.json` — 已处理的安全事件记录列表（含 anomaly_type/severity/confidence/disposition/notified_person）
- `health_records.json` — API 健康快照记录列表（含 health_score/status 多因子评分）
- `health_changes.json` — 处置前后的健康变化记录（delta + 对比）
- `internalized_knowledge.json` — 内化的知识条目（payload特征感知的学习模式+建议）
- `enterprise_knowledge.json` — 企业知识库（5类：policy/case/pattern/role_insight/best_practice）
- `persons.json` — 注册的责任人信息（name/role/email/phone）
- `bindings.json` — API 端点与责任人的绑定关系（含优先级）
- `reports/` — 生成的安全报告（Markdown 格式，按时间戳命名）
