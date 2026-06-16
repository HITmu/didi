# prompts — 统一 Prompt 管理

所有 LLM prompt 模板的集中管理目录，通过 `PromptManager` 统一加载和渲染。

## 目录结构

```
prompts/
├── manager.py                  # PromptManager（加载/缓存/渲染）
├── system/                     # 系统角色 prompt
│   ├── security_expert.txt     # 通用安全专家
│   ├── security_analyst.txt    # 综合安全态势分析师
│   └── crawler_analyst.txt     # 爬虫分析专家
├── detection/                  # 攻击检测 prompt（Stage 2 串行）
│   ├── unified.txt             # 通用检测（fallback）
│   ├── injection_attack.txt    # 注入攻击检测
│   ├── directory_traversal.txt # 目录遍历检测
│   ├── cross_site_scripting.txt# XSS 检测
│   ├── performance_issue.txt   # 性能/DoS 检测
│   ├── invalid_item_value.txt  # 无效参数检测
│   ├── sensitive_data_leakage.txt # 敏感数据泄露检测
│   └── unauthorized_access.txt # 越权访问检测
├── report/                     # 报告生成 prompt
│   ├── comprehensive_user.txt  # 综合报告 user prompt（含所有指标占位符）
│   └── schemas/                # JSON 输出 schema
│       ├── comprehensive_report.json
│       └── crawler_report.json
└── explanation/                # NLG 解释模板
    ├── recommendations.txt     # 处置建议模板（按攻击类型+payload变体）
    └── dispositions.txt        # 处置动作说明模板
```

## 使用方式

```python
from prompts.manager import get_prompt_manager

pm = get_prompt_manager()

# 加载 system prompt
system = pm.system_prompt("security_analyst")

# 加载检测模板
template = pm.detection_prompt("injection attack")

# 加载报告 schema
schema = pm.report_schema("comprehensive_report")

# 渲染模板（替换 {var} 占位符）
rendered = pm.render("report/comprehensive_user.txt",
    total_sessions=100, total_records=5000)
```

## 5 个集成点

| 模块 | 使用的 prompt |
|------|-------------|
| `engine/_run_secgpt_inference.py` | `system/security_analyst.txt`, `report/comprehensive_user.txt`, `report/schemas/comprehensive_report.json` |
| `llm_api_analyze/rag/prompt_builder.py` | `detection/*.txt`（7 种攻击检测模板） |
| `llm_api_analyze/rag/local_detector.py` | `system/security_expert.txt` |
| `malicious_crawler/pipeline.py` | `system/crawler_analyst.txt`, `report/schemas/crawler_report.json` |
| `incident_response/nlg_explainer.py` | `explanation/recommendations.txt`, `explanation/dispositions.txt` |

## 设计原则

- **单一入口**：所有 prompt 通过 `PromptManager` 加载，不散落在代码中
- **文件化管理**：prompt 内容存储在文件中，修改无需改 Python 代码
- **变量渲染**：`{var}` 占位符在运行时替换，模板不含硬编码数字
- **缓存**：加载的模板被缓存，避免重复磁盘 I/O
- **向后兼容**：`detection/` 目录下的文件与旧版 `prompts/*.txt` 内容一致
