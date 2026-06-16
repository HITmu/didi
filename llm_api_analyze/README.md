# LLM API 安全分析器

基于大模型 API（支持 OpenAI GPT-4o / Claude Opus 等）的安全日志分析模块。

## 文件说明

| 文件 | 说明 |
|------|------|
| `config.py` | API 配置（URL、模型、密钥） |
| `classifier.py` | RandomForest 二分类器（Stage 1） |
| `feature_extractor.py` | 16 维特征提取 |
| `analyzer.py` | RAG 安全分析器 |
| `main.py` | 主入口 |
| `rag/` | RAG 子模块（向量库、知识库、提示词构建、检测器） |
| `report/` | 报告生成 |

## 支持的攻击类型

SQL 注入、XSS、目录遍历、越权访问、敏感数据泄露、命令注入、SSRF、CSRF、性能问题、无效参数
