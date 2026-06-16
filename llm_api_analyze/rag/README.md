# RAG 安全分析模块

本目录包含基于 RAG（检索增强生成）的安全日志分析子模块，负责构建知识库、检索相似事件和串行攻击检测。

## 文件说明

- **`__init__.py`** — RAG 模块包初始化文件
- **`knowledge_base.py`** — 安全知识库构建器，从带标签的训练数据中提取结构化的安全事件知识块，为向量检索提供数据基础
- **`vector_db.py`** — 基于 ChromaDB 和 SentenceTransformers 的向量数据库管理器，负责嵌入向量的生成、存储和相似事件检索
- **`prompt_builder.py`** — RAG 提示词构建器，加载 7 种攻击类型的策略模板，结合日志详情和相似历史事件构建针对性的 LLM 提示词
- **`detector.py`** — 串行攻击检测器（LLM API 版），对每条日志按顺序检测 7 种攻击类型，发现异常即停止
- **`local_detector.py`** — **串行攻击检测器（SecGPT-7B + LoRA 本地模型版）**，当前流水线使用。4-bit NF4 量化，5.3GB VRAM，单卡 RTX 4090
