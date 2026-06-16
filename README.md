# 基于大模型的接口安全事件智能分析助手

基于大模型的接口安全事件智能分析助手

## 目录结构

```
├── engine/                    # 核心检测引擎
│   ├── run_comprehensive.py       # 主流水线
│   ├── _run_stage2_and_report.py  # Stage 2 RAG检测 + SecGPT报告
│   ├── mixed_attack_generator.py  # 攻击流量生成器
│   ├── data_source.py             # 多源数据接入
│   ├── session_stitcher.py        # Session拼接
│   └── rag_retriever.py           # RAG检索器
├── llm_api_analyze/                       # 检测模块
├── malicious_crawler/         # 爬虫检测（普通/分布式/众包）
├── incident_response/         # 事件响应 + Web UI（10页面）
├── prompts/                   # 统一Prompt管理
├── shared/                    # 共享工具
├── tests/                     # 测试套件
├── models/                    # 模型文件
│   ├── bge-large-en-v1.5/    # 嵌入模型
│   ├── secgpt-7B/            # 安全大模型
│   └── lora_adapter/         # LoRA权重
├── chroma_db/                 # 向量数据库
├── cyber_dataset_processing/  # 安全语料处理
├── secgpt_finetune/           # LoRA微调脚本
└── requirements.txt
```

## 系统架构

```
数据接入 → Stage 1 RF(16维特征) → Stage 2 三层检测 → 爬虫检测 → SecGPT报告
              ↓                        ↓                ↓              ↓
        70/30 split              指纹库+知识库+Regex    Ensemble    中文报告
                                  843条 + 1844条 + 60+规则
```

## 运行方式

```bash
# 完整流水线
/root/anaconda3/envs/rag/bin/python engine/run_comprehensive.py

# Web仪表盘
/root/anaconda3/envs/rag/bin/python -m incident_response.web.app
# http://localhost:8080

# 爬虫检测专项
/root/anaconda3/envs/rag/bin/python -m malicious_crawler.main
```

## 环境依赖

关键依赖：pandas, scikit-learn, fastapi, chromadb, sentence-transformers, torch, transformers, peft, bitsandbytes

详见 **requirements.txt**

## 模型

| 模型 | 大小 | 用途 |
|------|:----:|------|
| bge-large-en-v1.5 | 3.8GB | 文本嵌入 |
| SecGPT-7B | 15GB | 安全报告生成 |
| LoRA Adapter | 165MB | api安全事件检测适配 |

注：bge-large-en-v1.5/SecGPT-7B为开源模型，需自行下载
