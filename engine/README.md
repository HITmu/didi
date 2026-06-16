# 安全检测引擎 (engine)

全攻击类型检测流水线：**数据生成 → Stage 1 RF → 爬虫检测 → Stage 2 三层RAG → SecGPT中文报告**。

## 检测流水线

```
Step 1: mixed_attack_generator  → 合成攻击流量 (~7,000条, 10 API + 5 爬虫)
Step 2: Stage 1 RF (rag env)   → 16维特征, 70/30 split, 召回率100%
Step 4: Crawler Detection       → Ensemble F1=0.93 + 三层融合(分布式/众包)
Step 5: Stage 2 RAG + Report    → didienv子进程(GPU):
  Layer 1: attack_patterns DB (51条指纹, dist<0.05精准/<0.20模糊)
  Layer 2: attack_detection_knowledge DB (1,844条知识, dist<0.72语义)
  Layer 3: Regex回退 (conf≥0.85)
  → SecGPT-7B+LoRA 生成中文攻击样本分析报告
```

## Stage 2 三层RAG检测

| Layer | 数据源 | 规模 | 匹配方式 | 阈值 |
|-------|--------|:----:|---------|:----:|
| 1 指纹库 | 合成攻击payload (method+path) | 51条/7类型 | 余弦距离精准/模糊匹配 | <0.05/<0.20 |
| 2 知识库 | 安全语料(82K→1,844精选) | 1,844条/7类型 | 语义相似度匹配 | <0.72 |
| 3 Regex | 8组攻击签名 | ~40条规则 | 正则匹配 | conf≥0.85 |

## 最新检测结果

| 攻击类型 | 召回率 |
|----------|:------:|
| directory traversal attack | 100.0% |
| cross-site scripting attack | 100.0% |
| invalid item value | 96.2% |
| performance issue | 94.1% |
| injection attack | 93.2% |
| sensitive data leakage | 81.0% |
| unauthorized access attack | 79.3% |
| **7类型平均** | **92.0%** |

## 运行

```bash
# 完整流水线 (rag env + didienv GPU subprocess)
/root/anaconda3/envs/rag/bin/python engine/run_comprehensive.py
```

报告输出：`incident_response/data/reports/security_report_*.md`（中文，含攻击样本分析）

## 文件说明

| 文件 | 说明 |
|------|------|
| `run_comprehensive.py` | 主流水线编排（rag env） |
| `_run_stage2_and_report.py` | Stage 2三层RAG + SecGPT报告（didienv, GPU） |
| `mixed_attack_generator.py` | 全攻击类型流量生成器（10 API + 5 爬虫） |
| `data_source.py` | WAF/IDS/API网关数据源连接器 |
| `session_stitcher.py` | 多源Session拼接（IP+60s窗口） |
| `crawler_detector.py` | 单条日志爬虫行为检测 |
| `rag_retriever.py` | 报告生成RAG检索器 |
| `rule_engine.py` | 规则引擎基线 |
