# SecGPT-7B 微调项目

基于 QLoRA 对 SecGPT-7B 进行安全领域指令微调，提升安全报告生成能力。

## 项目结构

```
secgpt_finetune/
├── models/
│   └── SecGPT-7B/          # 原始 SecGPT-7B 模型（7.6B参数）
├── data/
│   ├── train.jsonl          # 训练集（2,011条QA对）
│   └── eval.jsonl           # 评估集（224条QA对）
├── scripts/
│   ├── train_qlora.py       # QLoRA 微调脚本（单卡）
│   ├── test_lora.py         # LoRA 推理测试
│   ├── generate_test_data.py # 测试数据生成器（500条）
│   ├── batch_inference.py   # 批量推理（Base + LoRA对比）
│   ├── analyze_results.py   # LLM分析+报告生成
│   └── run_eval_pipeline.py # 全流程自动化
├── output/
│   └── lora_adapter/        # 最终LoRA adapter（161MB）
├── test_results/
│   ├── api_attack_test_500.csv       # 500条测试数据
│   ├── base_model_results.csv        # Base模型推理结果
│   ├── lora_model_results.csv        # LoRA模型推理结果
│   ├── llm_eval_raw.json        # LLM原始评分
│   ├── llm_eval_structured.json # LLM结构化评分
│   └── lora_optimization_report.md   # 优化报告
├── lora_optimization_report.md       # 优化报告（根目录）
├── prompt_design.md                  # Prompt设计文档
└── finetune_guide.md                 # 微调指南
```

## 数据来源

训练数据为自行收集整理的接口安全语料，经以下流水线处理：

1. **采集与汇总**（约 27.7 万条原始安全语料）
2. **分片**（28 个 shard）
3. **API 安全提取**（LLM API 筛选出 API 安全相关条目）
4. **中英翻译**（调用 LLM 进行翻译）
5. **分类**：QA 对（2,243 条）→ 用于 SFT / 漏洞 Dump（82,207 条）→ 用于 RAG

## 训练配置

| 参数 | 值 |
|------|------|
| 基础模型 | SecGPT-7B（Qwen2架构） |
| 量化 | 4-bit NF4（QLoRA） |
| LoRA rank | 16 |
| LoRA alpha | 32 |
| 目标模块 | q/k/v/o/gate/up/down_proj |
| 训练设备 | 单卡 RTX 4090（24GB） |
| 训练轮次 | 8 |
| 有效batch size | 8 |
| 学习率 | 2e-4（cosine调度） |
| 最大序列长度 | 1024 |

## 使用流程

```bash
# 1. QLoRA 微调
conda run -n didienv python scripts/train_qlora.py

# 2. 快速测试
conda run -n didienv python scripts/test_lora.py

# 3. 全流程评估（生成500条测试→推理→分析→报告）
conda run -n didienv python scripts/run_eval_pipeline.py
```

## 评估结果

| 维度 | Base | LoRA | 提升 |
|------|------|------|------|
| 准确性 | 7.0 | 7.8 | +0.8 |
| 完整性 | 6.5 | 7.7 | +1.1 |
| 结构化 | 7.0 | 7.7 | +0.6 |
| 专业性 | 6.9 | 7.7 | +0.8 |

> 详细报告见 [lora_optimization_report.md](lora_optimization_report.md)

## Prompt 设计

详见 [prompt_design.md](prompt_design.md)，涵盖：
- 角色锚定、任务纯化、覆盖广度三原则
- System Prompt 设计要素
- 评估 Prompt 评分维度设计
- 对比方法论（控制变量、统计方法）

## 硬件

- GPU: 单卡 RTX 4090 (24GB)
- 量化: 4-bit NF4 (QLoRA)
- 推理速度: ~8s/条 (batch_size=4)
