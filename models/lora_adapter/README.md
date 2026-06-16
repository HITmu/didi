---
base_model: secgpt-7B
library_name: peft
pipeline_tag: text-generation
tags:
- lora
- sft
- transformers
- trl
- security
---

# LoRA Adapter — 接口安全事件分析

基于 QLoRA 在 SecGPT-7B 上微调得到的 LoRA 适配器，专用于 API 接口安全事件检测与中文安全报告生成。

## 模型概述

- **基础模型**：SecGPT-7B（Qwen2 架构，7.6B 参数）
- **微调方法**：QLoRA（4-bit NF4 量化）
- **任务类型**：文本生成（接口安全事件分析、攻击样本解读、中文安全报告）
- **适配场景**：与本项目主流水线（`engine/run_comprehensive.py`）配合，对 Stage 2 检测出的攻击样本进行差异化解释和综合报告生成
- **语言**：中文为主，兼容英文 payload

## 训练配置

| 参数 | 值 |
|------|------|
| LoRA rank | 16 |
| LoRA alpha | 32 |
| 目标模块 | q_proj / k_proj / v_proj / o_proj / gate_proj / up_proj / down_proj |
| 训练轮次 | 8 |
| 有效 batch size | 8 |
| 学习率 | 2e-4（cosine 调度） |
| 最大序列长度 | 1024 |
| 量化方案 | 4-bit NF4（QLoRA） |
| 训练硬件 | 单卡 RTX 4090（24GB） |

## 训练数据

- **训练集**：2,011 条 API 安全相关问答对（自行收集整理）
- **评估集**：224 条（自行收集整理）

## 使用方式

```python
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
import torch

base_path = "models/secgpt-7B"
adapter_path = "models/lora_adapter"

bnb_config = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_quant_type="nf4",
    bnb_4bit_compute_dtype=torch.bfloat16,
)

tokenizer = AutoTokenizer.from_pretrained(base_path, trust_remote_code=True)
base_model = AutoModelForCausalLM.from_pretrained(
    base_path,
    quantization_config=bnb_config,
    device_map="auto",
    trust_remote_code=True,
)
model = PeftModel.from_pretrained(base_model, adapter_path)
model.eval()
```

## 推理资源占用

- **VRAM**：约 5.3 GB（4-bit 量化 + LoRA）
- **单条推理耗时**：约 8 秒（batch_size=4）
- **推荐硬件**：CUDA 12.6+，单卡 RTX 4090 或同等显存设备

## 适用范围

本适配器面向以下场景：

- API 接口流量中的攻击样本解释（SQL 注入、XSS、目录遍历、越权访问、敏感数据泄露、命令注入、SSRF、CSRF、性能问题、无效参数）
- 检测结果的中文化安全报告生成
- 与 RAG 检索系统配合的攻击模式解读

## 局限与风险

- 训练数据规模有限（2,011 条 QA），对极端罕见的攻击变体覆盖不足
- 评估显示在准确性、完整性、结构化、专业性等维度相比基础模型均有提升，但仍建议与多层检测流水线协同使用，而非作为检测决策的唯一依据
- 不应直接用于生产环境的自动封禁等高风险操作；建议与 RandomForest + RAG 多层检测流水线配合使用
- 仅用于授权范围内的安全测试与防御研究，不得用于非法用途

## 框架版本

- PEFT 0.19.1
- Transformers 4.57.1
- bitsandbytes 0.45.4
- PyTorch 2.7.1+cu126
