# SecGPT-7B 微调指南

## 模型信息

| 属性 | 值 |
|------|------|
| 模型名称 | SecGPT-7B (云起无垠) |
| 基座架构 | Qwen2ForCausalLM |
| 参数量 | 7.6B (14.2GB) |
| 层数 | 28 层 |
| 注意力头 | 28 头, 4 KV 头 (GQA) |
| 隐藏层维度 | 3584 |
| 中间层维度 | 18944 |
| 上下文窗口 | 32K tokens |
| 词表大小 | 152,064 |
| 权重文件 | 4 个 safetensors 分片 |
| 数据类型 | float16 |
| 聊天模板 | Qwen2 格式 (`<|im_start|>`, `<|im_end|>`) |

## 目录结构

```
secgpt_finetune/
├── README.md              # 本文件
├── finetune_guide.md       # 微调指南
├── models/secgpt-7B/      # 原始 SecGPT-7B 权重 (15GB)
├── data/                  # 训练数据
│   ├── train.jsonl        # 训练集
│   └── eval.jsonl         # 评估集
├── scripts/               # 训练/评估脚本
│   ├── prepare_data.py    # 数据准备
│   ├── train_qlora.py     # QLoRA 微调
│   ├── merge_lora.py      # 合并权重
│   └── test_generation.py # 生成测试
└── output/                # LoRA adapter 输出
```

## 硬件需求

| 方案 | GPU显存 | 本机(2× RTX 4090) |
|------|:-------:|:-----------------:|
| QLoRA (4-bit) | ~8-10GB | ✅ 单卡轻松跑 |
| LoRA (8-bit) | ~12-16GB | ✅ 单卡足够 |
| LoRA (FP16) | ~20-24GB | ✅ 单卡刚好 |
| 全参微调 (FP16) | ~60-80GB | ❌ 显存不足 |

**推荐方案：QLoRA (4-bit NF4)**

---

## 数据准备

### 数据格式要求

将原始 instruction-output 数据转换成 Qwen2 聊天模板格式：

```json
{
  "messages": [
    {"role": "system", "content": "你是一个网络安全专家，擅长分析安全漏洞和生成安全报告。"},
    {"role": "user", "content": "CVE:CVE-2022-29047"},
    {"role": "assistant", "content": "该漏洞是..."}
  ]
}
```

### 报告生成专用数据

为提升报告生成能力，构造混合训练集：

```
50%  CVE问答数据（自行收集整理的 84,450 条）
30%  报告生成数据（从已有安全报告构造指令）
20%  安全策略+企业知识（从 enterprise_knowledge.json 提取）
```

报告生成样本格式：

```json
{
  "messages": [
    {"role": "system", "content": "你是一个安全报告分析师，擅长根据安全事件数据生成专业的分析报告。"},
    {"role": "user", "content": "请根据以下数据生成安全报告洞察章节：\n事件：15个安全事件，14个目录遍历攻击，1个SQL注入\n受影响API：/api/download, /api/login\n健康变化：15次变更，平均delta +0.0234\n知识条目：15条，平均有效性0.70"},
    {"role": "assistant", "content": "## 洞察与建议\n\n### 攻击模式分析\n本次检测到15个安全事件，其中目录遍历攻击占93%（14个）...\n\n### 建议\n1. 对 /api/download 端点实施路径白名单策略\n2. 对 /api/login 端点使用参数化查询..."}
  ]
}
```

---

## QLoRA 训练配置

### 核心参数

```python
# LoRA 配置
lora_r = 16                 # LoRA 秩（越大能力越强, 显存需求越高）
lora_alpha = 32             # 缩放因子
lora_dropout = 0.05         # Dropout
target_modules = [
    "q_proj", "k_proj",    # 注意力模块
    "v_proj", "o_proj",    # 注意力输出
    "gate_proj",           # MLP 门控
    "up_proj", "down_proj" # MLP 上下投影
]

# 量化配置
quantization = "4bit"       # bitsandbytes NF4
compute_dtype = "float16"   # 计算精度

# 训练参数
per_device_train_batch_size = 4
gradient_accumulation_steps = 4
learning_rate = 2e-4
num_train_epochs = 3
max_seq_length = 2048
logging_steps = 10
save_steps = 200
```

### 训练流程

```bash
# 1. 准备数据
python scripts/prepare_data.py

# 2. 启动 QLoRA 训练（双卡）
python scripts/train_qlora.py

# 3. 合并 LoRA 权重（可选）
python scripts/merge_lora.py

# 4. 测试生成
python scripts/test_generation.py
```

### 训练时间估算

| 场景 | GPU | 数据量 | 时间 |
|-----|:---:|:------:|:----:|
| QLoRA, 3 epoch | 1× RTX 4090 | 5M tokens | ~14 小时 |
| QLoRA, 3 epoch | 2× RTX 4090 | 5M tokens | ~7-8 小时 |
| QLoRA, 1 epoch (快速实验) | 2× RTX 4090 | 5M tokens | ~2.5 小时 |

---

## 效果评估方案

### 方法一：报告质量盲评（核心）

| 维度 | 权重 | 评分标准 (1-5分) |
|------|:----:|------------------|
| **准确性** | 40% | 安全建议是否正确？是否有幻觉？ |
| **可读性** | 20% | 语言是否自然流畅？ |
| **建议质量** | 25% | 建议是否具体、可操作？ |
| **完整性** | 15% | 是否覆盖所有关键发现？ |

操作流程：

```
同一份事件数据 → 分别用以下模型生成报告
  ① 当前模板引擎（基线）
  ② 原版 SecGPT-7B
  ③ 微调版 SecGPT-7B
→ 打乱顺序 → 盲评打分
```

### 方法二：自动检测指标

从报告中提取安全性建议，与企业知识库中的已知正确策略匹配验证：

```python
# 匹配示例
"建议对 /api/download 实施路径白名单"  ✓ 匹配 enterprise_knowledge 策略
"建议对 /api/login 使用参数化查询"       ✓ 匹配 enterprise_knowledge 策略
"建议使用机器学习检测"                   ✗ 太笼统，扣分
```

### 方法三：A/B 测试

在 `report_generator.py` 中增加 `use_secgpt=True/False` 开关，Web 仪表盘 `/report` 页面添加下拉框切换模型源，实时对比两版报告差异。

### 快速验证建议

先用当前已有的 15 条事件数据，让微调前后的 SecGPT 各生成一份"洞察与建议"章节，花 10 分钟盲评对比。有明显提升再扩展到全报告生成。

---

## 集成到现有系统

### 替换 NLG 模块

修改 `incident_response/nlg_explainer.py`，增加 SecGPT 选项：

```python
class NlgExplainer:
    def __init__(self, use_secgpt=False):
        self.use_secgpt = use_secgpt
        if use_secgpt:
            from transformers import AutoModelForCausalLM, AutoTokenizer
            self.model = AutoModelForCausalLM.from_pretrained(
                "secgpt_finetune/models/secgpt-7B",
                device_map="auto",
                load_in_4bit=True,
            )
            self.tokenizer = AutoTokenizer.from_pretrained("secgpt_finetune/models/secgpt-7B")
```

### 替换报告生成

修改 `incident_response/report_generator.py`，对"洞察与建议"章节使用 SecGPT 生成替代模板填充。
