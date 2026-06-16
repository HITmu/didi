# shared — 共享工具模块

LLM API 和 SEC 安全分析器共享的通用工具函数。

## 文件说明

| 文件 | 说明 |
|------|------|
| `__init__.py` | 模块初始化，导出 `load_json` 和 `save_json` |
| `metrics.py` | 二分类评估指标（准确率、精确率、召回率、F1、AUC）、LLM 调用成本计算、JSON 存储 |
| `persistence.py` | **新增** JSON 持久化工具，提供 `load_json` / `save_json` 统一接口，自动处理文件不存在和目录创建 |

## 使用示例

```python
from shared import load_json, save_json

# 加载（文件不存在时返回默认值）
data = load_json("incidents.json", default=[])

# 保存（自动创建父目录）
save_json("output/report.json", {"status": "ok"})
```

## 注意

当前流水线使用本地 SecGPT-7B + LoRA 模型进行 Stage 2 检测，LLM 调用成本为 0（无外部 API 费用）。
