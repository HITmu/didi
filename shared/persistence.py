"""共享 JSON 持久化工具，消除各模块中重复的 _load_json / _save_json 模式。"""
import json
import os
from typing import Any, Optional


def load_json(path: str, default: Any = None) -> Any:
    """从 JSON 文件加载数据，文件不存在时返回 default。"""
    if not os.path.exists(path):
        return default
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path: str, data: Any) -> None:
    """将数据写入 JSON 文件，自动创建父目录。"""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2, default=str)
