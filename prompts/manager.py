"""统一 Prompt 管理器。

集中管理项目中所有 LLM prompt 模板，支持：
- 文件加载：从 prompts/ 目录按路径加载
- 变量渲染：{var} 占位符替换
- 缓存：避免重复磁盘读取
- 回退：模板文件缺失时使用内置默认值

目录结构：
    prompts/
    ├── manager.py              # 本文件
    ├── system/                 # 系统角色 prompt
    ├── detection/              # 攻击检测 prompt（Stage 2 串行）
    ├── report/                 # 报告生成 prompt
    │   └── schemas/            # JSON 输出 schema
    ├── explanation/            # NLG 解释模板（YAML）
    └── misc/                   # 其他
"""
import os
import re
from typing import Any, Optional

PROMPT_ROOT = os.path.dirname(os.path.abspath(__file__))


class PromptManager:
    """统一 prompt 加载与渲染。"""

    def __init__(self, root: str = PROMPT_ROOT):
        self._root = root
        self._cache: dict[str, str] = {}

    # ── 核心 API ─────────────────────────────────

    def load(self, rel_path: str) -> str:
        """加载 prompt 文件内容（带缓存）。

        rel_path 相对于 prompts/ 根目录，如 "system/security_expert.txt"。
        """
        if rel_path not in self._cache:
            full = os.path.join(self._root, rel_path)
            if os.path.exists(full):
                with open(full, "r", encoding="utf-8") as f:
                    self._cache[rel_path] = f.read()
            else:
                self._cache[rel_path] = ""
        return self._cache[rel_path]

    def render(self, rel_path: str, **kwargs) -> str:
        """加载模板并用 kwargs 替换 {var} 占位符。"""
        template = self.load(rel_path)
        # 仅替换模板中存在的变量，未提供的保持原样
        def _replace(match):
            key = match.group(1)
            return str(kwargs.get(key, match.group(0)))
        return re.sub(r"\{(\w+)\}", _replace, template)

    def system_prompt(self, name: str) -> str:
        """加载 system 角色 prompt。"""
        return self.load(f"system/{name}.txt").strip()

    def detection_prompt(self, attack_type: str) -> str:
        """加载攻击检测 prompt。"""
        filename = _DETECTION_MAP.get(attack_type, "unified.txt")
        return self.load(f"detection/{filename}")

    def report_schema(self, name: str) -> str:
        """加载报告 JSON schema。"""
        return self.load(f"report/schemas/{name}.json")

    def explanation_template(self, name: str) -> str:
        """加载 NLG 解释模板。"""
        return self.load(f"explanation/{name}")

    def invalidate(self, rel_path: str = None):
        """清除缓存。"""
        if rel_path:
            self._cache.pop(rel_path, None)
        else:
            self._cache.clear()

    # ── 便捷方法 ─────────────────────────────────

    def build_report_prompt(self, report_type: str, **stats) -> str:
        """构建报告生成的完整 prompt（system + user + schema）。

        report_type: "comprehensive" | "crawler" | "incident"
        """
        user_tmpl = self.load(f"report/{report_type}_user.txt")
        schema = self.report_schema(f"{report_type}_report")
        rendered = user_tmpl
        for k, v in stats.items():
            rendered = rendered.replace("{" + k + "}", str(v))
        return rendered + "\n" + schema

    def build_detection_prompt(self, attack_type: str, **ctx) -> str:
        """构建攻击检测 prompt，注入上下文变量。"""
        template = self.detection_prompt(attack_type)
        for k, v in ctx.items():
            template = template.replace("{" + k + "}", str(v))
        return template


# ── 攻击类型 → 文件名 映射 ──────────────────────────

_DETECTION_MAP = {
    "injection attack": "injection_attack.txt",
    "directory traversal attack": "directory_traversal.txt",
    "cross-site scripting attack": "cross_site_scripting.txt",
    "performance issue": "performance_issue.txt",
    "invalid item value": "invalid_item_value.txt",
    "sensitive data leakage": "sensitive_data_leakage.txt",
    "unauthorized access attack": "unauthorized_access.txt",
}


# ── 全局单例 ──────────────────────────────────────

_prompt_manager: Optional[PromptManager] = None


def get_prompt_manager() -> PromptManager:
    """获取 PromptManager 单例。"""
    global _prompt_manager
    if _prompt_manager is None:
        _prompt_manager = PromptManager()
    return _prompt_manager
