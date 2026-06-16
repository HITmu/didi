"""RAG提示词构建器 - 使用攻击特定策略模板构建LLM提示词。"""

import os
import tiktoken


class RAGPromptBuilder:
    """使用预加载的策略模板为每种攻击类型构建针对性提示词。"""

    PROMPT_FILES = {
        "injection attack": "injection_attack.txt",
        "directory traversal attack": "directory_traversal.txt",
        "cross-site scripting attack": "cross_site_scripting.txt",
        "performance issue": "performance_issue.txt",
        "invalid item value": "invalid_item_value.txt",
        "sensitive data leakage": "sensitive_data_leakage.txt",
        "unauthorized access attack": "unauthorized_access.txt",
    }

    def __init__(self, attack_strategies_dir="attack_strategies", prompt_dir="prompts"):
        self.attack_strategies_dir = attack_strategies_dir
        self.prompt_dir = prompt_dir
        self.prompt_templates = {}
        if prompt_dir:
            self._load_prompt_templates()

    def _load_prompt_templates(self):
        """从统一 PromptManager 加载全部7个攻击类型的提示词模板。"""
        from prompts.manager import get_prompt_manager
        pm = get_prompt_manager()
        print(f"Loading prompt templates from PromptManager")
        for attack_type in self.PROMPT_FILES:
            content = pm.detection_prompt(attack_type)
            if content:
                self.prompt_templates[attack_type] = content
                print(f"  Loaded: {attack_type}")
        print(f"Total templates loaded: {len(self.prompt_templates)}")

    @staticmethod
    def count_tokens(text):
        """估算token数量。"""
        try:
            return len(tiktoken.get_encoding("gpt2").encode(text))
        except Exception:
            return len(text) // 4

    def build_targeted_prompt(self, batch_logs, start_idx, similar_events_map, target_attack_type):
        """构建针对特定攻击类型的提示词。

        结构：
          1. 攻击策略模板（专家知识）
          2. 日志详情
          3. 来自向量数据库的相似历史事件（RAG上下文）
          4. 输出格式指令
        """
        log_id = start_idx
        template = self.prompt_templates.get(target_attack_type)
        if not template:
            return self._create_default_prompt(target_attack_type)

        prompt = template.replace("{log_id}", str(log_id))
        prompt += self._add_log_content_section(batch_logs, log_id)

        if "HISTORICAL SIMILAR PATTERNS" not in prompt:
            prompt += self._add_similar_events_section(log_id, similar_events_map, target_attack_type)

        prompt += "\n## FINAL OUTPUT - START HERE:\n"
        prompt += "**ONLY OUTPUT THE RESULT IN THE SPECIFIED FORMAT**\n"
        return prompt

    def _add_log_content_section(self, batch_logs, log_id):
        """格式化日志条目用于提示词中。"""
        try:
            log = batch_logs[0]
            method = log[0] if len(log) > 0 else "unknown"
            request_body = str(log[1]) if len(log) > 1 else "unknown"
            request_url = log[2] if len(log) > 2 else "unknown"
            response_body = str(log[3]) if len(log) > 3 else "unknown"
            status = log[4] if len(log) > 4 else "unknown"
            response_time = log[5] if len(log) > 5 else "unknown"
            user_identity = log[6] if len(log) > 6 else "unknown"

            return (
                f"\n## LOG DETAILS (ID: {log_id}):\n"
                f"- Method: {method}\n"
                f"- URL: {request_url}\n"
                f"- Status: {status}\n"
                f"- Response Time: {response_time}ms\n"
                f"- User Identity: {user_identity}\n"
                f"- Request Body: {request_body}\n"
                f"- Response Body: {response_body}\n"
            )
        except Exception as e:
            return f"\nError parsing log {log_id}: {e}\n"

    def _add_similar_events_section(self, log_id, similar_events_map, target_attack_type):
        """添加RAG检索到的相似事件以提供上下文。"""
        section = "\n## HISTORICAL SIMILAR PATTERNS:\n"
        events = similar_events_map.get(log_id, [])
        relevant = [e for e in events[:2]
                    if e.get('metadata', {}).get('anomaly_type') == target_attack_type]

        if relevant:
            for ev in relevant:
                section += f"Historical {target_attack_type}: {ev['content'][:200]}...\n"
        else:
            section += f"No historical {target_attack_type} patterns found.\n"
        return section

    @staticmethod
    def _create_default_prompt(target_attack_type):
        """回退的默认提示词模板。"""
        return f"""
You are a security expert. Analyze the log and determine if it's a {target_attack_type}.
Output format: log_id|type|anomaly_type|confidence|reason
If normal: log_id|normal
If anomaly: log_id|anomaly|{target_attack_type}|confidence|specific reason
Log ID: {{log_id}}
"""
