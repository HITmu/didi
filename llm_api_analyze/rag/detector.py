"""串行攻击检测器 - 对每条日志依次检测7种攻击类型。"""

import os
import re
import asyncio
import aiohttp
import json
from datetime import datetime

from llm_api_analyze.config import (
    ATTACK_TYPES_ORDER, REQUEST_INTERVAL, BATCH_FILE_SIZE,
    LLM_MODEL, HEADERS, LLM_API_URL
)


class SerialAttackDetector:
    """通过逐个检测攻击类型来发现异常。

    对每条日志：
      1. 尝试攻击类型1 -> 如果异常，停止
      2. 尝试攻击类型2 -> 如果异常，停止
      ...
      7. 如果全部通过 -> 正常
    """

    def __init__(self, prompt_builder, api_url=None, headers=None):
        self.prompt_builder = prompt_builder
        self.api_url = api_url or LLM_API_URL
        self.headers = headers or HEADERS

    async def detect_serial(self, log_data, log_id, similar_events_map):
        """对一条日志执行所有攻击类型的串行检测。"""
        attack_types = self._get_attack_types_in_order()
        if not attack_types:
            return self._default_result(log_id, "normal", "", "No prompt templates available")

        print(f"Serial detection for log {log_id}: {len(attack_types)} attack types")
        async with aiohttp.ClientSession() as session:
            for idx, attack_type in enumerate(attack_types, 1):
                print(f"  Step {idx}/{len(attack_types)}: checking {attack_type}...")
                prompt = self.prompt_builder.build_targeted_prompt(
                    [log_data], log_id, similar_events_map, attack_type
                )
                if idx > 1:
                    await asyncio.sleep(REQUEST_INTERVAL)

                result = await self._call_api(session, prompt, log_id, attack_type)
                if result and result[1] == "anomaly":
                    print(f"  => ANOMALY: {attack_type}")
                    return result
                elif result and result[1] == "normal":
                    print(f"  => normal for {attack_type}")
                    continue
                else:
                    print(f"  => skipped (API error)")

            print(f"  => all clear, marking normal")
            return self._default_result(log_id, "normal", "", "All attack types cleared")

    def _get_attack_types_in_order(self):
        available = list(self.prompt_builder.prompt_templates.keys())
        return [t for t in ATTACK_TYPES_ORDER if t in available]

    async def _call_api(self, session, prompt, log_id, attack_type):
        """调用LLM API并解析响应。"""
        try:
            payload = {
                "model": LLM_MODEL,
                "messages": [
                    {"role": "system", "content": "You are a security expert analyzing web request logs."},
                    {"role": "user", "content": prompt}
                ],
                "temperature": 0.1,
                "max_tokens": 500,
                "stop": ["###", "\n\n"],
                "stream": False
            }
            async with session.post(self.api_url, json=payload, headers=self.headers, timeout=120) as resp:
                if resp.status != 200:
                    print(f"  API error {resp.status} for log {log_id} / {attack_type}")
                    return None
                data = await resp.json()
                if "error" in data or "choices" not in data or not data["choices"]:
                    return None
                content = data["choices"][0]["message"]["content"].strip()
                self._save_raw_result(content, log_id, attack_type)
                return self._parse_output(content, log_id, attack_type)

        except asyncio.TimeoutError:
            print(f"  Timeout for log {log_id} / {attack_type}")
            return None
        except Exception as e:
            print(f"  API exception for log {log_id}: {e}")
            return None

    def _parse_output(self, content, expected_id, attack_type):
        """逐行解析LLM输出以检测异常/正常。"""
        try:
            for line in content.split("\n"):
                line = line.strip()
                if not line or any(h in line.lower() for h in
                                   ["number|type", "number|detection", "logid", "output format",
                                    "begin output", "final output", "output now"]):
                    continue
                if "|" not in line:
                    continue

                parts = [p.strip() for p in line.split("|")]
                if len(parts) < 2:
                    continue

                # 提取日志ID
                log_id = expected_id
                nums = re.findall(r'\d+', parts[0])
                if nums:
                    try:
                        found = int(nums[0])
                        if abs(found - expected_id) <= 10:
                            log_id = found
                    except ValueError:
                        pass

                detection = parts[1].lower()

                if detection == "normal":
                    return self._default_result(log_id, "normal", "", f"No {attack_type} detected")
                elif detection == "anomaly":
                    # 格式: log_id|anomaly|attack_type|confidence|reason
                    anomaly_type = parts[2] if len(parts) >= 3 else attack_type
                    confidence = 0.9
                    if len(parts) >= 5:
                        try:
                            confidence = max(0.0, min(1.0, float(parts[3])))
                        except ValueError:
                            pass
                    reason = parts[4] if len(parts) >= 5 else (parts[3] if len(parts) >= 4 else "")
                    return self._default_result(log_id, "anomaly", anomaly_type, reason, confidence)
                else:
                    # 回退：关键词匹配
                    if attack_type.lower() in line.lower():
                        return self._default_result(log_id, "anomaly", attack_type,
                                                    f"Detected {attack_type} pattern", 0.85)
                    for known in ATTACK_TYPES_ORDER:
                        if known.lower() in line.lower():
                            return self._default_result(log_id, "anomaly", known,
                                                        f"Detected {known} pattern", 0.8)
            return None
        except Exception as e:
            print(f"Parse error: {e}")
            return None

    def _save_raw_result(self, content, log_id, attack_type):
        """保存原始分析结果到日志文件。"""
        try:
            ts = datetime.now().strftime('%H:%M:%S')
            preview = content[:150] + "..." if len(content) > 150 else content
            with open("serial_detection.log", "a", encoding="utf-8") as f:
                f.write(f"[{ts}] Log {log_id} - {attack_type}: {preview}\n")
        except Exception:
            pass

    @staticmethod
    def _default_result(log_id, result_type, anomaly_type, reason, confidence=0.5):
        status = "Success" if result_type != "error" else "Failed"
        return [log_id, result_type, anomaly_type, round(confidence, 4), reason, status]
