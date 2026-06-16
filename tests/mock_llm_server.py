"""用于测试的模拟 LLM API 服务器（FastAPI）。

模拟 LLM/本地模型 API 在 Stage 2 串行检测中的响应。
支持可配置的行为：始终正常、始终异常或基于类型检测。

用法：
    python tests/mock_llm_server.py          # 在端口 18000 上启动
    python tests/mock_llm_server.py --port 19000 --mode anomaly
"""

import argparse
import json
import re
import random
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI(title="用于安全分析测试的模拟 LLM 服务器")

# 可配置行为
RESPONSE_MODE = "auto"  # auto、normal、anomaly、mixed
FIXED_ATTACK_TYPE = "injection attack"
FIXED_CONFIDENCE = 0.92
ANOMALY_RATE = 0.3  # 混合模式使用

ATTACK_TYPES = [
    "directory traversal attack",
    "cross-site scripting attack",
    "unauthorized access attack",
    "injection attack",
    "performance issue",
    "sensitive data leakage",
    "invalid item value"
]


def detect_attack_from_prompt(prompt: str):
    """通过扫描提示词中的攻击签名来模拟检测。"""
    log_text = prompt.lower()

    # 简单的关键词匹配以模拟真实检测
    if "../" in log_text or "/etc/" in log_text or "directory traversal" in log_text:
        return "directory traversal attack", 0.95, "在请求 URL 中检测到路径遍历模式"
    if "<script" in log_text or "javascript:" in log_text or "xss" in log_text:
        return "cross-site scripting attack", 0.93, "在请求体中检测到 XSS 模式"
    if "' or" in log_text or "union select" in log_text or "sql injection" in log_text:
        return "injection attack", 0.94, "检测到 SQL 注入模式"
    if "password" in log_text and ("=" in log_text or ":" in log_text):
        return "sensitive data leakage", 0.91, "在响应中检测到敏感数据模式"
    if "/admin" in log_text or "unauthorized" in log_text:
        return "unauthorized access attack", 0.90, "未授权访问管理端点"
    if "limit" in log_text and "rows" in log_text:
        return "performance issue", 0.88, "性能问题：大量数据查询"
    if "null" in log_text or "undefined" in log_text:
        return "invalid item value", 0.87, "检测到无效参数值"

    return None, 0.0, ""


@app.post("/v1/chat/completions")
async def chat_completions(request: Request):
    """模拟 OpenAI 兼容的聊天补全 API。"""
    body = await request.json()

    # 提取提示词
    messages = body.get("messages", [])
    prompt = ""
    for msg in messages:
        if msg.get("role") == "user":
            prompt += msg.get("content", "")
        elif msg.get("role") == "system":
            prompt += msg.get("content", "")

    # 从提示词中提取日志 ID
    log_id_match = re.search(r'ID:?\s*(\d+)', prompt)
    log_id = log_id_match.group(1) if log_id_match else "0"

    # 从提示词中提取攻击类型
    attack_type = None
    for at in ATTACK_TYPES:
        if at.lower() in prompt.lower():
            attack_type = at
            break

    # 根据模式确定响应
    if RESPONSE_MODE == "normal":
        is_anomaly = False
    elif RESPONSE_MODE == "anomaly":
        is_anomaly = True
    elif RESPONSE_MODE == "mixed":
        is_anomaly = random.random() < ANOMALY_RATE
    else:  # auto - 智能检测
        detected_type, conf, reason = detect_attack_from_prompt(prompt)
        if detected_type:
            response_text = f"{log_id}|anomaly|{detected_type}|{conf}|{reason}"
        else:
            response_text = f"{log_id}|normal"
        return JSONResponse({
            "choices": [{"message": {"content": response_text}}]
        })

    if is_anomaly:
        at = attack_type or FIXED_ATTACK_TYPE
        response_text = f"{log_id}|anomaly|{at}|{FIXED_CONFIDENCE}|用于测试的模拟检测"
    else:
        response_text = f"{log_id}|normal"

    return JSONResponse({
        "choices": [{"message": {"content": response_text}}]
    })


@app.get("/health")
async def health():
    return {"status": "healthy", "mode": RESPONSE_MODE}


@app.post("/reset")
async def reset_mode(request: Request):
    """在运行时更改响应模式。"""
    global RESPONSE_MODE, ANOMALY_RATE
    body = await request.json()
    RESPONSE_MODE = body.get("mode", "auto")
    ANOMALY_RATE = body.get("anomaly_rate", 0.3)
    return {"status": "reset", "mode": RESPONSE_MODE, "anomaly_rate": ANOMALY_RATE}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=18000)
    parser.add_argument("--mode", type=str, default="auto",
                        choices=["auto", "normal", "anomaly", "mixed"])
    parser.add_argument("--anomaly-rate", type=float, default=0.3)
    args = parser.parse_args()

    global RESPONSE_MODE, ANOMALY_RATE
    RESPONSE_MODE = args.mode
    ANOMALY_RATE = args.anomaly_rate

    print(f"模拟 LLM 服务器正在端口 {args.port} 上启动")
    print(f"  模式：{RESPONSE_MODE}")
    print(f"  异常率：{ANOMALY_RATE}")
    uvicorn.run(app, host="0.0.0.0", port=args.port, log_level="info")


if __name__ == "__main__":
    main()
