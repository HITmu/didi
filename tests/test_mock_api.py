"""模拟 LLM API 服务器测试。"""

import os
import sys
import json
import time
import pytest
import requests
import subprocess
import signal

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ==================== 服务器管理 ====================

@pytest.fixture(scope="module")
def mock_server():
    """启动模拟 LLM 服务器用于测试。"""
    import threading
    import uvicorn
    from tests.mock_llm_server import app

    port = 18001  # 使用不同端口以避免冲突
    url = f"http://127.0.0.1:{port}"

    config = uvicorn.Config(app, host="0.0.0.0", port=port, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run)
    thread.daemon = True
    thread.start()

    # 等待服务器启动
    for _ in range(20):
        try:
            r = requests.get(f"{url}/health", timeout=2)
            if r.status_code == 200:
                break
        except requests.ConnectionError:
            time.sleep(0.3)

    yield {"url": url, "server": server}
    server.should_exit = True
    thread.join(timeout=5)


# ==================== API 测试 ====================

class TestMockAPI:
    """测试模拟 LLM API 服务器端点。"""

    def test_health_check(self, mock_server):
        """GET /health 应返回健康状态。"""
        r = requests.get(f"{mock_server['url']}/health", timeout=5)
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "healthy"

    def test_chat_completion_normal(self, mock_server):
        """POST /v1/chat/completions 使用正常日志应返回'normal'。"""
        payload = {
            "model": "test-model",
            "messages": [
                {"role": "system", "content": "You are a security expert."},
                {"role": "user", "content": "Log ID: 5 | 检查注入攻击 | Method: GET | URL: /api/status | Body: 正常请求"}
            ],
            "temperature": 0.1,
            "max_tokens": 500
        }
        r = requests.post(
            f"{mock_server['url']}/v1/chat/completions",
            json=payload,
            timeout=10
        )
        assert r.status_code == 200
        data = r.json()
        assert "choices" in data
        content = data["choices"][0]["message"]["content"]
        # 应为'normal'，因为没有攻击关键词
        assert "normal" in content.lower()

    def test_chat_completion_dir_traversal(self, mock_server):
        """应从提示内容中检测目录遍历。"""
        payload = {
            "model": "test-model",
            "messages": [
                {"role": "user", "content": "Log ID: 10 | 检查目录遍历攻击 | URL: /api/../../../etc/passwd | Method: GET"}
            ]
        }
        r = requests.post(
            f"{mock_server['url']}/v1/chat/completions",
            json=payload,
            timeout=10
        )
        data = r.json()
        content = data["choices"][0]["message"]["content"]
        assert "anomaly" in content.lower()
        assert "directory traversal" in content.lower()

    def test_chat_completion_xss(self, mock_server):
        """应从提示内容中检测 XSS。"""
        payload = {
            "model": "test-model",
            "messages": [
                {"role": "user", "content": "Log ID: 15 | 检查跨站脚本攻击 | Body: <script>alert('xss')</script>"}
            ]
        }
        r = requests.post(
            f"{mock_server['url']}/v1/chat/completions",
            json=payload,
            timeout=10
        )
        data = r.json()
        content = data["choices"][0]["message"]["content"]
        assert "anomaly" in content.lower()
        assert "xss" in content.lower() or "script" in content.lower()

    def test_api_format_compatibility(self, mock_server):
        """响应格式应与 OpenAI 兼容模式匹配。"""
        payload = {
            "model": "test-model",
            "messages": [{"role": "user", "content": "Log ID: 1|anomaly|test"}],
            "stream": False
        }
        r = requests.post(
            f"{mock_server['url']}/v1/chat/completions",
            json=payload,
            timeout=10
        )
        data = r.json()
        # OpenAI 格式：choices[0].message.content
        assert "choices" in data
        assert len(data["choices"]) > 0
        assert "message" in data["choices"][0]
        assert "content" in data["choices"][0]["message"]

    def test_empty_prompt_handling(self, mock_server):
        """应优雅地处理最小提示词。"""
        payload = {
            "model": "test-model",
            "messages": [{"role": "user", "content": ""}]
        }
        r = requests.post(
            f"{mock_server['url']}/v1/chat/completions",
            json=payload,
            timeout=10
        )
        assert r.status_code == 200

    def test_reset_mode(self, mock_server):
        """POST /reset 应更改响应模式。"""
        r = requests.post(
            f"{mock_server['url']}/reset",
            json={"mode": "anomaly", "anomaly_rate": 0.5},
            timeout=5
        )
        assert r.status_code == 200
        data = r.json()
        assert data["mode"] == "anomaly"

        # 重置回 auto
        requests.post(
            f"{mock_server['url']}/reset",
            json={"mode": "auto"},
            timeout=5
        )

    def test_serial_detection_mock_sequence(self, mock_server):
        """模拟一条日志的 7 次串行检测调用。"""
        attack_types = [
            "directory traversal attack",
            "cross-site scripting attack",
            "unauthorized access attack",
            "injection attack",
            "performance issue",
            "sensitive data leakage",
            "invalid item value"
        ]
        results = []
        for at in attack_types:
            payload = {
                "model": "test-model",
                "messages": [{"role": "user", "content": f"Log ID: 20 | 分析 {at} | URL: /api/test"}]
            }
            r = requests.post(
                f"{mock_server['url']}/v1/chat/completions",
                json=payload,
                timeout=10
            )
            content = r.json()["choices"][0]["message"]["content"]
            results.append({
                "attack_type": at,
                "response": content,
                "is_anomaly": "anomaly" in content.lower()
            })

        # 应找到至少一个异常或全部正常
        assert len(results) == 7
        for r in results:
            assert "normal" in r["response"].lower() or "anomaly" in r["response"].lower()
