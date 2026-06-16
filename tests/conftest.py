"""共享的 pytest 配置。"""

import os
import sys

# 将项目根目录添加到 Python 路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def pytest_configure(config):
    """注册自定义标记。"""
    config.addinivalue_line("markers", "slow: 标记慢速测试（使用 '-m \"not slow\"' 排除）")
    config.addinivalue_line("markers", "api: 标记需要模拟 API 服务器的测试")
    config.addinivalue_line("markers", "e2e: 标记端到端流水线测试")
