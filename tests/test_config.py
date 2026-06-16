"""测试配置 — 指向模拟服务器而非真实 API。"""

# 模拟服务器端点
MOCK_API_URL = "http://127.0.0.1:18000/v1/chat/completions"
MOCK_SERVER_PORT = 18000

# 测试数据路径（相对于项目根目录）
import os
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEST_TRAIN_CSV = os.path.join(PROJECT_ROOT, "final_training_data.csv")
TEST_INPUT_CSV = os.path.join(PROJECT_ROOT, "test_without_type.csv")
TEST_GROUND_TRUTH = os.path.join(PROJECT_ROOT, "cleaned_test.csv")
STAGE1_RESULT = os.path.join(PROJECT_ROOT, "stage1_test_result.csv")

# 模拟 API 的请求头
MOCK_HEADERS = {
    "Authorization": "Bearer mock-key",
    "Content-Type": "application/json"
}

# 用于测试的配置覆盖
LLM_OVERRIDE = {
    "LLM_API_URL": MOCK_API_URL,
    "LLM_API_KEY": "mock-key",
    "EMBEDDING_MODEL_PATH": "/root/.cache/modelscope/hub/models/BAAI/bge-large-en-v1.5",
}

SEC_OVERRIDE = {
    "API_URL": MOCK_API_URL,
    "HEADERS": MOCK_HEADERS,
    "EMBEDDING_MODEL_PATH": "/root/.cache/modelscope/hub/models/BAAI/bge-large-en-v1.5",
}
