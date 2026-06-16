"""LLM API 配置（大模型 API 版本）。"""

# ==================== LLM API 配置 ====================
# 支持 OpenAI 兼容 API（GPT-4o, Claude Opus 等）
LLM_API_KEY = "your-api-key-here"
LLM_API_URL = "https://api.openai.com/v1/chat/completions"
LLM_MODEL = "gpt-4o"

HEADERS = {
    "Authorization": f"Bearer {LLM_API_KEY}",
    "Content-Type": "application/json"
}

# ==================== 文件路径 ====================
MODEL_TRAIN_CSV = "final_training_data.csv"
RAG_KB_CSV = "sampled_dataset.csv"
TEST_CSV = "test_without_type.csv"
GROUND_TRUTH_CSV = "cleaned_test.csv"
OUTPUT_CSV = "rag_analysis_result.csv"

# ==================== 模型参数 ====================
PREDICTION_THRESHOLD = 0.017
RANDOM_SEED = 42

# ==================== RAG 配置 ====================
EMBEDDING_MODEL_PATH = "./models/bge-large-en-v1.5"
CURRENT_SIMILARITY_THRESHOLD = 0.8
MAX_CONTEXT_TOKENS = 8192
RESERVE_BASE_TOKENS = 1500

# ==================== 攻击类型（检测顺序） ====================
ATTACK_TYPES_ORDER = [
    "directory traversal attack",
    "cross-site scripting attack",
    "unauthorized access attack",
    "injection attack",
    "performance issue",
    "sensitive data leakage",
    "invalid item value"
]

# ==================== 处理配置 ====================
BATCH_FILE_SIZE = 50
REQUEST_INTERVAL = 1
LONG_BREAK_INTERVAL = 5
MAX_RETRIES = 3
RETRY_DELAY = 15

# ==================== 输出配置 ====================
MAIN_OUTPUT_DIR = "llm_serial_detection"
PROMPT_DIR = "prompts"
