"""应急响应系统：分派、通知、健康追踪和 RAG 知识内化。

与级联检测流水线 (llm_api_analyze) 集成，实现：
  1. 基于严重程度和置信度路由事件（自动记录 vs 通知）
  2. 将责任人绑定到 API 端点
  3. 追踪分派前后的 API 健康状态
  4. 将分派结果内化为 RAG 知识
"""

__version__ = "1.0.0"

from .enterprise_knowledge import EnterpriseKnowledgeBase
