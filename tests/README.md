# tests — 测试套件

该目录包含安全日志分析系统的完整测试套件，共计 74 项测试。

## 文件说明

| 文件 | 说明 |
|------|------|
| `__init__.py` | 测试包初始化 |
| `conftest.py` | pytest 共享配置，注册自定义标记（slow、api、e2e） |
| `quick_test.py` | 快速独立测试脚本（无需 pytest），用于 Stage1 验证、RAG 报告、配置检查 |
| `mock_llm_server.py` | 模拟 LLM API 服务器（FastAPI），用于 Stage2 串行检测测试 |
| `test_config.py` | 测试配置，指向模拟服务器 |
| `test_incident_response.py` | 事件响应系统测试（人员绑定、处置、健康、知识）：40 项 |
| `test_mock_api.py` | 模拟 LLM API 服务器端点测试：8 项 |
| `test_pipeline.py` | 端到端流水线测试（含模拟 LLM API 服务器）：8 项 |
| `test_stage1.py` | Stage1 特征提取与二分类测试：15 项 |
| `benchmark/` | 基准测试子目录 |
| `run_tests.sh` | 测试运行脚本 |
| `TEST_REPORT.md` | 测试报告 |
| `TEST_STEPS.md` | 测试步骤文档 |

## 运行方式

```bash
# 运行全部测试
pytest tests/ -v

# 运行特定模块
pytest tests/test_stage1.py -v
pytest tests/test_incident_response.py -v
pytest tests/test_pipeline.py -v
pytest tests/test_mock_api.py -v

# 运行快速检查（无需 pytest）
/root/anaconda3/envs/rag/bin/python tests/quick_test.py
```

## 测试分布

| 模块 | 测试数 | 覆盖范围 |
|------|:------:|----------|
| incident_response | 40 | DispositionEngine, HealthTracker, KnowledgeInternalizer, PersonBinding, EnterpriseKnowledge |
| stage1 | 15 | 特征提取、RandomForest 分类器、配置一致性 |
| mock_api | 8 | 模拟 LLM API 端点、请求/响应验证 |
| pipeline | 8 | 端到端流水线、Mock API 集成 |
| quick_test | 3 | Stage1 验证、RAG 报告、配置检查 |
