# Malicious Crawler Detection — 恶意爬虫识别模块

从 API 流量中区分**正常用户**、**合法爬虫**与**恶意爬虫**，弥补主项目 `incident_response` 在攻击意图深层语义解析方面的能力缺口。

---

## 目录

- [设计思路](#设计思路)
- [项目结构](#项目结构)
- [流量模拟](#流量模拟)
- [特征工程](#特征工程)
- [检测方法](#检测方法)
- [实验结果](#实验结果)
- [集成到主项目](#集成到主项目)

---

## 设计思路

爬虫检测的核心挑战在于合法爬虫（Googlebot、Bingbot）与恶意爬虫（数据爬取、撞库、DDoS 工具）在行为模式上存在重叠——两者都具有高频率、高自动化特征。区别要点：

| 维度 | 正常用户 | 合法爬虫 | 恶意爬虫 |
|------|---------|---------|---------|
| 请求速率 | 稀疏（秒级间隔） | 适中（带礼貌延迟） | 高密（毫秒级间隔） |
| 路径分布 | 分散、有浏览逻辑 | 按 sitemap 遍历 | 集中或模式化重复 |
| UA 标识 | 浏览器 | 知名爬虫名 | 伪造/裸库名 |
| 敏感路径 | 极少 | 不访问 | 主动探测 |
| 单路径重复 | 偶发 | 周期遍历 | 连续高频 |

本方案提取 **20 维会话级行为特征**，通过规则 + 随机森林 + 孤立森林 + 集成投票进行多方法检测。

---

## 项目结构

```
malicious_crawler/
├── __init__.py            # 包声明，导出主要类
├── main.py                # 实验入口
├── traffic_simulator.py   # 流量数据生成
├── feature_engineering.py # 特征提取
├── detector.py            # 检测引擎（规则/RF/孤立森林/集成）
├── experiment_runner.py   # 实验编排与评估
├── data/                  # 生成的流量数据
│   └── crawler_traffic.csv
├── results/               # 实验结果
│   └── experiment_results.json
└── README.md
```

### 与主项目的关系

```
didi_stest/
├── llm_api_analyze/                         ← 检测引擎（RandomForest + RAG-LLM）
├── incident_response/           ← 事件响应与报告
├── malicious_crawler/ (本模块)  ← 爬虫行为检测
│
│   # 集成方式：
│   from malicious_crawler import EnsembleDetector, extract_all_features
│   from malicious_crawler.traffic_simulator import TrafficSimulator
```

各模块导入方式：

```python
# 训练检测器
from malicious_crawler.detector import EnsembleDetector
from malicious_crawler.feature_engineering import extract_all_features

records = [...]  # API 日志列表
features = extract_all_features(records)
detector = EnsembleDetector().train(features)
results = detector.predict(features, records_by_session)

# 生成模拟流量
from malicious_crawler.traffic_simulator import TrafficSimulator
sim = TrafficSimulator()
sim.generate_mixed_dataset(n_normal=100, n_legit=40, n_malicious=60)
```

---

## 流量模拟

`TrafficSimulator` 生成三类会话流量：

| 类别 | 方法 | 行为特征 |
|------|------|---------|
| 正常用户 | `generate_normal_session` | 3-15 请求/会话，浏览器 UA，3 秒平均间隔 |
| 合法爬虫 | `generate_legit_crawler_session` | 20-50 请求/会话，Googlebot/Bingbot 等 UA，0.5-5 秒间隔 |
| 恶意爬虫 | `generate_malicious_crawler_session` | 50-200 请求/会话，3 种模式： |

**恶意爬虫三种模式：**

| 模式 | 特征 |
|------|------|
| `scraper` | 高速遍历页面（100-500ms 间隔），主动探测敏感路径（15% 概率） |
| `credential_stuffer` | 集中访问 `/api/login`，50-300ms 间隔，大量 401/403 |
| `ddos_tool` | 单一目标端点，10-100ms 间隔，毫秒级峰值 |

---

## 特征工程

基于 `session_id` 分组，每个会话提取 **20 维数值特征**：

| 特征 | 说明 |
|------|------|
| `request_count` | 会话总请求数 |
| `duration_sec` | 会话持续时间 |
| `avg_interval_sec` | 请求平均间隔 |
| `min_interval_ms` | 请求最小间隔（毫秒） |
| `requests_per_second` | 全局请求速率 |
| `unique_paths` | 访问的不同路径数 |
| `path_diversity_ratio` | `unique_paths / request_count` |
| `path_repetition_rate` | 路径重复率（1 - 多样性） |
| `path_concentration` | 最频繁路径占比 |
| `sensitive_path_ratio` | 敏感路径（admin/payment/export 等）访问率 |
| `error_rate` | 4xx/5xx 占比 |
| `auth_fail_count` | 401+403 次数 |
| `post_ratio` | POST 请求占比 |
| `peak_rps_1s` | 1 秒滑动窗口内最大密度 |
| `peak_rps_5s` | 5 秒滑动窗口内最大密度 |
| `max_consecutive_same_path` | 连续同路径的最大次数 |
| `known_crawler_ua_ratio` | 知名爬虫 UA 占比 |
| `suspicious_ua_ratio` | 可疑 UA（python-requests/curl 等）占比 |

---

## 检测方法

| 方法 | 类型 | 说明 |
|------|------|------|
| **RuleDetector** | 规则 | 6 条专家规则（UA、速率、路径集中度、重复模式、敏感路径、撞库检测），权重累加 + sigmoid 映射 |
| **RFDetector** | 有监督 ML | RandomForest（n=200, max_depth=10, balanced） |
| **IForestDetector** | 无监督 ML | Isolation Forest（contamination=0.25）作为无监督基线 |
| **EnsembleDetector** | 集成 | 加权投票（RF 0.45 + Rule 0.35 + IForest 0.2） |

---

## 实验结果

**实验配置**：80 正常用户 + 30 合法爬虫 + 40 恶意爬虫（含 scraper/credential_stuffer/ddos_tool 三种模式），70:30 训练测试拆分。

### 总体指标

| 方法 | 准确率 | 精确率 | 召回率 | F1 | AUC | FPR |
|------|:------:|:------:|:------:|:---:|:---:|:---:|
| **规则检测** | 0.8444 | 0.6316 | 1.0000 | 0.7742 | 1.000 | 0.2121 |
| **随机森林** | **1.0000** | **1.0000** | **1.0000** | **1.0000** | 1.000 | **0.0000** |
| 孤立森林（无监督） | 0.9556 | 0.8571 | 1.0000 | 0.9231 | 0.503 | 0.0606 |
| **集成投票** | **1.0000** | **1.0000** | **1.0000** | **1.0000** | 1.000 | **0.0000** |

### 各类别召回率

| 方法 | 恶意爬虫 | 正常用户 | 合法爬虫 |
|------|:--------:|:--------:|:--------:|
| 规则检测 | 1.0000 | 0.8750 | 0.5556 |
| 随机森林 | 1.0000 | 1.0000 | 1.0000 |
| 孤立森林 | 1.0000 | 0.9167 | 1.0000 |
| 集成投票 | 1.0000 | 1.0000 | 1.0000 |

### 特征重要性（RandomForest Top-10）

| 特征 | 重要性 |
|------|:------:|
| request_count | 0.150 |
| path_repetition_rate | 0.120 |
| requests_per_second | 0.110 |
| suspicious_ua_ratio | 0.105 |
| peak_rps_5s | 0.100 |
| avg_interval_sec | 0.095 |
| error_rate | 0.080 |
| min_interval_ms | 0.070 |
| path_diversity_ratio | 0.065 |
| peak_rps_1s | 0.055 |

### 关键结论

1. **随机森林和集成投票取得完美效果**（F1=1.0），验证了 20 维会话行为特征对于模拟场景下三种流量类型具有良好区分度。规则检测的弱势在于合法爬虫识别（recall=0.5556），因为合法爬虫的 UA 特征和速率行为与部分正常用户难以硬阈值区分。

2. **规则检测召回率 100%** 但精确率偏低（0.6316），说明规则倾向于"宁可误报不可漏报"，适合作为第一道防线。

3. **孤立森林作为无监督基线表现良好**（F1=0.9231），在无标签条件下可有效识别异常流量，适用于生产环境冷启动阶段。

4. **会话级特征远优于单请求级特征**——单条日志无法判断是否为爬虫，但聚合到一个会话（通常包含几十到几百条请求）后，速率、路径集中度、UA 特征形成清晰的区分信号。

---

## 集成到主项目

### 方案一：作为 Stage 0 预过滤

在主项目的流水线中，将爬虫检测作为 Stage 0 前置过滤，先识别并标记爬虫流量，再进入 RandomForest + LLM 的攻击检测：

```python
from malicious_crawler.detector import EnsembleDetector, extract_all_features

def pipeline_with_crawler_filter(logs: list[dict]):
    # Step 0: 爬虫检测
    features = extract_all_features(logs)
    detector = EnsembleDetector()
    detector.train(features)  # 生产环境应持久化模型
    crawler_results = detector.predict(features)
    
    # 过滤掉正常用户和合法爬虫的日志
    malicious_sessions = {r["session_id"] for r in crawler_results if r["pred_label"] == 1}
    filtered_logs = [log for log in logs if log["session_id"] not in malicious_sessions]
    
    # 进入 Stage 1 & 2
    return filtered_logs
```

### 方案二：作为健康评分输入

将爬虫检测结果纳入 `HealthTracker` 的健康评分因子：

```python
# incident_response/health_tracker.py
crawler_activity = compute_crawler_ratio(endpoint)  # 来自恶意爬虫模块
health_delta = -0.1 * crawler_activity  # 爬虫活跃度 → 健康分扣减
```

### 方案四：完整集成流水线（Pipeline）

从检测到报告输出一条龙，使用本地 SecGPT-7B+LoRA 生成分析报告：

```python
from malicious_crawler.pipeline import CrawlerPipeline

# 完整流水线（生成模拟数据 → 检测 → SecGPT 报告）
pipeline = CrawlerPipeline()
pipeline.run()  # 报告保存至 docs/crawler_security_report_*.md

# 使用自己的数据
pipeline.run(data_path="/path/to/traffic.csv")
```

```bash
# 命令行运行
/root/anaconda3/envs/didienv/bin/python -m malicious_crawler.pipeline

# 自定义会话数
/root/anaconda3/envs/didienv/bin/python -m malicious_crawler.pipeline \
    --normal 100 --legit 20 --distributed 50 --crowdsourced 50
```

**输出：**
- `docs/crawler_security_report_*.md` — 完整爬虫安全态势报告
- `malicious_crawler/results/pipeline_summary.json` — 结构化检测摘要

**环境要求：**
- Python 3.10（didienv 环境）
- CUDA 12.6+（驱动 ≥ 570），单卡 RTX 4090，模型需 ~5.3GB VRAM
- 依赖：torch 2.7.1+cu126, transformers 4.57.1, peft 0.19.1, bitsandbytes 0.45.4

### 方案三：作为独立检测服务

通过 REST API 独立部署：

```python
# 快速 API 封装
from flask import Flask, request
from malicious_crawler import EnsembleDetector

app = Flask(__name__)
detector = EnsembleDetector()  # 预加载

@app.route("/detect/crawler", methods=["POST"])
def detect():
    logs = request.json["logs"]
    features = extract_all_features(logs)
    results = detector.predict(features)
    return {"results": results}
```

---

## 用法

```bash
# 从项目根目录运行
cd /root/didi_stest

# 默认实验（80 正常 + 30 合法 + 40 恶意）
python -m malicious_crawler.main

# 自定义会话数
python -m malicious_crawler.main --normal 200 --legit 50 --malicious 100

# 使用已有数据
python -m malicious_crawler.main --data malicious_crawler/data/crawler_traffic.csv
```

### 输出

- 生成数据：`malicious_crawler/data/crawler_traffic.csv`
- 实验结果：`malicious_crawler/results/experiment_results.json`
- 控制台输出：4 种方法的准确率/精确率/召回率/F1/AUC/FPR 对比表 + 特征重要性 Top-10

---

## 综合检测流水线（最新）

`engine/run_comprehensive.py` 整合了全攻击类型（10种API攻击 + 5种爬虫模式）的端到端检测链路：

### 最新运行结果（6881 条数据）

```
Step 1: 数据生成
  → 10 种 API 攻击 × 290 条 + 正常用户 465 条 + 合法爬虫 303 条
  → 恶意爬虫 2404 条 + 分布式爬虫 778 条 + 众包爬虫 31 条
  → 总计 6881 条 / 3070 会话

Step 2: Stage 1 — RandomForest 二分类
  → 16 维特征 → 攻击召回率 100% (6113/6113)
  → 过滤 11.2% 正常流量

Step 3: Stage 2 — 策略隔离串行检测
  → 确认攻击 1160 条（XSS, 敏感泄露, 性能问题, 无效参数等）

Step 4: 爬虫检测
  → Ensemble: 恶意 86 / 正常 82 会话
  → 三层融合: 分布式爬虫 36 会话 / 众包爬虫 14 会话

Step 5: SecGPT-7B+LoRA 综合报告
  → VRAM 5.3GB, ~2min 加载+推理, 完整 Markdown 报告
  → 同时覆盖 API 攻击分析和爬虫分析
```

### 支持的检测类型

| 类别 | 数量 | 类型 |
|------|:----:|------|
| API 攻击 | 10 | SQL注入, XSS, 目录遍历, 越权访问, 敏感数据泄露, 命令注入, SSRF, CSRF, 性能问题, 无效参数 |
| 恶意爬虫 | 3 | scraper, credential_stuffer, ddos_tool |
| 分布式爬虫 | 1 | 时序关联 + 覆盖分析 + 网络拓扑融合 |
| 众包爬虫 | 1 | 碎片化覆盖分析（空闲率+完整度） |
