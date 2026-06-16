"""恶意爬虫识别模块。

用于从API流量中区分正常用户、合法爬虫与恶意爬虫。
可与主项目 incident_response 模块集成使用。

主要组件：
- traffic_simulator：模拟正常/恶意爬虫流量数据生成
- feature_engineering：从原始流量中提取行为特征
- detector：检测引擎（规则 + ML 多方法）
- distributed_detector：分布式/众包爬虫三层融合检测
- experiment_runner：实验编排与评估
- pipeline：完整集成流水线（检测 → SecGPT 报告输出）
"""

from .traffic_simulator import TrafficSimulator
from .feature_engineering import extract_all_features, extract_session_features, features_to_matrix
from .detector import RuleDetector, RFDetector, IForestDetector, EnsembleDetector
from .experiment_runner import run_experiment
from .pipeline import CrawlerPipeline
