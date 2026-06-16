"""用于基准测试的合成测试数据生成器。

生成带有已知真实标签的标注数据集，用于准确性测试。
"""

import csv
import json
import random
import os
from datetime import datetime, timedelta

# API 端点（真实端点与人为添加的脆弱端点混合）
API_ENDPOINTS = [
    "/api/users/{id}", "/api/orders/{id}", "/api/products/{id}",
    "/api/search", "/api/login", "/api/checkout",
    "/admin/users", "/admin/config", "/api/download",
    "/api/upload", "/api/profile", "/api/payments",
]

# 用于生成正样本的攻击签名
ATTACK_PAYLOADS = {
    "directory_traversal": [
        "../etc/passwd", "..\\windows\\system32", "../../../etc/shadow",
        "%2e%2e%2fetc%2fpasswd", "....//....//etc/passwd",
        "../../../../../../etc/hosts", "..%252f..%252f..%252fetc%2fpasswd",
        "/../../../etc/passwd", "../../etc/hosts%00",
    ],
    "injection": [
        "' OR '1'='1", "1; DROP TABLE users", "' UNION SELECT * FROM users--",
        "1' AND 1=1--", "'; DELETE FROM orders WHERE '1'='1",
        "' OR 1=1--", "1; SELECT * FROM admin--",
    ],
    "xss": [
        "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
        "javascript:alert(1)", "<svg onload=alert(1)>",
        "'';!--\"<XSS>=&{()}",
    ],
    "unauthorized_access": [
        "/admin", "/api/admin/users", "/config",
        "/internal/status", "/.env", "/backup",
    ],
}

# 正常请求模式
NORMAL_PATHS = [
    "/api/products/123", "/api/search?q=phone", "/api/login",
    "/api/users/profile", "/api/orders/list", "/api/checkout",
    "/api/payments/methods",
]

NORMAL_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH"]
ATTACK_METHODS = ["GET", "POST", "OPTIONS"]


def generate_dataset(num_samples: int = 1000, anomaly_ratio: float = 0.15,
                     output_dir: str = None) -> str:
    """生成带有已知真实标签的标注数据集。

    Args:
        num_samples: 要生成的日志条目总数
        anomaly_ratio: 异常条目的比例（0.0-1.0）
        output_dir: 输出文件的目录

    Returns:
        生成的 CSV 文件路径
    """
    if output_dir is None:
        output_dir = os.path.join(os.path.dirname(__file__), "data")
    os.makedirs(output_dir, exist_ok=True)

    num_anomalies = int(num_samples * anomaly_ratio)
    num_normal = num_samples - num_anomalies

    attack_types = list(ATTACK_PAYLOADS.keys())
    records = []
    start_time = datetime.now() - timedelta(hours=1)

    # 生成异常样本
    for i in range(num_anomalies):
        atype = random.choice(attack_types)
        payload = random.choice(ATTACK_PAYLOADS[atype])
        endpoint = random.choice(API_ENDPOINTS).format(id=random.randint(1, 1000))
        method = random.choice(ATTACK_METHODS)

        ts = start_time + timedelta(seconds=i * 2)
        records.append({
            "log_id": i + 1,
            "timestamp": ts.isoformat(),
            "method": method,
            "endpoint": endpoint,
            "url": f"{method} {endpoint}",
            "status": random.choice([200, 201, 403, 404, 500]),
            "response_time": round(random.uniform(50, 5000), 2),
            "request_body": payload,
            "label": "anomaly",
            "anomaly_type": atype,
        })

    # 生成正常样本
    for i in range(num_normal):
        endpoint = random.choice(NORMAL_PATHS)
        method = random.choice(NORMAL_METHODS)
        ts = start_time + timedelta(seconds=(num_anomalies + i) * 0.5)

        records.append({
            "log_id": num_anomalies + i + 1,
            "timestamp": ts.isoformat(),
            "method": method,
            "endpoint": endpoint,
            "url": f"{method} {endpoint}",
            "status": random.choice([200, 201, 204, 301, 302]),
            "response_time": round(random.uniform(10, 200), 2),
            "request_body": "",
            "label": "normal",
            "anomaly_type": "",
        })

    # 打乱顺序
    random.shuffle(records)

    # 写入 CSV
    csv_path = os.path.join(output_dir, f"benchmark_data_{num_samples}.csv")
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=records[0].keys())
        writer.writeheader()
        writer.writerows(records)

    # 写入 JSON（便于加载）
    json_path = os.path.join(output_dir, f"benchmark_data_{num_samples}.json")
    with open(json_path, "w") as f:
        json.dump(records, f, indent=2)

    # 写入摘要
    summary_path = os.path.join(output_dir, f"benchmark_data_{num_samples}_summary.json")
    summary = {
        "total": len(records),
        "anomalies": num_anomalies,
        "normal": num_normal,
        "anomaly_ratio": anomaly_ratio,
        "by_type": {t: sum(1 for r in records if r.get("anomaly_type") == t) for t in attack_types},
    }
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)

    print(f"已生成数据集：{num_samples} 个样本（{num_anomalies} 个异常，{num_normal} 个正常）")
    print(f"  CSV：{csv_path}")
    print(f"  JSON：{json_path}")
    return csv_path


if __name__ == "__main__":
    generate_dataset(1000, anomaly_ratio=0.15)
    generate_dataset(5000, anomaly_ratio=0.15)
