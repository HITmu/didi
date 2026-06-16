#!/usr/bin/env python3
"""综合攻击流量生成器：7种API攻击 + 3种爬虫 + 分布式爬虫 + 众包爬虫 + 正常用户 + 合法爬虫。

输出：至少 1000 条记录的 CSV，每条含真实标签便于评估。
"""

import csv, os, random, uuid
from datetime import datetime, timedelta

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")

# ── 路径池 ──────────────────────────────────────────
API_PATHS = {
    "normal": [
        "/api/products", "/api/product/1", "/api/search?q=laptop",
        "/api/items/2", "/api/profile", "/api/orders",
        "/api/comments", "/api/cart", "/api/checkout",
    ],
    "sql_injection": [
        "/api/products?id=1' OR '1'='1",
        "/api/login?user=admin'--",
        "/api/items/1 UNION SELECT * FROM users",
        "/api/search?q='; DROP TABLE orders--",
        "/api/products?id=1 AND 1=1",
        "/api/login?username=admin' OR '1'='1",
    ],
    "xss": [
        "/api/search?q=<script>alert(1)</script>",
        "/api/profile?name=<img src=x onerror=alert(1)>",
        "/api/comments?text=<script>document.cookie</script>",
        "/api/products?q=<svg onload=alert(1)>",
        "/api/feedback?msg=<iframe src=javascript:alert(1)>",
    ],
    "directory_traversal": [
        "/api/download?file=../../etc/passwd",
        "/api/static/../../../etc/shadow",
        "/api/backup?path=..%2f..%2fconfig",
        "/api/export?file=....//....//etc/hosts",
        "/api/view?name=../../proc/self/environ",
    ],
    "unauthorized_access": [
        "/admin/users", "/admin/config", "/admin/backups",
        "/api/payments", "/api/users/export",
        "/admin/logs", "/api/internal/metrics",
    ],
    "sensitive_data_leakage": [
        "/api/debug/env", "/api/config/database",
        "/api/logs/error", "/api/metrics/prometheus",
        "/api/.env", "/api/actuator/health",
    ],
    "command_injection": [
        "/api/ping?host=127.0.0.1;id",
        "/api/dns?domain=example.com|whoami",
        "/api/exec?cmd=cat /etc/passwd",
        "/api/convert?file=$(id)",
        "/api/run?command=ls -la",
    ],
    "ssrf": [
        "/api/fetch?url=http://169.254.169.254/latest/meta-data/",
        "/api/proxy?target=http://localhost:6379",
        "/api/import?source=file:///etc/passwd",
        "/api/redirect?url=http://internal-admin/",
    ],
    "csrf": [
        "/api/transfer?amount=1000&to=attacker",
        "/api/change-password?new=evil123",
        "/api/delete-account?confirm=yes",
    ],
    "performance_issue": [
        "/api/products?page=1000000",
        "/api/search?q=a" * 50,
        "/api/report?year=2099&month=13",
        "/api/export?format=csv&rows=999999",
        "/api/comments?sort=0" * 20,
    ],
    "invalid_item_value": [
        "/api/products?id=-1",
        "/api/items/abc!@#",
        "/api/order?qty=-999",
        "/api/rating?score=999",
        "/api/price?amount=0",
    ],
}

# ── 恶意爬虫路径 ────────────────────────────────────
CRAWL_PATHS = {
    "scraper": [
        "/api/products", "/api/product", "/api/items/1",
        "/api/items/2", "/api/items/3", "/api/payments",
        "/api/users/export", "/api/comments?page=1",
        "/api/comments?page=2", "/api/comments?page=3",
    ],
    "credential_stuffer": ["/api/login"],
    "ddos_tool": ["/api/products", "/api/search?q=laptop", "/api/login"],
}

# ── UA 池 ──────────────────────────────────────────
BROWSER_UA = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) Firefox/118.0",
]
LEGIT_CRAWLER_UA = [
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
]
MALICIOUS_UA = [
    "python-requests/2.31.0", "curl/7.88.1", "Go-http-client/2.0",
]

# ── 工具函数 ──────────────────────────────────────────

def _pick(choices):
    return random.choice(choices)

def _rand_path(path_dict):
    return random.choice(random.choice(list(path_dict.values())))

def _ts(base, offset_ms):
    return (base + timedelta(milliseconds=offset_ms)).isoformat()

def _status(path, method="GET"):
    if "/login" in path and method == "POST":
        return random.choices([200, 401, 403], weights=[3, 5, 2])[0]
    if "/admin/" in path:
        return 403
    return 200

# ── 生成器函数 ────────────────────────────────────────

def generate_mixed_attacks(n_per_type: int = 30) -> list[dict]:
    """生成 7 种 API 攻击流量。"""
    records = []
    base = datetime(2026, 5, 28, 8, 0, 0)
    idx = 0

    attack_types = [
        "sql_injection", "xss", "directory_traversal",
        "unauthorized_access", "sensitive_data_leakage",
        "command_injection", "ssrf", "csrf",
        "performance_issue", "invalid_item_value",
    ]

    for atype in attack_types:
        paths = API_PATHS[atype]
        for i in range(n_per_type):
            sid = f"attack_{atype}_{uuid.uuid4().hex[:6]}"
            path = random.choice(paths)
            method = "POST" if "login" in path else "GET"
            status = 403 if "/admin/" in path else 200
            records.append({
                "timestamp": _ts(base, idx * 500 + random.randint(0, 200)),
                "session_id": sid,
                "source_ip": f"10.{random.randint(1,5)}.{random.randint(0,255)}.{random.randint(1,254)}",
                "method": method,
                "path": path,
                "status": status,
                "user_agent": _pick(BROWSER_UA + MALICIOUS_UA),
                "category": atype,
                "repetitive_path_count": 0,
            })
            idx += 1
    return records

def generate_normal_users(n_sessions: int = 50) -> list[dict]:
    """生成正常用户流量。"""
    records = []
    base = datetime(2026, 5, 28, 8, 0, 0)
    idx = 0
    for s in range(n_sessions):
        sid = f"normal_{uuid.uuid4().hex[:6]}"
        n_req = random.randint(3, 12)
        t = base + timedelta(seconds=random.randint(0, 7200))
        for i in range(n_req):
            path = _pick(API_PATHS["normal"])
            t += timedelta(seconds=random.expovariate(1/3.0))
            records.append({
                "timestamp": t.isoformat(),
                "session_id": sid,
                "source_ip": f"192.168.{random.randint(0,10)}.{random.randint(1,254)}",
                "method": "GET",
                "path": path,
                "status": 200,
                "user_agent": _pick(BROWSER_UA),
                "category": "normal",
                "repetitive_path_count": 0,
            })
            idx += 1
    return records

def generate_legit_crawlers(n_sessions: int = 15) -> list[dict]:
    """生成合法爬虫流量。"""
    records = []
    base = datetime(2026, 5, 28, 8, 0, 0)
    for s in range(n_sessions):
        sid = f"legit_{uuid.uuid4().hex[:6]}"
        n_req = random.randint(15, 30)
        t = base + timedelta(seconds=random.randint(0, 7200))
        for i in range(n_req):
            path = _pick(API_PATHS["normal"])
            t += timedelta(seconds=random.uniform(0.5, 3.0))
            records.append({
                "timestamp": t.isoformat(),
                "session_id": sid,
                "source_ip": f"8.8.{random.randint(0,10)}.{random.randint(1,254)}",
                "method": "GET",
                "path": path,
                "status": 200,
                "user_agent": _pick(LEGIT_CRAWLER_UA),
                "category": "legit_crawler",
                "repetitive_path_count": 0,
            })
    return records

def generate_malicious_crawlers(n_sessions: int = 40) -> list[dict]:
    """生成 3 种恶意爬虫流量。"""
    records = []
    base = datetime(2026, 5, 28, 8, 0, 0)
    patterns = ["scraper", "credential_stuffer", "ddos_tool"]
    n_each = n_sessions // 3

    for pat in patterns:
        paths = CRAWL_PATHS.get(pat, [])
        if not paths:
            continue
        for s in range(n_each):
            sid = f"malicious_{pat}_{uuid.uuid4().hex[:6]}"
            n_req = random.randint(30, 80)
            t = base + timedelta(seconds=random.randint(0, 7200))
            for i in range(n_req):
                path = paths[i % len(paths)]
                delay_ms = {"scraper": (100, 300), "credential_stuffer": (50, 200), "ddos_tool": (10, 80)}[pat]
                t += timedelta(milliseconds=random.randint(*delay_ms))
                status = _status(path, "POST")
                method = "POST" if pat == "credential_stuffer" else "GET"
                records.append({
                    "timestamp": t.isoformat(),
                    "session_id": sid,
                    "source_ip": f"10.{random.randint(0,5)}.{random.randint(0,255)}.{random.randint(1,254)}",
                    "method": method,
                    "path": path,
                    "status": status,
                    "user_agent": _pick(MALICIOUS_UA),
                    "category": "malicious_crawler",
                    "repetitive_path_count": 0,
                })
    return records

def generate_distributed_crawlers(n_clusters: int = 3, sessions_per_cluster: int = 10) -> list[dict]:
    """生成分布式爬虫流量（多个 session 协同时序）。"""
    records = []
    base = datetime(2026, 5, 28, 8, 0, 0)

    for ci in range(n_clusters):
        cluster_time = base + timedelta(seconds=random.randint(0, 7200))
        all_paths = API_PATHS["normal"] + CRAWL_PATHS.get("scraper", [])
        if len(all_paths) < 6:
            shared_paths = all_paths
        else:
            shared_paths = random.sample(all_paths, k=6)
        for si in range(sessions_per_cluster):
            sid = f"malicious_distributed_scraper_{uuid.uuid4().hex[:6]}"
            t = cluster_time + timedelta(milliseconds=random.randint(0, 3000))
            for _ in range(random.randint(15, 30)):
                path = _pick(shared_paths)
                t += timedelta(milliseconds=random.randint(50, 200))
                records.append({
                    "timestamp": t.isoformat(),
                    "session_id": sid,
                    "source_ip": f"10.{ci}.{si}.{random.randint(1,254)}",
                    "method": "GET",
                    "path": path,
                    "status": 200,
                    "user_agent": _pick(MALICIOUS_UA),
                    "category": "distributed_crawler",
                    "repetitive_path_count": 0,
                })
    return records

def generate_crowdsourced_crawlers(n_sessions: int = 25) -> list[dict]:
    """生成众包爬虫流量（每个 session 1-3 条，覆盖完整）。"""
    records = []
    base = datetime(2026, 5, 28, 8, 0, 0)
    all_paths = [f"/api/items/{i}" for i in range(1, n_sessions + 1)]
    random.shuffle(all_paths)
    pi = 0
    while pi < len(all_paths):
        sid = f"malicious_crowdsourced_{uuid.uuid4().hex[:6]}"
        n_req = random.randint(1, 3)
        t = base + timedelta(seconds=random.randint(0, 3600))
        for _ in range(n_req):
            if pi < len(all_paths):
                path = all_paths[pi]; pi += 1
            else:
                path = _pick(API_PATHS["normal"])
            t += timedelta(milliseconds=random.randint(500, 3000))
            records.append({
                "timestamp": t.isoformat(),
                "session_id": sid,
                "source_ip": f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
                "method": "GET",
                "path": path,
                "status": 200,
                "user_agent": _pick(BROWSER_UA),
                "category": "crowdsourced_crawler",
                "repetitive_path_count": 0,
            })
    return records


def generate_all(n_sql=30, n_xss=30, n_traversal=30, n_unauth=30, n_sensitive=30,
                 n_cmd=30, n_ssrf=20, n_csrf=20, n_perf=20, n_invalid=20,
                 n_normal=50, n_legit=15, n_malicious=40,
                 n_dist_clusters=3, n_dist_per_cluster=10, n_crowd=25,
                 output_path=None) -> str:
    """生成包含所有攻击类型的混合流量数据集。"""
    if output_path is None:
        os.makedirs(DATA_DIR, exist_ok=True)
        output_path = os.path.join(DATA_DIR, "mixed_attack_data.csv")

    all_records = []

    # API 攻击（含 10 种类型）
    for atype, count in [("sql_injection", n_sql), ("xss", n_xss),
                          ("directory_traversal", n_traversal),
                          ("unauthorized_access", n_unauth),
                          ("sensitive_data_leakage", n_sensitive),
                          ("command_injection", n_cmd), ("ssrf", n_ssrf),
                          ("csrf", n_csrf), ("performance_issue", n_perf),
                          ("invalid_item_value", n_invalid)]:
        records = generate_mixed_attacks(count)
        all_records.extend(records)
        print(f"  {atype}: {len(records)} 条")

    # 正常用户
    records = generate_normal_users(n_normal)
    all_records.extend(records)
    print(f"  normal: {len(records)} 条")

    # 合法爬虫
    records = generate_legit_crawlers(n_legit)
    all_records.extend(records)
    print(f"  legit_crawler: {len(records)} 条")

    # 恶意爬虫（3 种模式）
    records = generate_malicious_crawlers(n_malicious)
    all_records.extend(records)
    print(f"  malicious_crawler(scraper+stuff+ddos): {len(records)} 条")

    # 分布式爬虫
    records = generate_distributed_crawlers(n_dist_clusters, n_dist_per_cluster)
    all_records.extend(records)
    print(f"  distributed_crawler: {len(records)} 条")

    # 众包爬虫
    records = generate_crowdsourced_crawlers(n_crowd)
    all_records.extend(records)
    print(f"  crowdsourced_crawler: {len(records)} 条")

    random.shuffle(all_records)

    fieldnames = ["timestamp", "session_id", "source_ip", "method", "path",
                   "status", "user_agent", "category", "repetitive_path_count"]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_records)

    print(f"\n  总计: {len(all_records)} 条 → {output_path}")
    return output_path


if __name__ == "__main__":
    generate_all()
