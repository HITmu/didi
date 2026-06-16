"""API 流量模拟器：生成正常用户、合法爬虫和恶意爬虫的流量数据。"""

import csv
import json
import os
import random
import time
import uuid
from datetime import datetime, timedelta
from typing import Generator

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")

# ── URL 池 ──────────────────────────────────────────

PUBLIC_URLS = [
    "/api/products", "/api/product", "/api/search?q=laptop",
    "/api/items/1", "/api/items/2", "/api/items/3",
    "/api/profile", "/api/orders", "/api/comments",
]
AUTH_URLS = [
    "/api/login", "/api/logout", "/api/register", "/api/reset-password",
]
SENSITIVE_URLS = [
    "/admin/users", "/admin/config", "/admin/backups",
    "/api/payments", "/api/users/export",
]
CRAWL_TARGETS = [
    "/api/products", "/api/product", "/api/search?q=laptop",
    "/api/search?q=phone", "/api/search?q=books",
    "/api/items/1", "/api/items/2", "/api/items/3",
    "/api/comments", "/api/profile",
]
SCRAPE_TARGETS = [
    "/api/products", "/api/product", "/api/items/1",
    "/api/items/2", "/api/items/3", "/api/users/export",
    "/api/payments", "/api/comments?page=1",
    "/api/comments?page=2",
]

# ── 用户代理池 ──────────────────────────────────────

BROWSER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) Firefox/118.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Mobile/15E148",
]
LEGIT_CRAWLER_AGENTS = [
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)",
    "Mozilla/5.0 (compatible; DuckDuckBot-Https/1.1; +https://duckduckgo.com/duckduckbot)",
]
MALICIOUS_AGENTS = [
    "python-requests/2.31.0",
    "curl/7.88.1",
    "Scrapy/2.9.0 (+https://scrapy.org)",
    "Mozilla/5.0 (compatible; MJ12bot/v1.4.8; http://mj12bot.com/)",
    "Go-http-client/2.0",
    "CustomScraper/1.0",
    "okhttp/4.12.0",
    "Apache-HttpClient/4.5.14",
]

# ── 工具函数 ────────────────────────────────────────


def _random_timestamp(base: datetime, max_offset_ms: int = 1000) -> str:
    return (base + timedelta(milliseconds=random.randint(0, max_offset_ms))).isoformat()


def _choose_weighted(choices: list, weights: list):
    return random.choices(choices, weights=weights, k=1)[0]


def _status_for_path(path: str, is_attack: bool = False) -> int:
    if "/admin/" in path and not is_attack:
        return 403
    if is_attack and random.random() < 0.3:
        return random.choice([403, 429, 500])
    return 200


# ── 流量模拟器 ──────────────────────────────────────


class TrafficSimulator:
    """生成多类型流量数据并保存为 CSV。"""

    def __init__(self, seed: int = 42):
        self.rng = random.Random(seed)

    def generate_normal_session(self, session_id: str, base_time: datetime, length: int = None) -> list[dict]:
        """生成一个正常用户会话。"""
        if length is None:
            length = self.rng.randint(3, 15)
        agent = self.rng.choice(BROWSER_AGENTS)
        records = []
        t = base_time
        for _ in range(length):
            path = self.rng.choice(PUBLIC_URLS + AUTH_URLS[:2])
            delay = self.rng.expovariate(1 / 3.0)  # 平均 3 秒间隔
            t += timedelta(seconds=max(0.5, delay))
            records.append({
                "timestamp": t.isoformat(),
                "session_id": session_id,
                "source_ip": "",
                "method": "GET" if "/login" not in path else "POST",
                "path": path,
                "status": _status_for_path(path),
                "user_agent": agent,
                "category": "normal",
                "repetitive_path_count": 0,
            })
        return records

    def generate_legit_crawler_session(self, session_id: str, base_time: datetime,
                                       length: int = None) -> list[dict]:
        """生成一个合法爬虫会话（遵守 robots.txt，合理速率）。"""
        if length is None:
            length = self.rng.randint(20, 50)
        agent = self.rng.choice(LEGIT_CRAWLER_AGENTS)
        records = []
        t = base_time
        for i in range(length):
            path = CRAWL_TARGETS[i % len(CRAWL_TARGETS)]
            if i > 0 and path == records[-1]["path"]:
                delay = self.rng.uniform(2.0, 5.0)  # 爬虫对重复页面较慢
            else:
                delay = self.rng.uniform(0.5, 2.0)
            t += timedelta(seconds=delay)
            is_dup = sum(1 for r in records if r["path"] == path)
            records.append({
                "timestamp": t.isoformat(),
                "session_id": session_id,
                "source_ip": "",
                "method": "GET",
                "path": path,
                "status": 200,
                "user_agent": agent,
                "category": "legit_crawler",
                "repetitive_path_count": is_dup,
            })
        return records

    def generate_malicious_crawler_session(self, session_id: str, base_time: datetime,
                                            length: int = None, pattern: str = "scraper") -> list[dict]:
        """生成一个恶意爬虫会话。

        pattern 参数:
          - scraper: 高速爬取，遍历页面
          - credential_stuffer: 登录接口爆破
          - ddos_tool: 高密度请求单一端点
        """
        if length is None:
            length = self.rng.randint(50, 200)

        if pattern == "credential_stuffer":
            agent = self.rng.choice(MALICIOUS_AGENTS + BROWSER_AGENTS[:1])
            records = []
            t = base_time
            for i in range(length):
                t += timedelta(milliseconds=self.rng.randint(50, 300))
                path = "/api/login"
                records.append({
                    "timestamp": t.isoformat(),
                    "session_id": session_id,
                    "source_ip": "",
                    "method": "POST",
                    "path": path,
                    "status": self.rng.choice([401, 401, 401, 403, 200]),
                    "user_agent": agent,
                    "category": "malicious_crawler",
                    "repetitive_path_count": i,
                })

        elif pattern == "ddos_tool":
            agent = self.rng.choice(MALICIOUS_AGENTS)
            target = self.rng.choice(["/api/products", "/api/search?q=laptop", "/api/login"])
            records = []
            t = base_time
            for i in range(length):
                t += timedelta(milliseconds=self.rng.randint(10, 100))
                records.append({
                    "timestamp": t.isoformat(),
                    "session_id": session_id,
                    "source_ip": "",
                    "method": "GET",
                    "path": target,
                    "status": _status_for_path(target, is_attack=(random.random() < 0.3)),
                    "user_agent": agent,
                    "category": "malicious_crawler",
                    "repetitive_path_count": i,
                })

        else:  # scraper
            agent = self.rng.choice(MALICIOUS_AGENTS)
            records = []
            t = base_time
            for i in range(length):
                path = SCRAPE_TARGETS[i % len(SCRAPE_TARGETS)]
                # 尝试敏感路径
                if self.rng.random() < 0.15:
                    path = self.rng.choice(SENSITIVE_URLS)
                t += timedelta(milliseconds=self.rng.randint(100, 500))
                is_dup = sum(1 for r in records if r["path"] == path)
                records.append({
                    "timestamp": t.isoformat(),
                    "session_id": session_id,
                    "source_ip": "",
                    "method": "GET",
                    "path": path,
                    "status": _status_for_path(path, is_attack=(path in SENSITIVE_URLS)),
                    "user_agent": agent,
                    "category": "malicious_crawler",
                    "repetitive_path_count": is_dup,
                })

        return records

    def generate_mixed_dataset(self, n_normal: int = 50, n_legit: int = 20,
                                n_malicious: int = 30, output_path: str = None) -> str:
        """生成混合流量数据集。

        Args:
            n_normal: 正常用户会话数
            n_legit: 合法爬虫会话数
            n_malicious: 恶意爬虫会话数
            output_path: CSV 输出路径

        Returns:
            CSV 文件路径
        """
        if output_path is None:
            os.makedirs(DATA_DIR, exist_ok=True)
            output_path = os.path.join(DATA_DIR, "crawler_traffic.csv")

        all_records = []
        base_time = datetime(2026, 5, 27, 8, 0, 0)

        for i in range(n_normal):
            sid = f"normal_{uuid.uuid4().hex[:8]}"
            offset = self.rng.randint(0, 3600 * 8)  # 分散在 8 小时内
            bt = base_time + timedelta(seconds=offset)
            all_records.extend(self.generate_normal_session(sid, bt))

        for i in range(n_legit):
            sid = f"legit_{uuid.uuid4().hex[:8]}"
            offset = self.rng.randint(0, 3600 * 8)
            bt = base_time + timedelta(seconds=offset)
            all_records.extend(self.generate_legit_crawler_session(sid, bt))

        patterns = ["scraper", "credential_stuffer", "ddos_tool"]
        n_each = max(1, n_malicious // 3)
        for i, pat in enumerate(patterns):
            for j in range(n_each):
                sid = f"malicious_{pat}_{uuid.uuid4().hex[:8]}"
                offset = self.rng.randint(0, 3600 * 8)
                bt = base_time + timedelta(seconds=offset)
                all_records.extend(self.generate_malicious_crawler_session(sid, bt, pattern=pat))
        # 补齐
        remaining = n_malicious - n_each * 3
        for k in range(remaining):
            sid = f"malicious_extra_{uuid.uuid4().hex[:8]}"
            offset = self.rng.randint(0, 3600 * 8)
            bt = base_time + timedelta(seconds=offset)
            all_records.extend(self.generate_malicious_crawler_session(sid, bt, pattern="scraper"))

        self.rng.shuffle(all_records)

        fieldnames = ["timestamp", "session_id", "source_ip", "method", "path",
                       "status", "user_agent", "category", "repetitive_path_count"]
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(all_records)

        stats = {"normal": n_normal, "legit_crawler": n_legit, "malicious_crawler": n_malicious}
        print(f"[TrafficSimulator] 生成 {len(all_records)} 条流量记录 → {output_path}")
        print(f"  会话分布: {stats}")
        return output_path


    def generate_distributed_crawler_sessions(
        self, n_sessions: int = 10, base_time: datetime = None,
        pattern: str = "scraper",
    ) -> list[list[dict]]:
        """生成分布式爬虫流量：多个 session 在相近时间访问相同资源。

        模拟分布式爬虫的多个节点协同采集，每个节点（session）产生中等量请求，
        但多个 session 在时间窗口内密集覆盖相同资源集合。
        """
        if base_time is None:
            base_time = datetime.now()

        agent = self.rng.choice(MALICIOUS_AGENTS)

        # 共享同一资源池
        shared_pool = SCRAPE_TARGETS + SENSITIVE_URLS[:2]
        resource_subset = self.rng.sample(
            shared_pool,
            k=self.rng.randint(len(shared_pool) // 2, len(shared_pool)),
        )

        sessions = []
        for i in range(n_sessions):
            sid = f"malicious_{pattern}_{uuid.uuid4().hex[:8]}"
            length = self.rng.randint(20, 50)
            records = []
            # 所有分布式节点在极短窗口内同时启动（3 秒内）
            t = base_time + timedelta(milliseconds=self.rng.randint(0, 3000))

            for j in range(length):
                path = resource_subset[j % len(resource_subset)]
                if self.rng.random() < 0.12:
                    path = self.rng.choice(SENSITIVE_URLS)

                t += timedelta(milliseconds=self.rng.randint(50, 300))  # 更快间隔
                is_dup = sum(1 for r in records if r["path"] == path)
                records.append({
                    "timestamp": t.isoformat(),
                    "session_id": sid,
                    "source_ip": f"10.0.{self.rng.randint(0, 5)}.{self.rng.randint(1, 254)}",
                    "method": "GET",
                    "path": path,
                    "status": _status_for_path(path, is_attack=(path in SENSITIVE_URLS)),
                    "user_agent": agent,
                    "category": "distributed_crawler",
                    "repetitive_path_count": is_dup,
                })
            sessions.append(records)

        return sessions

    def generate_crowdsourced_crawler_sessions(
        self, n_sessions: int = 20, base_time: datetime = None,
    ) -> list[list[dict]]:
        """生成众包爬虫流量：每个 session 仅 1-3 条请求，集体覆盖资源范围。

        模拟众包平台分发任务到真实用户设备，每个设备只做少量请求，
        但合起来形成系统性覆盖。
        """
        if base_time is None:
            base_time = datetime.now()

        # 目标资源范围：系统性地覆盖分页/ID 序列
        target_resources = [
            f"/api/items/{i}" for i in range(1, n_sessions + 1)
        ] + [
            f"/api/comments?page={i}" for i in range(1, max(2, n_sessions // 5) + 1)
        ]

        # 打乱分配，确保每个资源至少被访问一次
        self.rng.shuffle(target_resources)

        sessions = []
        base_idx = 0
        while base_idx < len(target_resources):
            sid = f"malicious_crowdsourced_{uuid.uuid4().hex[:8]}"
            # 每个 session 1-3 条请求
            n_req = self.rng.randint(1, 3)
            records = []
            t = base_time + timedelta(
                seconds=self.rng.randint(0, 3600),  # 分散在 1 小时内
            )

            for j in range(n_req):
                if base_idx < len(target_resources):
                    path = target_resources[base_idx]
                    base_idx += 1
                else:
                    path = self.rng.choice(PUBLIC_URLS)

                t += timedelta(milliseconds=self.rng.randint(500, 3000))
                records.append({
                    "timestamp": t.isoformat(),
                    "session_id": sid,
                    "source_ip": f"{self.rng.randint(1, 223)}.{self.rng.randint(0, 255)}.{self.rng.randint(0, 255)}.{self.rng.randint(1, 254)}",
                    "method": "GET",
                    "path": path,
                    "status": 200,
                    "user_agent": self.rng.choice(BROWSER_AGENTS),
                    "category": "crowdsourced_crawler",
                    "repetitive_path_count": 0,
                })
            sessions.append(records)

        return sessions

    def generate_distributed_mixed_dataset(
        self, n_normal: int = 50, n_legit: int = 10,
        n_distributed: int = 30, n_crowdsourced: int = 30,
        output_path: str = None,
    ) -> str:
        """生成包含分布式/众包爬虫的混合流量数据集。"""
        if output_path is None:
            os.makedirs(DATA_DIR, exist_ok=True)
            output_path = os.path.join(DATA_DIR, "distributed_crawler_traffic.csv")

        all_records = []
        base_time = datetime(2026, 5, 28, 8, 0, 0)

        # 正常用户
        for i in range(n_normal):
            sid = f"normal_{uuid.uuid4().hex[:8]}"
            offset = self.rng.randint(0, 3600 * 2)
            bt = base_time + timedelta(seconds=offset)
            all_records.extend(self.generate_normal_session(sid, bt))

        # 合法爬虫
        for i in range(n_legit):
            sid = f"legit_{uuid.uuid4().hex[:8]}"
            offset = self.rng.randint(0, 3600 * 2)
            bt = base_time + timedelta(seconds=offset)
            all_records.extend(self.generate_legit_crawler_session(sid, bt))

        # 分布式爬虫（多个协同 session）
        for pat in ["scraper", "credential_stuffer", "ddos_tool"]:
            bt = base_time + timedelta(hours=self.rng.randint(0, 2))
            sessions = self.generate_distributed_crawler_sessions(
                n_sessions=n_distributed // 3 + 1,
                base_time=bt, pattern=pat,
            )
            for s in sessions:
                all_records.extend(s)

        # 众包爬虫（大量短 session 系统性覆盖）
        bt = base_time + timedelta(hours=self.rng.randint(0, 2))
        sessions = self.generate_crowdsourced_crawler_sessions(
            n_sessions=n_crowdsourced, base_time=bt,
        )
        for s in sessions:
            all_records.extend(s)

        self.rng.shuffle(all_records)

        fieldnames = ["timestamp", "session_id", "source_ip", "method", "path",
                       "status", "user_agent", "category", "repetitive_path_count"]
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(all_records)

        stats = {
            "normal": n_normal, "legit_crawler": n_legit,
            "distributed_crawler": n_distributed, "crowdsourced_crawler": n_crowdsourced,
        }
        total = len(all_records)
        print(f"[TrafficSimulator] 生成 {total} 条分布式流量记录 → {output_path}")
        print(f"  会话分布: {stats}")
        return output_path


def main():
    sim = TrafficSimulator()
    sim.generate_mixed_dataset(n_normal=100, n_legit=40, n_malicious=60)


if __name__ == "__main__":
    main()
