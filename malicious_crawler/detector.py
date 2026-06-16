"""检测引擎：支持规则检测、随机森林、孤立森林等多种方法。"""

import csv
import math
import os
import statistics
from collections import Counter, defaultdict
from datetime import datetime

from .feature_engineering import extract_all_features, features_to_matrix

ROOT = os.path.dirname(__file__)

# ── 规则检测器 ──────────────────────────────────────


class RuleDetector:
    """基于专家规则的恶意爬虫检测器。

    规则来源：
    - UA 黑名单
    - 请求频率阈值
    - 路径集中度
    - 敏感路径访问率
    - 重复访问模式
    """

    def __init__(self):
        self.suspicious_ua_keywords = [
            "python-requests", "curl/", "scrapy", "go-http",
            "okhttp", "apache-httpclient", "mj12bot", "customscraper",
        ]
        self.known_crawler_ua = [
            "googlebot", "bingbot", "baiduspider", "duckduckbot",
        ]

    def predict_session(self, records: list[dict]) -> tuple[str, float, dict]:
        """对单个会话做规则判定。

        Returns:
            (prediction, confidence, reasons)
            prediction: "normal" | "legit_crawler" | "malicious_crawler"
        """
        reasons = []
        score = 0.0  # 正值 = 更恶意

        timestamps = []
        paths = []
        agents = []
        statuses = []
        for r in records:
            try:
                ts = datetime.fromisoformat(r.get("timestamp", "")).timestamp()
                timestamps.append(ts)
            except (ValueError, TypeError):
                continue
            paths.append(r.get("path", ""))
            agents.append(r.get("user_agent", "").lower())
            statuses.append(r.get("status", 200))

        if len(timestamps) < 2:
            return "normal", 0.0, {"reasons": ["insufficient data"]}

        n = len(timestamps)
        duration = timestamps[-1] - timestamps[0]

        # ── 规则 1: UA 检测 ──
        has_known_crawler = False
        has_suspicious_ua = False
        for a in agents:
            if any(kw in a for kw in self.known_crawler_ua):
                has_known_crawler = True
            if any(kw in a for kw in self.suspicious_ua_keywords):
                has_suspicious_ua = True

        if has_known_crawler and not has_suspicious_ua:
            score -= 1.0  # 合法爬虫倾向
            reasons.append("known_crawler_ua")

        if has_suspicious_ua:
            score += 2.0
            reasons.append("suspicious_ua")

        # ── 规则 2: 请求速率 ──
        rps = n / duration if duration > 0 else n
        if rps > 10:
            score += 2.5
            reasons.append(f"high_rps={rps:.1f}")
        elif rps > 3:
            score += 1.0
            reasons.append(f"medium_rps={rps:.1f}")

        # ── 规则 3: 路径集中度 ──
        path_counter = Counter(paths)
        top_path_count = path_counter.most_common(1)[0][1] if path_counter else 0
        concentration = top_path_count / n
        if concentration > 0.8:
            score += 2.0
            reasons.append(f"path_concentration={concentration:.2f}")
        elif concentration > 0.5:
            score += 0.5

        # ── 规则 4: 重复访问模式 ──
        consecutive = 0
        max_consecutive = 0
        for i in range(1, n):
            if paths[i] == paths[i - 1]:
                consecutive += 1
                max_consecutive = max(max_consecutive, consecutive)
            else:
                consecutive = 0
        if max_consecutive >= 5:
            score += 1.5
            reasons.append(f"consecutive_repeat={max_consecutive}")

        # ── 规则 5: 敏感路径 ──
        sensitive_kw = ["admin", "payment", "export", "backup", "config"]
        sensitive_count = sum(1 for p in paths if any(k in p.lower() for k in sensitive_kw))
        if sensitive_count > 0:
            score += sensitive_count * 0.3
            reasons.append(f"sensitive_paths={sensitive_count}")

        # ── 规则 6: 登录爆破 ──
        login_count = sum(1 for p in paths if "/login" in p.lower())
        auth_fail = sum(1 for s in statuses if s in (401, 403))
        if login_count > 10 and auth_fail > login_count * 0.5:
            score += 2.0
            reasons.append(f"credential_stuffing:login={login_count},fail={auth_fail}")

        # ── 阈值判定 ──
        # 用 soft 阈值映射到 [0,1] 置信度
        confidence = 1.0 / (1.0 + math.exp(-(score - 1.0)))

        if has_known_crawler and not has_suspicious_ua and score <= 1.0:
            return "legit_crawler", confidence, {"reasons": reasons, "score": round(score, 2)}
        elif score >= 1.5:
            return "malicious_crawler", confidence, {"reasons": reasons, "score": round(score, 2)}
        else:
            return "normal", 1.0 - confidence, {"reasons": reasons, "score": round(score, 2)}


# ── 随机森林检测器 ─────────────────────────────────


class RFDetector:
    """基于 session 级特征的随机森林检测器。"""

    def __init__(self):
        self.model = None
        self.feature_names = None

    def train(self, features: list[dict]):
        from sklearn.ensemble import RandomForestClassifier

        X, y, fnames, _ = features_to_matrix(features)
        self.feature_names = fnames

        self.model = RandomForestClassifier(
            n_estimators=200, max_depth=10,
            class_weight="balanced", random_state=42, n_jobs=-1,
        )
        self.model.fit(X, y)
        return self

    def predict(self, features: list[dict]) -> list[dict]:
        """批量预测，返回带概率的标注结果。"""
        X, y_true, fnames, ids = features_to_matrix(features)
        if self.model is None:
            raise RuntimeError("model not trained")

        y_proba = self.model.predict_proba(X)[:, 1]
        y_pred = self.model.predict(X)

        category_map = {f.get("session_id", ""): f.get("true_category", "unknown") for f in features}
        results = []
        for i, fid in enumerate(ids):
            results.append({
                "session_id": fid,
                "true_label": y_true[i],
                "pred_label": int(y_pred[i]),
                "confidence": round(float(y_proba[i]), 4),
                "true_category": category_map.get(fid, "unknown"),
            })
        return results


# ── 孤立森林检测器（无监督基线） ─────────────────────


class IForestDetector:
    """Isolation Forest 无监督异常检测。"""

    def __init__(self, contamination: float = 0.2):
        self.model = None
        self.contamination = contamination

    def train(self, features: list[dict]):
        from sklearn.ensemble import IsolationForest

        X, y, fnames, _ = features_to_matrix(features)
        self.feature_names = fnames
        # 无监督训练：不需要 y
        self.model = IsolationForest(
            n_estimators=200,
            contamination=self.contamination,
            random_state=42,
            n_jobs=-1,
        )
        self.model.fit(X)
        return self

    def predict(self, features: list[dict]) -> list[dict]:
        if self.model is None:
            raise RuntimeError("model not trained")

        X, y_true, fnames, ids = features_to_matrix(features)
        preds = self.model.predict(X)  # -1 = 异常, 1 = 正常
        scores = self.model.score_samples(X)
        # 归一化分数到 [0,1]
        min_s = min(scores)
        max_s = max(scores)
        norm_scores = [(s - min_s) / (max_s - min_s + 1e-10) for s in scores]

        category_map = {f.get("session_id", ""): f.get("true_category", "unknown") for f in features}
        results = []
        for i, fid in enumerate(ids):
            # 标签转换：1 -> 0 (normal), -1 -> 1 (anomaly)
            pred_label = 1 if preds[i] == -1 else 0
            confidence = 1 - norm_scores[i] if pred_label == 1 else norm_scores[i]
            results.append({
                "session_id": fid,
                "true_label": y_true[i],
                "pred_label": pred_label,
                "confidence": round(confidence, 4),
                "anomaly_score": round(float(scores[i]), 4),
                "true_category": category_map.get(fid, "unknown"),
            })
        return results


# ── 集成检测器 ──────────────────────────────────────


class EnsembleDetector:
    """集成规则、RF 和 IForest 的投票检测器。"""

    def __init__(self):
        self.rf = RFDetector()
        self.iforest = IForestDetector(contamination=0.25)
        self.rule = RuleDetector()
        self._trained = False

    def train(self, features: list[dict]):
        self.rf.train(features)
        self.iforest.train(features)
        self._trained = True
        return self

    def predict(self, features: list[dict],
                records_by_session: dict[str, list[dict]] = None) -> list[dict]:
        """集成预测：3 种方法投票 + 加权置信度。"""
        if not self._trained:
            raise RuntimeError("not trained")

        rf_results = self.rf.predict(features)
        if_results = self.iforest.predict(features)

        rf_map = {r["session_id"]: r for r in rf_results}
        if_map = {r["session_id"]: r for r in if_results}

        results = []
        for f in features:
            sid = f["session_id"]
            true_cat = f.get("true_category", "unknown")
            true_label = 1 if true_cat == "malicious_crawler" else 0

            # RF 投票
            rf_r = rf_map.get(sid, {})
            rf_vote = rf_r.get("pred_label", 0)
            rf_conf = rf_r.get("confidence", 0.5)

            # IForest 投票
            if_r = if_map.get(sid, {})
            if_vote = if_r.get("pred_label", 0)
            if_conf = if_r.get("confidence", 0.5)

            # Rule 投票
            if records_by_session:
                recs = records_by_session.get(sid, [])
                rule_pred, rule_conf, rule_info = self.rule.predict_session(recs)
                rule_vote = 0
                if rule_pred == "malicious_crawler":
                    rule_vote = 1
                elif rule_pred == "legit_crawler":
                    rule_vote = 0  # 合法爬虫不算恶意
            else:
                rule_vote = 0
                rule_conf = 0.5

            # 加权投票（RF 权重 0.45, Rule 0.35, IForest 0.2）
            avg_conf = (rf_conf * 0.45 + rule_conf * 0.35 + if_conf * 0.2)
            avg_vote = (rf_vote * 0.45 + rule_vote * 0.35 + if_vote * 0.2)
            pred_label = 1 if avg_vote >= 0.5 else 0

            results.append({
                "session_id": sid,
                "true_label": true_label,
                "true_category": true_cat,
                "pred_label": pred_label,
                "confidence": round(avg_conf, 4),
                "rf_vote": rf_vote,
                "rf_conf": rf_conf,
                "iforest_vote": if_vote,
                "iforest_conf": if_conf,
                "rule_vote": rule_vote,
                "rule_conf": round(rule_conf, 4),
            })

        return results
