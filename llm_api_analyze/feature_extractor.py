"""用于二分类的增强型安全日志特征提取器。"""

import re
import numpy as np


class EnhancedSecurityFeatureExtractor:
    """增强型安全日志特征提取器，包含8种攻击类型的模式。"""

    def __init__(self):
        self._init_enhanced_patterns()

    def _init_enhanced_patterns(self):
        # 1. 目录遍历攻击
        self.dir_traversal_patterns = [
            r"\.\./", r"\.\.\\", r"/etc/passwd", r"/etc/shadow",
            r"\.\.%2f", r"\.\.%5c", r"/proc/", r"/var/log/",
            r"\.\.\\\.\.", r"\.\./\."
        ]
        # 2. XSS跨站脚本攻击
        self.xss_enhanced_patterns = [
            r"<script.*?>.*?</script>", r"javascript:", r"alert\(.*?\)",
            r"onerror\s*=", r"onload\s*=", r"onclick\s*=", r"eval\s*\(",
            r"document\.cookie", r"window\.location", r"<iframe.*?>",
            r"<img.*?onerror.*?>", r"<svg.*?>.*?</svg>", r"<object.*?>"
        ]
        # 3. 注入攻击
        self.injection_patterns = [
            r"'.*?(or|and).*?=.*?'", r"union.*?select", r"sleep\(.*?\)",
            r"benchmark\(.*?\)", r"waitfor.*?delay", r"drop\s+table",
            r"insert\s+into", r"delete\s+from", r"update\s+.*?\s+set",
            r"\$\{.*?\}", r"\$ne\s*:", r"\$gt\s*:", r"\$where\s*:",
            r"\|\s*[a-z]", r";\s*[a-z]", r"`.*?`", r"\$\(.*?\)"
        ]
        # 4. 敏感数据泄露
        self.sensitive_data_patterns = [
            r"password\s*[:=]\s*['\"].{6,}['\"]", r"pwd\s*[:=]\s*['\"].{6,}['\"]",
            r"ssn\s*[:=]\s*['\"].{9}['\"]", r"credit.*?card",
            r"\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}",
            r"api[_-]?key\s*[:=]\s*['\"].{10,}['\"]", r"secret\s*[:=]\s*['\"].{10,}['\"]",
            r"token\s*[:=]\s*['\"].{10,}['\"]", r"authorization\s*[:=]\s*['\"].{10,}['\"]",
            r"bearer\s+[a-z0-9]{20,}", r"email\s*[:=]\s*['\"][^@]+@[^@]+\.[^@]+['\"]"
        ]
        # 5. 无效参数值
        self.invalid_value_patterns = [
            r"[<>]", r"\\x[0-9a-f]{2}", r"%[0-9a-f]{2}", r"\.\.",
            r"null", r"undefined", r"test.*?", r"admin.*?",
            r"or.*?1.*?=.*?1", r"';.*?--"
        ]
        # 6. 未授权访问
        self.unauthorized_patterns = [
            r"admin", r"root", r"superuser", r"privilege",
            r"delete", r"drop", r"truncate", r"shutdown",
            r"\.(exe|sh|bat|php|jsp|asp)$", r"\.(sql|bak|old)$",
            r"id=\d{5,}", r"user[id]?=\d+"
        ]
        # 7. 性能问题
        self.performance_patterns = [
            r"limit\s*=\s*\d{5,}", r"rows\s*=\s*\d{5,}",
            r"order\s+by.*?,\s*", r"group\s+by.*?,\s*",
            r"recursive", r"with\s+recursive"
        ]
        # 8. JSON结构异常
        self.json_anomaly_patterns = [
            r'\{[^{}]*\{', r'\[[^\[\]]*\[', r'""[^"]*""', r'[^:]:[^:]'
        ]

    @staticmethod
    def _get(log_row, names, default=""):
        """按名称或位置索引取字段值。优先用名称（dict/Series），回退到位置索引。"""
        if hasattr(log_row, 'get'):
            for n in names:
                v = log_row.get(n)
                if v is not None and str(v).strip():
                    return str(v)
        # 回退到位置索引：method=0, body=1, url=2, resp_body=3, status=4, rt=5, user=6
        pos_map = {'method':0, 'request_body':1, 'request_url':2, 'response_body':3,
                   'status':4, 'status_code':4, 'response_time':5, 'user_identity':6, 'user_role':6}
        for n in names:
            if n in pos_map:
                p = pos_map[n]
                try:
                    v = str(log_row[p]) if hasattr(log_row, '__getitem__') and len(log_row) > p else default
                    if v.strip(): return v
                except (IndexError, KeyError, TypeError):
                    pass
        return default

    def extract_features_from_log(self, log_row):
        """从日志行提取特征向量。支持命名列（dict/DataFrame）和位置索引。"""
        features = {}
        try:
            http_method = self._get(log_row, ['method', 'http_method'])
            status_code = self._get(log_row, ['status', 'status_code'])
            user_identity = self._get(log_row, ['user_identity', 'user_role', 'username'])

            for m in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                features[f'method_{m.lower()}'] = 1 if http_method.upper() == m else 0

            features['status_2xx'] = 1 if status_code.startswith('2') else 0
            features['status_4xx'] = 1 if status_code.startswith('4') else 0
            features['status_5xx'] = 1 if status_code.startswith('5') else 0
            features['status_client_error'] = 1 if status_code in ['400', '401', '403', '404'] else 0

            try:
                rt_str = self._get(log_row, ['response_time', 'response_time_ms'])
                rt = float(rt_str) if rt_str.strip() else 0
                features['response_time_ms'] = rt
                features['slow_response'] = 1 if rt > 1000 else 0
                features['very_slow_response'] = 1 if rt > 3000 else 0
            except (ValueError, Exception):
                features['response_time_ms'] = 0
                features['slow_response'] = 0
                features['very_slow_response'] = 0

            request_body = self._get(log_row, ['request_body'])
            request_url = self._get(log_row, ['request_url', 'path', 'endpoint'])
            response_body = self._get(log_row, ['response_body'])

            features['request_body_length'] = len(request_body)
            features['request_url_length'] = len(request_url)
            features['response_body_length'] = len(response_body)
            features['total_payload_length'] = len(request_body) + len(request_url) + len(response_body)

            combined_text = f"{request_body} {request_url} {response_body}"
            url_and_body = f"{request_url} {request_body}"

            # 特定攻击类型的得分
            features['dir_traversal_score'] = self._count_patterns(combined_text, self.dir_traversal_patterns)
            features['xss_score'] = self._count_patterns(combined_text, self.xss_enhanced_patterns)
            features['injection_score'] = self._count_patterns(combined_text, self.injection_patterns)
            features['sensitive_data_leakage'] = self._count_patterns(response_body, self.sensitive_data_patterns)
            features['sensitive_in_request'] = self._count_patterns(request_body, self.sensitive_data_patterns)
            features['invalid_value_score'] = self._count_patterns(url_and_body, self.invalid_value_patterns)

            # 未授权访问
            features['unauthorized_access_score'] = 0
            if user_identity.lower() in ['user', 'guest']:
                if any(p in request_url.lower() for p in ['/admin', '/delete', '/drop', '/truncate']):
                    features['unauthorized_access_score'] += 2
                if http_method.upper() in ['DELETE', 'PUT', 'PATCH']:
                    features['unauthorized_access_score'] += 1
            features['unauthorized_access_score'] += self._count_patterns(request_url, self.unauthorized_patterns)

            # 性能问题
            features['performance_issue_score'] = self._count_patterns(combined_text, self.performance_patterns)
            if features['response_body_length'] > 10000:
                features['performance_issue_score'] += 1
            if features['response_body_length'] > 50000:
                features['performance_issue_score'] += 2

            # JSON异常
            features['json_anomaly_score'] = self._count_patterns(
                request_body + response_body, self.json_anomaly_patterns
            )

            # 上下文特征
            features['url_depth'] = request_url.count('/')
            features['has_query_params'] = 1 if '?' in request_url else 0
            features['query_param_count'] = request_url.count('&') + (1 if '?' in request_url else 0)

            sensitive_endpoints = ['/admin', '/users', '/clients', '/sales', '/beSharedItems']
            features['is_sensitive_endpoint'] = 1 if any(
                ep in request_url for ep in sensitive_endpoints
            ) else 0

            features['is_admin'] = 1 if 'admin' in user_identity.lower() else 0
            features['is_root'] = 1 if 'root' in user_identity.lower() else 0
            features['is_privileged_user'] = features['is_admin'] or features['is_root']

            # 组合特征
            features['high_risk_combo'] = (
                (features['is_privileged_user'] == 0)
                and (features['is_sensitive_endpoint'] == 1)
                and (features.get('slow_response', 0) == 1)
            )
            features['injection_with_success'] = (
                (features['injection_score'] > 0) and (features['status_2xx'] == 1)
            )

            # 得分特征的布尔变体
            score_features = [
                'dir_traversal_score', 'xss_score', 'injection_score',
                'sensitive_data_leakage', 'invalid_value_score',
                'unauthorized_access_score', 'performance_issue_score', 'json_anomaly_score'
            ]
            for fn in score_features:
                bool_name = f'has_{fn.replace("_score", "")}'
                features[bool_name] = 1 if features.get(fn, 0) > 0 else 0

            return features

        except Exception as e:
            print(f"Feature extraction error: {e}")
            return {}

    def _count_patterns(self, text, patterns):
        """统计文本中正则模式匹配的次数。"""
        count = 0
        for pattern in patterns:
            try:
                matches = re.findall(pattern, text, re.IGNORECASE)
                count += len(matches)
            except Exception:
                continue
        return count
