"""从训练数据构建知识库。"""

import pandas as pd


class SecurityKnowledgeBase:
    """从带标签的安全事件构建结构化知识块。"""

    def build_knowledge_base(self, train_csv_path: str):
        """从训练CSV文件构建知识库（8列格式，包含类型标签）。

        每个知识块包含：
          - content: 描述安全事件的结构化文本
          - metadata: 异常类型、HTTP方法、端点、状态码等
        """
        try:
            print(f"Reading training data: {train_csv_path}")
            df = pd.read_csv(train_csv_path)
            print(f"Training data shape: {df.shape}")

            knowledge_chunks = []
            for idx, row in df.iterrows():
                try:
                    if len(row) < 7:
                        continue
                    chunk = {
                        'id': f"train_{idx}",
                        'content': self._create_knowledge_content(row, idx),
                        'metadata': {
                            'anomaly_type': str(row[7]) if len(row) > 7 else 'unknown',
                            'http_method': str(row[0]) if len(row) > 0 else 'unknown',
                            'request_body': str(row[1]) if len(row) > 1 else 'unknown',
                            'endpoint': str(row[2]) if len(row) > 2 else 'unknown',
                            'response_body': str(row[3]) if len(row) > 3 else 'unknown',
                            'status_code': str(row[4]) if len(row) > 4 else 'unknown',
                            'response_time': str(row[5]) if len(row) > 5 else 'unknown',
                            'user_role': str(row[6]) if len(row) > 6 else 'unknown',
                        }
                    }
                    knowledge_chunks.append(chunk)
                except Exception:
                    continue

            print(f"Knowledge base built: {len(knowledge_chunks)} security events")
            return knowledge_chunks
        except Exception as e:
            print(f"Knowledge base build failed: {str(e)}")
            return []

    @staticmethod
    def _create_knowledge_content(row, idx):
        """将知识块格式化为结构化文本。"""
        method = str(row[0]) if len(row) > 0 else "unknown"
        request_body = str(row[1]) if len(row) > 1 else "unknown"
        endpoint = str(row[2]) if len(row) > 2 else "unknown"
        response_body = str(row[3]) if len(row) > 3 else "unknown"
        status_code = str(row[4]) if len(row) > 4 else "unknown"
        response_time = str(row[5]) if len(row) > 5 else "unknown"
        user_role = str(row[6]) if len(row) > 6 else "unknown"

        parts = [
            f"Security Event {idx}:",
            f"HTTP Method: {method}",
            f"Endpoint: {endpoint}",
            f"Status Code: {status_code}",
            f"Response Time: {response_time}ms",
            f"User Role: {user_role}",
            f"Request Body: {request_body[:200]}",
            f"Response Body: {response_body[:200]}",
        ]
        if len(row) > 7:
            parts.append(f"Anomaly Type: {str(row[7])}")
        return " | ".join(parts)
