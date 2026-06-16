"""SecGPT 报告生成的 RAG 检索器（在 didienv 中运行，复用 GPU）。"""
import os
from typing import Optional

CHROMA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "chroma_db", "report_rag")
MODEL_PATH = "/root/.cache/modelscope/hub/models/BAAI/bge-large-en-v1.5"

# 每种攻击类型的检索查询词
ATTACK_QUERIES = {
    "injection attack": [
        "SQL injection attack prevention parameterized queries input validation defense",
        "command injection RCE remote code execution security fix mitigation",
    ],
    "cross-site scripting attack": [
        "XSS cross site scripting defense output encoding CSP content security policy",
    ],
    "directory traversal attack": [
        "directory traversal path traversal prevention input validation canonicalization",
    ],
    "unauthorized access attack": [
        "unauthorized access authentication authorization access control broken API security",
    ],
    "sensitive data leakage": [
        "sensitive data leakage information disclosure API security data protection encryption",
    ],
    "performance issue": [
        "API rate limiting DoS DDoS protection performance security throttling",
    ],
    "invalid item value": [
        "input validation parameter tampering type checking API security best practice",
    ],
    # 爬虫相关
    "crawler": [
        "web crawler scraper bot detection rate limiting defense fingerprinting",
        "distributed crawler detection IP reputation behavioral analysis anti-bot",
    ],
}

_retriever = None


def get_retriever():
    """懒加载 RAG 检索器单例。"""
    global _retriever
    if _retriever is None:
        _retriever = ReportRAGRetriever()
    return _retriever


class ReportRAGRetriever:
    """为报告生成提供知识增强检索。"""

    def __init__(self, chroma_dir: str = CHROMA_DIR, model_path: str = MODEL_PATH):
        self._chroma_dir = chroma_dir
        self._model_path = model_path
        self._model = None
        self._collection = None
        self._loaded = False

    def _ensure_loaded(self):
        if self._loaded:
            return
        import torch
        import chromadb
        from sentence_transformers import SentenceTransformer

        self._model = SentenceTransformer(self._model_path, device="cuda")
        self._client = chromadb.PersistentClient(path=self._chroma_dir)
        self._collection = self._client.get_collection("report_rag_knowledge")
        self._loaded = True

    def retrieve(self, queries: list[str], n: int = 3) -> list[dict]:
        """对多个查询执行检索，返回去重后的知识片段。"""
        self._ensure_loaded()
        seen, results = set(), []
        for q in queries:
            q_emb = self._model.encode([q])[0].tolist()
            res = self._collection.query(query_embeddings=[q_emb], n_results=n)
            for i, doc_id in enumerate(res['ids'][0]):
                if doc_id in seen:
                    continue
                seen.add(doc_id)
                doc = res['documents'][0][i] if res['documents'] else ""
                meta = res['metadatas'][0][i] if res['metadatas'] else {}
                # 截取关键内容：前200字符做摘要 + 中间防御建议部分
                text = doc
                if len(text) > 800:
                    # 取前200和后400字符（后部常含修复建议）
                    text = text[:200] + "\n...(省略)...\n" + text[-400:]
                results.append({
                    "id": doc_id,
                    "instruction": meta.get("instruction", ""),
                    "text": text,
                })
        return results

    def build_report_context(self, summary: dict, max_chunks: int = 8) -> str:
        """根据检测摘要构建 RAG 上下文文本块。"""
        stage2_types = summary.get("stage2_attack_types", {})
        ga = summary.get("global_assessment", {})

        queries = []
        # 检测到的 API 攻击类型（只检索低召回率类型，高召回率的不需要额外知识）
        s2_metrics = summary.get("stage2_metrics", {})
        per_type_recall = s2_metrics.get("per_type_recall", {})
        for atype in stage2_types:
            rec = per_type_recall.get(atype, 1.0)
            if rec < 0.9 and atype in ATTACK_QUERIES:  # 只检索召回率<90%的类型
                queries.extend(ATTACK_QUERIES[atype][:1])  # 每种类型只取第一个查询
        # 爬虫相关总是检索
        if ga.get("has_distributed_crawler") or ga.get("has_crowdsourced_crawler"):
            queries.extend(ATTACK_QUERIES.get("crawler", [])[:1])

        if not queries:
            return ""

        chunks = self.retrieve(queries, n=3)[:max_chunks]
        if not chunks:
            return ""

        lines = ["\n## 安全知识库参考（请优先参考以下知识来撰写防御建议）\n"]
        for i, c in enumerate(chunks, 1):
            title = c["instruction"][:80] if c["instruction"] else "安全知识"
            lines.append(f"### {title}")
            lines.append(c["text"])
            lines.append("")
        return "\n".join(lines)
