"""基于ChromaDB和SentenceTransformers的向量数据库管理器。"""

import os
import shutil
import hashlib
import torch
import chromadb
from sentence_transformers import SentenceTransformer

from llm_api_analyze.config import CURRENT_SIMILARITY_THRESHOLD


class VectorDatabaseManager:
    """基于ChromaDB的向量数据库，用于相似事件检索。"""

    def __init__(self, persist_directory: str, model_path: str):
        self.persist_directory = persist_directory
        self.model_path = model_path

        print(f"Initializing vector DB with model: {model_path}")
        if os.path.exists(self.persist_directory):
            shutil.rmtree(self.persist_directory)
        self._load_model()
        self._initialize_database()

    def _load_model(self):
        """加载嵌入模型。"""
        print("Loading embedding model...")
        self.embedding_model = SentenceTransformer(
            self.model_path,
            device="cuda" if torch.cuda.is_available() else "cpu"
        )
        self.model_dimension = self.embedding_model.get_sentence_embedding_dimension()
        self.actual_model_name = os.path.basename(self.model_path)
        print(f"Model loaded: {self.actual_model_name}, dim={self.model_dimension}")

    def _initialize_database(self):
        """创建或获取ChromaDB集合。"""
        self.client = chromadb.PersistentClient(path=self.persist_directory)
        model_safe_name = self.actual_model_name.replace("/", "_").replace("-", "_")
        collection_name = f"security_knowledge_{model_safe_name}"

        try:
            self.client.delete_collection(collection_name)
        except Exception:
            pass

        self.collection = self.client.get_or_create_collection(
            name=collection_name,
            metadata={"description": "Security Knowledge Base", "model_name": self.actual_model_name}
        )
        print("Vector DB initialized.")

    def add_to_knowledge_base(self, knowledge_base):
        """批量添加知识块到向量数据库中。"""
        if not knowledge_base:
            return

        documents, metadatas, ids = [], [], []
        for i, item in enumerate(knowledge_base):
            content = item.get('content', '') if isinstance(item, dict) else str(item)
            metadata = item.get('metadata', {}) if isinstance(item, dict) else {}
            if content and content.strip():
                documents.append(content.strip())
                metadatas.append(metadata)
                ids.append(f"kb_{i}_{hashlib.md5(content.encode()).hexdigest()[:8]}")

        print(f"Adding {len(documents)} documents to vector DB...")
        batch_size = 100
        success = 0
        for i in range(0, len(documents), batch_size):
            batch_docs = documents[i:i + batch_size]
            batch_meta = metadatas[i:i + batch_size]
            batch_ids = ids[i:i + batch_size]

            embeddings = self.embedding_model.encode(
                batch_docs, batch_size=8, show_progress_bar=False, normalize_embeddings=True
            )
            try:
                self.collection.add(
                    embeddings=embeddings.tolist(),
                    documents=batch_docs,
                    metadatas=batch_meta,
                    ids=batch_ids
                )
                success += len(batch_docs)
            except Exception as e:
                print(f"Batch insert failed: {e}")

        print(f"Vector DB ready: {success} records indexed.")

    def retrieve_similar_events(self, query_features, top_k: int = 3):
        """通过特征相似度从向量数据库检索相似事件。"""
        try:
            query_text = self._features_to_text(query_features)
            query_embedding = self.embedding_model.encode([query_text], normalize_embeddings=True)

            results = self.collection.query(
                query_embeddings=query_embedding.tolist(),
                n_results=top_k,
                include=["documents", "metadatas", "distances"]
            )

            similar_events = []
            if results.get('distances') and results.get('documents'):
                for i, distance in enumerate(results['distances'][0]):
                    similarity = 1 - distance
                    if similarity >= CURRENT_SIMILARITY_THRESHOLD:
                        similar_events.append({
                            'content': results['documents'][0][i],
                            'metadata': results['metadatas'][0][i] if results['metadatas'] else {},
                            'similarity': round(similarity, 4)
                        })
            return similar_events[:top_k]

        except Exception as e:
            print(f"Retrieval failed: {e}")
            return []

    @staticmethod
    def _features_to_text(features):
        """将特征字典转换为查询文本。"""
        return ". ".join(f"{k}: {v}" for k, v in features.items() if v)
