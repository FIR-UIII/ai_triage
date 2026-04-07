from typing import List, Dict, Optional
import chromadb
from sentence_transformers import SentenceTransformer
from chromadb.config import Settings


class ChromaDB:
    def __init__(self, collection_name: str = 'findings', persist_directory: str = './chroma_db_metadata'):
        self.client = chromadb.PersistentClient(path=persist_directory) # TODO: подумать над использованием Client вместо PersistentClient
        self.collection = self.client.get_or_create_collection(name=collection_name)

    def search_by_meta(self, cve: Optional[str], component_name: Optional[str], n_results: int = 5) -> List[Dict]:
        """
        Точный поиск
        """
        if not cve and not component_name:
            return []
        
        where = {"$and": [{"cve": cve},{"component_name": component_name}]}
        try:
            # Используем get, так как нам не нужен семантический поиск
            res = self.collection.get(where=where, limit=n_results)
            # В get ответ не вложенный, можно сразу использовать списки
            metadatas = res.get('metadatas', [])
            documents = res.get('documents', [])
            ids = res.get('ids', [])
            out = [] # формируем массив для получения 5 значений
            for md, doc, id_ in zip(metadatas, documents, ids):
                out.append({'id': id_, 'metadata': md, 'document': doc})
            return out
        except Exception as e:
            print(f"Ошибка поиска: {e}")
            return []

    def search_by_similarity(self, text: str, n_results: int = 1):
        """
        Поиск по векторам
        """
        try:
            res = self.collection.query(query_texts=[text], n_results=n_results)
            ids = res['ids'][0]
            documents = res['documents'][0]
            metadatas = res['metadatas'][0]
            distances = res['distances'][0]
            scores = [1 - d for d in distances] # TODO: разобраться с весами и сделать проверку по сравнению со неким коэф.
            # print(distances[0], scores[0])
            if round(scores[0], 3) >= -0.75: # округляем и сравниваем дистанцию ответа
                out = [] # формируем массив для получения 5 значений
                for md, doc, sc in zip(metadatas, documents, scores):
                    out.append({'score': sc, 'metadata': md, 'document': doc}) # TODO: сделать фильтр?
                return out

        except Exception as e:
            print(f"Ошибка поиска: {e}")
            return []


    def search_by_similarity_filtered(self, filter_param: str, n_results: int = 3):
        """
        Поиск для обогащения промпта LLM информацией из RAG для анализа схожих сработок по правилам SAST 
        """
        if not filter_param:
            return []
        
        where = {"rule": filter_param}
        # print(f'where is :{where}')
        try:
            res = self.collection.get(limit=n_results, where=where) # пока вместо query просто get
            # print(f'res :{res}')
            metadatas = res.get('metadatas', [])
            documents = res.get('documents', [])
            ids = res.get('ids', [])
            if ids != []: # проверяем что есть ответ
                return documents
            else:
                return None
        except Exception as e:
            print(f"Ошибка поиска: {e}")
            return []