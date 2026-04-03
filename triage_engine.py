from typing import List, Dict
from rules import analyze_finding
from rag_search import ChromaDB
from llm_client import chatllm


class TriageEngine:
    def __init__(self, dd_client, chroma_collection='example_collection', chroma_dir='./rag/chroma_db_metadata', llama_bin='./main', model_path=None):
        self.dd = dd_client
        self.rag = ChromaDB(collection_name=chroma_collection, persist_directory=chroma_dir)
        # self.llama_bin = llama_bin
        # self.model_path = model_path

    def run_batch(self, findings: List[Dict]):
        results = []
        for f in findings:
            res = self.process_finding(f)
            results.append({'finding': f, 'result': res})
        return results

    def triage(self, finding: Dict) -> Dict:
        # 1: используем детерминистические правила
        print("[info] проверка по детерминистическим правилам")
        matched, comment = analyze_finding(finding) # TODO: вызвать мастер фунцию чтобы она внутри проводила запуск
        if matched:
            print('[+] найдено совпадение по детерминистическим правилам')
            # self.dd.add_comment(finding_id=finding.get('id'), comment=comment)
            return {'category': 'false-positive', 'explanation': comment, 'confidence': 0.9}

        # 2: поиск direct meta (cve + component)
        print("[info] проверка direct meta")
        cve = finding['vulnerability_ids'][0]['vulnerability_id'] # TODO: нужна отладка на данных если будет несколько, нужно искать по началу value
        comp = finding.get('component_name')
        rag_meta_search_res = self.rag.search_by_meta(cve=cve, component_name=comp)
        # print(f'rule rag-search: {rag_meta_search_res}') # TODO: протестировать если будет возвращаться несколько значений - 5 шт
        
        if rag_meta_search_res:
            print('[+] найдено совпадение по правилу direct meta')
            comment = f"Similar findings:  https://ddojo.dev.rosatom.local/finding/{rag_meta_search_res[0]['metadata']['id']}"
            # self.dd.add_comment(finding_id=finding.get('id'), comment=comment)
            return {'action': 'rag_meta', 'matches': len(rag_meta_search_res), 'comment': comment}

        # 3: поиск RAG similarity search по CVE
        print("[info] проверка RAG similarity search by CVE")
        # text = finding.get('title') # плохая идея много букв и поиск очень нерелевантный
        if cve:
            sim_search_res = self.rag.search_by_similarity(cve)
            # print(f'RAG finding id: {sim_search_res[0]['metadata']['id']}')
            if sim_search_res:
                print('[+] найдено совпадение по правилу RAG similarity by CVE')
                comment = f"Possible similar findings:  https://ddojo.dev.rosatom.local/finding/{sim_search_res[0]['metadata']['id']}"
                # self.dd.add_comment(finding_id=finding.get('id'), comment=comment)
                return {'action': 'rag_similarity_search', 'matches': len(sim_search_res), 'comment': comment}

        # 4: используем LLM
        print("[info] совпадений не найдено, провожу анализ через LLM")
        rag_data = self.rag.search_by_similarity_filtered(finding.get("title")) #  нужно вычленить описание чтобы по нему была
        print(f'==== rag_data:{rag_data}')
        if rag_data != None:
            system_prompt = f"""
            Your task is determinate is finding is false-positive or not. 
            Here valid reasons to mark findings as false-positive: {rag_data}.
            Do not interpritate findings yourself, do not make assamptions, do not use previous context.
            Responce as json with with 3 fields:
                decision: false-positive|needs review, 
                confidence: 0.0 - 1.0, 
                explanation: 'short explanation'"
            """
            user_prompt = (
                f"Here new finding to analyze:\n{finding}\n"
            )
            # нужно нормализовать чтобы проверять длину finding и не отдавать все поля

            llm_resp = chatllm(user_prompt, system_prompt)
            print(f'llm_resp : {llm_resp}')
            # print(f'ответ llm {llm_resp}')
            if llm_resp:
                comment = f"Анализ LLM: {llm_resp}"
                # self.dd.add_comment(finding_id=finding.get('id'), comment=comment)
                return {'action': 'llm', 'verdict': 'manual review is needed', 'comment': comment}

        # 5: no decision? хз написал чтобы было
        comment = 'в БД не найдено схожей сработки'
        print(f'[info] {comment}')
        # self.dd.add_comment(finding_id=finding.get('id'), comment=comment)
        return {'verdict': 'manual review is needed', 'comment': comment}
