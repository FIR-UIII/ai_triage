from dd_api import DefectDojoClient
from triage_engine import TriageEngine
import os
import json

# TODO: как запускать и передавать параметры?
args = {"api_url": "https://ddojo.dev.rosatom.local", "api_key": "3d1ccf6ca95dce7d09ab2e0136107a994ab6e773", "test_id": 15540, "cache_file": "test_SCA.json", "output_file": "res.jsonl"}
dd = DefectDojoClient(api_url=args.get("api_url"), api_key=args.get("api_key"))

def load_findings():
    # TODO: пока закомментил, подумать нужен ли argparse для запуска
    # parser = build_parser()
    # args = parser.parse_args()
    # cache_file = args.cache_file or f"findings_{args.test_id}.json"

    # TODO: подумать над оптимизацией - много памяти может кушать работа с inmem var findings, либо работать через кеш redis или через файл
    findings = None
    if os.path.exists(args.get("cache_file")):
        try:
            with open(args.get("cache_file"), 'r', encoding='utf-8') as file:
                findings = json.load(file)
            print(f"Loaded {len(findings)} findings from cache {args.get("cache_file")}")
        except Exception as e:
            print(f"Failed to load cache {args.get("cache_file")}: {e}. Will re-fetch.")

    if findings is None:
        findings = dd.fetch_findings(test_id=args.get("test_id"))
        try:
            with open(args.get("cache_file"), 'w', encoding='utf-8') as file:
                json.dump(findings, file, ensure_ascii=False, indent=2)
            print(f"Saved {len(findings)} findings to cache {args.get("cache_file")}")
        except Exception as e:
            print(f"Failed to save findings to cache {args.get("cache_file")}: {e}")

def triage():
    engine = TriageEngine(dd_client=dd)

    with open(args["cache_file"], 'r', encoding='utf-8') as file:
        findings_triage = json.load(file)

    with open(args["output_file"], 'w', encoding='utf-8') as outfile:
        for f in findings_triage:
            result = engine.triage(f)
            f['triage_result'] = result
            # TODO: Записываем каждый объект на новой строке в jsonl пока так проще читать
            outfile.write(json.dumps(f, ensure_ascii=False) + '\n')

    print(f"Results saved to {args['output_file']} (JSON lines format)")

triage()
# load_findings()