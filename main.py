#!/usr/bin/env python3
"""
AI Triage – автоматически производит триаж уязвимостей с использованием RAG + LLM
Основной файл приложения, реализующий CLI с помощью Typer. Содержит команды для триажа, обогащения базы знаний, скачивания данных и бенчмаркинга.
Команды:
- triage: выполняет триаж сработок по test_id, сохраняет результаты в JSONL и может постить комментарии в DefectDojo
- enrich: обогащает базу знаний на основе закрытых false-positive сработок
- fetch: скачивает findings по test_id и сохраняет их в JSON файл
- bench: сравнивает результаты AI-триажа с окончательной ручной разметкой из DefectDojo
- rag-delete: удаляет данные из RAG базы знаний по finding ID, документу или правилу
- rag-add: добавляет один finding в базу знаний RAG на основе JSON файла с данными сработки
"""

import json
import logging
import os
import sys
from pathlib import Path
from typing import Optional

import typer
from dotenv import load_dotenv

load_dotenv()

# Отключаем телеметрию — иначе будут запросы от фреймворков к внешним сервисам
os.environ.setdefault("OPENAI_DISABLE_SEND_TELEMETRY", "1")
os.environ.setdefault("HF_HUB_OFFLINE", "1")
os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")

app = typer.Typer(
    help="AI Triage: автоматически производит триаж уязвимостей с использованием RAG + LLM",
    no_args_is_help=True,
)


def _setup_logging(level: str = "INFO") -> None:
    log_dir = Path("log")
    log_dir.mkdir(parents=True, exist_ok=True)

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)

    # File handler — DEBUG and above, detailed
    file_handler = logging.FileHandler(
        log_dir / "ai_triage.log", encoding="utf-8"
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    )
    root.addHandler(file_handler)

    # Console handler — respects the configured log level
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(getattr(logging, level.upper(), logging.WARNING))
    console_handler.setFormatter(
        logging.Formatter("[%(levelname)s] %(message)s")
    )
    root.addHandler(console_handler)

    # Выключаем логи OpenAI SDK
    logging.getLogger("openai").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)


def _load_settings():
    from config.settings import Settings
    return Settings()


def _build_dd_client(settings):
    from integrations.defectdojo.client import DefectDojoClient
    return DefectDojoClient(
        api_url=settings.dd_api_url,
        api_key=settings.dd_api_key,
        verify_ssl=settings.dd_verify_ssl,
    )


def _build_vector_store(settings):
    from knowledge.vector_store import VectorStore
    return VectorStore(
        collection_name=settings.chroma_collection,
        persist_directory=settings.chroma_dir,
        embedding_model=settings.embedding_model,
    )


def _build_llm_client(settings):
    from llm_backend.client import build_llm_client
    return build_llm_client(settings)


def _build_checker_llm_client(settings):
    from llm_backend.client import build_checker_llm_client
    if not settings.checker_llm_enabled:
        return None
    return build_checker_llm_client(settings)


def _build_engine(settings, vector_store=None, llm_client=None, repo_path=None):
    from triage.engine import TriageEngine
    store = vector_store or _build_vector_store(settings)
    llm = llm_client or _build_llm_client(settings)
    checker_llm = _build_checker_llm_client(settings)

    code_context = None
    if repo_path:
        from analysis.code_context import CodeContextProvider
        max_chars = settings.code_context_max_chars or (settings.llm_n_ctx * 3)
        code_context = CodeContextProvider(
            repo_root=repo_path,
            max_chars=max_chars,
            max_lines=settings.code_context_lines,
        )

    return TriageEngine(
        vector_store=store,
        llm_client=llm,
        dd_base_url=settings.dd_api_url,
        code_context_provider=code_context,
        checker_llm_client=checker_llm,
    )


def _load_or_fetch(dd_client, test_id: int, cache_file: str, logger) -> list:
    """
    Функция подгрузки findings. Если есть кеш - то загружает из него, если нет вызывает функцию для скачивания по test id если нет кеша 
    """
    cache_path = Path(cache_file)
    cache_path.parent.mkdir(parents=True, exist_ok=True)

    if cache_path.exists(): # создание файла для кеширования
        with open(cache_path, "r", encoding="utf-8") as f:
            findings = json.load(f)
        logger.info("Loaded %d findings from cache: %s", len(findings), cache_file)
        return findings

    findings = dd_client.fetch_findings(test_id=test_id) # формирование запроса на скачивание если нет кеша
    with open(cache_path, "w", encoding="utf-8") as f:
        json.dump(findings, f, ensure_ascii=False, indent=2)
    logger.info("Fetched and cached %d findings to: %s", len(findings), cache_file)
    return findings


@app.command()
def triage(
    test_id: int = typer.Option(..., "--test-id", "-t", help="DefectDojo test ID"),
    cache_file: Optional[str] = typer.Option(
        None, "--cache", "-c", help="Path to findings cache JSON (auto-created if absent)"
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Output JSONL file path"
    ),
    post_comments: bool = typer.Option(
        False, "--post-comments", help="Post triage results as DefectDojo comments"
    ),
    repo: Optional[str] = typer.Option(
        None, "--repo", "-r", help="Path to local repository checkout for source code context"
    ),
    false_positive: bool = typer.Option(
        False, "--false-positive", "-fp", help="Output only false-positive verdicts"
    ),
) -> None:
    """
    Команда для триажа findings, я не знаю как это работает, наверное магия AI =)
    """
    settings = _load_settings()
    _setup_logging(settings.log_level)
    logger = logging.getLogger(__name__)

    cache = cache_file or f"{settings.cache_dir}/findings_{test_id}.json"
    output = output_file or f"{settings.output_dir}/triage_{test_id}.jsonl"
    Path(output).parent.mkdir(parents=True, exist_ok=True)

    dd = _build_dd_client(settings) # загружаем класс DD
    engine = _build_engine(settings, repo_path=repo) # загружаем класс TriageEngine

    findings = _load_or_fetch(dd, test_id, cache, logger) # загрузка finding по test id для триажа

    # статистика
    fp_count = 0
    review_count = 0

    with open(output, "w", encoding="utf-8") as out:
        for finding in findings:
            result = engine.triage(finding)
            finding["triage_result"] = result.model_dump()

            if result.verdict == "false-positive":
                fp_count += 1
            else:
                review_count += 1

            if not false_positive or result.verdict == "false-positive":
                out.write(json.dumps(finding, ensure_ascii=False) + "\n")

            if post_comments and result.dd_comment:
                dd.add_comment(finding["id"], result.dd_comment)

    typer.echo(
        f"Успешно выполнено. \n К ложным сработкам отнесено: {fp_count} \n Требуют ручного анализа {review_count} \n Файл с результатами {output}"
    )


@app.command()
def enrich(
    test_id: int = typer.Option(
        ..., "--test-id", "-t", help="DefectDojo test ID"
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Preview changes without writing to knowledge base"
    ),
) -> None:
    """
    Команда для обогащения базы знаний на основе закрытых false-positive findings.
    """
    settings = _load_settings()
    _setup_logging(settings.log_level)
    logger = logging.getLogger(__name__)

    logger.debug("enrich: settings loaded, embedding_model=%s", settings.embedding_model)
    logger.debug("enrich: dry_run=%s, test_id=%d", dry_run, test_id)

    from knowledge.enrichment import KnowledgeEnricher

    logger.debug("enrich: building DefectDojo client ...")
    dd = _build_dd_client(settings)
    logger.debug("enrich: DD client ready")

    logger.debug("enrich: building VectorStore ...")
    store = _build_vector_store(settings)
    logger.debug("enrich: VectorStore ready")

    logger.debug("enrich: building LLM client ...")
    llm = _build_llm_client(settings)
    logger.debug("enrich: LLM client ready")

    enricher = KnowledgeEnricher(
        dd_client=dd,
        vector_store=store,
        llm_client=llm,
        dedup_threshold=settings.dedup_threshold,
    )

    logger.debug("enrich: starting enrichment pipeline ...")
    stats = enricher.enrich_from_product(test_id=test_id, dry_run=dry_run)
    logger.debug("enrich: pipeline complete")
    typer.echo(json.dumps(stats, indent=2))


@app.command()
def fetch(
    test_id: int = typer.Option(..., "--test-id", "-t", help="DefectDojo test ID"),
    output: Optional[str] = typer.Option(
        None, "--output", "-o", help="Output JSON file (default: cache dir)"
    ),
) -> None:
    """
    Функция для скачивания findings по test id и сохранения их в JSON файл. 
    Если указать --output, то сохраняет в него, иначе сохраняет в папку кеша.
    """
    settings = _load_settings()
    _setup_logging(settings.log_level)
    logger = logging.getLogger(__name__)

    dd = _build_dd_client(settings)
    dest = output or f"{settings.cache_dir}/findings_{test_id}.json"
    Path(dest).parent.mkdir(parents=True, exist_ok=True)

    findings = dd.fetch_findings(test_id=test_id)
    with open(dest, "w", encoding="utf-8") as f:
        json.dump(findings, f, ensure_ascii=False, indent=2)

    logger.info("Saved %d findings to %s", len(findings), dest)
    typer.echo(f"Saved {len(findings)} findings to {dest}")


@app.command()
def bench(
    input_file: str = typer.Option(
        ..., "--input", "-i", help="Path to JSONL file with previous triage results"
    ),
    test_id: int = typer.Option(
        ..., "--test-id", "-t", help="DefectDojo test ID to fetch final human-triaged findings"
    ),
) -> None:
    """
    Бенчмарк: сравнение результатов AI-триажа с окончательной ручной разметкой из DefectDojo.
    """
    settings = _load_settings()
    _setup_logging(settings.log_level)
    logger = logging.getLogger(__name__)

    # 1. Загрузить результаты AI-триажа из input файла
    input_path = Path(input_file)
    if not input_path.exists():
        typer.echo(f"Input file not found: {input_file}")
        raise typer.Exit(1)
    
    logger.debug("bench: input file загружен input_file=%s, test_id=%d", input_file, test_id)
    ai_results: dict[int, str] = {}  # finding_id -> verdict
    with open(input_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            finding = json.loads(line)
            fid = finding.get("id")
            logger.debug("bench: работаем с finding id=%s", fid)
            verdict = (finding.get("triage_result") or {}).get("verdict", "")
            if fid is not None:
                ai_results[fid] = verdict

    if not ai_results:
        typer.echo("No triage results found in input file")
        raise typer.Exit(1)
    typer.echo(f"  Загружено {len(ai_results)} AI-вердиктов")

    # 2. Скачать окончательно размеченные findings из DefectDojo
    typer.echo(f"Загрузка findings из DefectDojo (test_id={test_id}) ...")
    dd = _build_dd_client(settings)
    human_findings = dd.fetch_all_findings(test_id=test_id)
    typer.echo(f"  Получено {len(human_findings)} findings из DefectDojo")

    human_status: dict[int, bool] = {}  # finding_id -> is false_positive
    for f in human_findings:
        human_status[f["id"]] = bool(f.get("false_p", False))

    # 3. Сравнение
    typer.echo("Сравнение результатов ...")
    correct = 0
    incorrect = 0
    total_compared = 0

    for fid, ai_verdict in ai_results.items():
        if fid not in human_status:
            logger.warning("Finding %d from input not found in DefectDojo test %d, skipping", fid, test_id)
            continue

        total_compared += 1
        ai_is_fp = ai_verdict == "false-positive"
        human_is_fp = human_status[fid]

        if ai_is_fp == human_is_fp:
            correct += 1
        else:
            incorrect += 1

    # 4. Вывод статистики
    if total_compared == 0:
        typer.echo("No matching findings found for comparison")
        raise typer.Exit(1)

    correct_pct = correct / total_compared * 100
    incorrect_pct = incorrect / total_compared * 100

    typer.echo(f"Benchmark (test-id={test_id}):")
    typer.echo(f"  Всего сравнений: {total_compared}")
    typer.echo(f"  Верно:   {correct} ({correct_pct:.1f}%)")
    typer.echo(f"  Неверно: {incorrect} ({incorrect_pct:.1f}%)")


@app.command()
def rag_delete(
    delete_finding: Optional[int] = typer.Option(
        None, "--delete-finding", "-f", help="Delete entries by source finding ID"
    ),
    delete_entry: Optional[str] = typer.Option(
        None, "--delete-entry", "-e", help="Delete a single entry by its RAG document ID"
    ),
    delete_rule: Optional[str] = typer.Option(
        None, "--delete-rule", "-r", help="Delete all entries matching a SAST rule"
    ),
) -> None:
    """
    Функция для удаления данных из RAG базы знаний. Можно удалить по ID finding, по ID документа или по правилу SAST.
    Пример использования → python main.py rag-delete --delete-finding 12345
    Пример использования → python main.py rag-delete --delete-entry fp_12345_abcdef
    Пример использования → python main.py rag-delete --delete-rule rule_name
    """
    if not delete_finding and not delete_entry and not delete_rule:
        typer.echo("Specify at least one of: --delete-finding, --delete-entry, --delete-rule")
        raise typer.Exit(1)

    settings = _load_settings()
    _setup_logging(settings.log_level)
    store = _build_vector_store(settings)

    if delete_finding:
        count = store.delete_by_finding_id(delete_finding)
        typer.echo(f"Deleted {count} entries for finding_id={delete_finding}")
    if delete_entry:
        ok = store.delete_by_id(delete_entry)
        typer.echo(f"Deleted entry '{delete_entry}': {'OK' if ok else 'FAILED'}")
    if delete_rule:
        count = store.delete_by_rule(delete_rule)
        typer.echo(f"Deleted {count} entries for rule='{delete_rule}'")


@app.command()
def rag_add(
    add_finding: str = typer.Option(
        ..., "--add-finding", "-f", help="Path to JSON file with a finding to add"
    ),
) -> None:
    """
    Функция для добавления одного finding в базу знаний RAG. На вход принимает JSON файл с данными finding, формирует на его основе документ и сохраняет его в векторное хранилище.
    Пример использования → python main.py rag-add --add-finding example_finding.json
    """
    import hashlib

    settings = _load_settings()
    _setup_logging(settings.log_level)
    store = _build_vector_store(settings)

    with open(add_finding, "r", encoding="utf-8") as f:
        finding = json.load(f)

    from core.models import KnowledgeEntry
    from knowledge.enrichment import KnowledgeEnricher

    finding_id = finding.get("id", 0)
    cves = [v.get("vulnerability_id", "") for v in finding.get("vulnerability_ids", [])]
    cve = cves[0] if cves else None
    component = finding.get("component_name") or ""
    component_version = finding.get("component_version") or ""
    rule = finding.get("title") or ""

    notes = finding.get("notes") or []
    reason = "\n---\n".join(n.get("entry", "") for n in notes if n.get("entry"))
    if not reason:
        reason = finding.get("description") or finding.get("title") or ""

    document = KnowledgeEnricher._build_document(reason[:500], cve, component, component_version)
    doc_hash = hashlib.sha256(document.encode()).hexdigest()[:16]

    entry = KnowledgeEntry(
        id=f"fp_{finding_id}_{doc_hash}",
        document=document,
        cve=cve,
        component_name=component or None,
        component_version=component_version or None,
        rule=rule or None,
        source_finding_id=finding_id,
        product_id=finding.get("product") or finding.get("product_id"),
        test_id=finding.get("test"),
        file_path=finding.get("file_path") or finding.get("sast_source_file_path"),
        test_name=finding.get("test_name"),
        date=(finding.get("mitigated") or "")[:10] or None,
        hash=doc_hash,
    )

    if store.entry_exists(entry.id):
        typer.echo(f"Entry '{entry.id}' already exists, skipping")
        raise typer.Exit(0)

    ok = store.add_entry(entry)
    typer.echo(f"Added entry '{entry.id}': {'OK' if ok else 'FAILED'}")


if __name__ == "__main__":
    app()
