#!/usr/bin/env python3
"""
AI Triage – автоматически производит триаж уязвимостей с использованием RAG + LLM
Основной файл приложения, реализующий CLI с помощью Typer. Содержит команды для триажа, обогащения базы знаний и скачивания данных.
Команды:
- triage: выполняет триаж сработок продукта и сохраняет результаты в JSONL
- enrich: обогащает базу знаний на основе закрытых false-positive сработок
- fetch: скачивает findings по имени продукта и сохраняет их в JSON файл
- rag-delete: удаляет данные из RAG базы знаний по finding ID, документу или правилу
- rag-add: добавляет один finding в базу знаний RAG на основе JSON файла с данными сработки
- rules-check: валидирует prompt_rules.yaml и опционально показывает, какие правила совпадут с сработками из JSON файла
"""

import json
import logging
import os
import re
import sys
from pathlib import Path
from typing import Optional

import typer
from dotenv import load_dotenv

load_dotenv()

# Консоль Windows по умолчанию cp1251, а typer/rich рисуют сообщения об ошибках в рамке
# из символов ╭─│╰ — они в cp1251 не кодируются. В результате любая ошибка (например,
# ненайденный продукт) подменялась UnicodeEncodeError, и настоящая причина не доходила
# до пользователя. Переводим вывод в UTF-8 до первого обращения к typer.
for _stream in (sys.stdout, sys.stderr):
    _reconfigure = getattr(_stream, "reconfigure", None)
    if _reconfigure is not None:
        try:
            _reconfigure(encoding="utf-8", errors="replace")
        except (OSError, ValueError):  # поток перенаправлен/закрыт — вывод не критичен
            pass

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

    # Выключаем логи OpenAI SDK и sentence_transformers (иначе tqdm печатает "Batches: 100%...")
    logging.getLogger("openai").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("sentence_transformers").setLevel(logging.WARNING)


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
    from analysis.prompt_rules import load_prompt_rules
    store = vector_store or _build_vector_store(settings)
    llm = llm_client or _build_llm_client(settings)
    checker_llm = _build_checker_llm_client(settings)
    prompt_rules = load_prompt_rules(settings.prompt_rules_path)

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
        prompt_rules=prompt_rules,
    )


def _product_slug(product_name: str) -> str:
    """
    Превращает имя продукта в безопасный фрагмент имени файла: "Foo bar baz" -> "Foo_bar_baz".
    Заменяются не только пробелы, но и любые символы, недопустимые в путях Windows/Linux
    (\\ / : * ? " < > |), иначе продукт с таким именем ронял открытие файла кеша.
    Буквы (в т.ч. кириллица), цифры, '.', '-' и '_' сохраняются.
    """
    slug = re.sub(r"[^\w.-]+", "_", product_name.strip(), flags=re.UNICODE).strip("._-")
    return slug or "product"


def _load_or_fetch_product(dd_client, product_name: str, cache_file: str, logger) -> list:
    """
    Функция подгрузки findings. Если есть кеш — загружает из него, иначе скачивает по имени продукта.
    """
    cache_path = Path(cache_file)
    cache_path.parent.mkdir(parents=True, exist_ok=True)

    if cache_path.exists():
        with open(cache_path, "r", encoding="utf-8") as f:
            findings = json.load(f)
        logger.info("Loaded %d findings from cache: %s", len(findings), cache_file)
        return findings

    findings = dd_client.fetch_findings_by_product_name(product_name=product_name)
    with open(cache_path, "w", encoding="utf-8") as f:
        json.dump(findings, f, ensure_ascii=False, indent=2)
    logger.info("Fetched and cached %d findings to: %s", len(findings), cache_file)
    return findings


@app.command()
def triage(
    product_name: str = typer.Option(..., "--product-name", "-p", help="DefectDojo product name"),
    cache_file: Optional[str] = typer.Option(
        None, "--cache", "-c", help="Path to findings cache JSON (auto-created if absent)"
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Output JSONL file path"
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

    dd = _build_dd_client(settings)
    engine = _build_engine(settings, repo_path=repo)

    safe_name = _product_slug(product_name)
    cache = cache_file or f"{settings.cache_dir}/findings_product_{safe_name}.json"
    output = output_file or f"{settings.output_dir}/triage_product_{safe_name}.jsonl"
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    findings = _load_or_fetch_product(dd, product_name, cache, logger)

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

    typer.echo(
        f"Успешно выполнено. \n К ложным сработкам отнесено: {fp_count} \n Требуют ручного анализа {review_count} \n Файл с результатами {output}"
    )


@app.command()
def enrich(
    product_name: str = typer.Option(
        ..., "--product-name", "-p", help="DefectDojo product name"
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
    logger.debug("enrich: dry_run=%s, product_name=%r", dry_run, product_name)
    stats = enricher.enrich_from_product_name(product_name=product_name, dry_run=dry_run)
    logger.debug("enrich: pipeline complete")
    typer.echo(json.dumps(stats, indent=2))


@app.command()
def fetch(
    product_name: str = typer.Option(..., "--product-name", "-p", help="DefectDojo product name"),
    output: Optional[str] = typer.Option(
        None, "--output", "-o", help="Output JSON file (default: cache dir)"
    ),
) -> None:
    """
    Функция для скачивания findings по имени продукта и сохранения их в JSON файл.
    Если указать --output, то сохраняет в него, иначе сохраняет в папку кеша —
    туда же, откуда команда triage читает кеш.
    """
    settings = _load_settings()
    _setup_logging(settings.log_level)
    logger = logging.getLogger(__name__)

    dd = _build_dd_client(settings)
    safe_name = _product_slug(product_name)
    dest = output or f"{settings.cache_dir}/findings_product_{safe_name}.json"
    Path(dest).parent.mkdir(parents=True, exist_ok=True)

    findings = dd.fetch_findings_by_product_name(product_name=product_name)
    with open(dest, "w", encoding="utf-8") as f:
        json.dump(findings, f, ensure_ascii=False, indent=2)

    logger.info("Saved %d findings to %s", len(findings), dest)
    typer.echo(f"Saved {len(findings)} findings to {dest}")


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


@app.command()
def rules_check(
    config_path: Optional[str] = typer.Option(
        None, "--config", "-c", help="Path to prompt rules YAML (default: from settings)"
    ),
    finding_file: Optional[str] = typer.Option(
        None, "--finding", "-f", help="JSON file with a finding or list of findings to test matching"
    ),
) -> None:
    """
    Валидация prompt_rules.yaml и dry-run матчинга правил (без LLM и DefectDojo).
    Пример использования → python main.py rules-check
    Пример использования → python main.py rules-check --finding test/test_SAST.json
    """
    from analysis.prompt_rules import load_prompt_rules

    # Команде не нужен DefectDojo: настройки используются только для пути по умолчанию
    path = config_path
    log_level = "INFO"
    if path is None:
        try:
            settings = _load_settings()
            path = settings.prompt_rules_path
            log_level = settings.log_level
        except Exception:
            path = "./prompt_rules.yaml"
    _setup_logging(log_level)

    try:
        config = load_prompt_rules(path)
    except ValueError as e:
        typer.echo(f"ОШИБКА: {e}")
        raise typer.Exit(1)

    if config is None:
        typer.echo(f"Файл не найден: {path} — правила промптов отключены")
        raise typer.Exit(0)

    verdict_rules = [r for r in config.rules if r.verdict is not None]
    addition_rules = [r for r in config.rules if r.prompt_addition is not None]
    typer.echo(f"Конфигурация валидна: {path}")
    typer.echo(f"  Scanner-блоков: {len(config.scanners)} ({', '.join(b.test_name for b in config.scanners)})")
    typer.echo(
        f"  Meta-match блоков: {len(config.meta_match)} "
        f"({', '.join(f'{b.test_name}:{b.require}' for b in config.meta_match) or '-'})"
    )
    typer.echo(f"  Verdict-правил: {len(verdict_rules)} ({', '.join(r.name for r in verdict_rules)})")
    typer.echo(f"  Prompt-addition правил: {len(addition_rules)} ({', '.join(r.name for r in addition_rules)})")

    if not finding_file:
        return

    with open(finding_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    findings = data if isinstance(data, list) else [data]

    typer.echo(f"\nDry-run матчинга: {len(findings)} findings из {finding_file}")
    for finding in findings:
        scanner = next((b.test_name for b in config.scanners if b.matches(finding)), "-")
        hit = config.forced_verdict(finding)
        verdict_str = f"{hit[0]} -> {hit[1].value}" if hit else "-"
        additions = [name for name, _ in config.prompt_additions(finding)]
        typer.echo(
            f"  [{finding.get('id', '?')}] {str(finding.get('title', ''))[:60]}\n"
            f"      scanner: {scanner} | verdict-rule: {verdict_str} | additions: {additions or '-'}"
        )


if __name__ == "__main__":
    from core.exceptions import DDApiError

    try:
        app()
    except DDApiError as e:
        # Печатаем причину обычным текстом: rich-трейсбек рисует рамку из символов,
        # которых нет в cp1251, и настоящее сообщение до консоли не доходит
        logging.getLogger(__name__).error("DefectDojo error: %s", e)
        typer.echo(f"Ошибка обращения к DefectDojo: {e}", err=True)
        raise SystemExit(2)
