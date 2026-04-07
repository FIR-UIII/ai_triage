#!/usr/bin/env python3
"""
AI Triage – automated triage of security findings from DefectDojo
using a RAG + LLM pipeline.

Commands:
  triage   – run triage on findings from a DefectDojo test
  enrich   – populate the knowledge base from closed false-positives

Usage:
  python main.py triage --test-id 15540
  python main.py triage --test-id 15540 --post-comments
"""

import json
import logging
import sys
from pathlib import Path
from typing import Optional

import typer
from dotenv import load_dotenv

load_dotenv()

app = typer.Typer(
    help="AI Triage: automated security findings triage using RAG + LLM",
    no_args_is_help=True,
)


# ------------------------------------------------------------------
# Logging setup
# ------------------------------------------------------------------


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

    # Console handler — WARNING and above, minimal
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(logging.WARNING)
    console_handler.setFormatter(
        logging.Formatter("[%(levelname)s] %(message)s")
    )
    root.addHandler(console_handler)


# ------------------------------------------------------------------
# Shared factory helpers
# ------------------------------------------------------------------


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


def _build_engine(settings, vector_store=None, llm_client=None, repo_path=None):
    from triage.engine import TriageEngine
    store = vector_store or _build_vector_store(settings)
    llm = llm_client or _build_llm_client(settings)

    code_context = None
    if repo_path:
        from analysis.code_context import CodeContextProvider
        max_chars = settings.code_context_max_chars or (settings.llm_n_ctx * 3)
        code_context = CodeContextProvider(repo_root=repo_path, max_chars=max_chars)

    return TriageEngine(
        vector_store=store,
        llm_client=llm,
        dd_base_url=settings.dd_api_url,
        code_context_provider=code_context,
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


# ------------------------------------------------------------------
# CLI commands
# ------------------------------------------------------------------


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
) -> None:
    """
    Команда для триажа findings, я не знаю как это работает, наверное магия AI 
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
            out.write(json.dumps(finding, ensure_ascii=False) + "\n")

            if result.verdict == "false-positive":
                fp_count += 1
            else:
                review_count += 1

            if post_comments and result.dd_comment:
                dd.add_comment(finding["id"], result.dd_comment)

    typer.echo(
        f"Успешно выполнено. \n К ложным сработкам отнесено: {fp_count} \n Требуют ручного анализа {review_count} \n Файл с результатами → {output}"
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
    """Populate the knowledge base from closed False Positive findings."""
    import sys

    def _DEBUG(msg: str) -> None:
        print(f"[DEBUG] {msg}", file=sys.stderr, flush=True)

    settings = _load_settings()
    _setup_logging(settings.log_level)

    _DEBUG("enrich: settings loaded, embedding_model=%s" % settings.embedding_model)
    _DEBUG("enrich: dry_run=%s, test_id=%d" % (dry_run, test_id))

    from knowledge.enrichment import KnowledgeEnricher

    _DEBUG("enrich: building DefectDojo client ...")
    dd = _build_dd_client(settings)
    _DEBUG("enrich: DD client ready")

    _DEBUG("enrich: building VectorStore ...")
    store = _build_vector_store(settings)
    _DEBUG("enrich: VectorStore ready")

    _DEBUG("enrich: building LLM client ...")
    llm = _build_llm_client(settings)
    _DEBUG("enrich: LLM client ready")

    enricher = KnowledgeEnricher(
        dd_client=dd,
        vector_store=store,
        llm_client=llm,
        dedup_threshold=settings.dedup_threshold,
    )

    _DEBUG("enrich: starting enrichment pipeline ...")
    stats = enricher.enrich_from_product(test_id=test_id, dry_run=dry_run)
    _DEBUG("enrich: pipeline complete")
    typer.echo(json.dumps(stats, indent=2))


@app.command()
def fetch(
    test_id: int = typer.Option(..., "--test-id", "-t", help="DefectDojo test ID"),
    output: Optional[str] = typer.Option(
        None, "--output", "-o", help="Output JSON file (default: cache dir)"
    ),
) -> None:
    """Fetch findings from DefectDojo and save to a local cache file."""
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
def rag_delete(
    finding_id: Optional[int] = typer.Option(
        None, "--finding-id", "-f", help="Delete entries by source finding ID"
    ),
    entry_id: Optional[str] = typer.Option(
        None, "--entry-id", "-e", help="Delete a single entry by its RAG document ID"
    ),
    rule: Optional[str] = typer.Option(
        None, "--rule", "-r", help="Delete all entries matching a SAST rule"
    ),
) -> None:
    """Delete specific entries from the RAG knowledge base."""
    if not finding_id and not entry_id and not rule:
        typer.echo("Specify at least one of: --finding-id, --entry-id, --rule")
        raise typer.Exit(1)

    settings = _load_settings()
    _setup_logging(settings.log_level)
    store = _build_vector_store(settings)

    if finding_id:
        count = store.delete_by_finding_id(finding_id)
        typer.echo(f"Deleted {count} entries for finding_id={finding_id}")
    if entry_id:
        ok = store.delete_by_id(entry_id)
        typer.echo(f"Deleted entry '{entry_id}': {'OK' if ok else 'FAILED'}")
    if rule:
        count = store.delete_by_rule(rule)
        typer.echo(f"Deleted {count} entries for rule='{rule}'")


@app.command()
def rag_add(
    finding_file: str = typer.Option(
        ..., "--file", "-f", help="Path to JSON file with a finding to add"
    ),
) -> None:
    """Manually add a finding to the RAG knowledge base from a JSON file."""
    import hashlib

    settings = _load_settings()
    _setup_logging(settings.log_level)
    store = _build_vector_store(settings)

    with open(finding_file, "r", encoding="utf-8") as f:
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


# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------

if __name__ == "__main__":
    app()
