#!/usr/bin/env python3
"""
AI Triage – automated triage of security findings from DefectDojo
using a RAG + LLM pipeline.

Commands:
  triage   – run triage on findings from a DefectDojo test
  enrich   – populate the knowledge base from closed false-positives

Usage:
  python main.py triage --test-id 15540
  python main.py enrich --product-id 298 --dry-run
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
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stderr,
    )


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
    cache_path = Path(cache_file)
    cache_path.parent.mkdir(parents=True, exist_ok=True)

    if cache_path.exists():
        with open(cache_path, "r", encoding="utf-8") as f:
            findings = json.load(f)
        logger.info("Loaded %d findings from cache: %s", len(findings), cache_file)
        return findings

    findings = dd_client.fetch_findings(test_id=test_id)
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
    """Run triage on findings from a DefectDojo test."""
    settings = _load_settings()
    _setup_logging(settings.log_level)
    logger = logging.getLogger(__name__)

    cache = cache_file or f"{settings.cache_dir}/findings_{test_id}.json"
    output = output_file or f"{settings.output_dir}/triage_{test_id}.jsonl"
    Path(output).parent.mkdir(parents=True, exist_ok=True)

    dd = _build_dd_client(settings)
    engine = _build_engine(settings, repo_path=repo)

    findings = _load_or_fetch(dd, test_id, cache, logger)

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
        f"Done. {fp_count} FP | {review_count} needs-review → {output}"
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


# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------

if __name__ == "__main__":
    app()
