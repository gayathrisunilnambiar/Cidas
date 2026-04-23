"""Contextify pillar — AST-based project context extraction.

Parses JavaScript/TypeScript files in the project root using tree-sitter,
builds an embedding vector of what the project already imports, and scores
how semantically similar the candidate package is to existing dependencies.
A high similarity score is a weak trust signal (the pattern already exists);
an unfamiliar pattern in a mature project is slightly riskier.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

from ..models import PillarResult, ScreenRequest
from ..utils.embeddings import EmbeddingService
from ..utils.logger import get_logger

log = get_logger(__name__)

_EXTENSIONS = {".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"}
_MAX_FILES = 200


def _collect_sources(root: str) -> list[Path]:
    p = Path(root)
    if not p.is_dir():
        return []
    files: list[Path] = []
    for ext in _EXTENSIONS:
        files.extend(p.rglob(f"*{ext}"))
        if len(files) >= _MAX_FILES:
            break
    return files[:_MAX_FILES]


def _extract_imports_tree_sitter(source: str) -> list[str]:
    """Return a list of module specifiers found in the source."""
    try:
        import tree_sitter_javascript as tsjs
        from tree_sitter import Language, Parser

        JS = Language(tsjs.language())
        parser = Parser(JS)
        tree = parser.parse(source.encode())

        imports: list[str] = []
        cursor = tree.walk()

        def visit(node) -> None:  # type: ignore[no-untyped-def]
            if node.type in ("import_statement", "import_declaration"):
                for child in node.children:
                    if child.type == "string":
                        imports.append(child.text.decode().strip("'\""))
            for child in node.children:
                visit(child)

        visit(tree.root_node)
        return imports
    except Exception as exc:
        log.debug("tree-sitter parse failed: %s", exc)
        # Fallback: regex-based extraction
        import re
        pattern = re.compile(r"""(?:from|require)\s*\(?['"]([^'"]+)['"]\)?""")
        return pattern.findall(source)


async def _gather_project_imports(root: str) -> list[str]:
    files = _collect_sources(root)
    all_imports: list[str] = []
    for path in files:
        try:
            source = await asyncio.to_thread(path.read_text, encoding="utf-8", errors="ignore")
            all_imports.extend(_extract_imports_tree_sitter(source))
        except OSError:
            continue
    return list(set(all_imports))


async def run(req: ScreenRequest) -> PillarResult:
    signals: dict = {}
    score = 0.0

    if not req.project_root:
        return PillarResult(
            pillar="contextify",
            score=score,
            signals={"skipped": True},
            notes="No project root provided; context analysis skipped.",
        )

    existing_imports = await _gather_project_imports(req.project_root)
    signals["existing_import_count"] = len(existing_imports)

    if not existing_imports:
        return PillarResult(
            pillar="contextify",
            score=5.0,
            signals=signals,
            notes="No imports found in project; minimal context signal.",
        )

    # Semantic similarity: is the candidate package name related to existing imports?
    svc = EmbeddingService()
    similarity = await svc.max_similarity(req.package_name, existing_imports)
    signals["max_similarity_to_existing"] = round(similarity, 4)

    # Low similarity in a large project is a mild risk signal (new attack surface)
    if similarity < 0.25 and len(existing_imports) > 10:
        score = 20.0
        notes = "Package appears unrelated to existing project dependencies."
    elif similarity >= 0.6:
        score = 0.0
        notes = "Package is semantically consistent with existing project imports."
    else:
        score = 10.0
        notes = "Package is loosely related to existing project imports."

    return PillarResult(pillar="contextify", score=score, signals=signals, notes=notes)
