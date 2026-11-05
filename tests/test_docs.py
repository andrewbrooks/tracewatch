"""Generated and hand-written docs must not drift from the code they describe."""

import re
from pathlib import Path

from tracewatch.findings_catalog import CATALOG, render_markdown

DOCS = Path(__file__).parents[1] / "docs"


def test_findings_doc_is_generated_from_the_catalog_and_up_to_date():
    assert (DOCS / "FINDINGS.md").read_text() == render_markdown(), "run: python tools/gen_findings_doc.py"


def test_findings_doc_has_a_section_for_every_rule():
    text = (DOCS / "FINDINGS.md").read_text()
    for rule in CATALOG:
        assert f"\n## {rule}\n" in text, rule


def test_relative_links_in_the_docs_and_readme_resolve():
    root = DOCS.parent
    for md in [root / "README.md", root / "SECURITY.md", *DOCS.glob("*.md")]:
        for target in re.findall(r"\]\(([^)#\s]+)(?:#[^)]*)?\)", md.read_text()):
            if target.startswith(("http://", "https://", "mailto:")):
                continue
            assert (md.parent / target).resolve().exists(), f"{md.name} links to a missing file: {target}"


def test_docs_never_name_the_private_notes_file():
    root = DOCS.parent
    for md in [root / "README.md", root / "SECURITY.md", *DOCS.glob("*.md")]:
        assert "NOTES.md" not in md.read_text(), md.name
