"""The catalog and the rules must not drift apart."""

import re
from pathlib import Path

from tracewatch.findings_catalog import CATALOG, CATEGORIES, STATUSES

SRC = (Path(__file__).parents[1] / "src" / "tracewatch" / "findings.py").read_text()


def emitted_rules() -> set[str]:
    """Every rule id the code can emit: add("rule", ...) calls, with or without a line break after the paren."""
    return set(re.findall(r'\badd\(\s*"([a-z]+(?:-[a-z]+)*)"', SRC))


def test_every_emitted_rule_is_in_the_catalog_and_every_catalog_rule_is_emitted():
    assert emitted_rules() == set(CATALOG), emitted_rules() ^ set(CATALOG)


def test_entries_are_complete_and_well_formed():
    for rid, c in CATALOG.items():
        assert c["id"] == rid and c["category"] in CATEGORIES and c["status"] in STATUSES, rid
        assert c["severity"] in ("info", "low", "medium", "high"), rid
        assert len(c["title"]) > 8, rid
        for k in ("meaning", "cannot_know", "check"):
            assert len(c[k]) > 20, (rid, k)
        assert c["benign"] and all(len(b) > 8 for b in c["benign"]), rid


def test_emitted_categories_match_the_catalog():
    """A rule's category in the code must be its catalog category (the severity may be raised or lowered per case)."""
    for m in re.finditer(r'\badd\(\s*"([a-z-]+)",\s*(?:"[a-z]+"|sev|[^,]+),\s*"([a-z]+)"', SRC):
        rid, cat = m.groups()
        assert CATALOG[rid]["category"] == cat, (rid, cat)
