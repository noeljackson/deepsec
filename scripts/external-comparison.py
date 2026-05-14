#!/usr/bin/env python3
"""
External-scanner comparison adapter.

Reads a CSV export from an external scanner (Codex Cyber's
`codex-security-findings-*.csv` is the prototype) and a deepsec
`data/<project>/files/` directory, prints a coincidence + class
breakdown.

Usage:
  scripts/external-comparison.py <codex-csv> <deepsec-files-dir> [<project-root>]

Output is a text report suitable for pasting into a doc / PR
description. The adapter is intentionally one-shot — for
repeatable comparisons over time, port to bench/cmd/external-compare/
in Go and persist the diff under data/<project>/.

Caveat: this is a coincidence rate, not a recall rate. The external
scanner's findings include false positives and "intentional design"
flags that need human filtering. Use this report as a signal of
where to investigate, not as a fairness benchmark.
"""

import csv
import json
import os
import sys
from collections import Counter, defaultdict


def codex_class(title: str, desc: str) -> str:
    """Lossy keyword-matching bucketization of Codex Cyber's prose titles."""
    t = (title + " " + desc).lower()
    if "sql" in t and ("inject" in t or "concat" in t):
        return "sqli"
    if "command injection" in t or "shell metacharacter" in t or (
        "exec" in t and "arbitrary" in t
    ):
        return "command-injection"
    if "ssrf" in t:
        return "ssrf"
    if "open redirect" in t or ("redirect" in t and "unsafe" in t):
        return "open-redirect"
    if "xss" in t or "cross-site script" in t:
        return "xss"
    if "oauth" in t or "oidc" in t:
        return "auth-flow"
    if "csrf" in t:
        return "csrf"
    if "rbac" in t or ("kubernetes" in t and "permission" in t):
        return "k8s-rbac"
    if "workflow" in t or "github action" in t:
        return "ci-workflow"
    if "docker" in t and ("socket" in t or "mount" in t):
        return "docker-socket"
    if "tls" in t and ("skip" in t or "verif" in t or "insecure" in t):
        return "tls-skip"
    if "secret" in t or ("token" in t and "hardcod" in t):
        return "hardcoded-secret"
    if "path traversal" in t:
        return "path-traversal"
    if "xxe" in t:
        return "xxe"
    if "deserial" in t:
        return "deserialize"
    if "race" in t or "toctou" in t:
        return "race"
    return "other"


def deepsec_class(slug: str) -> str:
    """Map deepsec slug to the same taxonomy as codex_class."""
    s = slug.lower()
    if "sql" in s:
        return "sqli"
    if "command" in s and "injection" in s:
        return "command-injection"
    if "ssrf" in s:
        return "ssrf"
    if "open-redirect" in s:
        return "open-redirect"
    if "xss" in s:
        return "xss"
    if "oauth" in s or "oidc" in s or "jwt" in s:
        return "auth-flow"
    if "csrf" in s:
        return "csrf"
    if "rbac" in s:
        return "k8s-rbac"
    if "workflow" in s or "github-action" in s:
        return "ci-workflow"
    if "docker" in s and "socket" in s:
        return "docker-socket"
    if "tls" in s and "skip" in s:
        return "tls-skip"
    if "secret" in s or "hardcoded" in s:
        return "hardcoded-secret"
    if "path" in s and "traversal" in s:
        return "path-traversal"
    if "xxe" in s:
        return "xxe"
    if "deserialize" in s or "deserial" in s:
        return "deserialize"
    if "curl-pipe" in s:
        return "supply-chain"
    return "other"


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(2)
    codex_csv = sys.argv[1]
    deepsec_dir = sys.argv[2]
    project_root = sys.argv[3] if len(sys.argv) > 3 else None

    codex_findings = []
    codex_by_file = defaultdict(list)
    with open(codex_csv) as f:
        for r in csv.DictReader(f):
            codex_findings.append(r)
            cls = codex_class(r["title"], r["description"])
            r["_class"] = cls
            for p in r["relevant_paths"].split(" | "):
                if p:
                    codex_by_file[p].append(r)

    deepsec_by_file = defaultdict(list)
    total_candidates = 0
    for root, _, files in os.walk(deepsec_dir):
        for name in files:
            if not name.endswith(".json"):
                continue
            try:
                rec = json.load(open(os.path.join(root, name)))
            except Exception:
                continue
            cands = rec.get("candidates") or []
            if not cands:
                continue
            for c in cands:
                deepsec_by_file[rec["filePath"]].append(
                    {"slug": c["vulnSlug"], "class": deepsec_class(c["vulnSlug"])}
                )
                total_candidates += 1

    codex_files = set(codex_by_file.keys())
    deepsec_files = set(deepsec_by_file.keys())

    if project_root:
        codex_extant = {p for p in codex_files if os.path.exists(os.path.join(project_root, p))}
    else:
        codex_extant = codex_files

    overlap = codex_extant & deepsec_files
    codex_only = codex_extant - deepsec_files
    deepsec_only = deepsec_files - codex_files

    print(f"codex findings: {len(codex_findings)} across {len(codex_files)} files")
    print(f"deepsec candidates: {total_candidates} across {len(deepsec_files)} files")
    if project_root:
        print(f"codex files extant at HEAD: {len(codex_extant)} / {len(codex_files)}")
    print()
    print(f"file overlap (both flagged):  {len(overlap)}")
    print(f"codex-only files:             {len(codex_only)}")
    print(f"deepsec-only files:           {len(deepsec_only)}")
    print()

    aligned = 0
    for f in overlap:
        cclasses = {r["_class"] for r in codex_by_file[f]}
        dclasses = {c["class"] for c in deepsec_by_file[f]}
        if cclasses & dclasses:
            aligned += 1
    print(f"of {len(overlap)} overlap files, {aligned} agree on vuln class")
    print()

    codex_cls = Counter(r["_class"] for r in codex_findings if r.get("_class"))
    deepsec_cls = Counter()
    for cs in deepsec_by_file.values():
        for c in cs:
            deepsec_cls[c["class"]] += 1
    print(f"{'class':<22s} {'codex':>8s} {'deepsec':>8s}")
    all_cls = sorted(set(codex_cls) | set(deepsec_cls), key=lambda c: -codex_cls[c])
    for c in all_cls:
        print(f"  {c:<20s} {codex_cls[c]:>8d} {deepsec_cls[c]:>8d}")


if __name__ == "__main__":
    main()
