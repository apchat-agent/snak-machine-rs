#!/usr/bin/env python3
"""Check the frozen draft ledger and executable evidence, not semantic conformance.

Provisional TODOs are visible and permitted. --require-complete rejects them.
TSV columns: id, status, code (path:line;...), tests (path::test;...), closure,
note (required for N/A). A Markdown matrix with these headings is also accepted.
"""
import argparse
import collections
import csv
import io
import pathlib
import re
import subprocess
import sys

class AuditError(ValueError):
    pass

IDS = {f"R{n:03}" for n in range(1, 104)} | {f"C{n:02}" for n in range(1, 11)}
KEYWORD = re.compile(r"MUST|SHOULD|REQUIRED|MAY|RECOMMENDED")
STATUSES = {"DONE", "N/A", "TODO", "MISSING", "PARTIAL"}


def read_rows(text):
    if text.startswith("id\t"):
        return list(csv.DictReader(io.StringIO(text), delimiter="\t"))
    header = None
    result = []
    for line in text.split("\n"):
        if not line.startswith("|"):
            continue
        fields = [f.strip().strip('`') for f in line.strip().strip("|").split("|")]
        if fields[0].lower() == "id":
            header = [f.lower() for f in fields]
        elif re.fullmatch(r"[RC]\d{2,3}", fields[0]):
            if not header or len(fields) != len(header):
                raise AuditError("matrix header/column mismatch")
            result.append(dict(zip(header, fields)))
    return result


def checked_file(root, path):
    p = (root / path).resolve()
    if not p.is_relative_to(root.resolve()) or not p.is_file():
        raise AuditError(f"nonexistent or external citation: {path}")
    return p


def evidence(row, root, require_both=True):
    ident = row["id"]
    if require_both and (not row.get("code") or not row.get("tests")):
        raise AuditError(f"{ident}: DONE needs code and closure test")
    for ref in filter(None, row.get("code", "").split(";")):
        try:
            path, line = ref.rsplit(":", 1)
            count = len(checked_file(root, path).read_text().splitlines())
            if not 1 <= int(line) <= count:
                raise ValueError("out of range")
        except ValueError as exc:
            raise AuditError(f"{ident}: invalid code citation {ref}: {exc}") from exc
    for ref in filter(None, row.get("tests", "").split(";")):
        try:
            path, name = ref.split("::", 1)
        except ValueError as exc:
            raise AuditError(f"{ident}: invalid test citation {ref}") from exc
        source = checked_file(root, path).read_text()
        pattern = r"((?:[ \t]*#\[[^\n]*\]\s*)+)(?:pub\s+)?fn\s+" + re.escape(name) + r"\s*\("
        match = re.search(pattern, source)
        if not match or "#[test]" not in match[1] or re.search(r"\bignore\b", match[1]):
            raise AuditError(f"{ident}: nonexistent, non-test or ignored test {ref}")


def audit(draft, plan, rows, root, complete=False, expected_ids=None):
    expected = IDS if expected_ids is None else expected_ids
    ledger = {}
    physical = []
    for line in plan.split("\n"):
        if not re.match(r"\| [RC]\d{2,3} \|", line):
            continue
        cols = [f.strip() for f in line.strip("|").split("|")]
        ident = cols[0]
        if ident not in expected or ident in ledger:
            raise AuditError(f"unknown or duplicated ledger ID {ident}")
        ledger[ident] = cols
        if ident.startswith("R"):
            try:
                physical.extend(int(n.strip()) for n in cols[2].split(","))
            except ValueError as exc:
                raise AuditError(f"{ident}: malformed physical line list") from exc
    if set(ledger) != expected:
        raise AuditError(f"ledger IDs missing: {sorted(expected - set(ledger))}")
    keyword_lines = {i for i, line in enumerate(draft.split("\n"), 1) if KEYWORD.search(line)}
    counts = collections.Counter(physical)
    duplicates = [i for i, n in counts.items() if n != 1]
    if set(physical) != keyword_lines or duplicates:
        raise AuditError(f"keyword coverage: missing={sorted(keyword_lines-set(physical))}, "
                         f"extra={sorted(set(physical)-keyword_lines)}, duplicate={duplicates}")
    seen = set()
    unfinished = []
    for row in rows:
        ident = row.get("id")
        if ident not in expected or ident in seen:
            raise AuditError(f"unknown or duplicate matrix ID {ident}")
        seen.add(ident)
        status = row.get("status")
        if status not in STATUSES or not row.get("closure"):
            raise AuditError(f"{ident}: invalid status or missing closure milestone")
        if status == "N/A":
            if not ledger[ident][-1].startswith("N/A"):
                raise AuditError(f"{ident}: applicable ledger row cannot be reclassified N/A")
            if not row.get("note", "").strip():
                raise AuditError(f"{ident}: N/A requires a condition/reason")
        elif status == "DONE":
            evidence(row, root)
        else:
            unfinished.append(ident)
            # Even partial evidence cannot cite invented files or test names.
            if row.get("code") or row.get("tests"):
                evidence(row, root, require_both=False)
    if seen != expected:
        raise AuditError(f"matrix IDs missing: {sorted(expected-seen)}")
    if complete and unfinished:
        raise AuditError(f"incomplete applicable requirements: {', '.join(unfinished)}")
    return {"requirements": sum(i.startswith("R") for i in seen),
            "supplemental": sum(i.startswith("C") for i in seen),
            "keyword_lines": len(keyword_lines), "unfinished": len(unfinished)}


def runnable_tests(rows, root):
    by_path = collections.defaultdict(set)
    for row in rows:
        if row.get("tests"):
            for ref in filter(None, row.get("tests", "").split(";")):
                path, name = ref.split("::", 1)
                by_path[path].add(name)
    for path, names in by_path.items():
        # Listing compiles the actual test target, including cfgs, without
        # executing it or recursing into the auditor's own test.
        command = ["cargo", "test", "--locked", "--all-features", "--test",
                   pathlib.Path(path).stem, "--", "--list"]
        p = subprocess.run(command, cwd=root, text=True, capture_output=True, timeout=300)
        found = set(re.findall(r"^([\w:]+): test$", p.stdout, re.M))
        if p.returncode or not names <= found:
            raise AuditError(f"test target {path} does not list required tests {sorted(names-found)}: {p.stderr}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--draft", default="draft-ietf-snac-simple-12.txt")
    parser.add_argument("--plan", default="PLAN2.md")
    parser.add_argument("--matrix", default="tests/requirements.tsv")
    parser.add_argument("--tests", default="tests/requirements.tsv")
    parser.add_argument("--require-complete", action="store_true")
    args = parser.parse_args()
    root = pathlib.Path(__file__).resolve().parents[1]
    try:
        rows = read_rows((root / args.matrix).read_text())
        summary = audit((root / args.draft).read_text(), (root / args.plan).read_text(),
                        rows, root, args.require_complete)
        inventory = read_rows((root / args.tests).read_text())
        audit((root / args.draft).read_text(), (root / args.plan).read_text(),
              inventory, root, args.require_complete)
        # A separate matrix must agree with the executable inventory.
        for row in rows:
            match = next(r for r in inventory if r["id"] == row["id"])
            if row["status"] == "DONE" and not set(row["tests"].split(";")) <= set(match["tests"].split(";")):
                raise AuditError(f"{row['id']}: matrix test absent from inventory")
        runnable_tests(rows, root)
        print("conformance audit:", ", ".join(f"{k}={v}" for k, v in summary.items()))
        return 0
    except (AuditError, OSError, subprocess.SubprocessError) as exc:
        print(f"conformance audit failed: {exc}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
