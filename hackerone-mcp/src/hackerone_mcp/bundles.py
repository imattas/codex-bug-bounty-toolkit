"""Offline verification of the assessment and artifact contract of finding_bundle.py."""
import hashlib
import json
from datetime import datetime
from pathlib import Path
import re

from .client import HackerOneError


def _text(value):
    return isinstance(value, str) and bool(value.strip())


def _timestamp(value):
    try:
        return _text(value) and datetime.fromisoformat(value.replace("Z", "+00:00")).tzinfo is not None
    except ValueError:
        return False


def validate_bundle(bundle_path: str):
    """Verify recorded gates and hashes; this cannot establish the truth of a finding."""
    given = Path(bundle_path).expanduser()
    if given.is_symlink(): raise HackerOneError("Bundle must be a real local directory")
    root = given.resolve()
    if not root.is_dir(): raise HackerOneError("Bundle directory is missing")
    snapshot, total = {}, 0

    def read(relative, limit=10_000_000):
        nonlocal total
        rel = Path(relative)
        if rel.is_absolute() or ".." in rel.parts or not rel.parts or "\\" in str(relative):
            raise HackerOneError("Unsafe bundle artifact path")
        location = root / rel
        if any(parent.is_symlink() for parent in [location, *location.parents] if parent != root and parent.is_relative_to(root)):
            raise HackerOneError("Bundle artifacts must not be symlinks")
        if not location.resolve().is_relative_to(root) or not location.is_file():
            raise HackerOneError("Bundle file is missing or outside the bundle")
        try:
            with location.open("rb") as stream: raw = stream.read(limit + 1)
        except OSError:
            raise HackerOneError("Cannot read bundle file") from None
        total += len(raw)
        if len(raw) > limit or total > 20_000_000 or not raw.strip():
            raise HackerOneError("Bundle file is empty or exceeds size limits")
        snapshot[rel.as_posix()] = hashlib.sha256(raw).hexdigest()
        return raw

    try:
        metadata = json.loads(read("evidence/assessment.json", 1_000_000))
        report = read("report.md", 256_000).decode("utf-8").replace("\r\n", "\n")
    except (ValueError, UnicodeError):
        raise HackerOneError("Bundle assessment/report is malformed") from None
    if not isinstance(metadata, dict) or metadata.get("schema_version") != 1:
        raise HackerOneError("Expected bundle assessment schema_version 1")
    gates = metadata.get("gates", {})
    for name, required in {"scope": "in_scope", "validation": "confirmed", "actionability": "actionable", "duplicate": "no_known_duplicate"}.items():
        gate = gates.get(name, {}) if isinstance(gates, dict) else {}
        if not isinstance(gate, dict) or gate.get("status") != required or not _text(gate.get("rationale")):
            raise HackerOneError("Assessment gate is not satisfied: " + name)
    if not _timestamp(gates["scope"].get("checked_at")) or not _text(gates["scope"].get("source")):
        raise HackerOneError("Scope gate needs a dated policy source")
    duplicate = gates["duplicate"]
    if not _timestamp(duplicate.get("checked_at")) or not isinstance(duplicate.get("sources"), list) or not duplicate["sources"] or not all(_text(x) for x in duplicate["sources"]):
        raise HackerOneError("Duplicate gate needs dated actual sources searched")
    if metadata.get("artifacts_reviewed") is not True or not _text(metadata.get("program")) or not _text(metadata.get("root_cause_key")):
        raise HackerOneError("Assessment needs artifact review, program and root cause")
    hashes = metadata.get("artifact_sha256", {})
    if not isinstance(hashes, dict) or not hashes or len(hashes) > 100:
        raise HackerOneError("Assessment needs a bounded artifact hash manifest")
    for rel, expected in hashes.items():
        if not isinstance(rel, str) or not re.fullmatch(r"(?:poc|evidence)/[A-Za-z0-9][A-Za-z0-9._-]{0,119}", rel) or rel == "evidence/assessment.json" or not isinstance(expected, str) or not re.fullmatch(r"[a-f0-9]{64}", expected):
            raise HackerOneError("Invalid assessment artifact hash manifest")
        read(rel)
        if snapshot[rel] != expected: raise HackerOneError("Bundle artifact hash mismatch")
    if not any(rel.startswith("poc/") for rel in hashes) or not any(rel.startswith("evidence/") for rel in hashes):
        raise HackerOneError("Bundle needs both PoC and evidence artifacts")
    fields = metadata.get("report", {})
    if not isinstance(fields, dict) or any(not _text(fields.get(key)) for key in ("title", "asset", "weakness", "summary", "setup", "expected", "actual", "impact")):
        raise HackerOneError("Assessment lacks required report fields")
    if any('\n' in fields[key] or '\r' in fields[key] for key in ('title', 'asset', 'weakness')):
        raise HackerOneError("Report title, asset and weakness must be single lines")
    if not isinstance(fields.get('steps'), list) or not fields['steps'] or not all(_text(step) for step in fields['steps']):
        raise HackerOneError("Assessment needs explicit reproduction steps")
    if (not report.startswith("# " + fields["title"] + "\n") or "\nAsset: " + fields["asset"] + "\n" not in report or "\nWeakness: " + fields["weakness"] + "\n" not in report or "\n## Impact\n\n" + fields["impact"] + "\n" not in report):
        raise HackerOneError("Report and assessment fields do not agree")
    headings = ['## Description', '### Summary:', '### Steps To Reproduce:', '### Expected vs. Actual Behavior:', '### Supporting Material / References:', '## Impact']
    markers = ['\n' + heading + '\n' for heading in headings]
    if any(report.count(marker) != 1 for marker in markers):
        raise HackerOneError("Report must retain every required report-frame section exactly once")
    offsets = [report.index(marker) for marker in markers]
    if offsets != sorted(offsets): raise HackerOneError("Report sections are not in the required order")
    def section(index):
        start = offsets[index] + len(markers[index])
        end = offsets[index + 1] if index + 1 < len(offsets) else len(report)
        return report[start:end].strip()
    steps = '\n'.join(str(index) + '. ' + step for index, step in enumerate([fields['setup'], *fields['steps']], 1))
    if section(1) != fields['summary'].strip() or section(2) != steps or section(3) != 'Expected: ' + fields['expected'] + '\n\nActual: ' + fields['actual'] or section(5) != fields['impact'].strip():
        raise HackerOneError("Report summary, steps, expected/actual or impact differ from assessment")
    if any('[' + rel + '](' + rel + ')' not in section(4) for rel in hashes):
        raise HackerOneError("Report must reference every reviewed PoC/evidence artifact")
    severity, calculation = fields.get('severity', {}), metadata.get('calculation', {})
    try:
        from cvss import CVSS4
        from cvss.exceptions import CVSSError
        if not isinstance(severity, dict) or not isinstance(calculation, dict) or not isinstance(severity.get('vector'), str) or not severity['vector'].startswith('CVSS:4.0/'):
            raise HackerOneError("Assessment needs CVSS 4.0 severity and calculation")
        calculator = CVSS4(severity['vector'])
        score = calculator.scores()[0]
        vector = calculator.clean_vector()
        metrics = dict(part.split(':', 1) for part in vector.split('/')[1:])
        environmental = {'CR', 'IR', 'AR', 'MAV', 'MAC', 'MAT', 'MPR', 'MUI', 'MVC', 'MVI', 'MVA', 'MSC', 'MSI', 'MSA'}
        label = 'CVSS-B' + ('T' if metrics.get('E', 'X') != 'X' else '') + ('E' if any(metrics.get(key, 'X') != 'X' for key in environmental) else '')
        if type(severity.get('score')) not in (int, float) or severity['score'] != score or score <= 0 or calculation.get('vector') != vector or calculation.get('scores', [None])[0] != score or calculation.get('score_labels', [None])[0] != label:
            raise HackerOneError("Assessment severity/calculation does not match independent CVSS calculation")
        if '\nSeverity: ' + vector + ' / ' + str(score) + ' (' + label + ')\n' not in report:
            raise HackerOneError("Report severity differs from the selected assessment calculation")
    except ImportError:
        raise HackerOneError("Bundle severity validation requires the package's cvss dependency") from None
    except (CVSSError, ValueError, TypeError, IndexError, KeyError) as exc:
        if isinstance(exc, HackerOneError): raise
        raise HackerOneError("Malformed CVSS severity or assessment calculation") from None
    return {"valid": True, "bundle": str(root), "snapshot": snapshot, "assessment": metadata, "report_markdown": report, "limits": "Validates recorded decisions and file integrity; does not prove scope, novelty or vulnerability claims"}
