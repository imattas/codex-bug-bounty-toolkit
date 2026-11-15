"""Create a gated findings/<slug>/{report.md,poc/,evidence/} bundle offline.

python scripts/finding_bundle.py candidate.json --project /path/to/engagement
This checks recorded decisions and files, not the truth of vulnerability claims.
"""
import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile


def text(value):
    return isinstance(value, str) and bool(value.strip())


def timestamp(value):
    try:
        return text(value) and datetime.fromisoformat(value.replace("Z", "+00:00")).tzinfo is not None
    except ValueError:
        return False


def has_content(path):
    with path.open("rb") as handle:
        return any(chunk.strip() for chunk in iter(lambda: handle.read(65536), b""))


def file_hash(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def gate_reasons(data):
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        return ["Expected candidate schema_version 1"]
    gates = data.get("gates", {})
    if not isinstance(gates, dict):
        return ["Missing structured triage gates"]
    reasons = []
    for name, required in {"scope": "in_scope", "validation": "confirmed", "actionability": "actionable", "duplicate": "no_known_duplicate"}.items():
        gate = gates.get(name, {})
        if not isinstance(gate, dict) or gate.get("status") != required or not text(gate.get("rationale")):
            reasons.append(name + ": requires " + required + " with supporting rationale")
    scope = gates.get("scope", {})
    duplicate = gates.get("duplicate", {})
    if not isinstance(scope, dict) or not text(scope.get("source")) or not timestamp(scope.get("checked_at")):
        reasons.append("Scope needs a specific policy source and timezone-aware checked_at")
    if not isinstance(duplicate, dict) or not timestamp(duplicate.get("checked_at")) or not isinstance(duplicate.get("sources"), list) or not duplicate["sources"] or not all(text(x) for x in duplicate["sources"]):
        reasons.append("Duplicate check needs checked_at and the actual sources searched")
    if data.get("artifacts_reviewed") is not True:
        reasons.append("Explicit review of PoC/evidence for secrets and unrelated data required")
    return reasons


def local_duplicates(project, data):
    root = project / "findings"
    if root.exists() and (root.is_symlink() or not root.resolve().is_relative_to(project)):
        raise ValueError("findings must be a real directory inside the engagement project")
    key = (data["program"].strip().casefold(), data["root_cause_key"].strip().casefold())
    reviewed = data["gates"]["duplicate"].get("reviewed_legacy_reports", [])
    if not isinstance(reviewed, list) or not all(text(x) for x in reviewed):
        raise ValueError("reviewed_legacy_reports must be a list of project-relative report paths")
    for report in root.glob("*/report.md"):
        if not report.resolve().is_relative_to(project):
            raise ValueError("Local report points outside the engagement")
        metadata = report.parent / "evidence" / "assessment.json"
        if not metadata.exists():
            if report.relative_to(project).as_posix() not in reviewed:
                raise ValueError("Unreviewed legacy report: " + report.relative_to(project).as_posix())
            continue
        try:
            if not metadata.resolve().is_relative_to(project):
                raise ValueError("Assessment points outside project")
            prior = json.loads(metadata.read_text(encoding="utf-8"))
            prior_key = (prior["program"].strip().casefold(), prior["root_cause_key"].strip().casefold())
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
            raise ValueError("Cannot verify existing local assessment: " + str(metadata)) from exc
        if prior_key == key:
            raise ValueError("Known local duplicate root cause: update " + str(report) + " instead")


def artifacts(project, paths, kind):
    if not isinstance(paths, list) or not paths or not all(text(x) for x in paths):
        raise ValueError(kind + " requires at least one existing project-relative file")
    files = []
    used = {"assessment.json"} if kind == "evidence" else set()
    for rel in paths:
        candidate = Path(rel)
        if candidate.is_absolute() or ".." in candidate.parts:
            raise ValueError("Artifact path must stay within the project: " + rel)
        source = (project / candidate).resolve()
        if not source.is_relative_to(project) or not source.is_file():
            raise ValueError("Missing or outside-project artifact: " + rel)
        if not has_content(source):
            raise ValueError("Empty or whitespace-only artifact is not proof: " + rel)
        name = source.name
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,119}", name) or name.endswith((".", " ")) or name.split(".")[0].upper() in {"CON", "PRN", "AUX", "NUL", *("COM"+str(n) for n in range(1,10)), *("LPT"+str(n) for n in range(1,10))}:
            raise ValueError("Use a portable safe artifact filename: " + name)
        if name.casefold() in used:
            raise ValueError("Duplicate or reserved artifact filename: " + name)
        used.add(name.casefold())
        files.append((source, kind + "/" + name))
    return files


def render_report(report, files, scoring):
    steps = [report["setup"], *report["steps"]]
    refs = ["- ["+rel+"]("+rel+")" for _,rel in files]
    refs.extend("- "+ref for ref in report.get("references", []))
    return (
        "# " + report["title"] + "\n\n"
        + "Asset: " + report["asset"] + "\n\n"
        + "Weakness: " + report["weakness"] + "\n\n"
        + "Severity: " + scoring["vector"] + " / " + str(scoring["scores"][0]) + " (" + scoring["score_labels"][0] + ")\n\n"
        + "## Description\n\n### Summary:\n\n" + report["summary"]
        + "\n\n### Steps To Reproduce:\n\n" + "\n".join(str(i)+". "+s for i,s in enumerate(steps,1))
        + "\n\n### Expected vs. Actual Behavior:\n\nExpected: " + report["expected"]
        + "\n\nActual: " + report["actual"]
        + "\n\n### Supporting Material / References:\n\n" + "\n".join(refs)
        + "\n\n## Impact\n\n" + report["impact"] + "\n"
    )


def create_bundle(data, project):
    reasons = gate_reasons(data)
    if reasons:
        raise ValueError("Report not created: " + "; ".join(reasons))
    project = Path(project).resolve()
    if not project.is_dir():
        raise ValueError("Engagement project must already exist")
    for key in ("program", "root_cause_key", "slug"):
        if not text(data.get(key)):
            raise ValueError("Missing " + key)
    slug = data["slug"]
    if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", slug) or len(slug) > 80 or slug.upper() in {"CON", "PRN", "AUX", "NUL", *("COM"+str(n) for n in range(1,10)), *("LPT"+str(n) for n in range(1,10))}:
        raise ValueError("Use a portable lowercase hyphenated slug, max 80 characters")
    report = data.get("report", {})
    if not isinstance(report, dict):
        raise ValueError("Missing structured report")
    for key in ("title", "asset", "weakness", "summary", "setup", "expected", "actual", "impact"):
        if not text(report.get(key)):
            raise ValueError("Missing report field: " + key)
    for key in ("title", "asset", "weakness"):
        if "\n" in report[key] or "\r" in report[key]:
            raise ValueError(key + " must be one line")
    if not isinstance(report.get("steps"), list) or not report["steps"] or not all(text(x) for x in report["steps"]):
        raise ValueError("Reproduction requires explicit steps in addition to setup")
    if not isinstance(report.get("references", []), list) or not all(text(x) for x in report.get("references", [])):
        raise ValueError("References must be a list of text entries")
    files = artifacts(project, data.get("poc_files"), "poc") + artifacts(project, data.get("evidence_files"), "evidence")
    severity = report.get("severity", {})
    if not isinstance(severity, dict) or not text(severity.get("vector")) or not severity["vector"].startswith("CVSS:4.0/"):
        raise ValueError("This report frame requires a complete CVSS 4.0 vector")
    from cvss_score import assess
    scoring = assess(severity["vector"])
    if type(severity.get("score")) not in (int,float) or severity["score"] != scoring["scores"][0] or scoring["scores"][0] <= 0:
        raise ValueError("Claimed CVSS 4.0 score must match calculation and demonstrate nonzero severity")
    local_duplicates(project, data)
    target = project / "findings" / slug
    if target.exists():
        raise ValueError("Finding already exists; update it instead of overwriting: " + str(target))
    output = render_report(report, files, scoring)
    target.parent.mkdir(exist_ok=True)
    lock = target.parent / ".bundle-create.lock"
    try:
        handle = lock.open("x", encoding="utf-8")
    except FileExistsError as exc:
        raise ValueError("Another bundle creation may be active; inspect .bundle-create.lock before retrying") from exc
    published = False
    try:
        with handle:
            handle.write(str(os.getpid()))
        local_duplicates(project, data)
        if target.exists():
            raise ValueError("Finding appeared during creation; no overwrite performed")
        with tempfile.TemporaryDirectory(prefix=".pending-", dir=target.parent) as temp:
            staging = Path(temp)
            (staging/"poc").mkdir(); (staging/"evidence").mkdir()
            artifact_hashes = {}
            for source, rel in files:
                shutil.copyfile(source, staging/rel)
                if not has_content(staging/rel):
                    raise ValueError("Artifact became empty during copy; no report published: " + rel)
                artifact_hashes[rel] = file_hash(staging/rel)
            metadata = dict(data)
            metadata["calculation"] = scoring
            metadata["artifact_sha256"] = artifact_hashes
            metadata["generated_at"] = datetime.now().astimezone().isoformat()
            (staging/"evidence/assessment.json").write_text(json.dumps(metadata,indent=2)+"\n",encoding="utf-8")
            (staging/"report.md").write_text(output,encoding="utf-8")
            staging.rename(target)
            published = True
    finally:
        try:
            lock.unlink()
        except OSError as exc:
            state = "Bundle created at " + str(target) if published else "Bundle creation did not complete"
            print(state + "; lock cleanup failed; inspect " + str(lock) + ": " + str(exc), file=sys.stderr)
    return target


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--project", type=Path, required=True)
    args = parser.parse_args()
    try:
        data = json.loads(args.candidate.read_text(encoding="utf-8-sig"))
        result = create_bundle(data,args.project)
    except (ValueError,OSError) as exc:
        print(json.dumps({"created":False,"reason":str(exc)}))
        raise SystemExit(2)
    print(json.dumps({"created":True,"path":str(result)}))


if __name__ == "__main__":
    main()
