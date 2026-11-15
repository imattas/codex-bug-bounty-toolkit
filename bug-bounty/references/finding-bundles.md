# Finding bundle and report frame

Accepted findings live in the engagement project:

```text
findings/
  <one-root-cause-slug>/
    report.md
    poc/
      reproduce.http        # or exploit/reproducer script, browser steps, etc.
    evidence/
      control.txt           # selected redacted requests/responses, logs, images, etc.
      assessment.json       # internal triage decisions, calculation and artifact hashes
```

One directory per distinct qualifying root cause. `poc/` may contain a script, literal requests or reproducible browser instructions; a weaponized exploit is not required. `evidence/` contains actual retained artifacts, not empty placeholders. `assessment.json` is internal and is not automatically a submission attachment. Never store live credentials in this bundle.

## Create a bundle

1. Complete [pre-report triage](pre-report-triage.md). Keep failed/held candidates outside `findings/`.
2. Copy [candidate-assessment.json](../assets/candidate-assessment.json) into the engagement's working directory. Populate actual decisions, report fields and project-relative artifact paths. Empty defaults intentionally fail.
3. Use a stable program and root-cause key. Search semantically as well as by key. Set `artifacts_reviewed: true` only after inspecting the chosen files for secrets, unrelated data and adequate proof.
4. Run in an environment with the optional CVSS dependency from [helper setup](local-helpers.md):

```text
python /path/to/skill/scripts/finding_bundle.py /path/to/candidate.json --project /path/to/engagement
```

The helper rechecks recorded gates and the exact local root-cause key, validates required fields and existing nonblank in-project files, calculates the CVSS 4.0 vector and compares the stated score. It copies only explicitly selected artifacts, links them in the report, records hashes and stages the output before publishing the directory. Empty/whitespace-only files do not count as PoC or evidence. It does not execute a PoC, make network calls, search private reports, verify the truth of a scope assertion or submit anything.

Blocked input returns `created: false` with a nonzero exit code and no report. Existing findings are not overwritten. A local report lacking bundle metadata must be manually reviewed and listed in `gates.duplicate.reviewed_legacy_reports` using its project-relative path; otherwise creation stops. A stale `.bundle-create.lock` requires checking that no writer is active before removing the task's lock. Do not delete another writer's lock automatically.

If publication succeeds but lock cleanup fails, creation still returns success and a stderr warning identifies the remaining lock. Inspect the existing bundle and writer state rather than retrying creation as though nothing was written.

## Exact external frame

Use [report-template.md](../assets/report-template.md). The order is title; Asset; Weakness; Severity (CVSS 4.0 vector / calculated score); Description with Summary, numbered Steps To Reproduce, Expected vs. Actual Behavior, Supporting Material / References; then Impact. Put initial conditions in the first reproduction step. Keep evidence links relative to `report.md`.

Use the supported primary CWE/CAPEC/OWASP classification rather than listing many vaguely related categories. Keep metric rationale and scope/duplicate decisions in the internal assessment; do not add workflow boilerplate to the external report. Do not include the user's 'REPORT FRAME - IGNORE THIS LINE' marker. If a destination program also needs CVSS 3.1, retain that separately or map into its requested fields without mislabeling a 3.1 vector as 4.0.

## Update and reclassification

Update an existing root cause instead of generating a second directory. Read its current report and evidence first. If new information makes an existing finding excluded, informational or duplicate, stop further report generation, record the reason in working notes and preserve historical evidence. Do not silently delete or rewrite a previously submitted artifact.
