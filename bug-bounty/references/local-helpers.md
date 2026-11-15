# Offline helper commands

The Base calculator and inventory helper use Python's standard library. The extended calculator uses one optional dependency. All calculations/inventory are local and make no network requests. Run from the skill directory or use absolute script paths. Keep retained output in the engagement project.

## CVSS 3.1 Base

```text
python scripts/cvss31.py "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"
```

Returns canonical vector, score, rating, metrics and implementation/source. That exact input calculates to 4.3 / Medium; this does not mean every invoice disclosure deserves C:L. Select metrics from evidence first.

Supports all eight Base metrics and both Scope values. Rejects invalid, missing or duplicate metrics, other versions and Temporal/Environmental additions with nonzero exit status. Uses FIRST section 7 Base equations and Appendix A Roundup. Record exact input/output, script identity and execution date in the finding. For 4.0 or extended 3.1, use the adapter below; this Base script does not approximate them.

## CVSS 4.0 and extended 3.1

`scripts/cvss_score.py` delegates calculation to [RedHatProductSecurity/cvss](https://github.com/RedHatProductSecurity/cvss) and records the actual installed library version. Use an existing compatible environment or install the pinned optional dependency in a task-local virtual environment. Do not install into the user's global Python just to score a finding.

Windows example, replacing `{engagement}` with an actual writable project path and using the skill's absolute requirements/script paths when outside its folder:

```text
python -m venv {engagement}/.venv
{engagement}/.venv/Scripts/python -m pip install -r scripts/requirements-cvss.txt
{engagement}/.venv/Scripts/python scripts/cvss_score.py "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:N"
```

On POSIX use `.venv/bin/python`. Dependency installation needs package-network access; scoring does not. The adapter never auto-installs or fetches anything. Missing dependencies and rejected vectors produce nonzero exit status rather than an invented result.

Returns canonical/input vector, version, actual library version, scores and labels. For 3.1 it exposes Base, Temporal and Environmental outputs separately; do not select the highest blindly. For 4.0 it labels the assessment CVSS-B/BT/BE/BTE from assessed Threat/Environmental metrics; Supplemental metrics do not alter the label or numeric score. Preserve explicit optional-metric assumptions and use FIRST for disputed definitions. This wrapper is not an independent implementation of the library's algorithms.

## OpenAPI 3.0/3.1 JSON

```text
python scripts/openapi_inventory.py /path/to/openapi.json > /path/to/engagement/inventory.json
```

Returns methods/paths, security inheritance and alternatives, effective parameters, body declarations, server candidates, not-tested state and warnings. Resolves local references where used; does not fetch external references. Server candidates are not eligible targets until scope is checked.

This is not full schema validation/expansion. Schema refs can remain in output. Reference siblings are not merged and generate warnings. Swagger 2, YAML, OpenAPI 3.2, callbacks and webhooks are unsupported. Invalid JSON and unsupported top-level versions exit nonzero; warnings identify partial inventory gaps. Declarations do not prove runtime authentication or endpoint behavior. Specs can contain secret examples: inspect/redact inventory before sharing.

Try the [fictional training spec](../assets/examples/api-spec.json) with the same command to see an authenticated export declaration beside an anonymous admin-delete declaration. Neither declaration is an observed finding; the helper sends no requests.

## Gated finding bundles

```text
python scripts/finding_bundle.py /path/to/candidate.json --project /path/to/engagement
```

Creates `findings/<slug>/report.md`, `poc/` and `evidence/` only for passing recorded scope/validation/actionability/duplicate gates, existing reviewed artifacts and a matching calculated CVSS 4.0 score. Uses the same optional `cvss` dependency as extended scoring. It does not test targets or validate the truth of semantic triage decisions. Read [bundle usage](finding-bundles.md) and start from [candidate-assessment.json](../assets/candidate-assessment.json). Blocked candidates produce no report. The required report frame is rendered automatically.

## Verification

```text
python -m unittest discover -s tests -v
```

Tests exercise scores, changed-scope weighting, rounding, zero impact, invalid inputs, inherited/anonymous security, local/external/cyclic refs, parameter/server overrides and unsupported formats. Extended/version-4 tests run when the optional `cvss` dependency is available; otherwise unittest explicitly marks them skipped. Run the full suite in the optional virtual environment to include them. Tests validate helper behavior, not a target finding.
