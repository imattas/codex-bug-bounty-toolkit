# Submission review

Pass [pre-report triage](pre-report-triage.md) before creating any report: exact scope/report eligibility, confirmed evidence, actionable security consequence and a completed no-known-duplicate check. Excluded, informational, known-duplicate or unresolved items remain notes, not reports. Read current program rules and disclosure terms. Report creation does not authorize submission, sending or publication.

## Review gates

| Gate | Evidence needed |
|---|---|
| Eligibility | Exact asset/technique decision with source; reward exclusions handled separately |
| Reproduction | Triager can create required state and perform the documented steps |
| Boundary violation | Actor privileges, ownership and actual unauthorized effect established |
| Claim accuracy | Title, impact and affected scope match artifacts and labeled inferences |
| Severity | Required CVSS 4.0 frame, defensible metrics and a verified matching score; retain other program-required versions separately |
| Informational review | Concrete security effect, not merely a best-practice or scanner observation |
| Duplicate review | Accessible records searched, similar roots compared, exact local key checked, limitations stated |
| Evidence hygiene | Relevant artifacts attached/referenced; no credentials, unrelated personal data or unexplained placeholders |
| Program fit | Required fields, attachment restrictions and disclosure rules satisfied |

The user specifically requires a calculated CVSS 4.0 vector/score in this report frame. Missing proof, duplicate review, necessary files or scoring blocks report generation. A nonzero score does not substitute for actionability or eligibility.

## Decision

Return **eligible**, **hold**, **out_of_scope**, **informational** or **duplicate**, with supporting sources and the smallest useful next action. Only eligible items create [finding bundles](finding-bundles.md). Inaccessible private submissions are a disclosed search limit, not a claim of uniqueness or an automatic permanent hold when meaningful accessible searches are complete. Unresolved material similarities do hold generation. Scope uncertainty can block testing/reporting without blocking permitted analysis in notes.

If only supplied artifacts were reviewed, say that reproduction was not independently executed. A confident editorial review does not establish technical validity. Check PoC code and attachments as well as prose; a clean report with an unsafe or nonreproducible helper is not ready.

## After explicit submission authorization

Use the intended program and destination, follow its required fields, and avoid duplicate submissions. Capture the receipt or report ID returned by the service. If a submission times out, inspect whether it was created before retrying. Report the actual service result; an attempted upload is not confirmed delivery. Apply the same evidence standards to follow-up replies and retest claims.
