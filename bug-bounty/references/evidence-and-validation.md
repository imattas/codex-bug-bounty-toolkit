# Evidence and validation

## Evidence contract

Separate observations (what the artifact shows), inferences (what follows with stated assumptions) and hypotheses (what still needs testing). A scanner alert, response code, exception text or source pattern alone rarely proves the claimed security effect.

Every confirmed finding needs an attacker starting state, violated security expectation, reachable action, distinguishing result, causal link and bounded impact. For submitted evidence, identify what was observed by the researcher versus supplied by someone else. Never say 'I reproduced' when only reviewing artifacts.

## Controlled reproduction

1. Verify the test accounts' roles, ownership and isolation. Different usernames can still share an authorized workspace or public object.
2. Establish an authorized baseline with an owned object and a unique benign marker.
3. Change the relevant variable under a clearly identified attacker session. Keep method, path, body and necessary headers explicit.
4. Inspect the actual body or state change, not just status. Establish which account's data or authority was used.
5. Run a discriminating control appropriate to the claim: anonymous request, denied role, non-shared object, or benign input. Avoid mechanically demanding every control.
6. Save enough redacted evidence to reproduce the conclusion. If inconsistent, record conditions and frequency rather than hiding failures.

Use owned-account cross-access to demonstrate an authorization boundary without enumerating real users. Repeated requests are not required where a single controlled result is conclusive and further execution adds side effects. If active reproduction is unavailable, assess the supplied artifacts and clearly name missing facts.

## Artifact record

Give each artifact a stable ID and relative file path. Record UTC timestamp, method, target, actor label/role, owned object mapping, request parameters, response status and relevant content or observed state, correlation ID if available, capture source and redactions. Hash files when integrity or later comparison matters; hashes do not prove a claim true.

Store minimum necessary raw evidence locally with appropriate access restrictions. Create a shareable redacted copy. Replace tokens/cookies with consistent labels, not plausible fake secrets. Preserve the fields needed to see ownership and behavior. Do not embed secrets in command history, filenames, report attachments or screenshots. If only a redacted artifact exists, say so; do not claim an original is retained.

Screenshots and video can establish UI behavior but should be accompanied by reproducible text where possible. Source snippets need file/line or commit references and the caller conditions. OOB callbacks need a controlled destination, unique marker, time correlation and applicable program permission; a DNS lookup alone does not prove arbitrary code execution or sensitive-data access.

## Finding states

| State | Meaning |
|---|---|
| Hypothesis | Plausible issue; decisive evidence missing |
| Inconclusive | Attempted validation did not establish or reject it |
| Confirmed | Evidence establishes the stated boundary violation |
| Rejected | The tested claim was contradicted under recorded conditions |
| Blocked | Next meaningful validation step lacks permission or prerequisites |

Confirmation is separate from bounty eligibility and submission readiness. A confirmed defect can still be excluded, already known or insufficiently documented.

Confirmation alone does not authorize a report file. Apply [pre-report triage](pre-report-triage.md); excluded, informational, duplicate and unresolved items remain candidate notes outside findings/.

## Impact discipline

Invoice disclosure establishes access to invoice content under the demonstrated prerequisites. It does not establish account takeover, arbitrary writes, all-user access or availability loss. Broader consequences may be explained as conditional when supported by architecture and a causal chain; label them distinctly. Do not perform prohibited damage to demonstrate impact. Chains need evidence for each necessary transition and explicit assumptions for any untested link.

Deduplicate by root cause and affected boundary, not merely endpoint spelling. Keep distinct issues separate when fixes or prerequisites differ. Do not claim a program duplicate without evidence of its existing report.
