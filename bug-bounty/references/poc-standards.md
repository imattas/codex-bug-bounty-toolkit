# PoC standards

A PoC should let another tester establish the same security consequence with the fewest necessary actions. Match the format to the issue: HTTP transcript, browser steps, short script, source-assisted reproducer or a combination. Working exploit code is not required when a smaller artifact proves the claim.

## Required reproduction information

- Exact eligible target, endpoint/build and prerequisites.
- Actor roles, session labels, owned object creation and sharing/tenant relationships.
- Ordered actions with the necessary input and request context.
- Expected security behavior and the actual distinguishing response or state change.
- Evidence IDs and a control that rules out the material alternative explanation.
- Side effects, cleanup and environmental limitations where relevant.

If any element is missing, explain what prevents reproduction. HTTP 200 plus 'change the ID' is insufficient for a disclosure claim without ownership and returned-content evidence.

## Runnable helper requirements

Create code only if it reduces reproduction errors. Inspect existing project conventions before choosing a language. Use explicit target and object inputs; validate host/scheme/path as needed for the authorized boundary. Take credentials from environment variables, interactive input or a secret store. Keep secret values out of logs and exceptions.

Use known researcher-owned IDs rather than enumeration. Specify finite timeouts, bounded retries, request budget and concurrency. Disable automatic redirects unless every destination is checked against scope before requesting it; do not forward credentials to a new origin. Honor rate limits and stop on distress signals. Separate prerequisite creation, demonstration and cleanup so the tester can see each state change. Support a non-network preview when it materially helps review.

Print actor labels, relevant status/body markers and explicit success criteria. A success message must depend on the demonstrated security effect, not merely an HTTP success status. Exit clearly when prerequisites or expected markers are missing. Do not hide errors to make a demonstration look reliable.

## Minimal fictional HTTP demonstration

This illustrates evidence shape only. It is not a finding or permission to test a real service.

Setup: separate researcher-owned workspaces A/B; no sharing. Invoice `b1` belongs to B and contains `B-ONLY-742`. `TOKEN_A` and `TOKEN_B` are references to separate credentials.

```http
GET /invoices/b1 HTTP/1.1
Host: api.example.test
Authorization: Bearer <TOKEN_B>

HTTP/1.1 200 OK
Content-Type: application/json

{"id":"b1","memo":"B-ONLY-742"}
```

Replay the same request with A's token. If its response contains B's marker, preserve the response and account/ownership evidence. Do not prefill an observed result before running the test. An anonymous denial can help distinguish public exposure from authenticated cross-account access. A denial for A would contradict this specific disclosure hypothesis.

## Reproduction review

Could a fresh tester identify which session performs each action? Can they create their own equivalent objects instead of needing the researcher's private account? Are placeholders consistently explained? Does evidence prove the named impact? Has any cleanup affected retained evidence? Label supplied-only or unexecuted PoCs honestly.
