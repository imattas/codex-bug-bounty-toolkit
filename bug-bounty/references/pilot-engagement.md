# End-to-end local pilot

Run a deterministic owned loopback engagement before applying the tooling to an authorized real program. This pilot starts an ephemeral HTTP application bound to 127.0.0.1, supplies two fixture identities, uses the same budget/replay/evidence tools as an engagement and creates the actual gated finding bundle. It stops the lab afterward and never contacts HackerOne.

From the skill directory, with the optional CVSS dependency available:

```text
python scripts/pilot_engagement.py --output /path/to/new-pilot-directory
```

The output path must not exist. The pilot does not overwrite previous engagements. Its application is intentionally vulnerable and its report is labeled LOCAL LAB; it is not a real bounty finding or a HackerOne submission.

## What it exercises

- B's own export and A's own export establish separate identities and markers.
- A obtains B's marker from the intentionally unguarded export route; anonymous access is denied.
- The protected alternate route correctly denies cross-owner access.
- An update returns 200 and echoes a new contact but leaves authoritative state unchanged: no mutation report is created.
- A different hostname is rejected by the exact-origin allowlist.
- The qualifying lab read issue passes triage, calculates CVSS 4.0 and produces report.md, poc/ and evidence/.
- Recreating the same root cause under a different title is refused. An informational header observation remains notes.

Read `pilot-summary.json` and the retained controls rather than assuming a successful command means every claim passed. The summary names accepted/rejected cases and whether actual markers, denials and unpersisted state were observed. `.bug-bounty/candidates/` retains the triage and rejected-case decisions. The report links the captured redacted evidence.

## Real-program handoff

Replace the fixture with actual supplied program rules, exact eligible targets and owned accounts. Inspect the program's current scope, exclusions and submission state through the HackerOne integration or supplied policy. Define a new budget and allowlist for that engagement; do not reuse the loopback authorization or fixture tokens. Current policy, access, side effects and duplicate search must be established anew. Live account verification and platform submission require actual credentials and the user's applicable authorization.
