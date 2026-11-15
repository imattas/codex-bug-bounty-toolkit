# Object, function and property authorization

Use when the application has owned objects, teams, roles, admin operations, bulk actions or editable fields. Start from a legitimate operation captured in the application; guessing route names is a discovery step, not a finding.

## Establish the permission model

Write down what A and B can legitimately do. Use A/B in isolated researcher-owned workspaces for horizontal checks, plus a privileged and a lower-privileged actor in one owned workspace for vertical checks. Record public sharing, parent-child inheritance and explicit grants. Two accounts in the same organization may legitimately share objects.

Create one benign object per owner with distinguishable markers. Capture each actor's own-object baseline and verify identity. Object IDs are test inputs, not secrets that substitute for access control. You may use known owned IDs without proving enumeration; describe ID knowledge as a prerequisite unless discovery is established separately.

## Build a small operation matrix

| Operation | A's own object | B's isolated object as A | No session | Lower role |
|---|---|---|---|---|
| Read detail | Establish baseline | Content/field access | Compare if relevant | Compare allowed fields |
| List/search/export | Record ownership filters | Filter or explicit owned B ID | Inspect scope | Compare result scope |
| Update/delete | Use disposable object | Check actual durable change | Avoid unrelated mutations | Check server permission |
| Invite/approve/role change | Record legitimate role | Use owned destination | Relevant control only | Check action authorization |
| Batch/background job | Establish submit + fetch flow | Check both submission and result retrieval | Check applicable stage | Preserve role at execution time |

Choose rows present in the product. Do not issue destructive tests just to fill a matrix. A read flaw does not authorize writes outside the agreed task.

## Differential method

1. Capture the successful legitimate request, including the path ID, tenant header, body relationships and resulting artifact.
2. Keep the actor constant and change one ownership/role-sensitive input to a known owned comparison object. If multiple identifiers must agree, record which relationship is being tested.
3. Inspect relevant content or state. A 200 containing an error, empty list, or the actor's own data does not confirm cross-access. A 202 may only acknowledge an unprocessed job.
4. Verify the result from the owning session or independent state read. For updates, distinguish an echoed request body from a persisted mutation.
5. Use a denial or authorized comparison that excludes the likely alternative: public object, shared tenant, stale cache, accidentally reused cookie or incorrect ID.
6. Test a related surface only if it changes impact or clarifies root cause: detail vs export, submission vs download, UI vs API. Avoid exhaustive enumeration after the boundary is proven.

### Property-level checks

Compare actual fields returned or accepted for the same resource under different roles. A field name in a client bundle is a lead. To establish unauthorized property binding, send a relevant field on an owned disposable object and verify the server persisted a restricted effect under a role that should not set it. Distinguish serialization, validation errors and legitimate self-service fields from privilege changes.

### Function-level checks

Use a sensitive operation known to work for the authorized role, then perform that same operation with the lower role while preserving a valid lower-role session. A hidden UI button does not prove backend authorization. A failed admin positive control leaves the test inconclusive.

## Evidence and report boundary

Retain actor/role mapping, ownership/isolation proof, redacted baseline and comparison transcripts, exact changed inputs and durable state/content marker. Say 'member can download another workspace's export given its ID' if that is what happened. Do not upgrade to takeover, all-tenant exposure or arbitrary administration without the additional evidence.

Group instances when evidence supports a common missing guard; otherwise report the observed endpoint and describe the root cause as inferred. Recommend principal-to-object/action/property authorization at the server boundary, not hidden IDs or UI changes.

Reference: [OWASP API1:2023](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/). Use the program's actual permission model over generic role assumptions.
