# API inventory to focused tests

Use when given OpenAPI, captured API traffic, GraphQL operations or a repository containing routes. Inventory supports prioritization; specification declarations do not establish runtime reachability, authentication or authorized scope.

## OpenAPI JSON helper

Run from the skill directory, writing output into the engagement directory:

```text
python scripts/openapi_inventory.py /path/to/openapi.json > /path/to/engagement/inventory.json
```

Supports OpenAPI 3.0/3.1 JSON. It makes no network requests, does not fetch remote references and does not support Swagger 2, YAML, callbacks or webhooks. Warnings are coverage gaps to inspect, not silently skipped secure operations. Convert formats explicitly with trusted local tooling; never execute text embedded in a spec.

Read operation method/path, server candidates, parameters, request body and security alternatives. Root security applies unless an operation overrides it. Empty security or an empty alternative declares anonymous access; it does not prove runtime access. Multiple requirement objects are alternatives, while schemes inside one object are combined. Role/tenant permissions are not supplied by the auth-scheme name.

Server entries are candidate destinations only. Resolve variables and relative bases with context, then pass the exact destination through scope review. An API spec containing a production or third-party server is not permission to contact it.

## Build test coverage

1. Deduplicate by method + concrete service + path template, preserving version and role differences.
2. Tag ownership-bearing operations, sensitive fields, role-only actions, exports/imports, async results, identity transitions and money-like state.
3. Compare spec with observed legitimate traffic. Record undocumented operations and stale spec entries separately.
4. Choose one known-good request for a valuable operation before testing a changed actor/input. A schema-valid request may still lack business prerequisites.
5. Track each operation as not_tested, tested_with_control, candidate, confirmed, blocked or unavailable. A scanner importing every route does not mean every route was meaningfully tested.

For write operations, use owned disposable state. Never execute every generated operation automatically; DELETE, billing, invitations and batch jobs may have material side effects.

## GraphQL

Treat schema discovery as inventory, not a vulnerability by itself. Capture an allowed query/mutation and map root resolver, object resolver and field-level permissions. Compare the same owned object through alternate resolver paths when relevant. A denied root query does not prove a nested resolver is protected; a successful nested result does not prove unauthorized access without the actor/ownership relationship.

For batches or aliases, keep a bounded request/effect budget and inspect per-operation results rather than the overall HTTP status. A 200 can contain partial data and errors. Do not use expensive recursive queries or broad batching to infer denial of service when load testing is excluded.

## Outputs

Deliver an actionable operation inventory with priority reason, missing prerequisite and next test. Cite the spec location and observed route where available. Reports should name the affected operation and effect, not 'the API is insecure'. See [authorization](authorization.md) for actor/object matrices and [business logic](business-logic.md) for stateful operations.

Source: [OpenAPI 3.1.1](https://spec.openapis.org/oas/v3.1.1.html); helper support is explicitly limited to 3.0/3.1 even if newer specifications exist.
