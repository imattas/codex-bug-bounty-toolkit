# Technology-specific investigation

Choose a guide only after identifying the relevant framework/version and reachable code path. These are focused starting points for the existing authorization, identity and logic playbooks, not automatic vulnerability verdicts.

## Next.js App Router / server boundaries

Trace each sensitive entry point: Route Handler, Server Action, server-rendered data fetch or a separate backend. Record the actual installed version and deployment mode. Treat an action reference or client invocation as a public-facing request surface; inspect its own authentication and action/object permissions rather than assuming an upstream UI decision carries through.

Compare a legitimate owner request with the same operation under a verified lower role or a second owned tenant. Follow data fetched on the server into the client-visible payload: a server-only query can still return protected fields to an unintended actor if the application includes them in its output. Establish the actual returned fields and actor before calling it disclosure.

Review cache keys and invalidation only where observed behavior crosses users/workspaces. Use isolated contexts and unique owned markers to distinguish stale shared output from intentional public caching. A rendering mode or framework identifier alone is not a finding. For identity transitions, check the sensitive action again after login/role changes instead of relying on client components to reflect the new permission state.

Evidence: actual action/route request, principal and tenant mapping, called permission function, returned serialized fields and control outcome. Consult the installed version's behavior; do not borrow an exploit claim from another release. [Primary reference: Next.js data security](https://nextjs.org/docs/app/guides/data-security).

## Django applications

Map URL route to view, authentication middleware/decorators, permission evaluation and queryset/object lookup. Distinguish 'authenticated user' from 'authorized for this object'. In an owned two-tenant setup, compare the same detail/export/action operation with each actor's object and the other actor's known object. Inspect queryset scoping and object-level guards on the actual route, including alternate download or batch paths.

For form/update flows, identify which fields the server binds and which are derived from the request principal. Verify a restricted change by reading authoritative state with an authorized session. An accepted form or echoed field does not prove persistence. Review object ownership relationships, not simply whether a ModelForm or class-based view is present.

For browser claims, confirm the real cross-site request/execution conditions rather than inferring a bug from the presence or absence of framework defaults. CSRF exemptions, raw SQL or template trust markers are leads whose reachability and effect need context. A normal framework-provided admin or error page is not automatically sensitive exposure.

Evidence: route/view and guard locations, queryset/object scope, allowed baseline, alternate actor request and resulting content/state. [Primary reference: Django security overview](https://docs.djangoproject.com/en/5.2/topics/security/) is version-specific; read the target's corresponding docs where versions differ.

## FastAPI / dependency-based authorization

Map app, router and operation dependencies. Identify whether the dependency authenticates, authorizes a role, selects a tenant or verifies access to the requested object. Security metadata in OpenAPI can describe a scheme without proving each runtime operation enforces every relevant check.

Compare one known-good owned-object request with the same operation under another owned actor/role. Check alternate routers and response paths only where the code/traffic indicates a separate guard. For a background job, trace the principal and resource context at submission, execution and result retrieval; a permission check at submission need not govern later downloads.

Inspect input and output model fields in the actual operation. An input schema accepting a restricted field is a lead until the code binds it and a persisted unauthorized effect is shown. A response model with broad fields is a lead until sensitive content is returned to the wrong principal. Avoid reporting the mere existence of API docs as a vulnerability.

Evidence: operation and dependency call path, actual actor, required OAuth scopes/roles if used, resource ownership, returned fields or durable effect, and a successful authorized control. [Primary reference: FastAPI security](https://fastapi.tiangolo.com/tutorial/security/).

## Flow-specific extension rule

Use the framework to locate the check, then use the existing class playbook to test its consequence. A useful next module needs an observed target pattern, distinguishing controls and a reproducible effect; do not generate dozens of technology files from catalog names alone.
