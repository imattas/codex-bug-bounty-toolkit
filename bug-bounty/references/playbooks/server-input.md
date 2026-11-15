# Server-side input boundaries

Use when application input reaches a database/query layer, filesystem, URL fetcher, parser, template engine or process invocation. Choose the suspected interpreter from source or observed behavior; a string with special characters is not a universal test.

## Shared method

Map input → transformations → sensitive operation → effect. Establish the valid baseline and then change one input property. Prefer a benign unique marker or controlled resource that discriminates interpretation from validation, caching and ordinary application functionality. Check the strongest alternate explanation before escalating the claim.

| Boundary | Minimum useful proof | Common overstatement to avoid |
|---|---|---|
| Query construction | Controlled input changes query semantics or a complete reachable source path establishes unsafe construction | Database error alone proves extraction or database control |
| Server URL fetch | Controlled unique callback correlated with the exact request, including which protocol/action occurred | DNS lookup proves internal read, arbitrary protocols or code execution |
| File path | Response or controlled side effect maps to a known file outside the intended allowed namespace | Reflected filename or generic error proves file disclosure |
| File upload | Uploaded content reaches a privileged interpretation/serve boundary with a demonstrated effect | Accepted extension proves executable upload |
| Template/process invocation | Controlled effect distinguishes interpreter/argument behavior from ordinary rendering | Reflected text or shell metacharacters prove execution |
| Deserialization/parser | Reachable dangerous type/behavior with version and path context | Library presence proves an exploitable gadget chain |

## URL fetching

Use a permitted controlled destination first; preserve unique marker, time, originating test request and observed callback metadata. Distinguish DNS resolution, TCP/HTTP request and response-body delivery. Check whether a client browser, proxy, link preview or external security service generated the callback. A unique marker tied to a server workflow helps attribution but is not automatic proof of internal reachability.

Do not jump from an external callback to cloud metadata, unrelated internal hosts or service control planes without scope and technique coverage. State the narrower confirmed behavior and missing transition. URL validation seen at one input may not govern redirects or async processing; test only the relevant permitted path.

## Files and uploads

Use known benign owned files or markers when the environment allows it. Record the intended root, submitted path, resolved/read result and account permissions. Distinguish application routes, storage keys and OS paths. An encoded path producing a different error can be normalization behavior without unauthorized access.

For uploads, trace validation, storage, transformation and retrieval. Record content type, serving origin, disposition and effective browser/parser behavior. A file stored but never interpreted is not server code execution. A harmless file that executes in a privileged same-origin browser context is a different claim from server-side execution. Do not leave executable artifacts behind to maintain access.

## Query and command interpretation

Use a context-appropriate controlled comparison. Error-based observations need a stable baseline and a reason they identify the claimed parser. Timing observations need controls for ordinary jitter and a bounded design; one slow response is inconclusive. Avoid resource-intensive probes or data extraction that adds no evidence to the bounded finding.

For argument injection, inspect actual argv boundaries and tool behavior: shell-free execution can still allow unintended options, but it is not automatically shell execution. For source-only analysis, cite input reachability, call site, quoting/parameterization and the security effect; label untested runtime assumptions.

## Deliverable

Report the narrowest demonstrated interpreter boundary, exact prerequisites, benign reproduction, control and resulting effect. Separate confirmed server interaction from hypothetical internal pivots. Recommend a fix at the relevant boundary: parameterized operations, constrained namespace/destination or removal of unsafe interpretation, supported by the actual cause.
