# Browser validation

Use an available browser connector or automation tool suited to the environment. Do not assume the archive's `agent-browser` CLI exists. Follow the actual tool's session and element-reference semantics.

## Observe, act, verify

Inspect the current page before acting. Use element references from the latest applicable snapshot. After navigation, frame or tab changes, dialogs or significant rerenders, wait for a relevant condition and inspect again. Confirm screenshots by viewing them before citing what they show.

Use separate browser contexts or profiles for separate identities. Tabs in one context usually share authentication storage; a new tab alone is not an isolated account. Label every capture with its context and actor. Verify identity and workspace in the application's account UI or a reliable identity endpoint before comparing privileges.

## Authentication and controls

A 403 does not establish successful authentication. A 401, redirect or missing page element does not alone establish session expiry. Separate observed behavior from a diagnosis; verify session validity with an authorized positive control before treating denied access as a security control or a successful fix retest.

Keep each actor's baseline and attempted cross-access evidence separate. Record object ownership, sharing and workspace relationships. If access is unavailable, use an inconclusive outcome rather than silently switching accounts or interpreting setup failure as a fix.

## Security behavior

Preserve ordinary browser security settings when testing CORS, CSRF, frames, navigation and origin behavior. A result obtained with disabled protections does not establish the normal user's exposure. Document any relevant special configuration and distinguish it from default conditions.

For client execution claims, preserve a controlled observable effect and the exact origin/context; an auto-dismissed dialog or a screenshot of injected text does not alone establish script execution. Avoid exposing tokens through screenshots, DOM dumps, console output or recordings. Use only permitted controlled callback destinations.

If user interaction is required for login, use the environment's real handoff capability where available. Opening a page or announcing a pause does not prove a user has authenticated. Continue only after inspecting the resulting authorized session.
