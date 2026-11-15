# Authentication, recovery, invitations and OAuth

Use when identity, session ownership or account binding changes. Map the intended state transition first: unauthenticated → authenticated, invited → member, recovery pending → credential changed, external identity → local account linked. Write the invariant in one sentence, such as 'a recovery token for A must not reset B'.

## Owned identities and captures

Use two researcher-controlled accounts and addresses, separate browser contexts, and known roles. Save legitimate flow checkpoints with timestamps and consistent redacted token labels. Distinguish the application's account, identity-provider subject, email address and workspace membership; equality of email strings is not proof of identity equivalence.

| Flow | Focused boundary question | Decisive observation |
|---|---|---|
| Recovery | Is the action bound to the intended account and token purpose? | A credential/account state change, not just an accepted form |
| Invitation | Is acceptance bound to intended identity, workspace and role? | Actual resulting membership and role |
| Account linking | Who authorizes binding an external identity? | Controlled login resolves to an unintended owned local account |
| Session lifecycle | What happens to relevant sessions after logout or credential change? | Defined protected operation succeeds under a session expected to be invalid |
| Step-up/MFA | Does the sensitive server action require the completed challenge? | Actual sensitive action under a session missing that requirement |
| Token use | Does verification bind issuer, audience, signature and purpose? | A controlled token accepted for an unauthorized identity/action |

## Flow testing

Capture a legitimate end-to-end path, then alter one binding or transition using owned state. Check identity at the final protected operation. A reset email being delivered is different from obtaining an account session. A login page redirect is different from authentication success. A server-issued token after a bypass is not a forged token.

For single-use/expiry claims, preserve issue/consume times and prove the same token's effect with an application-side result. Check whether replay merely displays a cached confirmation page. Avoid publishing or reusing real reset tokens in report attachments.

For session invalidation, first establish the intended product/program requirement. Record which session is invalidated: current session, all sessions, refresh tokens, API keys or password-reset grants. A still-valid intentionally independent API key does not alone prove logout failure. Verify session identity with a positive control before interpreting denial or expiry.

## OAuth/OIDC evidence plan

Trace authorization initiation, callback, token exchange and local account/session creation. Record the participating client, issuer, redirect destination, state/nonce bindings and PKCE use where relevant. Inspect the actual flow; absence of a parameter in one captured leg does not establish absence from the system.

Use a controlled callback and owned identities within scope. Demonstrate what crosses the boundary: attacker-induced login to an unintended identity, authorization-code delivery to a controlled destination, or unintended account linkage. An open redirect alone does not prove token theft. State the exact artifact exposed and whether it can be exchanged or used under the actual client and grant conditions. Do not claim replay resistance is broken without a successful permitted replay or a complete source-level argument.

## Common false positives

- JWT contents can be decoded: encoding is not encryption and visibility alone is not forgery.
- Changing a token produces a different server error: that does not prove acceptance.
- Account enumeration: distinguish a stable meaningful identity signal from generic timing noise and confirm program eligibility.
- No rate limiting observed in a few requests: do not infer unlimited attempts or run credential attacks to fill the gap.
- Missing session access: inconclusive, not a fix or a successful bypass.

## Report boundary

Include initial access, affected identity transition, exact owned accounts and browser contexts, successful control, altered transition and final protected result. Claim takeover only when the attacker obtains the relevant account control; otherwise name the narrower exposure. Suggest binding the transition to identity, client, purpose and completed challenge based on the demonstrated flaw, without asserting unobserved implementation details.
