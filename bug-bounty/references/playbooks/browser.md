# Browser trust boundaries

Use for DOM/reflected/stored injection, cross-origin reads/actions, message handlers, framing or navigation. Follow [browser validation](../browser-validation.md) for context isolation and identity controls. The vulnerable behavior must occur with the browser configuration relevant to an actual user.

## Script injection

Identify input source, transformations, rendering context and attacker delivery route. Text in HTML, an attribute, a URL and a JavaScript string have different interpretation boundaries. Start with a benign unique marker; inspect where it lands before selecting a controlled context-specific demonstration.

For execution, use a harmless marker in the page or a non-sensitive application action. Record the executing origin, victim context, trigger and whether another actor can deliver the input. Do not exfiltrate cookies or tokens to prove execution. A self-only developer-console action, literal rendered markup, or execution requiring disabled browser protections is not equivalent to a remotely delivered victim-context flaw.

For stored behavior, record who can store the value and who later renders it. Compare an authorized actor and a second owned viewing context. A CSP may block a tested payload without making every sink safe; report what actually executed or remain inconclusive. Do not label an unsatisfied payload as confirmed XSS based only on a dangerous-looking sink.

## CSRF

Start with a real sensitive state change and the victim's owned authenticated context. Model the attacker's available origin and request capabilities in a normal browser. Demonstrate whether the browser sends the relevant credentials and whether the server accepts the cross-site operation without a necessary interaction or authorization check. Merely replaying a request in an HTTP client without a CSRF token does not establish a browser-deliverable attack.

Verify the durable state change and actual prerequisites. SameSite behavior, request type, headers, redirects and application checks can change the result; inspect rather than guessing from a token's presence/absence. Login CSRF and ordinary authenticated action CSRF have different effects and should be described accordingly.

## CORS and cross-origin disclosure

Header reflection is a lead. Use a controlled origin in a normal browser and show script can read sensitive content from the relevant owned victim context. Distinguish response access from sending a request. Preserve the origin, credential mode, preflight outcome where applicable and data actually readable. Public data, blocked reads and a response header alone do not demonstrate credentialed disclosure.

## Messages, frames and redirects

For message handlers, trace sender origin/window relationship, accepted data and resulting sensitive action or data return. Missing an origin check is a source lead until a reachable sender causes a boundary violation. For framing, establish a usable sensitive UI and actual interaction chain, not simply that a page renders in a frame. For redirects, show the controlled destination and relevant application flow; phishing potential alone is not proof of account takeover or token disclosure.

## Report evidence

Include attacker/victim origins, account context, normal browser configuration, trigger, exact benign payload or request, observed effect and control. State required victim interaction in the report and severity worksheet. Screenshots supplement reproducible steps and captured behavior; they do not replace the causal chain.
