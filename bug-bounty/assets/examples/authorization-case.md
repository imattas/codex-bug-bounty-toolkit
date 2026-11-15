# Fictional worked packet: successful response vs unauthorized change

Training data only. None of these results was observed on a real service. Use the shape of the reasoning, not these facts, in actual reports.

## Supplied evidence

Target: `https://api.example.test`; owned disposable projects permitted. A is a viewer and A2 an owner in an owned workspace. Product rules reserve billing-contact changes for owners. Sessions are separate and verified.

- E1: Owner A2 sends `PATCH /projects/a1` with `{"billing_contact":"owner-control@example.test"}`. Subsequent authoritative read shows the value persisted.
- E2: Viewer A reads `a1`; identity/role are verified.
- E3: Viewer A sends the same operation with a unique replacement contact. Response is 200 and echoes the supplied value.
- E4: Owner A2 reads the project again. Contact is unchanged from E1 and there is no viewer update in audit history.

## Correct assessment

E3 does not establish a persisted unauthorized mutation. E4 contradicts that claim. Preserve both. The tested viewer-write hypothesis is unsupported under these conditions; the echoed body is not proof of server state. Do not infer the implementation from it.

If another authoritative or async stage plausibly exists, inspect that within budget. Otherwise stop this hypothesis and retain the negative result. Do not assign impact from a successful status.

## Alternative confirmed evidence

Suppose E4 instead showed the viewer-supplied unique value in authoritative state and attributed the update to A. With E1–E3 and that actual E4, the role boundary violation would be supported. This is a distinct fictional alternative, not permission to rewrite a real contradictory artifact.

## Wording from the confirmed alternative

This passage demonstrates supported language only. It is not a current report file. Before rendering, pass scope/actionability/duplicate gates, determine the primary classification and calculate CVSS 4.0; use the canonical report template and bundle generator.

### Viewers can change a project's billing contact through the update API

The project update API accepts a billing-contact change from a viewer, although the permission model reserves that action for owners. The supplied evidence shows the change persisted and was visible from the owner's session.

**Setup:** Create a disposable project as an owner. Invite a second owned account as a viewer and sign in through separate sessions. Record the existing billing contact and a unique test replacement.

**Steps**

1. As the owner, update the billing contact and read it back to establish the authorized operation (E1).
2. As the viewer, read the same project and verify the viewer identity (E2).
3. Send `PATCH /projects/{owned-project-id}` with `{"billing_contact":"{unique-test-contact}"}` using the viewer session (E3).
4. Read the project as the owner. The contact now matches the viewer-supplied value, with an audit entry identifying the viewer (E4).

**Expected:** The viewer update is denied and the contact remains unchanged.

**Actual:** The update persists.

**Impact:** A viewer can modify a field reserved for owners. Whether this redirects sensitive messages requires separate evidence; the field name alone does not establish interception, payment access or account takeover.

**Suggested fix:** Check the caller's permission to update this field before committing the project change.

## Scoring decision

The confirmed alternative supports unauthorized integrity change; determine degree from the actual field's business effect. Do not invent confidentiality impact from 'billing'. Use the program's CVSS version and calculate only after deciding metrics. The contradictory original packet does not become a vulnerability because a plausible candidate score exists.
