"""Research workflows and the fail-closed, two-phase report submission boundary."""
import asyncio

from .bundles import validate_bundle
from .client import HackerOneClient, HackerOneError, handle_path
from .store import Store, digest
from .mapping import asset_matches, weakness_matches


class ResearchService:
    def __init__(self, client: HackerOneClient, store: Store | None, *, enable_writes=False):
        self.client, self.store, self.enable_writes = client, store, enable_writes

    def storage(self):
        if self.store is None: raise HackerOneError("Configure H1_DATA_DIR for local cache and submission journal")
        return self.store

    async def programs(self, max_pages=10):
        result = await self.client.pages("/hackers/programs", max_pages=max_pages)
        if self.store: self.store.cache("programs", result)
        return result

    async def program(self, handle):
        result = await self.client.get(handle_path(handle))
        if self.store: self.store.cache("program:" + handle, result)
        return result

    async def program_collection(self, handle, collection, max_pages=10):
        if collection not in ("structured_scopes", "scope_exclusions", "weaknesses"):
            raise HackerOneError("Unknown program collection")
        result = await self.client.pages(handle_path(handle) + "/" + collection, max_pages=max_pages)
        if self.store: self.store.cache(collection + ":" + handle, result)
        return result

    async def own_reports(self, max_pages=10):
        result = await self.client.pages("/hackers/me/reports", max_pages=max_pages)
        if self.store: self.store.cache("own_reports", result)
        return result

    async def report(self, report_id):
        if not str(report_id).isdigit() or len(str(report_id)) > 20:
            raise HackerOneError("Invalid report ID")
        result = await self.client.get("/hackers/reports/" + str(report_id))
        if self.store: self.store.cache("own_report:" + str(report_id), result)
        return result

    async def hacktivity(self, query="", max_pages=10):
        if not isinstance(query, str) or len(query) > 500:
            raise HackerOneError("Hacktivity query must be at most 500 characters")
        disclosed_query = "disclosed:true" + (" AND (" + query + ")" if query else "")
        result = await self.client.pages("/hackers/hacktivity", {"queryString": disclosed_query}, max_pages=max_pages)
        # Keep only explicitly disclosed items even if an upstream query behaves differently.
        result["data"] = [item for item in result["data"] if item.get("attributes", {}).get("disclosed") is True or item.get("attributes", {}).get("disclosed_at")]
        if self.store: self.store.cache("disclosed:" + digest({"query": query})[:16], result)
        return result

    async def briefing(self, handle, search_query):
        program = await self.program(handle)
        scopes = await self.program_collection(handle, "structured_scopes")
        exclusions = await self.program_collection(handle, "scope_exclusions")
        cached = self.storage().search(search_query, program=handle)
        cached["matches"] = [item for item in cached["matches"] if item["cache_key"].startswith(("own_reports", "own_report:", "disclosed:"))]
        return {"program": program, "scopes": scopes, "exclusions": exclusions, "cached_related_reports": cached, "limits": "Live program terms plus local own/disclosed report cache. No assurance about undisclosed duplicates or permission to test."}

    async def _mapping(self, handle, scope_id, weakness_id, assessment):
        if type(scope_id) is not int or scope_id <= 0 or type(weakness_id) is not int or weakness_id <= 0:
            raise HackerOneError("Select positive integer structured_scope_id and weakness_id")
        if assessment["program"] != handle:
            raise HackerOneError("Assessment program must exactly match target handle")
        program = await self.program(handle)
        attrs = program["data"].get("attributes", {})
        if attrs.get("handle") != handle or attrs.get("submission_state") != "open" or not isinstance(attrs.get("policy"), str) or not attrs["policy"].strip():
            raise HackerOneError("Program submission eligibility or policy is unknown/closed")
        scopes = await self.program_collection(handle, "structured_scopes")
        exclusions = await self.program_collection(handle, "scope_exclusions")
        weaknesses = await self.program_collection(handle, "weaknesses")
        if not all(result["complete"] for result in (scopes, exclusions, weaknesses)):
            raise HackerOneError("Complete scopes, exclusions and weaknesses are required for submission mapping")
        selected = [scope for scope in scopes["data"] if str(scope.get("id")) == str(scope_id)]
        if len(selected) != 1: raise HackerOneError("Selected structured scope is unknown or ambiguous")
        scope = selected[0]
        asset = assessment["report"]["asset"]
        if scope.get("attributes", {}).get("eligible_for_submission") is not True or asset_matches(scope["attributes"], asset) is not True:
            raise HackerOneError("Selected scope must be eligible and conservatively contain the assessment web asset; unknown asset types/forms are refused")
        for row in scopes["data"]:
            row_attrs = row.get("attributes", {})
            if row_attrs.get("eligible_for_submission") is not True and asset_matches(row_attrs, asset) is True:
                raise HackerOneError("Assessment asset matches an ineligible structured scope")
        selected_weakness = [item for item in weaknesses["data"] if str(item.get("id")) == str(weakness_id)]
        if len(selected_weakness) != 1 or not weakness_matches(assessment["report"]["weakness"], selected_weakness[0].get("attributes", {})):
            raise HackerOneError("Selected weakness ID must match the assessment's single primary CWE or exact weakness name")
        return {"program": {"id": program["data"].get("id"), "attributes": attrs}, "scope": scope, "exclusions": exclusions["data"], "weakness": selected_weakness[0]}

    async def prepare_bundle(self, bundle_path, handle, structured_scope_id, weakness_id, severity_rating):
        store = self.storage()
        verified = validate_bundle(bundle_path)
        if severity_rating not in ("low", "medium", "high", "critical"):
            raise HackerOneError("Select low, medium, high or critical severity")
        score = verified["assessment"]["report"].get("severity", {}).get("score")
        if type(score) not in (int, float) or not 0 < score <= 10:
            raise HackerOneError("Assessment requires a nonzero numeric severity score")
        calculated_rating = "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"
        if severity_rating != calculated_rating:
            raise HackerOneError("Selected severity rating must agree with the bundle score")
        mapping = await self._mapping(handle, structured_scope_id, weakness_id, verified["assessment"])
        fields = verified["assessment"]["report"]
        payload = {"data": {"type": "report", "attributes": {"team_handle": handle, "title": fields["title"], "vulnerability_information": verified["report_markdown"], "impact": fields["impact"], "severity_rating": severity_rating, "structured_scope_id": structured_scope_id, "weakness_id": weakness_id}}}
        reviewed = {"payload": payload, "snapshot": verified["snapshot"], "mapping": mapping}
        prepared_hash = digest(reviewed)
        return store.prepare(prepared_hash, {**reviewed, "bundle": verified["bundle"], "payload_hash": digest(payload), "mapping_hash": digest(mapping), "review_notes": "Review exact JSON, policy, exclusions, scope and severity before commit. Local PoC/evidence links are not uploaded by this tool; include essential reproduction details in report.md."})

    async def commit(self, expected_prepared_hash, *, confirm=False):
        if self.enable_writes is not True: raise HackerOneError("Writes are disabled; set H1_ENABLE_WRITES=true in server environment")
        if confirm is not True: raise HackerOneError("Explicit confirm=true is required for the reviewed prepared hash")
        store = self.storage()
        record = store.prepared(expected_prepared_hash)
        if record["state"] != "prepared":
            raise HackerOneError("Submission already claimed: " + record["state"] + "; inspect receipt or reconcile manually, never blindly resend")
        if digest({key: record[key] for key in ("payload", "snapshot", "mapping")}) != expected_prepared_hash or digest(record["payload"]) != record["payload_hash"]:
            raise HackerOneError("Stored content does not match the reviewed hash")
        verified = validate_bundle(record["bundle"])
        if verified["snapshot"] != record["snapshot"]:
            raise HackerOneError("Bundle changed since preparation; review and prepare again")
        attrs = record["payload"]["data"]["attributes"]
        mapping = await self._mapping(attrs["team_handle"], attrs["structured_scope_id"], attrs["weakness_id"], verified["assessment"])
        if digest(mapping) != record["mapping_hash"]:
            raise HackerOneError("Program policy, exclusions, scope or weakness changed since review; prepare and review again")
        # Recheck files after live API reads and persist the exclusive claim before POST.
        if validate_bundle(record["bundle"])["snapshot"] != record["snapshot"]:
            raise HackerOneError("Bundle changed during submission checks")
        if not store.claim(expected_prepared_hash):
            raise HackerOneError("Another process already claimed this submission")
        try:
            receipt = await self.client.submit(record["payload"])
            if not isinstance(receipt.get("data"), dict) or not str(receipt["data"].get("id", "")).isdigit():
                raise HackerOneError("Submission response has no report receipt ID")
        except asyncio.CancelledError:
            store.finish(expected_prepared_hash, "uncertain", {"reason": "Submission cancelled after send claim; reconcile manually"})
            raise
        except Exception:
            return store.finish(expected_prepared_hash, "uncertain", {"reason": "Submission outcome unknown; inspect own reports and reconcile with HackerOne before any manual recovery. Automatic resend is permanently blocked for this payload hash."})
        return store.finish(expected_prepared_hash, "succeeded", receipt)
