"""MCP adapters for the existing skill; all filesystem work is root-confined.

The configured skill directory is trusted executable code. Tool input cannot
change it. Network tests still require an explicit engagement allowlist/budget.
"""
from __future__ import annotations
import asyncio
import importlib.util
import json
import os
from pathlib import Path
import re
import sys


def register_local_tools(mcp, *, environ=None):
    env=dict(os.environ if environ is None else environ)
    skill=Path(env.get("BUG_BOUNTY_SKILL_DIR",str(Path.home()/".codex/skills/bug-bounty"))).resolve()
    modules={}

    def helper(name):
        if name not in modules:
            scripts=skill/"scripts"; path=scripts/(name+".py")
            if not path.is_file(): raise ValueError("Skill helper missing; configure BUG_BOUNTY_SKILL_DIR to the installed bug-bounty skill")
            if str(scripts) not in sys.path: sys.path.insert(0,str(scripts))
            module_name="bugbounty_mcp_"+name
            spec=importlib.util.spec_from_file_location(module_name,path)
            module=importlib.util.module_from_spec(spec); sys.modules[module_name]=module
            spec.loader.exec_module(module); modules[name]=module
        return modules[name]

    def project_path(project, *, must_exist=True):
        configured=env.get("BUG_BOUNTY_PROJECT_ROOT")
        if not configured: raise ValueError("Set BUG_BOUNTY_PROJECT_ROOT to explicitly grant an engagement directory before filesystem/network tools")
        root=Path(configured).resolve()
        if not root.is_dir(): raise ValueError("Configured project root must already exist")
        value=Path(project); result=(value if value.is_absolute() else root/value).resolve()
        if not result.is_relative_to(root): raise ValueError("Project path is outside BUG_BOUNTY_PROJECT_ROOT")
        if must_exist and not result.is_dir(): raise ValueError("Engagement project must already exist")
        return result

    def input_file(project,value):
        path=Path(value); path=(path if path.is_absolute() else project/path).resolve()
        if not path.is_relative_to(project) or not path.is_file(): raise ValueError("Input file is missing or outside the engagement")
        return path

    @mcp.tool(annotations={"readOnlyHint":True,"openWorldHint":False})
    def bugbounty_score_cvss(vector: str) -> dict:
        """Calculate supplied CVSS 3.1/4.0 metrics locally; does not justify metric selection."""
        if vector.startswith("CVSS:3.1/") and len(vector.split("/"))==9:
            return helper("cvss31").assess(vector)
        return helper("cvss_score").assess(vector)

    @mcp.tool(annotations={"readOnlyHint":True,"openWorldHint":False})
    def bugbounty_openapi_inventory(document: dict) -> dict:
        """Inventory supplied OpenAPI 3.0/3.1 JSON offline; no ref fetching or authorization inference."""
        return helper("openapi_inventory").inventory(document)

    @mcp.tool(annotations={"readOnlyHint":False,"destructiveHint":False,"openWorldHint":False})
    def bugbounty_budget_init(project: str, max_requests: int=30, rate_per_second: float=2.0, concurrency: int=1, duration_seconds: float=300.0) -> dict:
        """Initialize a new project-local shared budget; never resets an existing engagement."""
        path=project_path(project)
        helper("engagement_runtime").init_budget(path,max_requests=max_requests,rate_per_second=rate_per_second,concurrency=concurrency,duration_seconds=duration_seconds)
        return helper("engagement_runtime").budget_status(path)

    @mcp.tool(annotations={"readOnlyHint":True,"openWorldHint":False})
    def bugbounty_budget_status(project: str) -> dict:
        """Read consumed/remaining constraints from the engagement's shared budget."""
        path=project_path(project)
        return helper("engagement_runtime").budget_status(path)

    @mcp.tool(annotations={"readOnlyHint":False,"destructiveHint":True,"openWorldHint":True})
    async def bugbounty_http_replay(project: str, actor: str, url: str, allowlist: list[str], method: str="GET", credential_env: dict[str,str]|None=None, headers: dict[str,str]|None=None, body: str|None=None, allow_write: bool=False, timeout: float=10.0, retries: int=0, max_response_bytes: int=1048576, secret_envs: list[str]|None=None) -> dict:
        """Replay an authorized allowlisted request with a shared budget and redacted captures. No redirects. Credentials must be environment references; allow_write is only for already-authorized owned-state operations."""
        path=project_path(project)
        if any(re.search(r"authorization|cookie|password|secret|token|api[-_]?key",k,re.I) for k in (headers or {})):
            raise ValueError("Credential headers require credential_env references, never literal tool arguments")
        runtime=helper("engagement_runtime")
        return await asyncio.to_thread(runtime.replay,path,actor,url,allowlist=allowlist,method=method,credential_env=credential_env,headers=headers,body=None if body is None else body.encode(),allow_write=allow_write,timeout=timeout,retries=retries,max_response_bytes=max_response_bytes,follow_redirects=False,secret_envs=tuple(secret_envs or ()))

    @mcp.tool(annotations={"readOnlyHint":False,"destructiveHint":False,"openWorldHint":True})
    async def bugbounty_browser_capture(project: str, allowlist: list[str], actors: list[dict], timeout: float=10.0) -> dict:
        """Capture authorized read-only pages in independent nonpersistent browser contexts. Each actor object has actor,url,credential_env and optional mask_selectors. Browser installation is explicit; protections remain enabled."""
        path=project_path(project)
        if not actors or len(actors)>8: raise ValueError("Provide 1-8 bounded actor captures")
        for item in actors:
            if not isinstance(item,dict) or set(item)-{"actor","url","credential_env","mask_selectors"} or not isinstance(item.get("actor"),str) or not isinstance(item.get("url"),str):
                raise ValueError("Actor captures require actor/url and only documented fields; no literal credentials")
        def capture():
            output=[]
            with helper("browser_sessions").BrowserSessionManager(path,allowlist=allowlist,timeout=timeout) as manager:
                for item in actors:
                    manager.new_session(item["actor"],credential_env=item.get("credential_env"))
                    navigation=manager.navigate(item["actor"],item["url"])
                    screenshot=manager.screenshot(item["actor"],mask_selectors=tuple(item.get("mask_selectors",())))
                    output.append({"navigation":navigation,"screenshot":screenshot})
            return {"captures":output,"identities_isolated":True,"persistent_storage":False,"note":"Screenshots need visual review; this is not a vulnerability verdict."}
        return await asyncio.to_thread(capture)

    @mcp.tool(annotations={"readOnlyHint":False,"destructiveHint":False,"openWorldHint":False})
    async def bugbounty_create_finding(project: str, candidate_path: str) -> dict:
        """Create the required gated report/PoC/evidence bundle from an inspected candidate file. Excluded/informational/duplicate/unresolved candidates are refused. Does not submit."""
        path=project_path(project); source=input_file(path,candidate_path)
        data=json.loads(source.read_text(encoding="utf-8-sig"))
        result=await asyncio.to_thread(helper("finding_bundle").create_bundle,data,path)
        return {"created":True,"path":str(result),"submitted":False}

    @mcp.tool(annotations={"readOnlyHint":False,"destructiveHint":False,"openWorldHint":True})
    async def bugbounty_run_pilot(output_project: str) -> dict:
        """Run an owned ephemeral LOOPBACK-ONLY lab through replay, controls, triage and a labeled finding bundle. Output must be new; never contacts HackerOne or a public target."""
        path=project_path(output_project,must_exist=False)
        return await asyncio.to_thread(helper("pilot_engagement").run_pilot,path)

    @mcp.tool(annotations={"readOnlyHint":True,"openWorldHint":False})
    def bugbounty_local_duplicate_candidates(project: str, program: str, root_cause_key: str) -> dict:
        """Inspect local exact root-cause matches; semantic/remote duplicate review is still required."""
        path=project_path(project); matches=[]; unindexed=[]
        for report in (path/"findings").glob("*/report.md"):
            metadata=report.parent/"evidence/assessment.json"
            if not report.resolve().is_relative_to(path) or not metadata.resolve().is_relative_to(path): raise ValueError("Local finding points outside project")
            if not metadata.is_file(): unindexed.append(str(report.relative_to(path))); continue
            prior=json.loads(metadata.read_text(encoding="utf-8"))
            if str(prior.get("program","")).strip().casefold()==program.strip().casefold() and str(prior.get("root_cause_key","")).strip().casefold()==root_cause_key.strip().casefold(): matches.append(str(report.relative_to(path)))
        return {"matches":matches,"unindexed_reports":unindexed,"coverage":"local exact keys only","private_or_semantic_duplicates_checked":False}
