"""Run an owned loopback engagement through replay, triage and report bundling.

python scripts/pilot_engagement.py --output /path/to/new-pilot-directory
Creates a deliberately vulnerable ephemeral lab bound only to 127.0.0.1.
No public-target testing, HackerOne access or submissions occur.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading


class LabHandler(BaseHTTPRequestHandler):
    def log_message(self,*args):
        pass

    def send(self,status,value):
        body=json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(body)))
        self.end_headers(); self.wfile.write(body)

    def actor(self):
        return {"Bearer pilot-owned-token-a-742":"A","Bearer pilot-owned-token-b-742":"B"}.get(self.headers.get("Authorization"))

    def do_GET(self):
        actor=self.actor()
        if not actor:
            self.send(401,{"error":"authentication required"}); return
        if self.path=="/projects/a1":
            self.send(200,{"id":"a1","billing_contact":"original@example.test"}); return
        if self.path.startswith(("/exports/","/secure/")):
            object_id=self.path.rsplit("/",1)[-1]
            owner={"a1":"A","b1":"B"}.get(object_id)
            if not owner:
                self.send(404,{"error":"not found"}); return
            if self.path.startswith("/secure/") and owner!=actor:
                self.send(403,{"error":"access denied"}); return
            # Intentional lab BOLA in /exports only; no production service.
            self.send(200,{"id":object_id,"workspace":owner,"marker":owner+"-ONLY-742"}); return
        self.send(404,{"error":"not found"})

    def do_POST(self):
        if self.path!="/projects/a1" or self.actor()!="A":
            self.send(403,{"error":"denied"}); return
        length=int(self.headers.get("Content-Length","0"))
        if length>4096:
            self.send(413,{"error":"too large"}); return
        data=json.loads(self.rfile.read(length) or b"{}")
        # Intentional echo with NO state mutation: a false-positive exercise.
        self.send(200,data)


def run_pilot(output):
    from engagement_runtime import init_budget, replay
    from finding_bundle import create_bundle
    from cvss_score import assess
    root=Path(output).resolve()
    if root.exists():
        raise ValueError("Pilot output must be a new directory; existing work is never overwritten")
    root.mkdir(parents=True)
    work=root/".bug-bounty/candidates/export"; work.mkdir(parents=True)
    server=ThreadingHTTPServer(("127.0.0.1",0),LabHandler)
    thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
    origin="http://127.0.0.1:"+str(server.server_port)
    env_values={"LAB_ACTOR_A_AUTH":"Bearer pilot-owned-token-a-742","LAB_ACTOR_B_AUTH":"Bearer pilot-owned-token-b-742"}
    previous={key:os.environ.get(key) for key in env_values}
    os.environ.update(env_values)
    try:
        init_budget(root,max_requests=12,rate_per_second=1000.0,concurrency=1,duration_seconds=60)
        captures=[]
        def request(actor,path,**kwargs):
            credentials={} if actor=="anonymous" else {"Authorization":"LAB_ACTOR_"+actor+"_AUTH"}
            result=replay(root,actor,origin+path,allowlist=[origin],credential_env=credentials,**kwargs)
            captures.append(result)
            return result
        b=request("B","/exports/b1")
        a=request("A","/exports/a1")
        cross=request("A","/exports/b1")
        anonymous=request("anonymous","/exports/b1")
        protected=request("A","/secure/b1")
        before=request("A","/projects/a1")
        echo=request("A","/projects/a1",method="POST",body=b'{"billing_contact":"replacement@example.test"}',headers={"Content-Type":"application/json"},allow_write=True)
        after=request("A","/projects/a1")
        checks={
            "cross_workspace_marker_observed":b["status"]==200 and "B-ONLY-742" in b["body"] and a["status"]==200 and "A-ONLY-742" in a["body"] and "B-ONLY-742" in cross["body"] and anonymous["status"]==401,
            "protected_route_denied":protected["status"]==403,
            "write_echo_not_persisted":"replacement@example.test" in echo["body"] and before["body"]==after["body"] and "replacement@example.test" not in after["body"],
        }
        if not all(checks.values()):
            raise RuntimeError("Pilot did not establish its expected controlled observations: "+str(checks))
        scope_denied=False
        try:
            replay(root,"A","http://localhost:"+str(server.server_port)+"/exports/a1",allowlist=[origin],credential_env={"Authorization":"LAB_ACTOR_A_AUTH"})
        except ValueError:
            scope_denied=True
        if not scope_denied:
            raise RuntimeError("Different-host request was not rejected by the allowlist")
        now=datetime.now(timezone.utc).isoformat()
        policy=root/".bug-bounty/policy.txt"
        policy.write_text("LOCAL LAB ONLY\nOwner authorizes this temporary loopback application for read/owned-state tests.\nEligible exact origin: "+origin+"\nKnown issues: none previously recorded in this new lab project.\nNo external program or real report submission is authorized.\n",encoding="utf-8")
        evidence=[]
        for index,result in enumerate(captures,1):
            for kind,key in (("request","request_path"),("response","response_path"),("metadata","metadata_path")):
                source=Path(result[key])
                if not source.is_absolute(): source=root/source
                if not source.resolve().is_relative_to(root): raise ValueError("Unexpected outside-project evidence path")
                target=work/("E"+str(index)+"-"+kind+source.suffix)
                shutil.copyfile(source,target)
                evidence.append(target.relative_to(root).as_posix())
        poc=work/"reproduce.http"
        poc.write_text("# LOCAL LAB. Use two owned isolated actor credentials supplied separately.\n# Verify B's marker as B, then A's own marker, then replay B's ID as A.\nGET "+origin+"/exports/b1 HTTP/1.1\nAuthorization: Bearer <ACTOR_A_TOKEN>\n\n# Actual controlled evidence: E1 B baseline, E2 A baseline, E3 cross-access, E4 anonymous denial.\n",encoding="utf-8")
        reproduction=work/"lab-reproduction.txt"
        reproduction.write_text("LOCAL LAB REPRODUCTION\nRequires the bug-bounty skill scripts and cvss==3.6 in the selected Python environment.\nRun: python /path/to/skill/scripts/pilot_engagement.py --output /path/to/a/new-directory\nThe helper starts its owned fixture, supplies fixture credentials in memory, executes all controls, captures evidence and stops the server.\nThe loopback port changes on each run; use the new run's evidence rather than contacting the stopped address in the older transcript.\nNo HackerOne credentials or public target are involved.\n",encoding="utf-8")
        vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
        candidate={"schema_version":1,"slug":"cross-workspace-export","program":"local-pilot","root_cause_key":"export-download-missing-owner-check","artifacts_reviewed":True,"gates":{
            "scope":{"status":"in_scope","source":".bug-bounty/policy.txt","checked_at":now,"rationale":"Owned loopback origin and read technique explicitly authorized; no external scope."},
            "validation":{"status":"confirmed","rationale":"Actual B marker returned to A; A/B own controls succeed and anonymous denied."},
            "actionability":{"status":"actionable","rationale":"Private marker disclosure across owned isolated workspace identities in deliberately vulnerable lab."},
            "duplicate":{"status":"no_known_duplicate","checked_at":now,"sources":["new local findings directory","owned lab known-issues policy"],"rationale":"No prior lab issue recorded; no statement about external/private program reports."}},
            "report":{"title":"[LOCAL LAB] Members can read another workspace's export","asset":origin+"/exports/{id}","weakness":"CWE-639: Authorization Bypass Through User-Controlled Key","severity":{"vector":vector,"score":assess(vector)["scores"][0]},"summary":"The deliberately vulnerable lab export endpoint returns B's private export to A. Captured controls distinguish this from public data or an invalid session.","setup":"Use the installed skill's pilot_engagement.py with --output pointing to a new directory; see poc/lab-reproduction.txt for dependencies and the exact command. It creates isolated actors A/B and exports a1/b1, supplies fixture credentials in memory and stops the lab after capture. This is not a real bounty submission.","steps":["As B request /exports/b1 and verify B-ONLY-742 (E1). As A request /exports/a1 and verify A-ONLY-742 (E2).","Keep A's session and request /exports/b1. The response contains B-ONLY-742 (E3). Without authentication the request is denied (E4)."],"expected":"A cannot read B's private export.","actual":"A receives B's export marker.","references":["Owned loopback lab policy; see internal assessment for provenance."],"impact":"In this local lab, an authenticated member with another workspace's export ID can read its content. The test proves the specific read boundary; it does not establish writes or takeover."},"poc_files":[poc.relative_to(root).as_posix(),reproduction.relative_to(root).as_posix()],"evidence_files":evidence}
        (work/"assessment-input.json").write_text(json.dumps(candidate,indent=2)+"\n",encoding="utf-8")
        bundle=create_bundle(candidate,root)
        duplicate=dict(candidate); duplicate["slug"]="same-root-different-endpoint"
        duplicate_blocked=False
        try: create_bundle(duplicate,root)
        except ValueError: duplicate_blocked=True
        if not duplicate_blocked: raise RuntimeError("Local duplicate was not rejected")
        rejected={"informational":"Missing-header observation has no demonstrated security consequence.","duplicate":"Same program/root cause already represented by the accepted bundle.","out_of_scope":"Different hostname was rejected before an HTTP request.","unpersisted_write":"Echoed contact value did not persist in authoritative state."}
        notes=root/".bug-bounty/candidates/rejected.json"; notes.write_text(json.dumps(rejected,indent=2)+"\n",encoding="utf-8")
        summary={"local_lab_only":True,"accepted_findings":1,"rejected_candidates":list(rejected),"controlled_checks":checks,"captured_requests":len(captures),"finding_path":str(bundle.relative_to(root)),"report_submission_performed":False,"lab_stopped_after_run":True}
        (root/"pilot-summary.json").write_text(json.dumps(summary,indent=2)+"\n",encoding="utf-8")
        return summary
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=5)
        for key,value in previous.items():
            if value is None: os.environ.pop(key,None)
            else: os.environ[key]=value


def main():
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    try: result=run_pilot(args.output)
    except (ValueError,RuntimeError,OSError) as exc: parser.error(str(exc))
    print(json.dumps(result,indent=2))


if __name__=="__main__": main()
