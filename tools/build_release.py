"""Build a source-only ZIP and hash-bound pipe installers; never publishes."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import zipfile

ARCHIVE="codex-bug-bounty-toolkit.zip"
BLOCKED_DIRS={".git",".venv","__pycache__","node_modules","build","dist","engagements","artifacts","findings","evidence","data","private",".hackerone-data"}
BLOCKED_FILES={"credentials.json","credentials.enc","h1_credentials.json","credential-store.json","secret-store.json"}
EXTENSIONS={".py",".md",".toml",".txt",".json",".yaml",".yml",".ps1",".sh",".in",".html",".css",".js"}


def package_files(root):
    selected=[]
    for name in ("bug-bounty","hackerone-mcp","installer"):
        folder=root/name
        if not folder.is_dir(): raise ValueError("Missing release component: "+name)
        for f in folder.rglob("*"):
            rel=f.relative_to(root)
            if any(part in BLOCKED_DIRS or part.endswith(".egg-info") for part in rel.parts): continue
            if not f.is_file() or f.name in BLOCKED_FILES or f.name.startswith(".env") or f.suffix not in EXTENSIONS: continue
            if not f.resolve().is_relative_to(root.resolve()): raise ValueError("Release file escapes source root: "+str(rel))
            selected.append((f,rel.as_posix()))
    for name in ("README.md","install.ps1","install.sh"):
        if not (root/name).is_file(): raise ValueError("Missing release file: "+name)
        selected.append((root/name,name))
    screenshot=root/"docs/images/dashboard.png"
    if screenshot.is_file():
        if not screenshot.resolve().is_relative_to(root.resolve()): raise ValueError("Dashboard image escapes source root")
        selected.append((screenshot,"docs/images/dashboard.png"))
    return sorted(selected,key=lambda pair:pair[1])


def build_release(root,output,*,repository,tag):
    if repository is not None and (not re.fullmatch(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+",repository) or repository.endswith(("/.","/.."))):
        raise ValueError("Repository must be an HTTPS github.com/owner/repository URL")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}",tag): raise ValueError("Use a safe immutable release tag")
    root=Path(root).resolve(); output=Path(output).resolve()
    files=package_files(root)
    if output.exists() and any(output.iterdir()): raise ValueError("Release output must be new or empty; existing assets are never overwritten")
    output.mkdir(parents=True,exist_ok=True)
    archive=output/ARCHIVE
    with zipfile.ZipFile(archive,"w",compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
        for source,name in files:
            info=zipfile.ZipInfo(name,date_time=(2026,1,1,0,0,0)); info.compress_type=zipfile.ZIP_DEFLATED
            info.external_attr=(0o100755 if name.endswith(".sh") else 0o100644)<<16
            z.writestr(info,source.read_bytes())
    sha=hashlib.sha256(archive.read_bytes()).hexdigest()
    source_url=repository+"/releases/download/"+tag+"/"+ARCHIVE if repository else None
    hashes={ARCHIVE:sha}
    for name in ("install.ps1","install.sh"):
        template=(root/name).read_text(encoding="utf-8")
        for marker in ("__TOOLKIT_SOURCE_URL__","__TOOLKIT_SOURCE_SHA256__"):
            if marker not in template: raise ValueError("Installer missing release rendering marker: "+name)
        rendered=template.replace("__TOOLKIT_SOURCE_URL__",source_url).replace("__TOOLKIT_SOURCE_SHA256__",sha) if source_url else template
        (output/name).write_text(rendered,encoding="utf-8",newline="\n")
        hashes[name]=hashlib.sha256((output/name).read_bytes()).hexdigest()
    (output/"SHA256SUMS.txt").write_text("".join(value+"  "+name+"\n" for name,value in hashes.items()),encoding="utf-8")
    result={"tag":tag,"repository":repository,"archive":str(archive),"archive_url":source_url,"sha256":sha,"source_files":len(files),"asset_sha256":hashes}
    (output/"release.json").write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source",type=Path,default=Path(__file__).resolve().parents[1]); parser.add_argument("--output",type=Path,default=Path("dist"))
    parser.add_argument("--repository"); parser.add_argument("--local-only",action="store_true"); parser.add_argument("--tag",required=True)
    args=parser.parse_args()
    if not args.repository and not args.local_only: parser.error("Provide --repository for published assets or --local-only for a checkout distribution")
    if args.repository and args.local_only: parser.error("Choose --repository or --local-only")
    try: result=build_release(args.source,args.output,repository=args.repository,tag=args.tag)
    except (ValueError,OSError,zipfile.BadZipFile) as exc: parser.error(str(exc))
    print(json.dumps(result,indent=2))


if __name__=="__main__": main()
