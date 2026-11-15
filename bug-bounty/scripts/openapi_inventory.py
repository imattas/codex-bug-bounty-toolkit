"""Inventory OpenAPI 3.0/3.1 JSON offline. Never sends requests or fetches refs.

python scripts/openapi_inventory.py api.json > inventory.json
Declarations are planning inputs, not authorization or observed runtime behavior.
"""
import argparse
import json
from pathlib import Path
from urllib.parse import unquote

METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")


def inventory(document):
    if not isinstance(document, dict):
        raise ValueError("Expected an OpenAPI JSON object")
    version = document.get("openapi", "")
    if not isinstance(version, str) or not version.startswith(("3.0.", "3.1.")):
        raise ValueError("Only OpenAPI 3.0/3.1 JSON supported; convert other formats explicitly")
    if not isinstance(document.get("paths"), dict):
        raise ValueError("paths must be an object")
    warnings = []

    def resolve(value, where):
        seen = set()
        while isinstance(value, dict) and "$ref" in value:
            ref = value["$ref"]
            if not isinstance(ref, str) or not ref.startswith("#/"):
                warnings.append(where + ": unresolved external or unsupported reference " + str(ref))
                return None
            if ref in seen:
                warnings.append(where + ": cyclic reference " + ref)
                return None
            seen.add(ref)
            if len(value) > 1:
                warnings.append(where + ": reference siblings not merged; inspect manually")
            value = document
            try:
                for token in unquote(ref[2:]).split("/"):
                    token = token.replace("~1", "/").replace("~0", "~")
                    value = value[int(token)] if isinstance(value, list) else value[token]
            except (KeyError, TypeError, IndexError, ValueError):
                warnings.append(where + ": missing reference " + ref)
                return None
        return value

    operations = []
    for path, raw_item in document["paths"].items():
        if not path.startswith("/"):
            warnings.append(str(path) + ": not a path entry; skipped")
            continue
        item = resolve(raw_item, path)
        if not isinstance(item, dict):
            warnings.append(path + ": unavailable path item")
            continue
        for method in METHODS:
            if method not in item:
                continue
            op = item[method]
            where = method.upper() + " " + path
            if not isinstance(op, dict) or "$ref" in op:
                warnings.append(where + ": invalid/unsupported operation object")
                continue
            security_source = "operation" if "security" in op else "root" if "security" in document else "unspecified"
            security = op.get("security", document.get("security"))
            if security is None:
                declaration = "unspecified"
                if security_source != "unspecified":
                    warnings.append(where + ": null security declaration; inspect manually")
            elif not isinstance(security, list) or any(not isinstance(s, dict) for s in security):
                declaration = "unresolved"
                warnings.append(where + ": invalid security declaration")
            else:
                declaration = "anonymous_allowed" if not security or {} in security else "credentials_declared"
            params = {}
            for owner in (item, op):
                raw_params = owner.get("parameters", [])
                if not isinstance(raw_params, list):
                    warnings.append(where + ": invalid parameters array")
                    continue
                for raw in raw_params:
                    p = resolve(raw, where + " parameter")
                    if not isinstance(p, dict) or not isinstance(p.get("name"), str) or p.get("in") not in ("path", "query", "header", "cookie"):
                        warnings.append(where + ": unresolved/invalid parameter")
                        continue
                    params[(p["in"], p["name"])] = {"name": p["name"], "in": p["in"], "required": p.get("required", False), "schema": p.get("schema"), "content": p.get("content")}
            body = resolve(op.get("requestBody", {}), where + " requestBody")
            root_servers = document.get("servers", [{"url": "/"}])
            if root_servers == []:
                root_servers = [{"url": "/"}]
            servers = op.get("servers", item.get("servers", root_servers))
            operations.append({"method": method.upper(), "path": path, "operation_id": op.get("operationId"), "tags": op.get("tags", []), "security_source": security_source, "security_declaration": declaration, "security_alternatives": security, "parameters": list(params.values()), "request_body": body, "server_candidates": servers, "deprecated": op.get("deprecated", False), "state": "not_tested"})
    return {"openapi_version": version, "authorizes_testing": False, "note": "Specification declarations only; inventory does not prove runtime authentication, endpoint existence, or scope. External refs are not fetched; callbacks/webhooks are not inventoried.", "operations": operations, "warnings": warnings}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("spec", type=Path)
    args = parser.parse_args()
    try:
        result = inventory(json.loads(args.spec.read_text(encoding="utf-8-sig")))
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
