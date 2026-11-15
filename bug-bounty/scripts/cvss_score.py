"""CVSS 3.1/4.0 calculation adapter using the optional cvss==3.6 package.

Does not install dependencies or transmit vectors. See local-helpers.md for setup.
"""
import argparse
import importlib.metadata
import json

ENVIRONMENT4 = {"CR", "IR", "AR", "MAV", "MAC", "MAT", "MPR", "MUI", "MVC", "MVI", "MVA", "MSC", "MSI", "MSA"}


def assess(vector):
    vector = vector.strip()
    if not vector.startswith(("CVSS:3.1/", "CVSS:4.0/")):
        raise ValueError("Only CVSS 3.1 and 4.0 vectors are supported")
    try:
        from cvss import CVSS3, CVSS4
        from cvss.exceptions import CVSSError
    except ImportError as exc:
        raise ValueError("Optional dependency missing: install scripts/requirements-cvss.txt in a task-local virtual environment; or use cvss31.py for dependency-free 3.1 Base") from exc
    try:
        calculator = CVSS4(vector) if vector.startswith("CVSS:4.0/") else CVSS3(vector)
    except CVSSError as exc:
        # The library has its own exception hierarchy; present validation failures
        # without converting a bad input into a partial or guessed calculation.
        raise ValueError("CVSS vector rejected: " + str(exc)) from exc
    version = "4.0" if isinstance(calculator, CVSS4) else "3.1"
    metrics = dict(part.split(":", 1) for part in vector.split("/")[1:])
    assessment = "Base/Temporal/Environmental outputs"
    labels = ["Base", "Temporal", "Environmental"]
    if version == "4.0":
        threat = metrics.get("E", "X") != "X"
        environment = any(metrics.get(key, "X") != "X" for key in ENVIRONMENT4)
        assessment = "CVSS-B" + ("T" if threat else "") + ("E" if environment else "")
        labels = [assessment]
    return {"version": version, "assessment": assessment, "vector": calculator.clean_vector(), "input_vector": vector, "scores": list(calculator.scores()), "score_labels": labels, "ratings": list(calculator.severities()), "implementation": "RedHatProductSecurity/cvss", "implementation_version": importlib.metadata.version("cvss"), "source": "https://github.com/RedHatProductSecurity/cvss", "note": "Calculation only; metric selection, deployment conditions and program priority require evidence. Unspecified optional metrics use library/spec defaults."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("vector")
    args = parser.parse_args()
    try:
        result = assess(args.vector)
    except ValueError as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
