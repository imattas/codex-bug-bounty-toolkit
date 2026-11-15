"""Offline CVSS v3.1 Base only, following FIRST section 7 and Appendix A.

python scripts/cvss31.py 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N'
This calculates supplied metrics; it does not justify them or assess eligibility.
"""
import argparse
import json
import math

SOURCE = "https://www.first.org/cvss/v3.1/specification-document"
ORDER = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
VALUES = {"AV": "NALP", "AC": "LH", "PR": "NLH", "UI": "NR", "S": "UC", "C": "NLH", "I": "NLH", "A": "NLH"}


def round_up(value):
    """FIRST Appendix A integer rounding, avoiding floating point overshoot."""
    integer = math.floor(value * 100000 + 0.5)
    return integer / 100000 if integer % 10000 == 0 else (integer // 10000 + 1) / 10


def assess(vector):
    parts = vector.strip().split("/")
    if parts[0] != "CVSS:3.1":
        raise ValueError("Expected CVSS:3.1; other versions are not supported")
    metrics = {}
    for part in parts[1:]:
        if part.count(":") != 1:
            raise ValueError("Malformed metric: " + part)
        key, value = part.split(":")
        if key not in VALUES:
            raise ValueError("Only eight Base metrics supported; unsupported metric: " + key)
        if key in metrics:
            raise ValueError("Duplicate metric: " + key)
        if len(value) != 1 or value not in VALUES[key]:
            raise ValueError("Invalid value for " + key)
        metrics[key] = value
    missing = set(ORDER) - metrics.keys()
    if missing:
        raise ValueError("Missing Base metrics: " + ", ".join(sorted(missing)))
    changed = metrics["S"] == "C"
    impacts = {"N": 0.0, "L": 0.22, "H": 0.56}
    iss = 1 - math.prod(1 - impacts[metrics[k]] for k in ("C", "I", "A"))
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    av = {"N": .85, "A": .62, "L": .55, "P": .2}[metrics["AV"]]
    ac = {"L": .77, "H": .44}[metrics["AC"]]
    pr = {"N": .85, "L": .68 if changed else .62, "H": .5 if changed else .27}[metrics["PR"]]
    ui = {"N": .85, "R": .62}[metrics["UI"]]
    exploitability = 8.22 * av * ac * pr * ui
    score = 0.0 if impact <= 0 else round_up(min((impact + exploitability) * (1.08 if changed else 1), 10))
    rating = "None" if score == 0 else "Low" if score < 4 else "Medium" if score < 7 else "High" if score < 9 else "Critical"
    return {"version": "3.1", "assessment": "Base", "vector": "CVSS:3.1/" + "/".join(k+":"+metrics[k] for k in ORDER), "score": score, "rating": rating, "metrics": metrics, "implementation": "bug-bounty/cvss31.py, FIRST section 7 Base equations and Appendix A", "source": SOURCE, "note": "Calculation only; metric selection requires evidence. No Temporal or Environmental metrics."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("vector")
    args = parser.parse_args()
    try:
        print(json.dumps(assess(args.vector), indent=2))
    except ValueError as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
