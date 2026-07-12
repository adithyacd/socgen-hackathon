"""Evaluation harness — score the engines against the official ground-truth labels.

Reports the metrics the hackathon README specifies (precision/recall/F1 on is_risky,
per-category recall, false-positive rate), plus the exploitability breakdown that
powers the prioritization differentiator.
"""
from __future__ import annotations

from collections import Counter

from ..models import Dataset, Finding

VULN_TYPES = ("vulnerable", "transitive_vuln")
LICENSE_TYPES = ("license_conflict", "transitive_license_conflict", "license_unknown")

# label risk_type -> detection category
_CATEGORY = {
    "vulnerable": "vulnerability",
    "transitive_vuln": "vulnerability",
    "license_conflict": "license",
    "transitive_license_conflict": "license",
    "license_unknown": "license",
    "unmaintained": "maintenance",
}


def _rate(num: int, den: int) -> float:
    return round(num / den, 4) if den else 0.0


def evaluate(ds: Dataset, findings: list[Finding]) -> dict:
    labels = {(l.app_id, l.library, l.version): l for l in ds.labels}
    # predicted risk types per node (primary + secondary)
    pred_types: dict[tuple, set[str]] = {}
    pred_finding: dict[tuple, Finding] = {}
    for f in findings:
        k = (f.app_id, f.library, f.version)
        pred_types.setdefault(k, set()).update({f.risk_type, *f.secondary_risks})
        pred_finding[k] = f

    if not labels:
        return {"available": False}

    tp = fp = fn = tn = 0
    cat_hit, cat_tot = Counter(), Counter()
    sev_match = sev_total = 0
    trans_hit = trans_tot = 0

    for k, l in labels.items():
        predicted = k in pred_types
        if l.is_risk and predicted:
            tp += 1
        elif l.is_risk and not predicted:
            fn += 1
        elif not l.is_risk and predicted:
            fp += 1
        else:
            tn += 1

        if l.is_risk:
            cat = _CATEGORY.get(l.risk_type)
            if cat:
                cat_tot[cat] += 1
                types = pred_types.get(k, set())
                got = False
                if cat == "vulnerability":
                    got = bool(types & set(VULN_TYPES))
                elif cat == "license":
                    got = bool(types & set(LICENSE_TYPES))
                elif cat == "maintenance":
                    got = "unmaintained" in types
                if got:
                    cat_hit[cat] += 1
            if l.risk_type == "transitive_vuln":
                trans_tot += 1
                if "transitive_vuln" in pred_types.get(k, set()) or "vulnerable" in pred_types.get(k, set()):
                    trans_hit += 1
            # severity agreement on detected risks
            f = pred_finding.get(k)
            if f is not None:
                sev_total += 1
                if f.severity == l.severity:
                    sev_match += 1

    precision = _rate(tp, tp + fp)
    recall = _rate(tp, tp + fn)
    f1 = round(2 * precision * recall / (precision + recall), 4) if (precision + recall) else 0.0

    # Exploitability prioritization (the differentiator).
    vuln_findings = [f for f in findings if f.risk_type in VULN_TYPES]
    expl = Counter((f.exploitability or "unknown").lower() for f in vuln_findings)
    total_v = len(vuln_findings)
    actionable = expl.get("high", 0) + expl.get("medium", 0)

    return {
        "available": True,
        "dataset": "official",
        "totals": {"labels": len(labels), "risky": sum(1 for l in labels.values() if l.is_risk),
                   "clean": sum(1 for l in labels.values() if not l.is_risk)},
        "overall": {"precision": precision, "recall": recall, "f1": f1,
                    "false_positive_rate": _rate(fp, fp + tn),
                    "tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "detection": {
            "vulnerability": {"recall": _rate(cat_hit["vulnerability"], cat_tot["vulnerability"]),
                              "hit": cat_hit["vulnerability"], "total": cat_tot["vulnerability"], "target": 0.85},
            "transitive_resolution": {"recall": _rate(trans_hit, trans_tot),
                                      "hit": trans_hit, "total": trans_tot, "target": 1.0},
            "license": {"recall": _rate(cat_hit["license"], cat_tot["license"]),
                        "hit": cat_hit["license"], "total": cat_tot["license"], "target": 0.90},
            "maintenance": {"recall": _rate(cat_hit["maintenance"], cat_tot["maintenance"]),
                            "hit": cat_hit["maintenance"], "total": cat_tot["maintenance"], "target": 0.90},
        },
        "false_positive_rate": {"value": _rate(fp, fp + tn), "target": 0.20},
        "severity_agreement": {"rate": _rate(sev_match, sev_total), "target": 0.90},
        "exploitability": {
            "total_vuln_alerts": total_v,
            "high": expl.get("high", 0), "medium": expl.get("medium", 0),
            "low": expl.get("low", 0), "none": expl.get("none", 0),
            "actionable": actionable,
            "actionable_pct": _rate(actionable, total_v),
            "deprioritized_pct": _rate(total_v - actionable, total_v),
        },
    }
