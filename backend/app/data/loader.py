"""Load the synthetic dataset files into typed models."""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Optional

from ..config import settings
from ..models import (
    Application,
    Dataset,
    Dependency,
    Label,
    LicenseRule,
    Vulnerability,
)


def _as_bool(value: str) -> bool:
    return str(value).strip().lower() in ("true", "1", "yes")


def load_dataset(data_dir: Optional[Path] = None) -> Dataset:
    d = Path(data_dir) if data_dir else settings.data_dir

    apps = [Application(**a) for a in json.loads((d / "applications.json").read_text("utf-8"))]
    vulns = [Vulnerability(**v) for v in json.loads((d / "vulnerability_db.json").read_text("utf-8"))]
    rules = [LicenseRule(**r) for r in json.loads((d / "license_rules.json").read_text("utf-8"))]

    deps: list[Dependency] = []
    with (d / "dependencies.csv").open(encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            deps.append(Dependency(
                app_id=row["app_id"], library=row["library"], version=row["version"],
                license=row["license"], is_direct=_as_bool(row["is_direct"]),
                parent_library=row["parent_library"], parent_version=row["parent_version"],
                used=_as_bool(row["used"]), version_constraint=row["version_constraint"],
                last_updated=row["last_updated"], maintainer_count=int(row["maintainer_count"]),
            ))

    labels: list[Label] = []
    labels_path = d / "labels.csv"
    if labels_path.exists():
        with labels_path.open(encoding="utf-8", newline="") as f:
            for row in csv.DictReader(f):
                labels.append(Label(
                    app_id=row["app_id"], library=row["library"], version=row["version"],
                    is_risk=_as_bool(row["is_risk"]), risk_type=row["risk_type"],
                    severity=row["severity"], is_reachable=_as_bool(row["is_reachable"]),
                    explanation=row["explanation"],
                ))

    return Dataset(applications=apps, dependencies=deps, vulnerabilities=vulns,
                   license_rules=rules, labels=labels)
