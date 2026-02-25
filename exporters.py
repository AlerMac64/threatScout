"""Export helpers for threatScout IoC records."""

from __future__ import annotations

import csv
import json
import logging
from pathlib import Path

from models import IoCRecord

logger = logging.getLogger(__name__)


def export_json(records: list[IoCRecord], path: Path) -> None:
    """Serialise IoC records to a JSON file.

    Args:
        records: List of validated ``IoCRecord`` objects.
        path: Destination file path.
    """
    data = [
        {
            "value": r.value,
            "type": r.type.value,
            "source": r.source,
            "timestamp": r.timestamp.isoformat(),
            "risk_level": r.risk_level.value,
        }
        for r in records
    ]
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    logger.info("Exported %d records to %s (JSON).", len(records), path)


def export_csv(records: list[IoCRecord], path: Path) -> None:
    """Serialise IoC records to a CSV file.

    Args:
        records: List of validated ``IoCRecord`` objects.
        path: Destination file path.
    """
    fieldnames = ["value", "type", "source", "timestamp", "risk_level"]
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for r in records:
            writer.writerow(
                {
                    "value": r.value,
                    "type": r.type.value,
                    "source": r.source,
                    "timestamp": r.timestamp.isoformat(),
                    "risk_level": r.risk_level.value,
                }
            )
    logger.info("Exported %d records to %s (CSV).", len(records), path)
