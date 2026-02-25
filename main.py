#!/usr/bin/env python3
"""threatScout — CLI entry-point for threat-intelligence collection."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from database import DatabaseManager
from exporters import export_csv, export_json
from parsers import FeodoTrackerParser, IntelSource, URLHausParser

logger = logging.getLogger("threatScout")

# available sources (extend this list when adding new parsers)

_SOURCES: list[type[IntelSource]] = [
    URLHausParser,
    FeodoTrackerParser,
]


def _configure_logging(verbose: bool = False) -> None:
    """Set up root logger with timestamp, level and module name."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def _collect(db: DatabaseManager) -> None:
    """Iterate over all registered OSINT sources and persist records."""
    total_inserted = 0
    for source_cls in _SOURCES:
        source = source_cls()
        logger.info("── Source: %s ──", source.name)
        try:
            records = source.fetch()
        except Exception as exc:
            logger.error("Unhandled error in %s: %s", source.name, exc)
            continue
        inserted = db.insert_many(records)
        total_inserted += inserted

    logger.info("Collection complete. %d new records stored. Total in DB: %d",
                total_inserted, db.count())


def _export(db: DatabaseManager, fmt: str, output: Path) -> None:
    """Export stored records to the requested format."""
    records = db.fetch_all()
    if not records:
        logger.warning("No records in the database — nothing to export.")
        return

    if fmt == "json":
        export_json(records, output)
    elif fmt == "csv":
        export_csv(records, output)
    else:
        logger.error("Unsupported format: %s. Use 'json' or 'csv'.", fmt)
        sys.exit(1)


def main() -> None:
    """Parse CLI arguments and run the requested sub-command."""
    parser = argparse.ArgumentParser(
        prog="threatScout",
        description="Automated OSINT-based Threat Intelligence collector.",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable debug-level logging."
    )
    parser.add_argument(
        "--db", type=Path, default=Path("threat_intel.db"),
        help="Path to the SQLite database (default: threat_intel.db).",
    )

    subparsers = parser.add_subparsers(dest="command")

    # collect
    subparsers.add_parser("collect", help="Fetch IoCs from all registered OSINT sources.")

    # export
    export_parser = subparsers.add_parser("export", help="Export stored IoCs to a file.")
    export_parser.add_argument(
        "-f", "--format", choices=["json", "csv"], required=True,
        help="Output format (json or csv).",
    )
    export_parser.add_argument(
        "-o", "--output", type=Path, required=True,
        help="Destination file path.",
    )

    args = parser.parse_args()
    _configure_logging(verbose=args.verbose)

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    db = DatabaseManager(db_path=args.db)
    db.connect()

    try:
        if args.command == "collect":
            _collect(db)
        elif args.command == "export":
            _export(db, args.format, args.output)
    finally:
        db.close()


if __name__ == "__main__":
    main()
