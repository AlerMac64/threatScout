"""OSINT feed parsers for threatScout.

Each parser inherits from ``IntelSource`` and implements ``fetch()`` to return
a list of normalised ``IoCRecord`` objects.
"""

from __future__ import annotations

import csv
import io
import logging
from abc import ABC, abstractmethod

import httpx

from models import DataNormalizer, IoCRecord, IoCType, RiskLevel

logger = logging.getLogger(__name__)

_REQUEST_TIMEOUT = 30  # seconds


class IntelSource(ABC):
    """Abstract base class for all threat-intelligence feed parsers.

    Subclasses must implement ``fetch()`` which returns a list of validated
    ``IoCRecord`` instances.
    """

    def __init__(self) -> None:
        self._normalizer = DataNormalizer()

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name of this intelligence source."""

    @abstractmethod
    def fetch(self) -> list[IoCRecord]:
        """Retrieve and parse the feed, returning normalised IoC records.

        The method must handle network and parsing errors internally so
        that a failure in one source does not crash the pipeline.
        """


class URLHausParser(IntelSource):
    """Parser for the Abuse.ch URLHaus recent-URLs CSV feed.

    Feed URL: https://urlhaus.abuse.ch/downloads/csv_recent/
    """

    FEED_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"

    @property
    def name(self) -> str:
        return "URLHaus"

    def fetch(self) -> list[IoCRecord]:
        """Download and parse the URLHaus CSV feed."""
        logger.info("Fetching URLHaus feed …")
        try:
            response = httpx.get(self.FEED_URL, timeout=_REQUEST_TIMEOUT, follow_redirects=True)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            logger.error("URLHaus feed unavailable: %s", exc)
            return []

        records: list[IoCRecord] = []
        reader = csv.reader(io.StringIO(response.text))

        for row in reader:
            if not row or row[0].startswith("#"):
                continue
            # CSV columns: id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter
            if len(row) < 3:
                continue
            url_value = row[2].strip().strip('"')
            if not url_value:
                continue
            try:
                record = self._normalizer.normalize(
                    value=url_value,
                    source=self.name,
                    ioc_type=IoCType.URL,
                    risk_level=RiskLevel.HIGH,
                )
                records.append(record)
            except (ValueError, Exception) as exc:
                logger.debug("Skipping invalid URLHaus entry: %s", exc)

        logger.info("URLHaus: parsed %d records.", len(records))
        return records


class FeodoTrackerParser(IntelSource):
    """Parser for the Abuse.ch Feodo Tracker Botnet C2 IP Blocklist.

    Feed URL: https://feodotracker.abuse.ch/downloads/ipblocklist.csv
    """

    FEED_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"

    @property
    def name(self) -> str:
        return "FeodoTracker"

    def fetch(self) -> list[IoCRecord]:
        """Download and parse the Feodo Tracker CSV feed."""
        logger.info("Fetching Feodo Tracker feed …")
        try:
            response = httpx.get(self.FEED_URL, timeout=_REQUEST_TIMEOUT, follow_redirects=True)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            logger.error("Feodo Tracker feed unavailable: %s", exc)
            return []

        records: list[IoCRecord] = []
        reader = csv.reader(io.StringIO(response.text))

        for row in reader:
            if not row or row[0].startswith("#"):
                continue
            # CSV columns: first_seen_utc, dst_ip, dst_port, c2_status, last_online, malware
            if len(row) < 2:
                continue
            ip_value = row[1].strip().strip('"')
            if not ip_value:
                continue
            try:
                record = self._normalizer.normalize(
                    value=ip_value,
                    source=self.name,
                    ioc_type=IoCType.IP,
                    risk_level=RiskLevel.CRITICAL,
                )
                records.append(record)
            except (ValueError, Exception) as exc:
                logger.debug("Skipping invalid FeodoTracker entry: %s", exc)

        logger.info("FeodoTracker: parsed %d records.", len(records))
        return records
