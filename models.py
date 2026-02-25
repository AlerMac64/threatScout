"""Pydantic models and data normalizer for threatScout."""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)

# regex patterns for IoC type inference

_RE_IPV4 = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
_RE_MD5 = re.compile(r"^[a-f0-9]{32}$", re.IGNORECASE)
_RE_SHA1 = re.compile(r"^[a-f0-9]{40}$", re.IGNORECASE)
_RE_SHA256 = re.compile(r"^[a-f0-9]{64}$", re.IGNORECASE)
_RE_URL = re.compile(r"^https?://", re.IGNORECASE)
_RE_DOMAIN = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$"
)


class IoCType(str, Enum):
    """Enumeration of supported Indicator of Compromise types."""

    IP = "ip"
    URL = "url"
    HASH = "hash"
    DOMAIN = "domain"


class RiskLevel(str, Enum):
    """Qualitative risk classification for an IoC."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IoCRecord(BaseModel):
    """Single Indicator of Compromise entry.

    Attributes:
        value: The indicator itself (IP address, URL, hash, or domain).
        type: Category of the indicator.
        source: Name of the OSINT feed that produced this record.
        timestamp: UTC datetime when the record was collected.
        risk_level: Qualitative severity assigned by the feed or normalizer.
    """

    value: str
    type: IoCType
    source: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    risk_level: RiskLevel = RiskLevel.MEDIUM

    @field_validator("value")
    @classmethod
    def value_must_not_be_empty(cls, v: str) -> str:
        """Reject blank indicator values."""
        stripped = v.strip()
        if not stripped:
            raise ValueError("IoC value must not be empty")
        return stripped


class DataNormalizer:
    """Sanitises and normalises raw feed data into validated IoCRecord instances."""

    def normalize(
        self,
        value: str,
        source: str,
        ioc_type: IoCType | None = None,
        risk_level: RiskLevel = RiskLevel.MEDIUM,
        timestamp: datetime | None = None,
    ) -> IoCRecord:
        """Create a validated IoCRecord from raw strings.

        Args:
            value: Raw indicator string from a feed.
            source: Name of the originating OSINT feed.
            ioc_type: Explicit type; inferred automatically when ``None``.
            risk_level: Severity to assign to the record.
            timestamp: Collection time; defaults to now (UTC).

        Returns:
            A validated ``IoCRecord``.

        Raises:
            ValueError: If the value is empty or the type cannot be determined.
        """
        value = value.strip()

        if ioc_type is None:
            ioc_type = self._infer_type(value)

        if ioc_type == IoCType.DOMAIN:
            value = value.lower()

        return IoCRecord(
            value=value,
            type=ioc_type,
            source=source,
            timestamp=timestamp or datetime.now(timezone.utc),
            risk_level=risk_level,
        )

    # private helpers

    @staticmethod
    def _infer_type(value: str) -> IoCType:
        """Determine IoC type from the value string using regex heuristics."""
        if _RE_URL.match(value):
            return IoCType.URL
        if _RE_IPV4.match(value):
            return IoCType.IP
        if _RE_SHA256.match(value) or _RE_SHA1.match(value) or _RE_MD5.match(value):
            return IoCType.HASH
        if _RE_DOMAIN.match(value):
            return IoCType.DOMAIN
        raise ValueError(f"Cannot infer IoC type for value: {value!r}")
