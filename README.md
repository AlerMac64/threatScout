# threatScout

Automated OSINT-based Threat Intelligence collector.  
Fetches Indicators of Compromise (IoCs) from public feeds, normalises them via Pydantic, stores them in SQLite with deduplication, and exports to JSON / CSV for SIEM or firewall integration.

---

## Quick Start

```bash
# 1. Create a virtual environment
python -m venv .venv && source .venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Collect IoCs from all registered feeds
python main.py collect

# 4. Export collected data
python main.py export --format json --output iocs.json
python main.py export --format csv  --output iocs.csv
```

### CLI Reference

| Command | Description |
|---------|-------------|
| `python main.py collect` | Fetch IoCs from every registered OSINT source and store them in SQLite. |
| `python main.py export -f json -o FILE` | Export all stored IoCs to a JSON file. |
| `python main.py export -f csv -o FILE` | Export all stored IoCs to a CSV file. |
| `python main.py -v collect` | Run collection with debug-level logging. |
| `python main.py --db custom.db collect` | Use a custom database path. |

---

## Project Structure

```
threatScout/
├── main.py          # CLI entry-point and orchestration
├── models.py        # Pydantic models (IoCRecord) and DataNormalizer
├── database.py      # SQLite manager with deduplication
├── parsers.py       # OSINT feed parsers (IntelSource ABC)
├── exporters.py     # JSON / CSV export helpers
├── requirements.txt
└── README.md
```

---

## Adding a New Parser

All parsers live in `parsers.py` and inherit from `IntelSource`.

### Step 1 — Create the class

```python
class MyNewFeedParser(IntelSource):
    """Parser for My New Feed."""

    FEED_URL = "https://example.com/feed.csv"

    @property
    def name(self) -> str:
        return "MyNewFeed"

    def fetch(self) -> list[IoCRecord]:
        logger.info("Fetching MyNewFeed …")
        try:
            response = httpx.get(self.FEED_URL, timeout=_REQUEST_TIMEOUT, follow_redirects=True)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            logger.error("MyNewFeed unavailable: %s", exc)
            return []

        records: list[IoCRecord] = []
        # … parse response.text and build IoCRecord objects
        # Use self._normalizer.normalize(...) for validation
        return records
```

### Step 2 — Register the parser

Open `main.py` and add the new class to `_SOURCES`:

```python
from parsers import URLHausParser, SSLBlacklistParser, MyNewFeedParser

_SOURCES: list[type[IntelSource]] = [
    URLHausParser,
    SSLBlacklistParser,
    MyNewFeedParser,        # ← add here
]
```

That's it — the next `python main.py collect` will include your new feed.

---

## Data Model

Each IoC record contains:

| Field | Type | Description |
|-------|------|-------------|
| `value` | `str` | The indicator itself (IP, URL, hash, domain) |
| `type` | `ip` · `url` · `hash` · `domain` | Category of the indicator |
| `source` | `str` | OSINT feed name |
| `timestamp` | `datetime` (UTC) | When the record was collected |
| `risk_level` | `low` · `medium` · `high` · `critical` | Severity assigned by the feed/normalizer |

---

## License

See [LICENSE](LICENSE) for details.
