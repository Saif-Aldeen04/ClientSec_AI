"""ClientSec AI - Member 1: reconnaissance and asset ingestion.

Example::

    import asyncio
    from clientsec_crawler import CrawlConfig, crawl

    result = asyncio.run(crawl("https://authorized-example.test", CrawlConfig(max_pages=50)))
"""

from .config import CrawlConfig
from .crawler import Crawler, crawl, crawl_sync
from .errors import CrawlerError, InvalidTargetError
from .exporter import to_json, write_json
from .models import SCHEMA_VERSION
from .progress import CancellationToken, ProgressEvent
from .scope import validate_target_url

__all__ = [
    "SCHEMA_VERSION",
    "CancellationToken",
    "CrawlConfig",
    "Crawler",
    "CrawlerError",
    "InvalidTargetError",
    "ProgressEvent",
    "crawl",
    "crawl_sync",
    "to_json",
    "validate_target_url",
    "write_json",
]
