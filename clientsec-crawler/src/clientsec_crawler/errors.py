"""Exception types used by the crawler."""

from __future__ import annotations


class CrawlerError(Exception):
    """Base class for all crawler-specific exceptions."""


class InvalidURLError(CrawlerError, ValueError):
    """A URL could not be parsed or is not acceptable (wrong scheme, credentials, ...)."""

    def __init__(self, message: str, code: str = "invalid_url") -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class InvalidTargetError(CrawlerError, ValueError):
    """The user supplied target URL was rejected by validation."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class FetchError(CrawlerError):
    """A single fetch (page or asset) failed in an expected way.

    ``code`` is one of the stable error codes documented in the README.
    """

    def __init__(
        self,
        code: str,
        message: str,
        *,
        status_code: int | None = None,
        final_url: str | None = None,
        content_type: str | None = None,
        redirect_chain: list[str] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.final_url = final_url
        self.content_type = content_type
        self.redirect_chain: list[str] = list(redirect_chain or [])
