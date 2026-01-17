"""
VirusTotal API v3 integration.

Provides file hash lookup and submission capabilities.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from ..utils.config import get_config
from ..utils.logger import get_logger
from ..utils.exceptions import IntegrationError

if TYPE_CHECKING:
    import httpx

logger = get_logger("virustotal")


@dataclass
class VTReport:
    """VirusTotal scan report."""

    sha256: str
    detection_count: int = 0
    total_engines: int = 0
    detection_ratio: float = 0.0
    verdict: str = "unknown"
    scan_date: str = ""
    permalink: str = ""

    # Detection details
    detections: Dict[str, str] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)

    # File metadata from VT
    file_type: str = ""
    file_size: int = 0
    first_seen: str = ""
    last_seen: str = ""

    # Behavioral info
    sandbox_verdicts: List[Dict[str, Any]] = field(default_factory=list)
    sigma_rules: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sha256": self.sha256,
            "detection_count": self.detection_count,
            "total_engines": self.total_engines,
            "detection_ratio": round(self.detection_ratio, 2),
            "verdict": self.verdict,
            "scan_date": self.scan_date,
            "permalink": self.permalink,
            "detections": dict(list(self.detections.items())[:20]),
            "tags": self.tags[:20],
            "file_type": self.file_type,
            "file_size": self.file_size,
        }


class VirusTotalClient:
    """
    VirusTotal API v3 client.

    Features:
    - File hash lookup
    - File upload/submission
    - Report retrieval
    - Rate limiting
    """

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: Optional[str] = None) -> None:
        """
        Initialize VirusTotal client.

        Args:
            api_key: VirusTotal API key (or from config)
        """
        config = get_config()
        self._api_key = api_key or config.get("integrations.virustotal.api_key", "")
        self._enabled = config.get("integrations.virustotal.enabled", True)

        # Rate limiting
        self._last_request_time = 0.0
        self._min_interval = 15.0  # Free API: 4 requests/minute

        # HTTP client
        self._http_client: Optional[httpx.AsyncClient] = None

    @property
    def is_configured(self) -> bool:
        """Check if API key is configured."""
        return bool(self._api_key) and self._enabled

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._http_client is None:
            try:
                import httpx
                self._http_client = httpx.AsyncClient(
                    timeout=30.0,
                    headers={
                        "x-apikey": self._api_key,
                        "Accept": "application/json",
                    },
                )
            except ImportError:
                raise IntegrationError(
                    "httpx package required for VirusTotal integration",
                    service="virustotal",
                )
        return self._http_client

    async def _rate_limit(self) -> None:
        """Apply rate limiting."""
        elapsed = time.time() - self._last_request_time
        if elapsed < self._min_interval:
            await asyncio.sleep(self._min_interval - elapsed)
        self._last_request_time = time.time()

    async def lookup_hash(self, file_hash: str) -> Optional[VTReport]:
        """
        Look up file by hash.

        Args:
            file_hash: MD5, SHA1, or SHA256 hash

        Returns:
            VTReport if found, None otherwise
        """
        if not self.is_configured:
            logger.warning("VirusTotal API key not configured")
            return None

        await self._rate_limit()

        try:
            client = await self._get_client()
            url = f"{self.BASE_URL}/files/{file_hash}"

            response = await client.get(url)

            if response.status_code == 404:
                logger.info(f"Hash not found in VirusTotal: {file_hash[:16]}...")
                return None

            if response.status_code != 200:
                logger.error(f"VirusTotal API error: {response.status_code}")
                return None

            data = response.json()
            return self._parse_report(data)

        except Exception as e:
            logger.error(f"VirusTotal lookup failed: {e}")
            return None

    async def submit_file(self, file_path: Path) -> Optional[str]:
        """
        Submit file to VirusTotal for scanning.

        Args:
            file_path: Path to file

        Returns:
            Analysis ID if submitted successfully
        """
        if not self.is_configured:
            logger.warning("VirusTotal API key not configured")
            return None

        await self._rate_limit()

        try:
            client = await self._get_client()

            # Check file size
            file_size = file_path.stat().st_size
            if file_size > 32 * 1024 * 1024:  # 32MB limit
                # Need to get upload URL for large files
                url = f"{self.BASE_URL}/files/upload_url"
                response = await client.get(url)
                upload_url = response.json().get("data", "")
            else:
                upload_url = f"{self.BASE_URL}/files"

            # Upload file
            with open(file_path, "rb") as f:
                files = {"file": (file_path.name, f, "application/octet-stream")}
                response = await client.post(upload_url, files=files)

            if response.status_code not in [200, 201]:
                logger.error(f"File submission failed: {response.status_code}")
                return None

            data = response.json()
            analysis_id = data.get("data", {}).get("id")

            logger.info(f"File submitted to VirusTotal: {analysis_id}")
            return analysis_id

        except Exception as e:
            logger.error(f"File submission failed: {e}")
            return None

    async def get_analysis(self, analysis_id: str) -> Optional[VTReport]:
        """
        Get analysis results.

        Args:
            analysis_id: Analysis ID from submission

        Returns:
            VTReport when analysis complete
        """
        if not self.is_configured:
            return None

        await self._rate_limit()

        try:
            client = await self._get_client()
            url = f"{self.BASE_URL}/analyses/{analysis_id}"

            response = await client.get(url)

            if response.status_code != 200:
                return None

            data = response.json()
            status = data.get("data", {}).get("attributes", {}).get("status")

            if status != "completed":
                return None

            # Get file report
            sha256 = data.get("data", {}).get("attributes", {}).get("sha256")
            if sha256:
                return await self.lookup_hash(sha256)

            return None

        except Exception as e:
            logger.error(f"Analysis retrieval failed: {e}")
            return None

    def _parse_report(self, data: Dict[str, Any]) -> VTReport:
        """Parse API response into VTReport."""
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        results = attrs.get("last_analysis_results", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values())

        detection_count = malicious + suspicious
        detection_ratio = detection_count / total if total > 0 else 0

        # Determine verdict
        if detection_ratio > 0.5:
            verdict = "malicious"
        elif detection_ratio > 0.2:
            verdict = "suspicious"
        elif detection_count > 0:
            verdict = "potentially_unwanted"
        else:
            verdict = "clean"

        # Extract detections
        detections: Dict[str, str] = {}
        for engine, result in results.items():
            if result.get("category") in ["malicious", "suspicious"]:
                detections[engine] = result.get("result", "")

        return VTReport(
            sha256=attrs.get("sha256", ""),
            detection_count=detection_count,
            total_engines=total,
            detection_ratio=detection_ratio,
            verdict=verdict,
            scan_date=attrs.get("last_analysis_date", ""),
            permalink=f"https://www.virustotal.com/gui/file/{attrs.get('sha256', '')}",
            detections=detections,
            tags=attrs.get("tags", []),
            file_type=attrs.get("type_description", ""),
            file_size=attrs.get("size", 0),
            first_seen=attrs.get("first_submission_date", ""),
            last_seen=attrs.get("last_submission_date", ""),
        )

    def lookup_hash_sync(self, file_hash: str) -> Optional[VTReport]:
        """
        Synchronous hash lookup wrapper.

        Note: This creates a new event loop. Avoid calling from async context.
        """
        try:
            # Check if we're already in an async context
            try:
                loop = asyncio.get_running_loop()
                # We're in an async context, can't use asyncio.run
                logger.warning(
                    "lookup_hash_sync called from async context. "
                    "Use 'await lookup_hash()' instead."
                )
                # Create a task and run it
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    future = pool.submit(asyncio.run, self.lookup_hash(file_hash))
                    return future.result(timeout=60)
            except RuntimeError:
                # No running event loop, safe to use asyncio.run
                return asyncio.run(self.lookup_hash(file_hash))
        except Exception as e:
            logger.error(f"Sync lookup failed: {e}")
            return None

    async def close(self) -> None:
        """Close HTTP client."""
        if self._http_client is not None:
            await self._http_client.aclose()
            self._http_client = None

    async def __aenter__(self) -> VirusTotalClient:
        """Async context manager entry."""
        return self

    async def __aexit__(
        self,
        exc_type: Optional[type],
        exc_val: Optional[BaseException],
        exc_tb: Optional[Any],
    ) -> None:
        """Async context manager exit. Does not suppress exceptions."""
        await self.close()
