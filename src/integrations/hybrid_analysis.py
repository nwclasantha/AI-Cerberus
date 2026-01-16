"""
Hybrid Analysis API v2 integration.

Provides sandbox submission and analysis retrieval for malware samples.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
import asyncio
import time

from ..utils.config import get_config
from ..utils.logger import get_logger
from ..utils.exceptions import IntegrationError

logger = get_logger("hybrid_analysis")


@dataclass
class SandboxReport:
    """Hybrid Analysis sandbox report."""

    job_id: str
    sha256: str = ""
    verdict: str = "unknown"
    threat_score: int = 0

    # Analysis metadata
    environment: str = ""
    analysis_start_time: str = ""
    analysis_end_time: str = ""
    submission_type: str = ""

    # Detection results
    malware_family: str = ""
    av_detect: int = 0
    vx_family: str = ""

    # Behavioral indicators
    processes: List[Dict] = field(default_factory=list)
    network_activity: List[Dict] = field(default_factory=list)
    file_activity: List[Dict] = field(default_factory=list)
    registry_activity: List[Dict] = field(default_factory=list)

    # MITRE ATT&CK
    mitre_techniques: List[str] = field(default_factory=list)

    # URLs and references
    report_url: str = ""

    def to_dict(self) -> Dict:
        return {
            "job_id": self.job_id,
            "sha256": self.sha256,
            "verdict": self.verdict,
            "threat_score": self.threat_score,
            "environment": self.environment,
            "malware_family": self.malware_family,
            "av_detect": self.av_detect,
            "processes": len(self.processes),
            "network_connections": len(self.network_activity),
            "file_operations": len(self.file_activity),
            "registry_operations": len(self.registry_activity),
            "mitre_techniques": self.mitre_techniques,
            "report_url": self.report_url,
        }


class HybridAnalysisClient:
    """
    Hybrid Analysis API v2 client.

    Features:
    - File submission to sandbox
    - Analysis report retrieval
    - Hash lookup
    - Environment selection (Windows 7/10/11, Linux, Android)
    """

    BASE_URL = "https://www.hybrid-analysis.com/api/v2"

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize Hybrid Analysis client.

        Args:
            api_key: Hybrid Analysis API key (or from config)
        """
        config = get_config()
        self._api_key = api_key or config.get("integrations.hybrid_analysis.api_key", "")
        self._enabled = config.get("integrations.hybrid_analysis.enabled", False)

        # Default environment
        self._default_env = config.get("integrations.hybrid_analysis.environment", "win10x64")

        # Rate limiting
        self._last_request_time = 0
        self._min_interval = 15.0  # Free API rate limit

        # HTTP client
        self._http_client = None

    @property
    def is_configured(self) -> bool:
        """Check if API key is configured."""
        return bool(self._api_key) and self._enabled

    async def _get_client(self):
        """Get or create HTTP client."""
        if self._http_client is None:
            try:
                import httpx
                self._http_client = httpx.AsyncClient(
                    timeout=60.0,
                    headers={
                        "api-key": self._api_key,
                        "User-Agent": "Malware Analyzer",
                        "Accept": "application/json",
                    },
                )
            except ImportError:
                raise IntegrationError("httpx package required for Hybrid Analysis integration")
        return self._http_client

    async def _rate_limit(self) -> None:
        """Apply rate limiting."""
        elapsed = time.time() - self._last_request_time
        if elapsed < self._min_interval:
            await asyncio.sleep(self._min_interval - elapsed)
        self._last_request_time = time.time()

    async def submit_file(
        self,
        file_path: Path,
        environment: Optional[str] = None,
        comment: str = ""
    ) -> Optional[str]:
        """
        Submit file to sandbox for analysis.

        Args:
            file_path: Path to file
            environment: Analysis environment (win10x64, win7x64, linux64, android, etc.)
            comment: Optional comment for submission

        Returns:
            Job ID if submitted successfully
        """
        if not self.is_configured:
            logger.warning("Hybrid Analysis API key not configured")
            return None

        await self._rate_limit()

        env = environment or self._default_env

        try:
            client = await self._get_client()
            url = f"{self.BASE_URL}/submit/file"

            # Check file size (max 100MB for free tier)
            file_size = file_path.stat().st_size
            if file_size > 100 * 1024 * 1024:
                logger.error(f"File too large for submission: {file_size} bytes")
                return None

            # Prepare submission
            with open(file_path, "rb") as f:
                files = {
                    "file": (file_path.name, f, "application/octet-stream")
                }
                data = {
                    "environment_id": self._get_environment_id(env),
                    "comment": comment or f"Submitted from Malware Analyzer",
                }

                response = await client.post(url, files=files, data=data)

            if response.status_code not in [200, 201]:
                logger.error(f"File submission failed: {response.status_code}")
                logger.error(f"Response: {response.text}")
                return None

            result = response.json()
            job_id = result.get("job_id")

            logger.info(f"File submitted to Hybrid Analysis: {job_id}")
            return job_id

        except Exception as e:
            logger.error(f"File submission failed: {e}")
            return None

    async def lookup_hash(self, file_hash: str) -> Optional[List[SandboxReport]]:
        """
        Look up file by hash.

        Args:
            file_hash: SHA256 hash

        Returns:
            List of SandboxReport if found
        """
        if not self.is_configured:
            logger.warning("Hybrid Analysis API key not configured")
            return None

        await self._rate_limit()

        try:
            client = await self._get_client()
            url = f"{self.BASE_URL}/search/hash"

            data = {"hash": file_hash}
            response = await client.post(url, data=data)

            if response.status_code == 404:
                logger.info(f"Hash not found in Hybrid Analysis: {file_hash[:16]}...")
                return None

            if response.status_code != 200:
                logger.error(f"Hybrid Analysis API error: {response.status_code}")
                return None

            results = response.json()

            if not results:
                return None

            reports = []
            for item in results:
                report = self._parse_report(item)
                reports.append(report)

            return reports

        except Exception as e:
            logger.error(f"Hybrid Analysis lookup failed: {e}")
            return None

    async def get_report(self, job_id: str) -> Optional[SandboxReport]:
        """
        Get analysis report by job ID.

        Args:
            job_id: Job ID from submission

        Returns:
            SandboxReport when analysis complete
        """
        if not self.is_configured:
            return None

        await self._rate_limit()

        try:
            client = await self._get_client()
            url = f"{self.BASE_URL}/report/{job_id}/summary"

            response = await client.get(url)

            if response.status_code != 200:
                logger.error(f"Report retrieval failed: {response.status_code}")
                return None

            data = response.json()
            return self._parse_report(data)

        except Exception as e:
            logger.error(f"Report retrieval failed: {e}")
            return None

    async def get_state(self, job_id: str) -> Optional[str]:
        """
        Get analysis state.

        Args:
            job_id: Job ID from submission

        Returns:
            State: IN_QUEUE, IN_PROGRESS, SUCCESS, ERROR
        """
        if not self.is_configured:
            return None

        await self._rate_limit()

        try:
            client = await self._get_client()
            url = f"{self.BASE_URL}/report/{job_id}/state"

            response = await client.get(url)

            if response.status_code != 200:
                return None

            data = response.json()
            return data.get("state")

        except Exception as e:
            logger.error(f"State check failed: {e}")
            return None

    def _parse_report(self, data: Dict) -> SandboxReport:
        """Parse API response into SandboxReport."""

        # Determine verdict from threat score
        threat_score = data.get("threat_score", 0)
        if threat_score >= 70:
            verdict = "malicious"
        elif threat_score >= 50:
            verdict = "suspicious"
        elif threat_score > 0:
            verdict = "potentially_unwanted"
        else:
            verdict = "clean"

        return SandboxReport(
            job_id=data.get("job_id", ""),
            sha256=data.get("sha256", ""),
            verdict=verdict,
            threat_score=threat_score,
            environment=data.get("environment_description", ""),
            analysis_start_time=data.get("analysis_start_time", ""),
            submission_type=data.get("submission_type", ""),
            malware_family=data.get("vx_family", ""),
            av_detect=data.get("av_detect", 0),
            vx_family=data.get("vx_family", ""),
            processes=data.get("processes", []),
            network_activity=data.get("domains", []),
            mitre_techniques=data.get("mitre_attcks", []),
            report_url=f"https://www.hybrid-analysis.com/sample/{data.get('sha256', '')}",
        )

    def _get_environment_id(self, environment: str) -> int:
        """Map environment name to ID."""
        env_map = {
            "win7x64": 110,
            "win7x86": 100,
            "win10x64": 120,
            "win11x64": 200,
            "linux64": 300,
            "android": 400,
        }
        return env_map.get(environment, 120)  # Default to Win10x64

    def submit_file_sync(self, file_path: Path, environment: Optional[str] = None) -> Optional[str]:
        """Synchronous file submission wrapper."""
        try:
            return asyncio.run(self.submit_file(file_path, environment))
        except Exception as e:
            logger.error(f"Sync submission failed: {e}")
            return None

    def lookup_hash_sync(self, file_hash: str) -> Optional[List[SandboxReport]]:
        """Synchronous hash lookup wrapper."""
        try:
            return asyncio.run(self.lookup_hash(file_hash))
        except Exception as e:
            logger.error(f"Sync lookup failed: {e}")
            return None

    async def close(self) -> None:
        """Close HTTP client."""
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None
