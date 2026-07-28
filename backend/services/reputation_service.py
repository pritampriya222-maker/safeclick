"""
backend/services/reputation_service.py
────────────────────────────────────────────────────────────────────────────
Domain reputation service with multi-source lookup:

Priority order:
1. VirusTotal API (free community key, 500 req/day, 4/min)
   → Set VIRUSTOTAL_API_KEY env var. Skip if not configured.
2. OpenPhish community feed (genuinely free, no key required)
   → Fetched at startup and refreshed every REPUTATION_CACHE_TTL seconds.
3. Graceful degradation → returns { known_malicious: False, source: 'unavailable' }

Caching:
- In-process TTL cache (cachetools) — default 6h TTL.
- Optional Redis (set REDIS_URL env var) for distributed deployments.
  Falls back to in-process if Redis is unreachable.
"""

import asyncio
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

import httpx
from cachetools import TTLCache


# ── Configuration ──────────────────────────────────────────────────────────────

VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
VIRUSTOTAL_BASE_URL = "https://www.virustotal.com/api/v3"

OPENPHISH_FEED_URL: str = os.getenv(
    "OPENPHISH_FEED_URL", "https://openphish.com/feed.txt"
)

REPUTATION_CACHE_TTL: int = int(os.getenv("REPUTATION_CACHE_TTL", "21600"))  # 6 hours
REPUTATION_CACHE_MAXSIZE = 10_000

REDIS_URL: str = os.getenv("REDIS_URL", "")

# Rate limiting: VT free tier = 4 req/min = 1 req per 15s
VT_REQUEST_DELAY_SECONDS = 15


# ── Data model ─────────────────────────────────────────────────────────────────

@dataclass
class ReputationResult:
    domain: str
    known_malicious: bool
    source: str  # matches extension ReputationResult.source type
    last_checked: str  # ISO 8601
    confidence: float
    detail: Optional[str] = None


# ── Reputation Service ─────────────────────────────────────────────────────────

class ReputationService:
    """
    Multi-source domain reputation checker with TTL caching.

    Usage:
        service = ReputationService()
        await service.initialize()          # fetch OpenPhish feed at startup
        result = await service.check_domain("phishing.example.com")
    """

    def __init__(self):
        # In-process TTL cache: domain → ReputationResult
        self._cache: TTLCache = TTLCache(
            maxsize=REPUTATION_CACHE_MAXSIZE,
            ttl=REPUTATION_CACHE_TTL,
        )
        # OpenPhish feed: set of malicious hostnames/domains
        self._openphish_domains: set[str] = set()
        self._openphish_loaded = False

        # Redis client (optional)
        self._redis = None
        self._redis_available = False

        # VT rate limiting semaphore (1 request per 15s on free tier)
        self._vt_semaphore = asyncio.Semaphore(1)
        self._last_vt_request = 0.0

    async def initialize(self) -> None:
        """
        Startup initialization:
        1. Try to connect to Redis (optional)
        2. Fetch OpenPhish community feed
        """
        await self._try_connect_redis()
        await self._refresh_openphish_feed()

    # ── Public interface ───────────────────────────────────────────────────────

    async def check_domain(self, domain: str) -> ReputationResult:
        """
        Check domain reputation. Always returns, never raises.
        Results are cached per domain for REPUTATION_CACHE_TTL seconds.
        """
        # Normalize: strip www, lowercase
        normalized = domain.lower().lstrip("www.")

        # Check in-process cache first
        if normalized in self._cache:
            cached = self._cache[normalized]
            return ReputationResult(
                domain=normalized,
                known_malicious=cached.known_malicious,
                source="cache",
                last_checked=cached.last_checked,
                confidence=cached.confidence,
                detail=f"Cached ({cached.source}): {cached.detail or ''}",
            )

        # Check Redis cache (if available)
        if self._redis_available:
            redis_result = await self._get_from_redis(normalized)
            if redis_result:
                return redis_result

        # Run lookups in priority order
        result = await self._lookup(normalized)

        # Cache the result
        self._cache[normalized] = result
        if self._redis_available:
            await self._set_in_redis(normalized, result)

        return result

    # ── Private: Lookup pipeline ──────────────────────────────────────────────

    async def _lookup(self, domain: str) -> ReputationResult:
        """Run the full lookup pipeline."""
        now = datetime.now(timezone.utc).isoformat()

        # 1. OpenPhish local cache (instant, no network) ──────────────────────
        if self._openphish_loaded and domain in self._openphish_domains:
            return ReputationResult(
                domain=domain,
                known_malicious=True,
                source="openphish",
                last_checked=now,
                confidence=0.85,
                detail="Domain found in OpenPhish community phishing feed.",
            )

        # 2. VirusTotal (if API key configured) ───────────────────────────────
        if VIRUSTOTAL_API_KEY:
            vt_result = await self._check_virustotal(domain)
            if vt_result is not None:
                return vt_result

        # 3. Graceful degradation ─────────────────────────────────────────────
        return ReputationResult(
            domain=domain,
            known_malicious=False,
            source="unavailable",
            last_checked=now,
            confidence=0.0,
            detail="Domain not found in any reputation database.",
        )

    # ── Private: VirusTotal ───────────────────────────────────────────────────

    async def _check_virustotal(self, domain: str) -> Optional[ReputationResult]:
        """
        Check VirusTotal domain report.
        Free tier: 500 req/day, 4 req/min.
        Returns None if VT is unavailable or rate limited.

        Endpoint: GET /api/v3/domains/{domain}
        Docs: https://developers.virustotal.com/reference/domain-info
        """
        async with self._vt_semaphore:
            # Enforce rate limit: min 15s between requests
            now = asyncio.get_event_loop().time()
            elapsed = now - self._last_vt_request
            if elapsed < VT_REQUEST_DELAY_SECONDS:
                await asyncio.sleep(VT_REQUEST_DELAY_SECONDS - elapsed)
            self._last_vt_request = asyncio.get_event_loop().time()

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(
                    f"{VIRUSTOTAL_BASE_URL}/domains/{domain}",
                    headers={
                        "x-apikey": VIRUSTOTAL_API_KEY,
                        "Accept": "application/json",
                    },
                )

            if response.status_code == 404:
                # Domain unknown to VT — not malicious, low confidence
                return ReputationResult(
                    domain=domain,
                    known_malicious=False,
                    source="virustotal",
                    last_checked=datetime.now(timezone.utc).isoformat(),
                    confidence=0.3,
                    detail="Domain not found in VirusTotal database.",
                )

            if response.status_code == 429:
                # Rate limited — skip VT this time
                print(f"[SafeClick] VirusTotal rate limit hit for {domain}")
                return None

            if not response.is_success:
                print(f"[SafeClick] VirusTotal returned {response.status_code} for {domain}")
                return None

            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

            malicious_count = stats.get("malicious", 0)
            suspicious_count = stats.get("suspicious", 0)
            total_engines = sum(stats.values()) if stats else 0

            is_malicious = malicious_count >= 3  # ≥3 engines flag it
            confidence = min(1.0, (malicious_count + suspicious_count * 0.5) / max(total_engines, 1))

            return ReputationResult(
                domain=domain,
                known_malicious=is_malicious,
                source="virustotal",
                last_checked=datetime.now(timezone.utc).isoformat(),
                confidence=round(confidence, 3),
                detail=(
                    f"{malicious_count}/{total_engines} VirusTotal engines flagged this domain as malicious."
                    if is_malicious else
                    f"VirusTotal: {malicious_count}/{total_engines} engines flagged (threshold: 3)."
                ),
            )

        except (httpx.TimeoutException, httpx.ConnectError) as e:
            print(f"[SafeClick] VirusTotal network error for {domain}: {e}")
            return None
        except Exception as e:
            print(f"[SafeClick] VirusTotal unexpected error for {domain}: {e}")
            return None

    # ── Private: OpenPhish feed ───────────────────────────────────────────────

    async def _refresh_openphish_feed(self) -> None:
        """
        Fetch the OpenPhish community feed and extract malicious domains.
        Feed format: one phishing URL per line, e.g.:
            https://phishing.example.com/steal-creds
            http://another.phishing.tk/verify
        """
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(OPENPHISH_FEED_URL)

            if not response.is_success:
                print(f"[SafeClick] OpenPhish feed returned {response.status_code}")
                self._openphish_loaded = True  # Mark as attempted even if failed
                return

            domains: set[str] = set()
            for line in response.text.splitlines():
                line = line.strip()
                if not line or not line.startswith("http"):
                    continue
                try:
                    # Extract hostname from URL
                    match = re.match(r"https?://([^/?\s]+)", line)
                    if match:
                        hostname = match.group(1).lower().split(":")[0]
                        # Extract registered domain (eTLD+1 approximation)
                        registered = self._extract_registered_domain(hostname)
                        if registered:
                            domains.add(registered)
                            domains.add(hostname)
                except Exception:
                    continue

            self._openphish_domains = domains
            self._openphish_loaded = True
            print(f"[SafeClick] OpenPhish feed loaded: {len(domains)} malicious domains cached.")

        except (httpx.TimeoutException, httpx.ConnectError) as e:
            print(f"[SafeClick] OpenPhish feed fetch failed (network): {e}")
            self._openphish_loaded = True  # Don't block startup
        except Exception as e:
            print(f"[SafeClick] OpenPhish feed fetch failed: {e}")
            self._openphish_loaded = True

    def _extract_registered_domain(self, hostname: str) -> Optional[str]:
        """Simple eTLD+1 extraction for OpenPhish feed processing."""
        labels = hostname.split(".")
        if len(labels) < 2:
            return None
        return ".".join(labels[-2:])

    # ── Private: Redis (optional) ─────────────────────────────────────────────

    async def _try_connect_redis(self) -> None:
        """Try to connect to Redis; silently skip if unavailable."""
        if not REDIS_URL:
            return
        try:
            import redis.asyncio as aioredis  # type: ignore
            self._redis = aioredis.from_url(REDIS_URL, decode_responses=True)
            await self._redis.ping()
            self._redis_available = True
            print(f"[SafeClick] Redis connected: {REDIS_URL}")
        except Exception as e:
            print(f"[SafeClick] Redis unavailable (falling back to in-process cache): {e}")
            self._redis = None
            self._redis_available = False

    async def _get_from_redis(self, domain: str) -> Optional[ReputationResult]:
        """Retrieve cached result from Redis."""
        try:
            import json
            data = await self._redis.get(f"safeclick:rep:{domain}")
            if data:
                d = json.loads(data)
                return ReputationResult(**d)
        except Exception:
            pass
        return None

    async def _set_in_redis(self, domain: str, result: ReputationResult) -> None:
        """Store result in Redis with TTL."""
        try:
            import json
            import dataclasses
            await self._redis.setex(
                f"safeclick:rep:{domain}",
                REPUTATION_CACHE_TTL,
                json.dumps(dataclasses.asdict(result)),
            )
        except Exception:
            pass
