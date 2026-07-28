"""
backend/tests/test_reputation.py
────────────────────────────────────────────────────────────────────────────
Pytest tests for:
1. ReputationService — OpenPhish feed parsing, TTL cache, VT lookup
2. GET /api/v1/reputation endpoint — contract, error cases
"""

import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from httpx import AsyncClient, Response

# We test the API endpoint via the FastAPI test client
from fastapi.testclient import TestClient


# ── Fixtures ───────────────────────────────────────────────────────────────────

@pytest.fixture
def mock_openphish_feed():
    """Mock OpenPhish feed with 3 phishing URLs."""
    return (
        "https://phishing-example-test.tk/login\n"
        "http://fakebank-example.ga/verify\n"
        "https://paypal-secure-fake-test.xyz/signin\n"
        "# not a url line\n"
        "\n"
    )


@pytest.fixture
def reputation_service():
    """Create a ReputationService with mocked initialization."""
    from services.reputation_service import ReputationService
    svc = ReputationService()
    # Pre-populate the openphish domains without network call
    svc._openphish_domains = {
        "phishing-example-test.tk",
        "fakebank-example.ga",
        "paypal-secure-fake-test.xyz",
    }
    svc._openphish_loaded = True
    return svc


@pytest.fixture
def app_with_service(reputation_service):
    """FastAPI app with a pre-configured reputation service."""
    import sys
    import os
    # Add parent dir so imports resolve
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
    from main import app
    app.state.reputation_service = reputation_service
    return app


# ── ReputationService unit tests ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_openphish_known_malicious(reputation_service):
    """Domain in OpenPhish cache → known_malicious=True."""
    result = await reputation_service.check_domain("phishing-example-test.tk")
    assert result.known_malicious is True
    assert result.source == "openphish"
    assert result.confidence > 0


@pytest.mark.asyncio
async def test_unknown_domain_returns_unavailable(reputation_service):
    """Unknown domain (not in OpenPhish, no VT key) → known_malicious=False, source=unavailable."""
    result = await reputation_service.check_domain("totally-unknown-safe-example.com")
    assert result.known_malicious is False
    assert result.source in ("unavailable",)
    assert result.confidence == 0.0


@pytest.mark.asyncio
async def test_caching_returns_cached_result(reputation_service):
    """Second lookup for same domain uses cache."""
    # First call
    result1 = await reputation_service.check_domain("phishing-example-test.tk")
    assert result1.known_malicious is True

    # Second call — should hit cache
    result2 = await reputation_service.check_domain("phishing-example-test.tk")
    # Cache returns source="cache"
    assert result2.source == "cache"
    assert result2.known_malicious is True  # Cached verdict preserved


@pytest.mark.asyncio
async def test_www_prefix_stripping(reputation_service):
    """www.phishing-example-test.tk should match phishing-example-test.tk in feed."""
    result = await reputation_service.check_domain("www.phishing-example-test.tk")
    assert result.known_malicious is True


@pytest.mark.asyncio
async def test_openphish_feed_parsing(mock_openphish_feed):
    """Test that OpenPhish feed is parsed and malicious domains extracted."""
    from services.reputation_service import ReputationService
    import respx
    import httpx

    svc = ReputationService()

    with respx.mock:
        respx.get("https://openphish.com/feed.txt").mock(
            return_value=httpx.Response(200, text=mock_openphish_feed)
        )
        await svc._refresh_openphish_feed()

    assert svc._openphish_loaded is True
    assert len(svc._openphish_domains) > 0
    # Check extracted domains
    assert any("phishing-example-test" in d for d in svc._openphish_domains)


@pytest.mark.asyncio
async def test_openphish_feed_network_failure_is_graceful():
    """Network failure fetching OpenPhish feed → service still initializes (graceful)."""
    from services.reputation_service import ReputationService
    import respx
    import httpx

    svc = ReputationService()
    with respx.mock:
        respx.get("https://openphish.com/feed.txt").mock(
            side_effect=httpx.ConnectError("Connection refused")
        )
        await svc._refresh_openphish_feed()

    # Service should still be marked as loaded (no blocking)
    assert svc._openphish_loaded is True
    assert len(svc._openphish_domains) == 0  # Empty but didn't crash


@pytest.mark.asyncio
async def test_virustotal_malicious_verdict():
    """VT API returning ≥3 malicious engines → known_malicious=True."""
    from services.reputation_service import ReputationService
    import respx
    import httpx

    svc = ReputationService()
    svc._openphish_loaded = True
    svc._openphish_domains = set()

    mock_vt_response = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 5,
                    "suspicious": 1,
                    "harmless": 60,
                    "undetected": 10,
                }
            }
        }
    }

    with patch("services.reputation_service.VIRUSTOTAL_API_KEY", "fake-test-key"):
        with respx.mock:
            respx.get(
                "https://www.virustotal.com/api/v3/domains/evil-test-example.com"
            ).mock(return_value=httpx.Response(200, json=mock_vt_response))

            result = await svc.check_domain("evil-test-example.com")

    assert result.known_malicious is True
    assert result.source == "virustotal"
    assert "5/" in result.detail  # "5/76 VirusTotal engines..."


@pytest.mark.asyncio
async def test_virustotal_clean_verdict():
    """VT returning <3 malicious engines → known_malicious=False."""
    from services.reputation_service import ReputationService
    import respx
    import httpx

    svc = ReputationService()
    svc._openphish_loaded = True
    svc._openphish_domains = set()

    mock_vt_response = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 1,
                    "suspicious": 0,
                    "harmless": 70,
                    "undetected": 5,
                }
            }
        }
    }

    with patch("services.reputation_service.VIRUSTOTAL_API_KEY", "fake-test-key"):
        with respx.mock:
            respx.get(
                "https://www.virustotal.com/api/v3/domains/clean-example.com"
            ).mock(return_value=httpx.Response(200, json=mock_vt_response))

            result = await svc.check_domain("clean-example.com")

    assert result.known_malicious is False
    assert result.source == "virustotal"


@pytest.mark.asyncio
async def test_virustotal_timeout_falls_back_to_unavailable():
    """VT timeout → graceful fallback to unavailable."""
    from services.reputation_service import ReputationService
    import respx
    import httpx

    svc = ReputationService()
    svc._openphish_loaded = True
    svc._openphish_domains = set()

    with patch("services.reputation_service.VIRUSTOTAL_API_KEY", "fake-test-key"):
        with respx.mock:
            respx.get(
                "https://www.virustotal.com/api/v3/domains/timeout-example.com"
            ).mock(side_effect=httpx.TimeoutException("Timeout"))

            result = await svc.check_domain("timeout-example.com")

    assert result.known_malicious is False
    assert result.source == "unavailable"


# ── API Endpoint tests ─────────────────────────────────────────────────────────

def test_reputation_endpoint_returns_200(app_with_service):
    """GET /api/v1/reputation?domain=example.com → 200."""
    with TestClient(app_with_service) as client:
        response = client.get("/api/v1/reputation?domain=example.com")
    assert response.status_code == 200
    data = response.json()
    assert "domain" in data
    assert "known_malicious" in data
    assert "source" in data
    assert "confidence" in data
    assert "last_checked" in data


def test_reputation_endpoint_schema(app_with_service):
    """Verify all required fields are present and correctly typed."""
    with TestClient(app_with_service) as client:
        response = client.get("/api/v1/reputation?domain=example.com")
    data = response.json()

    assert isinstance(data["domain"], str)
    assert isinstance(data["known_malicious"], bool)
    assert isinstance(data["confidence"], float)
    assert 0.0 <= data["confidence"] <= 1.0
    assert isinstance(data["last_checked"], str)
    assert data["source"] in [
        "virustotal", "openphish", "local_blocklist",
        "top_domain_list", "unavailable", "cache"
    ]


def test_reputation_endpoint_known_malicious_domain(app_with_service):
    """Known malicious domain → known_malicious=True in response."""
    with TestClient(app_with_service) as client:
        response = client.get("/api/v1/reputation?domain=phishing-example-test.tk")
    data = response.json()
    assert data["known_malicious"] is True


def test_reputation_endpoint_missing_domain_param(app_with_service):
    """Missing domain param → 422 Unprocessable Entity."""
    with TestClient(app_with_service) as client:
        response = client.get("/api/v1/reputation")
    assert response.status_code == 422


def test_reputation_endpoint_invalid_domain(app_with_service):
    """Domain without TLD → 400 Bad Request."""
    with TestClient(app_with_service) as client:
        response = client.get("/api/v1/reputation?domain=notadomain")
    assert response.status_code == 400


def test_health_endpoint(app_with_service):
    """Health check endpoint returns ok."""
    with TestClient(app_with_service) as client:
        response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
