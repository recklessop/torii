"""The bare hostname should land a human somewhere useful.

A 404 at `/` reads as "this service is broken" to anyone who types the
hostname into a browser, which is exactly what happened the first time the
dev-host deploy was opened by hand.
"""

import httpx
import pytest

from torii import app as app_module


@pytest.fixture
def client():
    transport = httpx.ASGITransport(app=app_module.app)
    return httpx.AsyncClient(
        transport=transport, base_url="http://test", follow_redirects=False
    )


async def test_root_redirects_to_the_ui(client):
    async with client as http:
        response = await http.get("/")
    assert response.status_code == 302
    assert response.headers["location"] == "/ui"


async def test_root_does_not_404(client):
    """Regression: the whole point of the route."""
    async with client as http:
        response = await http.get("/")
    assert response.status_code != 404
