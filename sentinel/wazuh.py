"""Wazuh Manager API and OpenSearch indexer helpers."""

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def get_token(api_url: str, user: str, password: str) -> str | None:
    """Authenticate with the Wazuh API and return a JWT token."""
    try:
        r = requests.post(
            f"{api_url}/security/user/authenticate",
            auth=(user, password),
            verify=False,
            timeout=10,
        )
        return r.json()["data"]["token"]
    except Exception:
        return None


def api_get(api_url: str, endpoint: str, token: str) -> dict:
    """GET a Wazuh Manager API endpoint."""
    try:
        r = requests.get(
            f"{api_url}{endpoint}",
            headers={"Authorization": f"Bearer {token}"},
            verify=False,
            timeout=10,
        )
        return r.json()
    except Exception:
        return {}


def indexer_search(indexer_url: str, user: str, password: str, query: dict) -> dict:
    """Search the Wazuh OpenSearch indexer."""
    try:
        r = requests.post(
            f"{indexer_url}/wazuh-alerts-*/_search",
            auth=(user, password),
            json=query,
            verify=False,
            timeout=10,
        )
        return r.json()
    except Exception:
        return {}
