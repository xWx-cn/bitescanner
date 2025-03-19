import pytest

@pytest.fixture(scope="session")
def test_config():
    return {
        "test_host": "127.0.0.1",
        "test_ports": [80, 443]
    }