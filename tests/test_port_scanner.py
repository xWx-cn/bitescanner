import pytest
from scanner.modules.port_scanner import PortScanner

@pytest.fixture
def localhost_scanner():
    return PortScanner("127.0.0.1", [80, 443], "connect")

class TestPortScanner:
    def test_connect_scan(self, localhost_scanner):
        open_ports = localhost_scanner.run()
        assert isinstance(open_ports, list)