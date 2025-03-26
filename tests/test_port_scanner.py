import pytest
from scanner.modules.port_scanner import PortScanner

@pytest.fixture
def local_scanner():
    return PortScanner("127.0.0.1", [80, 443], "connect")

class TestPortScanner:
    def test_connect_scan(self, local_scanner):
        open_ports = local_scanner.run()
        assert isinstance(open_ports, list)
        assert 80 in open_ports or 443 in open_ports  # 假设本地有服务运行
    
    def test_invalid_scan_type(self):
        with pytest.raises(ValueError):
            PortScanner("127.0.0.1", [80], "invalid_type").run()