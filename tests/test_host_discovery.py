import pytest
from scanner.modules.host_discovery import HostDiscovery

class TestHostDiscovery:
    @pytest.mark.parametrize("target,expected", [
        ("127.0.0.1", True),
        ("invalid_ip", False)
    ])
    def test_icmp_ping(self, target, expected):
        result = HostDiscovery(target)._icmp_ping()
        assert bool(result) == expected

    def test_arp_scan(self):
        # 需在测试环境中设置已知设备
        targets = HostDiscovery("192.168.1.0/24").discover()
        assert isinstance(targets, list)