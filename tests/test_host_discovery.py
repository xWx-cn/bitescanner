import pytest
from scanner.modules.host_discovery import HostDiscovery

class TestHostDiscovery:
    @pytest.mark.parametrize("target,expected", [
        ("192.168.56.101", True),    # 单IP测试
        ("192.168.56.0/30", 2),      # CIDR测试（期望2个主机）
        ("invalid_ip", False)        # 无效IP测试
    ])
    def test_discover(self, target, expected):
        result = HostDiscovery(target).discover()
        if isinstance(expected, bool):
            assert bool(result) == expected
        else:
            assert len(result) == expected