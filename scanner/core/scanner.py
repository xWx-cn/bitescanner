import os
import sys
from concurrent.futures import ThreadPoolExecutor
from ..modules.host_discovery import HostDiscovery
from ..modules.port_scanner import PortScanner
from ..modules.vulnerability import VulnerabilityDetector
from ..report.report_gen import ScanReport
from .exceptions import PrivilegeError

class SecurityScanner:
    def __init__(self, target, ports):
        self.target = target
        self.ports = ports
        self.scan_type = self._check_privilege()
        
    def _check_privilege(self):
        if os.name == 'posix' and os.getuid() != 0:
            raise PrivilegeError()
        return 'syn' if os.name == 'posix' else 'connect'

    def run_scan(self):
        hosts = HostDiscovery(self.target).discover()
        with ThreadPoolExecutor(max_workers=50) as executor:
            results = list(executor.map(self._scan_host, hosts))
        return ScanReport(results)

    def _scan_host(self, host):
        ports = PortScanner(host, self.ports, self.scan_type).run()
        vulns = VulnerabilityDetector(host, ports).check_all()
        return {'ip': host, 'ports': ports, 'vulnerabilities': vulns}