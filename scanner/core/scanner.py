import os
import logging
from concurrent.futures import ThreadPoolExecutor
from ..modules.host_discovery import HostDiscovery
from ..modules.port_scanner import PortScanner
from ..modules.vulnerability import VulnerabilityDetector
from ..report.report_gen import ScanReport
from .exceptions import PrivilegeError

class SecurityScanner:
    def __init__(self, target, ports, scan_type='connect', threads=100, 
                 timeout=2.0, rate_limit=None, cve_db_path=None, 
                 password_list_path=None, skip_brute=False, top_ports=None):
        
        # 基础参数
        self.target = target
        self.ports = self._process_ports(ports, top_ports)
        self.scan_type = scan_type
        self.threads = threads
        self.timeout = timeout
        self.rate_limit = rate_limit
        
        # 漏洞检测参数
        self.cve_db_path = cve_db_path or os.path.join('scanner', 'data', 'cve_db.json')
        self.password_list_path = password_list_path or os.path.join('scanner', 'data', 'weak_passwords.txt')
        self.skip_brute = skip_brute
        
        # 初始化检测
        self._check_permissions()
        
    def _process_ports(self, ports, top_ports):
        if top_ports:
            return [80, 443, 22, 21, 25, 3389][:top_ports]
        return ports or [21, 22, 80, 443, 3306, 3389] 
    
    def _check_permissions(self):
        if self.scan_type == 'syn' and os.name == 'posix' and os.getuid() != 0:
            raise PrivilegeError("SYN扫描需要root权限")
    
    def run_scan(self):
        # 主机发现（CIDR/IP范围）
        hosts = HostDiscovery(self.target).discover()
        if not hosts:
            return ScanReport([])
        
        # 多线程扫描（线程参数）
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self._scan_host, host) for host in hosts]
            results = [f.result() for f in futures]
        
        return ScanReport(results)
    
    def _scan_host(self, host):
        # 端口扫描
        port_scanner = PortScanner(
            host=host,
            ports=self.ports,
            scan_type=self.scan_type,
            timeout=self.timeout,
            rate_limit=self.rate_limit
        )
        open_ports = port_scanner.run()
        
        # 漏洞检测
        vuln_detector = VulnerabilityDetector(
            host=host,
            ports=open_ports,
            cve_db_path=self.cve_db_path,
            password_list_path=self.password_list_path,
            skip_brute=self.skip_brute
        )
        vulnerabilities = vuln_detector.check_all()
        
        return {
            'ip': host,
            'ports': open_ports,
            'vulnerabilities': vulnerabilities
        }