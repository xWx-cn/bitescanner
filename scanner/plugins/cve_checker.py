from typing import Dict, List
import re
import logging
from scanner.plugins import BasePlugin

class CVECheckerPlugin(BasePlugin):
    def __init__(self, cve_db: Dict):
        self.cve_db = cve_db
        self.logger = logging.getLogger("CVEChecker")
    
    def check(self, host: str, port: int, banner: str) -> List[str]:
        """实现CVE检测插件逻辑"""
        vulns = []
        for sw in self.cve_db:
            if re.search(sw, banner, re.IGNORECASE):
                match = re.search(self.cve_db[sw]['pattern'], banner)
                if match and match.group(1) in self.cve_db[sw]['vulnerable']:
                    vulns.extend(self.cve_db[sw]['cves'])
                    self.logger.info(f"发现 {sw} 漏洞: {self.cve_db[sw]['cves']}")
        return vulns