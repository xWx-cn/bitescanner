from abc import ABC, abstractmethod

class BasePlugin(ABC):
    """插件基类"""
    @abstractmethod
    def check(self, host, port, banner):
        pass

class CVECheckerPlugin(BasePlugin):
    """CVE检测插件"""
    def __init__(self, cve_db_path):
        import json
        with open(cve_db_path) as f:
            self.cve_db = json.load(f)

    def check(self, host, port, banner):
        vulnerabilities = []
        for sw in self.cve_db:
            if sw in banner:
                vulns = self._match_version(banner, sw)
                vulnerabilities.extend(vulns)
        return vulnerabilities

    def _match_version(self, banner, software):
        import re
        pattern = self.cve_db[software]['pattern']
        match = re.search(pattern, banner)
        if match and match.group(1) in self.cve_db[software]['vulnerable']:
            return self.cve_db[software]['cves']
        return []