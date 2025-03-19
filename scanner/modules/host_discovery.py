import scapy.all as scapy
import ipaddress

class HostDiscovery:
    def __init__(self, target):
        self.target = target
        
    def discover(self):
        if '/' in self.target:
            return self._arp_scan()
        else:
            return [self.target] if self._icmp_ping() else []
    
    def _arp_scan(self):
        ans, _ = scapy.srp(
            scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=self.target),
            timeout=2, verbose=0
        )
        return [rcv.psrc for snd, rcv in ans]
    
    def _icmp_ping(self):
        ans, _ = scapy.sr(scapy.IP(dst=self.target)/scapy.ICMP(), 
                         timeout=2, verbose=0)
        return len(ans) > 0