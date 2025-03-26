import time
import socket
import random
import scapy.all as scapy
from scapy.layers.inet import TCP, IP

class PortScanner:
    def __init__(self, host, ports, scan_type='connect', timeout=2.0, rate_limit=None):
        self.host = host
        self.ports = random.sample(ports, len(ports)) if scan_type == 'syn' else ports  # 兼容旧版随机化
        self.scan_type = scan_type
        self.timeout = timeout
        self.rate_limit = rate_limit
    
    def run(self):
        if self.scan_type == 'syn':
            return self._syn_scan()
        elif self.scan_type == 'connect':
            return self._connect_scan()
        else:
            raise ValueError("不支持的扫描类型")
    
    def _syn_scan(self):
        open_ports = []
        packet = IP(dst=self.host)/TCP(flags="S", dport=self.ports)
        
        if self.rate_limit:
            interval = 1.0 / self.rate_limit
            for port in self.ports:
                scapy.send(packet, verbose=0)
                time.sleep(interval)
        else:
            ans, _ = scapy.srp(packet, timeout=self.timeout, verbose=0)
            open_ports = [snd[TCP].dport for snd, rcv in ans if rcv[TCP].flags == 0x12]
        
        return open_ports
    
    def _connect_scan(self):
        open_ports = []
        for port in self.ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(self.timeout)
                    if s.connect_ex((self.host, port)) == 0:
                        open_ports.append(port)
            except:
                pass
        return open_ports