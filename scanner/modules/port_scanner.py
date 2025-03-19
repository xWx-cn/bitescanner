import scapy.all as scapy
import socket
import random

class PortScanner:
    def __init__(self, host, ports, scan_type):
        self.host = host
        self.ports = random.sample(ports, len(ports))
        self.scan_type = scan_type
    
    def run(self):
        return self._syn_scan() if self.scan_type == 'syn' else self._connect_scan()
    
    def _syn_scan(self):
        ans, _ = scapy.sr(
            scapy.IP(dst=self.host)/scapy.TCP(dport=self.ports, flags="S"),
            timeout=2, verbose=0
        )
        return [snd.dport for snd, rcv in ans if rcv.flags == 0x12]
    
    def _connect_scan(self):
        open_ports = []
        for port in self.ports:
            with socket.socket() as sock:
                sock.settimeout(1)
                if sock.connect_ex((self.host, port)) == 0:
                    open_ports.append(port)
        return open_ports