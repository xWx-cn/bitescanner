import scapy.all as scapy
import ipaddress
import logging
from typing import List, Union

class HostDiscovery:
    def __init__(self, target: str, interface: str = None):
        self.target = target
        self.interface = interface or scapy.conf.iface.name
        self.logger = logging.getLogger("HostDiscovery")
        self._validate_target()

    def _validate_target(self) -> None:
        """严格验证目标格式"""
        try:
            if '/' in self.target:
                ipaddress.IPv4Network(self.target, strict=False)
            else:
                ipaddress.IPv4Address(self.target)
        except ValueError as e:
            raise ValueError(f"无效的目标格式: {self.target}") from e

    def discover(self) -> List[str]:
        """执行主机发现（自动选择最佳探测方式）"""
        try:
            if self._is_local_network():
                return self._arp_scan()
            return self._icmp_scan() or self._tcp_scan()
        except PermissionError:
            self.logger.error("需要root权限执行ARP/TCP扫描")
            return []
        except Exception as e:
            self.logger.error(f"主机发现失败: {str(e)}")
            return []

    def _is_local_network(self) -> bool:
        """判断目标是否在本地网络"""
        if '/' not in self.target:
            target_ip = ipaddress.IPv4Address(self.target)
            local_ips = [ipaddress.IPv4Address(ip) for ip in scapy.get_if_addr()]
            return any(target_ip in ip.network for ip in local_ips)
        return True

    def _arp_scan(self) -> List[str]:
        """ARP扫描（局域网专用）"""
        self.logger.info(f"启动ARP扫描: {self.target}")
        try:
            ans, _ = scapy.srp(
                scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=self.target),
                timeout=2,
                iface=self.interface,
                verbose=0,
                retry=2
            )
            return [rcv[scapy.ARP].psrc for _, rcv in ans]
        except scapy.Scapy_Exception as e:
            self.logger.error(f"ARP扫描异常: {str(e)}")
            return []

    def _icmp_scan(self) -> List[str]:
        """ICMP Ping扫描（跨网络）"""
        self.logger.info(f"尝试ICMP Ping: {self.target}")
        try:
            ans, _ = scapy.sr(
                scapy.IP(dst=self.target)/scapy.ICMP(),
                timeout=2,
                iface=self.interface,
                verbose=0,
                retry=1
            )
            return [self.target] if ans else []
        except scapy.Scapy_Exception as e:
            self.logger.warning(f"ICMP检测失败: {str(e)}")
            return []

    def _tcp_scan(self) -> List[str]:
        """TCP SYN扫描（备用方案）"""
        self.logger.info(f"尝试TCP SYN探测: {self.target}")
        try:
            ans, _ = scapy.sr(
                scapy.IP(dst=self.target)/scapy.TCP(dport=80,flags="S"),
                timeout=2,
                iface=self.interface,
                verbose=0
            )
            return [self.target] if any(rcv[scapy.TCP].flags == 0x12 for _, rcv in ans) else []
        except scapy.Scapy_Exception as e:
            self.logger.warning(f"TCP扫描异常: {str(e)}")
            return []