import os
import ipaddress
import logging
from typing import Union

def setup_logger(name: str, log_level: int = logging.INFO) -> logging.Logger:
    """配置日志记录器"""
    logger = logging.getLogger(name)
    if logger.handlers:  # 避免重复添加handler
        return logger
    
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        '%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(log_level)
    return logger

def validate_ip(ip: str) -> bool:
    """验证IPv4/IPv6地址有效性"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def parse_ports(port_str: Union[str, List[int]]) -> List[int]:
    """将端口字符串解析为列表"""
    if isinstance(port_str, list):
        return port_str
        
    ports = []
    for part in port_str.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.extend(range(start, end+1))
        else:
            ports.append(int(part))
    return ports